// Package ipc is the channel between the window a person uses and the component
// that runs the tunnel.
//
// It is small, and the smallness is the design. The component decides for
// itself: it reads the configuration out of the device, verifies its MAC, and
// makes its own calls at every handshake. So it is not told what to do step by
// step — it is told which identity, which peer, and given a token to act with.
// Four verbs and a stream of events cover it. See docs/ARCHITECTURE-GUI.md.
//
// What crosses is a scoped, expiring token and nothing else. Not the passphrase,
// not key material, not the configuration. A test holds that, because a struct
// grows a field at a time and each one is convenient on its own.
//
// The transport is deliberately io.Reader and io.Writer rather than a socket
// type. The arrangement this replaces had to pass a file descriptor, which tied
// it to a unix socket and had no Windows counterpart at all; here the component
// creates the descriptor and keeps it, so the same framing runs over a unix
// socket and a named pipe without knowing which it is.
package ipc

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/version"
)

// Op names what the window is asking for. Strings rather than integers so a
// mismatched pair fails legibly rather than performing the wrong operation
// because the numbering drifted.
type Op string

const (
	// OpStart brings a tunnel up: which identity, which peer, and a token to
	// act with. Refused when one is already running — one window, one tunnel.
	OpStart Op = "start"

	// OpStop takes it down and leaves the component idle.
	OpStop Op = "stop"

	// OpRefresh replaces the token mid-session.
	//
	// Renewal is a human act and the human is at the window: the session ends
	// when the token expires, and without this verb the only thing the window
	// could offer is to disconnect and start again.
	OpRefresh Op = "refresh"

	// OpWhoami asks the component two things it can answer without being
	// trusted: which build it is, and who it thinks the caller is.
	//
	// It carries no token and changes nothing, and it exists because the two
	// questions it answers are the two that fail silently. A build mismatch is
	// refused at OpStart with both numbers named, but only once somebody has
	// typed a passphrase; and the caller's identity is the whole of the
	// authorisation here, computed from the connection rather than from anything
	// sent, so nothing on either side would notice it being wrong. On Windows it
	// is how a caller finds out that the pipe reported them as ANONYMOUS LOGON.
	//
	// Telling somebody their own identity grants nothing: it is the answer the
	// component would act on anyway, and they are the only one who receives it.
	OpWhoami Op = "whoami"
)

// Build identifies which artifact is speaking, closely enough to refuse a pair
// that should not be talking.
//
// Release carries the commit when build.sh stamped it, so a window and a
// component from different builds recognise each other as different.
//
// Descr is the record length, and it is here because of how badly the mismatch
// presents. A 128-byte window against a 64-byte component does not fail to
// start: the record length is inside the configuration MAC, so it fails at
// verification — which is what a tampered configuration looks like. Refusing by
// name at the handshake is the difference between "these two builds disagree"
// and a security warning about nothing.
type Build struct {
	Release string `json:"release"`
	Descr   int    `json:"descr"`
}

// Current describes the build this code is part of.
func Current() Build {
	return Build{Release: version.Version, Descr: descr.Size}
}

func (b Build) String() string { return fmt.Sprintf("%s (descr %d B)", b.Release, b.Descr) }

// Matches reports whether two builds may drive each other.
func (b Build) Matches(other Build) bool {
	return b.Release == other.Release && b.Descr == other.Descr
}

// Request is everything the component is ever told.
//
// Token is the one secret here and it is meant to be: scoped to a single
// interface key and expiring on its own, it is what the component acts with and
// the reason it needs nothing else. There is no passphrase, no pre-shared key
// and no configuration — it reads that itself.
//
// There is no field for skipping TLS verification, and there must never be. A
// person typing a flag about their own session is one thing; a message telling a
// privileged process to stop checking certificates is not the same act.
type Request struct {
	Op    Op    `json:"op"`
	Build Build `json:"build,omitempty"`

	HEMURL   string `json:"hem_url,omitempty"`
	Identity string `json:"identity,omitempty"` // interface key id
	Peer     string `json:"peer,omitempty"`     // peer key id

	// Token is the session's credential, scoped keymgmt:use:<Identity>, and the
	// only one. It is what the component acts with at every handshake, for as
	// long as the tunnel is up, and it is the one whose theft the threat model
	// is about.
	Token string `json:"token,omitempty"`

	// PubKeys are the public keys the component would otherwise read from the
	// device one call at a time, by identifier, base64 as the device gives them.
	//
	// They are here so that `keymgmt:get` does not have to be, and the handover
	// is one token rather than a bundle. Supplying them is safe for a reason
	// unrelated to trusting whoever supplied them: `KID = SHA-1(pubkey)[0:16]`
	// (§3), so a key is checked against the identifier it claims, and offering a
	// different one is a second-preimage attack rather than a substitution.
	//
	// What is *not* supplied is the records. The component reads those itself,
	// freshly, because a MAC authenticates a tree without saying which version
	// of it is current — an old configuration replayed would verify perfectly
	// well, and a fresh search is the only thing that notices.
	//
	// Public information, all of it: §8 treats records and public keys as such.
	PubKeys map[string]string `json:"pubkeys,omitempty"`
}

// Type discriminates what came back: an answer to a request, or something that
// happened.
type Type string

const (
	TypeReply Type = "reply"
	TypeEvent Type = "event"
)

// Msg is one thing the component sent. Replies and events share a stream
// because they share a connection, and a window reads them in the order they
// happened.
type Msg struct {
	Type  Type   `json:"type"`
	Reply *Reply `json:"reply,omitempty"`
	Event *Event `json:"event,omitempty"`
}

// Reply answers a request.
type Reply struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`

	// Kind names what sort of thing went wrong, in the vocabulary of
	// internal/session. A window shows a different screen for a device that
	// refused, one that could not be reached, a passphrase that was not
	// accepted and a configuration that does not authenticate; without this it
	// would be parsing prose to tell them apart.
	Kind string `json:"kind,omitempty"`

	// Build is answered on start, so a refusal names both sides rather than
	// leaving somebody to work out which half is old.
	Build *Build `json:"build,omitempty"`

	// Who is answered on whoami: the caller as the component identified them,
	// in whatever terms the platform gave — a uid on Linux, a SID on Windows.
	Who string `json:"who,omitempty"`
}

// Event is what the window draws. A snapshot rather than a delta: a late
// subscriber cannot end up displaying a state that was never true.
type Event struct {
	State     string `json:"state"`
	Interface string `json:"interface,omitempty"`

	// Addrs is what the interface was given, in CIDR form. The window shows it
	// because it is the one thing about a tunnel a person is asked for by
	// somebody else — "what is your address on the VPN" — and reading it out of
	// `ip addr` means knowing the interface name first.
	Addrs []string `json:"addrs,omitempty"`

	Peer     string `json:"peer,omitempty"` // label
	PeerKID  string `json:"peer_kid,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`

	Rx uint64 `json:"rx,omitempty"`
	Tx uint64 `json:"tx,omitempty"`

	LastHandshake time.Time `json:"last_handshake,omitempty"`

	// ExpiresAt is read from the token, never computed from the lifetime asked
	// for. A soak on 2026-08-11 requested eight hours and ended after seven and
	// a half; a countdown derived from the request would have been wrong by
	// twenty-seven minutes, in the direction that strands somebody.
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Notice carries something worth telling the user that is not an error —
	// failover having moved to another peer, most of all.
	Notice string `json:"notice,omitempty"`
}

// Encode and Decode are here rather than inlined so both ends share one
// definition of the wire format, and so a test can round-trip it without a
// connection.
func Encode(v any) ([]byte, error) { return json.Marshal(v) }

func DecodeRequest(b []byte) (Request, error) {
	var r Request
	err := json.Unmarshal(b, &r)
	return r, err
}

func DecodeMsg(b []byte) (Msg, error) {
	var m Msg
	err := json.Unmarshal(b, &m)
	return m, err
}

// Validate rejects a request the component should not act on. It runs there, not
// in the window: a caller asking nicely is not a control, and a component that
// trusts whatever reaches its socket is only as safe as the socket's permissions
// — which are the actual control, and are set elsewhere.
func (r Request) Validate() error {
	switch r.Op {
	case OpStart:
		if r.HEMURL == "" {
			return fmt.Errorf("start needs the address of the device")
		}
		if r.Identity == "" {
			return fmt.Errorf("start needs an interface key id: the token names one key and means nothing without it")
		}
		if r.Token == "" {
			return fmt.Errorf("start needs a token; the component authenticates nothing itself")
		}
		if r.Build.Release == "" {
			return fmt.Errorf("start needs to say which build is asking")
		}
	case OpRefresh:
		if r.Token == "" {
			return fmt.Errorf("refresh needs a token")
		}
	case OpStop, OpWhoami:
	default:
		return fmt.Errorf("unknown operation %q", r.Op)
	}
	return nil
}
