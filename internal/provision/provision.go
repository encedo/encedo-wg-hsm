// Package provision writes a complete WireGuard configuration into the module:
// an identity key, one imported key per peer, the addressing and routing in
// their descr fields, and a MAC over the whole tree. Nothing reaches disk.
//
// It was inside the command until the window needed it. `cmdProvision`
// interleaved flag parsing, validation and device work in one function and
// returned its result through fmt.Println, so nothing but os.Args could drive
// it - which meant the window could offer to import a configuration only by
// re-implementing what the command already did correctly, against a device
// nobody can unit-test. The split is Params in, Result out, progress through a
// callback, and refusals as errors carrying a kind rather than an exit code.
//
// What it deliberately does not do is decide anything. Which addresses, which
// peers, whether to adopt, where the pre-shared key comes from - all settled by
// the caller, because a command line and a window ask those questions in
// entirely different ways and neither should be the one this package assumes.
package provision

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strings"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/handoff"
	"github.com/encedo/encedo-wg-hsm/internal/mac"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// Params is a configuration to write, already validated as far as it can be
// without a device. Validate reports what is wrong; Run assumes it passed.
type Params struct {
	Addrs      []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	ListenPort int
	Label      string
	Peers      []PeerSpec

	// KID reuses an existing Curve25519 key instead of creating one. Empty
	// means create, which is the ordinary case.
	KID string

	// PSK is the raw pre-shared key, or nil for none. The caller owns it and
	// is the one that zeroes it; this package only wraps it, once per peer.
	PSK []byte

	// PSKGenerated says the caller made this key up rather than being given
	// it, which is the only case where the far end has to be told what it is.
	// It changes nothing about how the key is stored - only what Result says.
	PSKGenerated bool

	// Adopt reuses a peer already in the device even when its stored settings
	// differ from the ones asked for.
	Adopt bool
}

// Result is what a caller has to do something with afterwards: hand the public
// key to whoever runs the server, and show the pre-shared key once if there is
// one to show.
type Result struct {
	IfKID     string
	PublicKey string // base64
	PeerCount int

	// PSK is base64 and set only when Params.PSKGenerated was. The stored copy
	// is wrapped inside the device and cannot be read back, so this is the only
	// time it can be shown.
	PSK string

	// Server is the entry an administrator has to add at the far end.
	Server handoff.Peer
}

// Validate reports what is wrong with a set of parameters before any of it
// reaches a device.
//
// Separate from Run and exported, because a window wants to say "this is what
// would be written" while somebody is still looking at a file, and asking for a
// passphrase first to find out the MTU is out of range is the wrong order.
func (p Params) Validate() error {
	if len(p.Addrs) == 0 {
		return session.Fail(session.KindUsage, "at least one address is required")
	}
	if len(p.Peers) == 0 {
		return session.Fail(session.KindUsage, "at least one peer is required")
	}
	if len(p.Peers) > mac.MaxPeers {
		return session.Fail(session.KindUsage,
			"%d peers, but the device's message limit allows %d in one authenticated tree",
			len(p.Peers), mac.MaxPeers)
	}
	seen := map[string]bool{}
	for i, peer := range p.Peers {
		fp := string(peer.PubKey)
		if seen[fp] {
			return session.Fail(session.KindUsage, "peer #%d: duplicate public key", i+1)
		}
		seen[fp] = true
	}
	if p.MTU < 0 || p.MTU > 65535 {
		return session.Fail(session.KindUsage, "MTU out of range")
	}
	if p.ListenPort < 0 || p.ListenPort > 65535 {
		return session.Fail(session.KindUsage, "listen port out of range")
	}

	// Encode every record now, before the device is touched, so an over-budget
	// peer cannot leave a half-written configuration behind. The wrapped key is
	// a stand-in of the right length: what matters is how much room it takes.
	for i, peer := range p.Peers {
		probe := p.PSK
		if probe != nil {
			probe = make([]byte, descr.PSKWrappedLen)
		}
		if _, err := peer.Record(probe); err != nil {
			return session.Fail(session.KindUsage, "peer #%d (%s): %w", i+1, peer.Label, err)
		}
	}
	return nil
}

// Cleanup is what a failed run left behind, so a caller can say so in its own
// words rather than being handed a sentence written for a terminal.
//
// A key this run created, which no record yet names, is litter only this run
// can identify: `wipe` searches by the WG: prefix and a bare key carries none.
// So Run takes it back out, and reports here whether it managed to.
type Cleanup struct {
	// IdentityKID is the key the run created, when there is one worth naming -
	// either because it could not be removed, or because a re-run could reuse it.
	IdentityKID string

	// IdentityRemoved says the created key went back out cleanly.
	IdentityRemoved bool

	// RemovalErr is why it did not, when it did not.
	RemovalErr error

	// ImportedPeers is how many peer keys were written before the failure.
	// Named only when some actually were: pointing at a wipe for peers that
	// were never written sends somebody looking for what is not there.
	ImportedPeers int
}

// Run writes the configuration. notify receives progress in whole sentences and
// may be nil.
//
// On failure it reports through cleanup what state the device was left in,
// alongside the error. The rollback is narrow on purpose: an adopted key
// belongs to the caller, and once the interface record is written the tree may
// already be a working configuration, so a failure after that point is not
// licence to delete anything.
func Run(ctx context.Context, client *hem.Client, auth *session.Auth, p Params, notify func(string)) (res Result, cleanup Cleanup, err error) {
	if notify == nil {
		notify = func(string) {}
	}
	if err := p.Validate(); err != nil {
		return Result{}, Cleanup{}, err
	}

	ifKID := p.KID
	createdIdentity := false
	recordWritten := false
	imported := 0

	defer func() {
		if err == nil {
			return
		}
		cleanup.ImportedPeers = imported
		if createdIdentity && !recordWritten {
			cleanup.IdentityKID = ifKID
			if rmErr := deleteKey(ctx, client, auth, ifKID); rmErr != nil {
				cleanup.RemovalErr = rmErr
			} else {
				cleanup.IdentityRemoved = true
			}
			return
		}
		// Not removed, but still worth naming: a re-run can reuse it instead of
		// leaving a second key behind beside the first.
		cleanup.IdentityKID = ifKID
	}()

	if ifKID == "" {
		tok, tErr := auth.Token(ctx, "keymgmt:gen")
		if tErr != nil {
			return Result{}, cleanup, tErr
		}
		ifKID, err = client.CreateKey(ctx, tok, p.Label, keyType, nil, "")
		if err != nil {
			return Result{}, cleanup, session.Classify(err, session.KindDevice, "creating the identity key")
		}
		createdIdentity = true
		notify("Identity key created: " + ifKID)
	} else {
		notify("Reusing identity key " + ifKID)
	}

	useTok, err := auth.Token(ctx, "keymgmt:use:"+ifKID)
	if err != nil {
		return Result{}, cleanup, err
	}
	ifKey, err := client.GetPubKey(ctx, useTok, ifKID)
	if err != nil {
		return Result{}, cleanup, session.Classify(err, session.KindDevice, "reading the identity public key")
	}
	if ifKey.Type != "" && !strings.Contains(ifKey.Type, keyType) {
		return Result{}, cleanup, session.Fail(session.KindUsage,
			"key %s is of type %s, expected %s", ifKID, ifKey.Type, keyType)
	}
	if len(ifKey.PubKey) != pubKeyLen {
		return Result{}, cleanup, session.Fail(session.KindDevice,
			"identity public key is %d bytes, expected %d", len(ifKey.PubKey), pubKeyLen)
	}
	var ifPub [pubKeyLen]byte
	copy(ifPub[:], ifKey.PubKey)

	ifRec := descr.Interface{
		Addrs:      p.Addrs,
		MTU:        uint16(p.MTU),
		DNS:        p.DNS,
		ListenPort: uint16(p.ListenPort),
		HasMAC:     true,
	}
	var peerRecords []mac.PeerRecord
	for _, peer := range p.Peers {
		// The pre-shared key is wrapped once per peer, under a key that exists
		// only inside the device - the interface key's ECDH against itself,
		// bound to this peer. Wrapping under ECDH(interface, peer) would instead
		// hand the key-encryption key to whoever holds the peer's private key.
		wrapped, wErr := WrapPSK(ctx, client, useTok, ifKID, descr.KID(peer.PubKey), p.PSK)
		if wErr != nil {
			return Result{}, cleanup, wErr
		}
		rec, rErr := peer.Record(wrapped)
		if rErr != nil {
			return Result{}, cleanup, session.Fail(session.KindUsage, "peer %s: %w", peer.Label, rErr)
		}
		enc, eErr := rec.Encode()
		if eErr != nil {
			return Result{}, cleanup, session.Fail(session.KindUsage, "peer %s: %w", peer.Label, eErr)
		}
		_, adopted, pErr := PlacePeer(ctx, client, auth, peer, enc, p.Adopt, notify)
		if pErr != nil {
			return Result{}, cleanup, pErr
		}
		if adopted {
			// The stored record is what the tree must authenticate, not the one
			// the caller described.
			stored, sErr := ReadPeerRecord(ctx, client, auth, descr.KID(peer.PubKey))
			if sErr != nil {
				return Result{}, cleanup, sErr
			}
			enc = *stored
		}
		// Reference order is failover priority, so it follows the given order.
		ifRec.PeerRefs = append(ifRec.PeerRefs, descr.MakePeerRef(peer.PubKey))

		var pr mac.PeerRecord
		copy(pr.PubKey[:], peer.PubKey)
		pr.Descr = enc
		peerRecords = append(peerRecords, pr)
		if !adopted {
			imported++
			notify("Peer imported: " + peer.Label + " (" + peer.Endpoint.String() + ")")
		}
	}

	// The MAC is computed over the record as it will be stored, with the MAC
	// tag present and zeroed, so signing and verifying see the same bytes.
	unsigned, err := ifRec.Encode()
	if err != nil {
		return Result{}, cleanup, session.Fail(session.KindUsage, "interface record: %w", err)
	}
	sum, err := mac.Sign(ctx, client, useTok, ifKID, ifPub, unsigned, peerRecords)
	if err != nil {
		return Result{}, cleanup, session.Classify(err, session.KindDevice, "authenticating the configuration")
	}
	ifRec.MAC = sum
	signed, err := ifRec.Encode()
	if err != nil {
		return Result{}, cleanup, session.Fail(session.KindUsage, "interface record: %w", err)
	}

	updTok, err := auth.Token(ctx, "keymgmt:upd")
	if err != nil {
		return Result{}, cleanup, err
	}
	// The label goes with it. The reference suite always sends both, and a
	// device may reject an update carrying only a description.
	if err := client.UpdateKey(ctx, updTok, ifKID, p.Label, signed[:]); err != nil {
		return Result{}, cleanup, session.Classify(err, session.KindDevice, "writing the interface record")
	}
	// From here the key is named by a record, so a later failure leaves
	// something `wipe` can find - and something that may already be a working
	// configuration. Either way it is no longer this run's to remove.
	recordWritten = true

	// Read it back and verify, so provisioning fails here rather than at the
	// first startup on the machine that will actually use it.
	if err := mac.Verify(ctx, client, useTok, ifKID, ifPub, signed, peerRecords); err != nil {
		return Result{}, cleanup, session.Fail(session.KindIntegrity,
			"the configuration just written does not verify: %w", err)
	}

	res = Result{
		IfKID:     ifKID,
		PublicKey: base64.StdEncoding.EncodeToString(ifPub[:]),
		PeerCount: len(p.Peers),
	}
	res.Server = handoff.Peer{
		PublicKey: res.PublicKey,
		Addresses: p.Addrs,
		Label:     p.Label,
	}
	if p.PSKGenerated {
		res.PSK = base64.StdEncoding.EncodeToString(p.PSK)
		res.Server.PresharedKey = res.PSK
	}
	return res, cleanup, nil
}

// deleteKey takes back a key this run created and no record names.
func deleteKey(ctx context.Context, client *hem.Client, auth *session.Auth, kid string) error {
	tok, err := auth.Token(ctx, "keymgmt:del")
	if err != nil {
		return err
	}
	return client.DeleteKey(ctx, tok, kid)
}
