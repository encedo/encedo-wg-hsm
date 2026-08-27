package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/ipc"
	"github.com/encedo/encedo-wg-hsm/internal/provision"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// liveSession is the real thing behind the same interface fakeSession
// implements: it authenticates a person, reads what the device holds, and hands
// a privileged component one scoped token to run a tunnel with.
//
// What it never does is run one. Everything privileged is on the other side of
// the socket, which is why this file imports neither netlink nor wireguard-go
// and a test proves it - see deps_test.go. See docs/ARCHITECTURE-GUI.md.
type liveSession struct {
	hemURL string
	socket string

	// Choose settles which identity, and which peer, when the device holds more
	// than one. Supplied rather than decided here: a window puts up a control, a
	// scripted run takes the first, and neither belongs in the part that talks to
	// the device.
	ChooseIdentity func([]config.Identity) (string, error)
	ChoosePeer     func([]config.Peer) (string, error)

	events chan Event

	mu     sync.Mutex
	conn   net.Conn
	closed bool
	last   Event
}

func newLiveSession(hemURL, socket string) *liveSession {
	return &liveSession{
		hemURL: hemURL,
		socket: socket,
		events: make(chan Event, 16),
		last:   Event{State: NoModule},
	}
}

func (s *liveSession) Events() <-chan Event { return s.events }

// Connect does everything that needs a person, then gets out of the way.
//
// The order is forced rather than chosen: `keymgmt:use:<if_kid>` names one key,
// so the identity has to be settled before the token that depends on it can be
// asked for. See docs/ARCHITECTURE-GUI.md, "Which identity, and why the order is
// forced".
func (s *liveSession) Connect(ctx context.Context, passphrase []byte) error {
	defer session.Zero(passphrase)

	s.emit(Event{State: Connecting, HEM: s.hemURL})

	dev := session.Device{
		URL:     s.hemURL,
		ExpSecs: int(sessionLength.Seconds()),
		// Handed over rather than read: the reading was done by a password
		// field, and this is only where it is spent.
		Passphrase: func() ([]byte, error) { return passphrase, nil },
		Notify:     func(msg string) { s.emit(Event{State: Connecting, HEM: s.hemURL, Notice: msg}) },
	}

	client, auth, err := dev.Connect(ctx)
	if err != nil {
		return s.failed(err)
	}
	defer auth.Wipe()

	// The first token is where the passphrase is spent, and spending it means
	// 600,000 rounds of PBKDF2 before anything reaches the network.
	//
	// The count is not ours to lower: the device derives the same key from the
	// same passphrase and the same salt, so it is protocol rather than a
	// setting. What was in our gift is saying so, because connecting took about
	// five seconds on Windows while the window claimed to be waiting for a
	// handshake it was nowhere near.
	//
	// Whether those five seconds are this derivation is not established. It was
	// asserted here once, on the strength of a 51 ms measurement taken on arm64,
	// which says nothing about the other architecture; Go has a SHA-NI path for
	// amd64 and the processor in question has SHA-NI, so the arithmetic does not
	// work. The other candidates are the round trips to the device and a
	// real-time scanner examining a newly built and unsigned executable. Until
	// somebody times it there, this sentence is what the window can honestly say
	// about a wait it cannot explain.
	s.emit(Event{State: Connecting, HEM: s.hemURL,
		Notice: "Working out the key from your passphrase. On some machines this takes a few seconds."})

	ids, err := config.Identities(ctx, client, auth.Token)
	if err != nil {
		return s.failed(err)
	}
	ifKID, err := pickIdentity(ids, s.ChooseIdentity)
	if err != nil {
		// Declining to choose is not a failure, and drawing it as one would
		// tell somebody their module is broken because they pressed Cancel.
		// Back to Ready with a sentence and no error attached, which is what
		// keeps the notice from being painted red.
		if errors.Is(err, errNoProfileChosen) {
			s.emit(Event{State: Ready, HEM: s.hemURL, Notice: humanError(err)})
			return err
		}
		return s.failed(err)
	}

	// Read and check the whole tree here as well as in the component. It is one
	// device round trip, and it buys the person a legible refusal before
	// anything privileged is asked to do anything - a configuration that does
	// not authenticate should not first become a failed tunnel.
	tree, err := config.LoadIdentity(ctx, client, auth.Token, ifKID)
	if err != nil {
		return s.failed(err)
	}
	peerKID, err := pickPeer(tree.Peers, s.ChoosePeer)
	if err != nil {
		return s.failed(err)
	}

	useTok, err := auth.Token(ctx, "keymgmt:use:"+ifKID)
	if err != nil {
		return s.failed(err)
	}

	conn, err := dialControl(ctx, s.socket)
	if err != nil {
		return s.failed(session.Fail(session.KindDevice,
			"the privileged component is not answering on %s: %v\n"+
				"Is the service running?", s.socket, err))
	}

	req := ipc.Request{
		Op: ipc.OpStart, Build: ipc.Current(),
		HEMURL: s.hemURL, Identity: ifKID, Peer: peerKID,
		Token:   useTok,
		PubKeys: publicKeys(tree),
	}
	if err := ipc.WriteMsg(conn, req); err != nil {
		conn.Close()
		return s.failed(session.Fail(session.KindDevice, "asking for a tunnel: %v", err))
	}

	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	go s.consume(conn)
	return nil
}

// publicKeys is what spares the component a keymgmt:get token: it already has
// the identifiers from its own search, and a key is checked against the
// identifier it claims.
func publicKeys(tree *config.Tree) map[string]string {
	keys := map[string]string{
		tree.IfKID: base64.StdEncoding.EncodeToString(tree.IfPubKey[:]),
	}
	for _, p := range tree.Peers {
		keys[p.KID] = base64.StdEncoding.EncodeToString(p.PubKey[:])
	}
	return keys
}

// consume turns what the component says into what the window draws, until the
// connection ends - which is also when the tunnel does.
func (s *liveSession) consume(conn net.Conn) {
	// Whatever ends this connection ends the tunnel with it, so the session goes
	// back to being one that can be started again - and the presence watcher,
	// which stands aside while a tunnel is up, starts answering once more.
	defer func() {
		s.mu.Lock()
		if s.conn == conn {
			s.conn = nil
		}
		s.mu.Unlock()
		s.emit(Event{State: Ready, HEM: s.hemURL})
	}()

	for {
		raw, err := ipc.ReadMsg(conn)
		if err != nil {
			return
		}
		m, err := ipc.DecodeMsg(raw)
		if err != nil {
			continue
		}
		switch {
		case m.Type == ipc.TypeReply && m.Reply != nil && !m.Reply.OK:
			s.emit(Event{State: Ready, HEM: s.hemURL,
				Notice: m.Reply.Err, Err: errors.New(m.Reply.Err)})
		case m.Type == ipc.TypeEvent && m.Event != nil:
			ev := fromIPC(*m.Event, s.hemURL)
			s.emit(ev)

			// The component takes the tunnel down on stop and keeps the
			// connection, so nothing else would ever end it: the session stayed
			// one that held a connection, the presence watch stood aside as it
			// does while a tunnel is up, and the passphrase never came back.
			//
			// Ending it on the component saying the tunnel ended, rather than in
			// Disconnect, is what also covers a tunnel that ended on its own -
			// an expired token, or a peer nobody could reach.
			if ev.State == Ended {
				conn.Close()
			}
		}
	}
}

func fromIPC(e ipc.Event, hemURL string) Event {
	out := Event{
		HEM: hemURL, Peer: e.Peer, Addrs: e.Addrs,
		Rx: e.Rx, Tx: e.Tx,
		LastHandshake: e.LastHandshake, ExpiresAt: e.ExpiresAt,
		Notice: e.Notice,
	}
	switch e.State {
	case "connecting":
		out.State = Connecting
	case "connected":
		out.State = Connected
	case "ended":
		out.State = Ended
	default:
		out.State = Ready
	}
	return out
}

func (s *liveSession) Disconnect() error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return nil
	}
	s.emit(Event{State: Disconnecting, HEM: s.hemURL})
	return ipc.WriteMsg(conn, ipc.Request{Op: ipc.OpStop})
}

// Close ends the session for good. Closing the connection is what takes the
// tunnel down: the component gives it to whoever opened it and takes it back
// when they go.
func (s *liveSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.conn != nil {
		s.conn.Close()
	}
	close(s.events)
	return nil
}

func (s *liveSession) emit(e Event) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.last = e
	s.mu.Unlock()

	select {
	case s.events <- e:
	default: // a window that is not reading is not a reason to block a tunnel
	}
}

// failed reports an error as a state the window can draw, and returns it for the
// caller that asked.
func (s *liveSession) failed(err error) error {
	s.emit(Event{State: Ready, HEM: s.hemURL, Notice: humanError(err), Err: err})
	return err
}

// pickIdentity and pickPeer apply the same rule the command line does: one is
// used without asking, several are offered (section 6.2 step 5, section 2).
func pickIdentity(ids []config.Identity, choose func([]config.Identity) (string, error)) (string, error) {
	switch {
	case len(ids) == 0:
		return "", session.Fail(session.KindIntegrity, "this module holds no configuration - provision it first")
	case len(ids) == 1:
		return ids[0].KID, nil
	case choose == nil:
		// The window supplies a chooser, so reaching this is not a person
		// meeting a limitation - it is a caller with nobody to ask, which on
		// this side means a test or a session built before the window was.
		return "", session.Fail(session.KindDevice,
			"this module holds %d identities and nothing here can ask which to use", len(ids))
	}
	return choose(ids)
}

func pickPeer(peers []config.Peer, choose func([]config.Peer) (string, error)) (string, error) {
	switch {
	case len(peers) == 0:
		return "", session.Fail(session.KindIntegrity, "the configuration names no peers")
	case len(peers) == 1 || choose == nil:
		// The stored order is the failover priority, so the first is the answer
		// somebody already wrote down.
		return peers[0].KID, nil
	}
	return choose(peers)
}

// sessionLength is how long a token is asked for.
//
// An hour was the command line's default because a terminal is watched. A window
// is not: TODO.md records that a session ending mid-afternoon is the complaint
// this interface exists partly to answer, and the countdown it draws comes from
// the token rather than from this number.
var sessionLength = 8 * time.Hour

// watch says whether the module is there, so the window can offer a button that
// will work rather than one that explains itself afterwards.
//
// `GET /api/system/version` needs no authorisation, which is what makes this
// possible at all: presence is answered without asking anybody for anything. It
// is the same call the tunnel uses to check the HEM survived its own routes.
//
// Polled rather than pushed. A personal appliance appears when somebody plugs it
// in, and nothing tells us; three seconds is far below the patience of a person
// who has just done that, and the call is a round trip to a device on a USB link.
func (s *liveSession) watch(ctx context.Context) {
	tick := time.NewTicker(presencePoll)
	defer tick.Stop()

	present := false
	why := ""
	for {
		now, reason := s.probe(ctx)
		// The reason is followed as well as the answer: a device that stays
		// away for a new reason - it answered, now the certificate is refused -
		// is a change worth redrawing for, and the old text would otherwise sit
		// there describing something that is no longer what is wrong.
		if now != present || reason != why {
			present, why = now, reason
			if present {
				s.emit(Event{State: Ready, HEM: s.hemURL})
			} else {
				s.emit(Event{State: NoModule, HEM: s.hemURL, Reach: reason})
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// probe asks the device whether it is there, and stops asking while a tunnel is
// up: the answer is then either obvious or being carried over the tunnel itself.
func (s *liveSession) probe(ctx context.Context) (bool, string) {
	s.mu.Lock()
	busy := s.conn != nil || s.closed
	url := s.hemURL
	s.mu.Unlock()
	if busy {
		return true, ""
	}

	ctx, cancel := context.WithTimeout(ctx, presenceTimeout)
	defer cancel()
	_, err := hem.NewClient(url, hem.Config{}).GetVersion(ctx)
	if err != nil {
		// Kept rather than discarded, and shown in the advanced panel rather
		// than on the main screen. "No module" is four different facts wearing
		// one word - nothing plugged in, no route to it, a name that does not
		// resolve, a certificate the system will not accept - and they are
		// indistinguishable from the outside, which on Windows cost an evening.
		// The friendly sentence stays where it is, because on a machine with
		// nothing plugged in a dial error is a worse first thing to read than
		// "plug in your key".
		return false, err.Error()
	}
	return true, ""
}

// setHEM points the session at another appliance. The window offers this on the
// one screen where "no module" and "wrong address" are indistinguishable.
func (s *liveSession) setHEM(url string) {
	s.mu.Lock()
	s.hemURL = url
	s.mu.Unlock()
}

const (
	presencePoll    = 3 * time.Second
	presenceTimeout = 2 * time.Second
)

// Import writes a configuration into the module. See Session.Import.
//
// A separate authorisation from Connect's, and deliberately so: this asks for
// keymgmt:gen, imp, upd and search, none of which a running tunnel needs, and
// the token is wiped when the write is done rather than living as long as a
// session. Somebody importing a profile is not somebody starting a tunnel, and
// the module is asked for exactly what each of those is.
func (s *liveSession) Import(ctx context.Context, passphrase []byte, p provision.Params) (provision.Result, error) {
	defer session.Zero(passphrase)

	dev := session.Device{
		URL: s.hemURL,
		// Long enough to write a configuration and no longer. Provisioning is
		// a handful of round trips; the eight hours a tunnel asks for would be
		// eight hours of a token that can create and delete keys.
		ExpSecs:    int(importSessionLength.Seconds()),
		Passphrase: func() ([]byte, error) { return passphrase, nil },
		Notify:     func(msg string) { s.emit(Event{State: s.state(), HEM: s.hemURL, Notice: msg}) },
	}

	client, auth, err := dev.Connect(ctx)
	if err != nil {
		return provision.Result{}, err
	}
	defer auth.Wipe()

	res, cleanup, err := provision.Run(ctx, client, auth, p,
		func(msg string) { s.emit(Event{State: s.state(), HEM: s.hemURL, Notice: msg}) })
	if err != nil {
		return provision.Result{}, importFailure(err, cleanup)
	}
	return res, nil
}

// importSessionLength is how long the token that writes a configuration lives.
var importSessionLength = 5 * time.Minute

// state is what the window is showing right now, so a progress line does not
// also change the screen underneath it.
func (s *liveSession) state() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last.State
}

// importFailure adds what was left in the module to the reason it failed.
//
// The command line prints these as instructions naming flags. A window has no
// flags, so it says the same facts as a sentence - and says them at all, because
// a failed import that leaves a key behind and does not mention it is how a
// module ends up with keys nobody can account for.
func importFailure(err error, c provision.Cleanup) error {
	switch {
	case c.RemovalErr != nil:
		return fmt.Errorf("%w\n\nThe key it created (%s) could not be removed either: %v. "+
			"It carries no configuration record, so it has to be deleted by key id.",
			err, c.IdentityKID, c.RemovalErr)
	case c.IdentityRemoved && c.ImportedPeers > 0:
		return fmt.Errorf("%w\n\nThe identity key it created was removed, but %d peer key(s) "+
			"were written before it failed and are still there.", err, c.ImportedPeers)
	case c.IdentityRemoved:
		return fmt.Errorf("%w\n\nNothing was left behind: the key it created was removed.", err)
	}
	return err
}
