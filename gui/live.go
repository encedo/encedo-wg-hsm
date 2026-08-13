package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"time"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/ipc"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// liveSession is the real thing behind the same interface fakeSession
// implements: it authenticates a person, reads what the device holds, and hands
// a privileged component one scoped token to run a tunnel with.
//
// What it never does is run one. Everything privileged is on the other side of
// the socket, which is why this file imports neither netlink nor wireguard-go
// and a test proves it — see deps_test.go. See docs/ARCHITECTURE-GUI.md.
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

	ids, err := config.Identities(ctx, client, auth.Token)
	if err != nil {
		return s.failed(err)
	}
	ifKID, err := pickIdentity(ids, s.ChooseIdentity)
	if err != nil {
		return s.failed(err)
	}

	// Read and check the whole tree here as well as in the component. It is one
	// device round trip, and it buys the person a legible refusal before
	// anything privileged is asked to do anything — a configuration that does
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

	conn, err := net.Dial("unix", s.socket)
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
// connection ends — which is also when the tunnel does.
func (s *liveSession) consume(conn net.Conn) {
	// Whatever ends this connection ends the tunnel with it, so the session goes
	// back to being one that can be started again — and the presence watcher,
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
			// Disconnect, is what also covers a tunnel that ended on its own —
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
	s.emit(Event{State: Ready, HEM: s.hemURL, Notice: err.Error(), Err: err})
	return err
}

// pickIdentity and pickPeer apply the same rule the command line does: one is
// used without asking, several are offered (§6.2 step 5, §2).
func pickIdentity(ids []config.Identity, choose func([]config.Identity) (string, error)) (string, error) {
	switch {
	case len(ids) == 0:
		return "", session.Fail(session.KindIntegrity, "this module holds no configuration — provision it first")
	case len(ids) == 1:
		return ids[0].KID, nil
	case choose == nil:
		return "", session.Fail(session.KindDevice,
			"this module holds %d identities and this window cannot yet offer the choice", len(ids))
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
	for {
		now := s.probe(ctx)
		if now != present {
			present = now
			if present {
				s.emit(Event{State: Ready, HEM: s.hemURL})
			} else {
				s.emit(Event{State: NoModule, HEM: s.hemURL})
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
func (s *liveSession) probe(ctx context.Context) bool {
	s.mu.Lock()
	busy := s.conn != nil || s.closed
	url := s.hemURL
	s.mu.Unlock()
	if busy {
		return true
	}

	ctx, cancel := context.WithTimeout(ctx, presenceTimeout)
	defer cancel()
	_, err := hem.NewClient(url, hem.Config{}).GetVersion(ctx)
	return err == nil
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
