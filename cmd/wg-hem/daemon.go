package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/daemon"
	"github.com/encedo/encedo-wg-hsm/internal/ipc"
	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
	"github.com/encedo/encedo-wg-hsm/internal/session"
	"github.com/encedo/encedo-wg-hsm/internal/tunnel"
)

// cmdDaemon is the same binary listening instead of being typed at.
//
// It is a second entry point rather than a second program, which is the rule at
// the top of docs/ARCHITECTURE-GUI.md: a second implementation of the tunnel
// would be a second thing to test against real hardware, and the first one took
// a week. Nothing about `wg-hem up` changes because this exists, and an
// administrator who wants none of it never meets it.
func cmdDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	sock := fs.String("socket", defaultSocket(), controlFlagUsage)
	group := fs.String("socket-group", "", controlAccessFlagUsage)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wg-hem daemon - run tunnels on behalf of a graphical client

  wg-hem daemon [--socket PATH]

Listens for a window, which authenticates a person, chooses an identity and a
peer, and hands over one scoped token. This process reads the configuration out
of the device, verifies its MAC, and runs the tunnel. It holds no passphrase and
never asks for one.

The tunnel belongs to the connection that started it: when that connection
closes, the tunnel comes down.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return failf(exitUsage, "%w", err)
	}

	// The same two conditions `up` checks, and for the same reason: netlink
	// answering "operation not permitted" three layers down, after a window has
	// already asked somebody for their passphrase, is a failure nobody can act
	// on.
	if err := rt.Preflight(); err != nil {
		return failf(exitUsage, "%w", err)
	}

	ln, err := listenOn(*sock, *group)
	if err != nil {
		return err
	}
	defer os.Remove(*sock)

	srv := &daemon.Server{
		Open:  openTunnel,
		Build: ipc.Current(),
		Log:   func(msg string) { fmt.Fprintln(os.Stderr, msg) },
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Fprintln(os.Stderr, "Stopping; any tunnel goes with the connection that owns it.")
		ln.Close()
	}()

	fmt.Fprintf(os.Stderr, "Listening on %s as %s.\n", *sock, ipc.Current())
	if err := srv.Serve(ln); err != nil {
		return failf(exitDevice, "serving: %w", err)
	}
	return nil
}

// openTunnel turns a start request into a running tunnel. This is the only place
// the daemon package meets internal/tunnel, which is what keeps netlink and
// wireguard-go out of everything that only accepts connections.
func openTunnel(ctx context.Context, req ipc.Request) (daemon.Tunnel, error) {
	client := hem.NewClient(req.HEMURL, hem.Config{})

	if err := client.Checkin(ctx); err != nil {
		return nil, session.Classify(err, session.KindNetwork, "checkin")
	}

	keys, err := decodeKeys(req.PubKeys)
	if err != nil {
		return nil, session.Fail(session.KindDevice, "%v", err)
	}

	// One token, and it names one key. Anything else asked for is a mistake in
	// the window rather than something to go and fetch, since this process
	// cannot authenticate and must not learn how.
	tok := func(_ context.Context, scope string) (string, error) {
		if scope == "keymgmt:use:"+req.Identity {
			return req.Token, nil
		}
		return "", session.Fail(session.KindAuth,
			"no token for %s: this component is given one, scoped to the interface key, "+
				"and reads records by anonymous search - the device needs allow_keysearch", scope)
	}

	tree, err := config.LoadIdentityWithKeys(ctx, client, tok, req.Identity, keys)
	if err != nil {
		return nil, classifyLoadKind(err)
	}

	peer, err := peerByKID(tree, req.Peer)
	if err != nil {
		return nil, err
	}

	dt := &daemonTunnel{tree: tree, peer: peer, expiry: hem.TokenExpiry(req.Token)}
	dt.t = tunnel.New(ctx, tunnel.Opts{
		Client: client, Tree: tree,
		UseTok: req.Token, HEMURL: req.HEMURL,
		Ifname: "wg0",
		// Nobody to ask, so it walks the stored order and reports what it did.
		SelectNext: tunnel.WalkPeers(),
		// The tunnel is built here and run later, so what it says goes to a
		// sink the adapter fills in when it has somewhere to send it.
		Notify: dt.say,
	})
	return dt, nil
}

func decodeKeys(in map[string]string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(in))
	for kid, b64 := range in {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("the public key offered for %s is not base64: %w", kid, err)
		}
		out[kid] = raw
	}
	return out, nil
}

// peerByKID finds the peer the window chose. An identifier rather than a
// position, because a position means nothing across a process boundary and
// would silently mean something different if the configuration changed between
// the window reading it and this reading it again.
func peerByKID(tree *config.Tree, kid string) (*config.Peer, error) {
	if kid == "" {
		return &tree.Peers[0], nil
	}
	for i := range tree.Peers {
		if tree.Peers[i].KID == kid {
			return &tree.Peers[i], nil
		}
	}
	return nil, session.Fail(session.KindIntegrity,
		"the configuration this component read holds no peer %s; it may have changed since the window looked", kid)
}

// daemonTunnel adapts what the tunnel says to what the window is drawing. The
// tunnel states facts in sentences; a window wants a state and some fields.
type daemonTunnel struct {
	t    *tunnel.Tunnel
	tree *config.Tree
	peer *config.Peer

	// expiry is when the session ends, read from the token rather than from the
	// lifetime asked for: a run on 2026-08-11 requested eight hours and ended
	// after seven and a half, so anything derived from the request would have
	// been half an hour optimistic about when somebody loses their tunnel.
	expiry time.Time

	// mu guards sink, which Run fills in and the tunnel's own goroutines read.
	mu   sync.Mutex
	sink func(string)
}

// say passes a sentence on, if it is one the window should see and there is
// anywhere to pass it yet.
//
// Progress is dropped here rather than in the window: "Interface wg0 is up" and
// "Handshake completed" are the tunnel narrating what the state already says,
// and the window draws state as a word and a coloured dot. Sending them anyway
// is what put a handshake in an alert box beside a green dot that meant the same
// thing.
//
// The tunnel is also built before it is run, and nothing it might say in between
// has anywhere to go yet.
func (d *daemonTunnel) say(kind tunnel.Note, line string) {
	if kind != tunnel.News {
		return
	}
	d.mu.Lock()
	sink := d.sink
	d.mu.Unlock()
	if sink != nil {
		sink(line)
	}
}

func (d *daemonTunnel) Run(ctx context.Context, emit func(ipc.Event)) error {
	e := d.snapshot()
	e.State = "connecting"
	emit(e)

	// The window draws counters, a last handshake and a countdown, and none of
	// them are things the tunnel announces - it says five sentences over a
	// session and is silent in between. So they are read from the interface on a
	// timer, which is the same place `wg-hem status` reads them and the same
	// place `wg show` would.
	//
	// A second, because that is what a countdown ticking in front of somebody
	// needs; the question is answered over a local socket and costs nothing.
	go d.report(ctx, emit)

	// Every sentence the tunnel produces becomes a notice on the current state.
	// Turning them into states here would be guessing at meaning from prose;
	// what the window needs to know about state changes it learns from the
	// handshake, which is a fact rather than a sentence.
	d.mu.Lock()
	d.sink = func(line string) {
		ev := d.snapshot()
		ev.State = "connected"
		ev.Notice = line
		emit(ev)
	}
	d.mu.Unlock()

	err := d.t.Run(d.peer)

	done := d.snapshot()
	done.State = "ended"
	if err != nil {
		done.Notice = err.Error()
	}
	emit(done)
	return err
}

// addrStrings puts the addresses on the wire as text. netip.Prefix marshals to
// JSON on its own, but as a bare string either way - going through the wire type
// as strings keeps the protocol readable to anything that is not this program.
func addrStrings(addrs []netip.Prefix) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func (d *daemonTunnel) Refresh(token string) error { return d.t.Refresh(token) }

// classifyLoadKind keeps a MAC failure a MAC failure across the boundary: a
// window shows a different screen for a configuration that does not
// authenticate than for a device that would not answer.
func classifyLoadKind(err error) error {
	if session.KindOf(err) != session.KindDevice {
		return err
	}
	return session.Classify(err, session.KindIntegrity, "reading the configuration")
}

// reportEvery is how often the interface is asked what it has carried. A
// countdown in front of somebody wants a second; the question is answered over a
// local socket by the interface itself, so it costs nothing worth counting.
const reportEvery = time.Second

// snapshot is everything the window draws, as of now.
//
// The peer and the endpoint come from the configuration, which does not change
// under a running tunnel unless failover moves it. The counters and the last
// handshake come from the interface, and the expiry from the token - read from
// the token itself and never computed from the length anybody asked for, since a
// device issues what it chooses.
func (d *daemonTunnel) snapshot() ipc.Event {
	// The peer the tunnel is on now, not the one it started with: failover
	// changes it, and reporting the old one would hide the single thing that
	// happened.
	peer := d.peer
	if current := d.t.Peer(); current != nil {
		peer = current
	}
	e := ipc.Event{
		Interface: d.t.Interface(),
		Addrs:     addrStrings(d.t.Addrs()),
		Peer:      peer.Label,
		PeerKID:   peer.KID,
		Endpoint:  peer.Endpoint.String(),
		ExpiresAt: d.expiry,
	}

	// A tunnel whose UAPI listener could not be opened carries traffic and
	// cannot be asked about it - Windows without LocalSystem. Nothing to add,
	// and nothing worth complaining about once per second.
	live, err := rt.Status(e.Interface)
	if err != nil {
		return e
	}
	for _, p := range live.Peers {
		e.Rx += p.RxBytes
		e.Tx += p.TxBytes
		if p.LastHandshake.After(e.LastHandshake) {
			e.LastHandshake = p.LastHandshake
		}
	}
	return e
}

// report sends a snapshot on a timer for as long as the tunnel is up.
func (d *daemonTunnel) report(ctx context.Context, emit func(ipc.Event)) {
	tick := time.NewTicker(reportEvery)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		e := d.snapshot()
		// Before the first handshake there is nothing to report but the fact of
		// still trying, and saying "connected" then would be a lie the window
		// would draw as a green dot.
		if e.LastHandshake.IsZero() {
			e.State = "connecting"
		} else {
			e.State = "connected"
		}
		emit(e)
	}
}
