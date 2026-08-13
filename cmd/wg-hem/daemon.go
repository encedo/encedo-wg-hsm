package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

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
	sock := fs.String("socket", defaultSocket(), "unix socket to listen on")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wg-hem daemon — run tunnels on behalf of a graphical client

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

	ln, err := listenOn(*sock)
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

// defaultSocket is where the service's own runtime directory is.
//
// Deliberately not /var/run/wireguard: that directory belongs to the
// command-line client, which an administrator sets up for themselves, and two
// entry points writing one root-owned directory under different owners is the
// fight the rule about not changing the CLI exists to avoid.
func defaultSocket() string {
	if dir := os.Getenv("RUNTIME_DIRECTORY"); dir != "" {
		return filepath.Join(dir, "wg-hem.sock")
	}
	return "/run/encedo-wg/wg-hem.sock"
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
				"and reads records by anonymous search — the device needs allow_keysearch", scope)
	}

	tree, err := config.LoadIdentityWithKeys(ctx, client, tok, req.Identity, keys)
	if err != nil {
		return nil, classifyLoadKind(err)
	}

	peer, err := peerByKID(tree, req.Peer)
	if err != nil {
		return nil, err
	}

	dt := &daemonTunnel{tree: tree, peer: peer}
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

	// mu guards sink, which Run fills in and the tunnel's own goroutines read.
	mu   sync.Mutex
	sink func(string)
}

// say passes a sentence on, if there is anywhere to pass it yet. The tunnel is
// built before it is run, and nothing it might say in between has anywhere to go.
func (d *daemonTunnel) say(line string) {
	d.mu.Lock()
	sink := d.sink
	d.mu.Unlock()
	if sink != nil {
		sink(line)
	}
}

func (d *daemonTunnel) Run(ctx context.Context, emit func(ipc.Event)) error {
	base := func() ipc.Event {
		return ipc.Event{
			Interface: d.t.Interface(),
			Peer:      d.peer.Label,
			PeerKID:   d.peer.KID,
			Endpoint:  d.peer.Endpoint.String(),
		}
	}

	e := base()
	e.State = "connecting"
	emit(e)

	// Every sentence the tunnel produces becomes a notice on the current state.
	// Turning them into states here would be guessing at meaning from prose;
	// what the window needs to know about state changes it learns from the
	// handshake, which is a fact rather than a sentence.
	d.mu.Lock()
	d.sink = func(line string) {
		ev := base()
		ev.State = "connected"
		ev.Notice = line
		emit(ev)
	}
	d.mu.Unlock()

	err := d.t.Run(d.peer)

	done := base()
	done.State = "ended"
	if err != nil {
		done.Notice = err.Error()
	}
	emit(done)
	return err
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

// listenOn opens the socket the window will find, and settles who may reach it.
//
// A leftover socket from a process that is gone is not a reason to refuse to
// start — after a crash there is always one, and somebody having to delete a
// file they have never heard of is not a recovery procedure. One that something
// is still listening on is a different matter, and is refused.
//
// The mode is the primary access control: who may connect at all is decided by
// the filesystem, and SO_PEERCRED then says which of them it is, so a tunnel can
// belong to the person who started it.
func listenOn(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, failf(exitDevice, "the socket directory: %w", err)
	}
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return nil, failf(exitUsage, "something is already listening on %s", path)
	}
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, failf(exitDevice, "listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, failf(exitDevice, "setting permissions on %s: %w", path, err)
	}
	return ln, nil
}
