// Package tunnel is one interface's life: the device that holds its key, the
// kernel objects it created, and the peer it is currently pointed at.
//
// It lives apart from internal/session on purpose. This is the half that needs
// netlink, the patched wireguard-go and the platform layer, and anything
// importing it inherits all three — which is right for the process that runs a
// tunnel and wrong for the window that only authenticates a person. The two
// halves meet at a scoped token: see docs/ARCHITECTURE-GUI.md.
//
// Nothing here decides anything a person would have an opinion about. Which
// peer, what to say, and what to do when one stops answering all arrive as
// functions, because a terminal, a window and a daemon answer them differently
// and the tunnel is the same in all three.
package tunnel

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/paths"
	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// Opts is everything a tunnel needs that it cannot work out for itself.
type Opts struct {
	Client *hem.Client
	Tree   *config.Tree

	// UseTok covers the rest of the run: the ECDH at every handshake, the
	// unwrap of each pre-shared key, and reading the interface's own public key.
	UseTok string

	// HEMURL is where the device is, kept because routing has to know whether
	// the tunnel is about to swallow it.
	HEMURL string

	// Ifname is the name asked for. macOS hands back a utun name instead, and
	// the one that comes back is the one everything afterwards uses.
	Ifname string

	// Notify carries what the tunnel has to say. Five sentences over the life of
	// a session, and every one of them is something a window would show
	// differently — a status line, a toast, a coloured dot — so the tunnel states
	// the fact and lets whoever is watching decide how it appears.
	Notify func(string)

	// SelectNext is asked for another peer when the current one never answers.
	//
	// A function rather than a prompt: choosing is the one part of failover that
	// belongs to whoever is watching. A terminal asks and reads a line; a window
	// or a daemon walks the stored order and says so afterwards. The tunnel does
	// not need to know which, and the moment it does it can only ever be driven
	// from a terminal.
	SelectNext func(tree *config.Tree, failed *config.Peer) (*config.Peer, error)
}

// Tunnel is one interface's life. Failover changes the peer it points at and
// leaves everything else standing.
type Tunnel struct {
	ctx  context.Context
	opts Opts

	ifname string

	dev  *device.Device
	hsm  *rt.HSM
	pins *rt.Pins

	// dnsSet records that this process gave the resolver something, so that
	// teardown only takes back what it gave.
	//
	// Undoing what was never done is not free here. `resolvectl revert` is a
	// privileged call, and a client running on a capability instead of as root
	// is one polkit asks a human about: Ctrl+C on a tunnel with no DNS of its
	// own raised an authentication dialogue, on a desktop, to undo nothing.
	// Running as root hid this — root is never asked.
	dnsSet bool

	// blind records that the UAPI listener could not be opened, so nothing —
	// including this process — can ask the interface what it is doing. The
	// tunnel still carries traffic; failover is what goes, because it is
	// answered entirely from the handshake timestamp.
	blind bool

	// mu guards peer, which failover replaces from the goroutine holding the
	// tunnel while anything reporting on it reads from another.
	mu   sync.Mutex
	peer *config.Peer
	psk  []byte

	// hemInside is whether the current peer's AllowedIPs cover the HEM. The
	// probe that acts on it waits until the routes are actually in.
	hemInside bool
	hemHost   string
}

// runDir is where a running interface leaves its public key. The private key is
// not there and never will be — `wg` cannot even derive the public one, because
// the device is configured with a zeroed private key.
//
// A variable rather than the constant it starts as, so a test can write
// somewhere it is allowed to. It moved here with the code that writes the file;
// the command has not needed it since.
var runDir = paths.RunDir

func New(ctx context.Context, o Opts) *Tunnel {
	return &Tunnel{ctx: ctx, opts: o, ifname: o.Ifname}
}

// Interface is the name the tunnel ended up with, which is not always the one
// that was asked for.
func (t *Tunnel) Interface() string { return t.ifname }

// Peer is the peer the tunnel is currently pointed at, which failover changes
// under whoever is watching. Reported rather than assumed: a window showing the
// peer it was started with, after a walk moved to another, would be stating the
// one thing failover exists to change.
func (t *Tunnel) Peer() *config.Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.peer
}

// Refresh replaces the token every subsequent handshake acts with, so a session
// can be renewed without the tunnel going down and up around it.
func (t *Tunnel) Refresh(token string) error {
	if t.hsm == nil {
		return session.Fail(session.KindDevice, "the tunnel is not up yet")
	}
	t.hsm.SetToken(token)
	return nil
}

func (t *Tunnel) notify(format string, args ...any) {
	if t.opts.Notify != nil {
		t.opts.Notify(fmt.Sprintf(format, args...))
	}
}

// Run brings the interface up on peer and holds it until something ends it,
// offering another peer whenever the current one never answers (§6.4).
func (t *Tunnel) Run(peer *config.Peer) error {
	if err := t.openDevice(); err != nil {
		return err
	}
	t.pins = &rt.Pins{}

	// The peer goes in before the interface's own routes: pinning its endpoint
	// has to happen before a default route can capture it.
	if err := t.usePeer(peer); err != nil {
		t.teardown()
		return err
	}
	if err := t.configureInterface(); err != nil {
		t.teardown()
		return err
	}

	st := &session.State{
		PID: os.Getpid(), Interface: t.ifname, IfKID: t.opts.Tree.IfKID,
		PeerKID: peer.KID, PeerLabel: peer.Label, Endpoint: peer.Endpoint.String(),
		HEMURL: t.opts.HEMURL, Started: time.Now(),
		TokenExpiry: hem.TokenExpiry(t.opts.UseTok),
	}
	if err := st.Save(); err != nil {
		t.teardown()
		return session.Fail(session.KindDevice, "recording the interface state: %v", err)
	}

	// The UAPI listener is how anything outside this process sees the tunnel:
	// `wg show`, `wg-hem status`, and the handshake watch that failover depends
	// on. It is not how packets move — the device was configured in memory by
	// IpcSet — so failing to open it is a loss of sight, not of function, and
	// refusing to carry traffic because nobody can watch is the worse trade.
	//
	// Windows is where this happens. Upstream's pipe is created with SYSTEM as
	// its owner, which an elevated administrator may not assign; the account it
	// wants is LocalSystem, which is the service the graphical client's
	// component will run as. Until then the tunnel runs blind rather than not at
	// all. On Linux the preflight check has already established that the
	// directory is writable, before the passphrase was even asked for.
	uapiErr := make(chan error, 1)
	if uapi, err := rt.UAPIListen(t.ifname); err != nil {
		t.blind = true
		t.notify("WARNING: the tunnel is up but nothing can observe it: %v\n"+
			"         `wg show` and `wg-hem status` will not find this interface, and a peer\n"+
			"         that never answers cannot be noticed, so failover is off for this run.", err)
	} else {
		defer uapi.Close()
		go func() {
			for {
				c, err := uapi.Accept()
				if err != nil {
					uapiErr <- err
					return
				}
				go t.dev.IpcHandle(c)
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// ending closes when the tunnel is over for a reason no other peer would
	// fix. Failover is the one kind of trouble that is worth staying up for.
	ending := make(chan struct{})
	var endMsg string
	go func() {
		select {
		case <-stop:
		case <-uapiErr:
		case <-t.dev.Wait():
		// Cancelling the context is how a caller with no terminal ends a tunnel.
		// A daemon's own SIGTERM means the daemon is going down, which is a
		// different event from this tunnel being asked to stop, and conflating
		// the two would make a window's Disconnect indistinguishable from the
		// service restarting.
		case <-t.ctx.Done():
		case <-t.hsm.Dead():
			endMsg = "The HEM is gone or the token has expired — bringing the interface down."
		}
		close(ending)
	}()

	t.notify("Interface %s is up.", t.ifname)

	if err := t.hold(st, ending); err != nil {
		t.teardown()
		return err
	}
	if endMsg != "" {
		t.notify("%s", endMsg)
	}
	t.teardown()
	t.notify("Interface %s is down.", t.ifname)
	return nil
}

// hold waits for the current peer to answer, and offers another when it does
// not (§6.4). Once a handshake has happened it just waits for the end: a peer
// that answers and later stops is v2's problem, with the health check and the
// hysteresis that telling a quiet tunnel from a dead one actually needs.
func (t *Tunnel) hold(st *session.State, ending <-chan struct{}) error {
	if t.blind {
		// Nothing to watch with. Waiting fifteen seconds and then declaring the
		// peer dead would be worse than not looking: it would take a working
		// tunnel down on the strength of a question that was never asked.
		<-ending
		return nil
	}
	for {
		if awaitHandshake(t.ifname, ending) {
			t.notify("Handshake with %q completed.", t.peer.Label)
			<-ending
			return nil
		}
		select {
		case <-ending:
			return nil
		default:
		}

		failed := t.peer
		next, err := t.opts.SelectNext(t.opts.Tree, failed)
		if err != nil {
			return err
		}
		if err := t.usePeer(next); err != nil {
			return err
		}
		// Said here rather than by whoever chose. A prompt announces itself by
		// existing — the person reading it already knows what happened — but a
		// walk that moves silently leaves somebody looking at a tunnel that is
		// working through a peer they did not pick.
		t.notify("Moved to %q — %q did not answer within %s.", next.Label, failed.Label, FailoverTimeout)
		st.PeerKID, st.PeerLabel, st.Endpoint = next.KID, next.Label, next.Endpoint.String()
		if err := st.Save(); err != nil {
			t.notify("WARNING: the state file no longer names the active peer: %v", err)
		}
	}
}

// openDevice reads the interface's public key, binds the handshake path to the
// HEM, and creates the tunnel device. None of it depends on which peer is
// chosen, so failover leaves all of it alone.
func (t *Tunnel) openDevice() error {
	ifPub, err := t.opts.Client.GetPubKey(t.ctx, t.opts.UseTok, t.opts.Tree.IfKID)
	if err != nil {
		return session.Classify(err, session.KindDevice, "reading the interface public key")
	}
	var ifPubKey device.NoisePublicKey
	copy(ifPubKey[:], ifPub.PubKey)

	// The private key never enters this process, so every handshake is a live
	// call into the device.
	t.hsm = rt.NewHSM(t.opts.Client, t.opts.UseTok, t.opts.Tree.IfKID, ifPubKey)
	t.hsm.Inject()

	tdev, err := tun.CreateTUN(t.ifname, int(t.opts.Tree.MTU()))
	if err != nil {
		return session.Fail(session.KindDevice, "creating the tunnel interface: %v", err)
	}
	if name, err := tdev.Name(); err == nil && name != "" {
		t.ifname = name
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", t.ifname))
	t.dev = device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	// Explicitly, rather than as a side effect of something else.
	//
	// On Linux the tunnel device reports an up event when the interface is
	// brought up, and wireguard-go's own event reader turns that into this call
	// — so bringing the link up with netlink did it for us, and this client
	// never had to. Windows has no such event: Wintun emits none, which is why
	// upstream's own Windows entry point calls Up itself.
	//
	// Without it the device is created, configured and silent. Tested on
	// 2026-08-13: the adapter appeared, the static ECDH answered, addresses and
	// routes went in, and nothing ever handshook, because a device that is not
	// up does not send. Relying on a platform to bring itself up was the bug;
	// asking is a line.
	if err := t.dev.Up(); err != nil {
		return session.Fail(session.KindDevice, "bringing the tunnel device up: %v", err)
	}

	_ = os.MkdirAll(runDir, 0755)
	_ = os.WriteFile(t.pubPath(), []byte(base64.StdEncoding.EncodeToString(ifPub.PubKey)+"\n"), 0644)
	return nil
}

// usePeer points the interface at a peer: its pre-shared key out of the device,
// its endpoint pinned outside the tunnel, and the peer itself into wireguard-go
// — which precomputes the static-static DH as it goes in, one more call the
// device answers.
func (t *Tunnel) usePeer(peer *config.Peer) error {
	psk, err := t.opts.Tree.UnwrapPSK(t.ctx, t.opts.Client, t.opts.UseTok, *peer)
	if err != nil {
		return session.Classify(err, session.KindDevice, "pre-shared key")
	}
	fail := func(err error) error {
		session.Zero(psk)
		return err
	}

	// The peer's key is in the device, so its static-static DH can be done with
	// both operands inside. Recording that has to precede adding the peer,
	// because adding it is what triggers the DH.
	var pub device.NoisePublicKey
	copy(pub[:], peer.PubKey[:])
	t.hsm.AddPeerKID(pub, peer.KID)

	plan, err := rt.PlanRouting([]rt.Peer{{
		Endpoint:   peer.Endpoint.String(),
		AllowedIPs: peer.AllowedIPs,
	}}, t.opts.HEMURL)
	if err != nil {
		return fail(session.Fail(session.KindNetwork, "%v", err))
	}
	if err := t.pins.Add(plan.Endpoints); err != nil {
		return fail(session.Fail(session.KindDevice, "%v", err))
	}

	uapi := uapiConfig(t.opts.Tree, peer, psk)
	if t.peer != nil {
		if msg := allowedIPsDiffer(t.peer, peer); msg != "" {
			t.notify("%s", msg)
		}
		uapi = uapiReplacePeer(peer, psk)
		// Routes are added, never withdrawn: traffic is using the ones already
		// there, and taking them back mid-flight is the more dangerous mistake.
		if err := rt.AddRoutes(t.ifname, peer.AllowedIPs); err != nil {
			return fail(session.Fail(session.KindDevice, "installing routes: %v", err))
		}
	}
	if err := t.dev.IpcSet(uapi); err != nil {
		return fail(session.Fail(session.KindDevice, "configuring the tunnel: %v", err))
	}

	session.Zero(t.psk)
	t.mu.Lock()
	t.peer, t.psk = peer, psk
	t.mu.Unlock()
	t.hemInside, t.hemHost = plan.HEMInside, plan.HEMHost
	return nil
}

// configureInterface does the interface-level work: address, MTU, routes, DNS,
// and the check that the HEM survived them.
func (t *Tunnel) configureInterface() error {
	if err := rt.Up(t.ifname, t.opts.Tree.Iface.Addrs); err != nil {
		return session.Fail(session.KindDevice, "bringing %s up: %v", t.ifname, err)
	}
	if err := rt.SetMTU(t.ifname, int(t.opts.Tree.MTU())); err != nil {
		return session.Fail(session.KindDevice, "setting the MTU: %v", err)
	}
	if err := rt.AddRoutes(t.ifname, t.peer.AllowedIPs); err != nil {
		return session.Fail(session.KindDevice, "installing routes: %v", err)
	}
	if servers := dnsServers(t.opts.Tree); len(servers) > 0 {
		if err := rt.SetDNS(t.ifname, servers); err != nil {
			return session.Fail(session.KindDevice, "setting DNS: %v", err)
		}
		t.dnsSet = true
	}
	// With the routes in place, confirm the HEM is still there. It is consulted
	// at every handshake, so losing it is not a degraded tunnel — it is one that
	// stops at the first rekey, roughly two minutes in.
	if t.hemInside {
		if err := rt.ProbeHEM(t.opts.Client, t.hemHost); err != nil {
			return session.Fail(session.KindNetwork, "%v", err)
		}
	}
	return nil
}

func (t *Tunnel) pubPath() string { return runDir + "/" + t.ifname + ".pub" }

// teardown undoes everything this process created, in the order that leaves the
// host as it was found. Every way out goes through it, so the abort path cannot
// drift from the one that runs on Ctrl+C.
func (t *Tunnel) teardown() {
	// DNS goes back before the device closes, not after. Closing removes the
	// interface, and `resolvectl revert` on an interface that is gone prints
	// "Failed to resolve interface: No such device" on its own stderr — so every
	// clean shutdown ended with an error message about a failure that had not
	// happened. Seen in the 7.5-hour soak of 2026-08-11.
	if t.dnsSet {
		rt.RevertDNS(t.ifname)
	}
	if t.dev != nil {
		t.dev.Close()
	}
	_ = rt.Down(t.ifname)
	if t.pins != nil {
		t.pins.Restore()
	}
	session.Zero(t.psk)
	_ = os.Remove(t.pubPath())
	session.Remove(t.ifname, func(msg string) { t.notify("WARNING: %s", msg) })
}
