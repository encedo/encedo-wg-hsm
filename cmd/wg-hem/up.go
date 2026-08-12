package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
)

// runDir is where a running interface leaves its public key and its state file.
// The private key is not there and never will be — `wg` cannot even derive the
// public one, because the device is configured with a zeroed private key.
//
// The location differs per platform, so it comes from internal/runtime with
// everything else that does. A variable so tests can write somewhere they are
// allowed to.
var runDir = rt.RunDir

// cmdUp brings the tunnel up from the configuration in the device (§6.2). No
// file is read and nothing is written to disk beyond the public key and the
// state file that lets `down` and `status` find this process.
func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	dev := addDeviceFlags(fs)
	ifname := fs.String("interface", "wg0", "name of the tunnel interface")
	peerIndex := fs.Int("peer", 0, "connect to peer N as numbered by `wg-hem verify` (1-based)")
	peerKey := fs.String("peer-pubkey", "", "connect to the peer whose base64 public key starts with this prefix")
	debug := fs.Bool("debug", false, "trace every handshake ECDH on stderr (no key material: values are shown head…tail)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wg-hem up — bring the tunnel up from the configuration in the device

  wg-hem up [--interface wg0] [--peer N | --peer-pubkey PREFIX] [device flags]

With more than one peer and neither selection flag, the peer is asked for; the
order is the one the interface record stores, which is the failover priority.
A peer that never answers is reported and another is offered.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return failf(exitUsage, "%w", err)
	}
	if *peerIndex != 0 && *peerKey != "" {
		return failf(exitUsage, "--peer and --peer-pubkey select the same thing; pass one")
	}
	if *debug {
		rt.SetDebug(true)
	}

	// Before the passphrase, not after. Everything this checks is knowable
	// without touching the device, and discovering it later means the person has
	// authenticated, waited, and then been told "operation not permitted" by
	// netlink — at which point the obvious move is sudo, which works and teaches
	// the wrong lesson. Nothing here wants root; one capability and a writable
	// directory are the whole of it.
	if err := rt.Preflight(); err != nil {
		return failf(exitUsage, "%w", err)
	}

	ctx := context.Background()
	client, auth, tree, err := dev.load(ctx)
	if err != nil {
		return err
	}
	defer auth.wipe()

	peer, err := selectPeer(tree, *peerIndex, *peerKey)
	if err != nil {
		return err
	}

	// One scope covers the rest of the run: the ECDH at every handshake, the
	// unwrap of each pre-shared key, and reading the interface's own public key.
	useTok, err := auth.token(ctx, "keymgmt:use:"+tree.IfKID)
	if err != nil {
		return err
	}

	t := &tunnel{
		ctx: ctx, client: client, tree: tree,
		useTok: useTok, hemURL: dev.url(), ifname: *ifname,
		selectNext: repromptPeer,
		notify:     func(line string) { fmt.Fprintln(os.Stderr, line) },
	}
	return t.run(peer)
}

// tunnel is one interface's life: the device that holds its key, the kernel
// objects it created, and the peer it is currently pointed at. Failover changes
// the last of those and leaves the rest standing.
type tunnel struct {
	ctx    context.Context
	client *hem.Client
	tree   *config.Tree
	useTok string
	hemURL string
	ifname string

	dev  *device.Device
	hsm  *rt.HSM
	pins *rt.Pins

	// dnsSet records that this process gave the resolver something, so that
	// teardown only takes back what it gave.
	//
	// Undoing what was never done is not free here. `resolvectl revert` is a
	// privileged call, and now that the client runs on a capability instead of
	// as root, a privileged call it is not entitled to make is one polkit asks a
	// human about: Ctrl+C on a tunnel with no DNS of its own raised an
	// authentication dialogue, on a desktop, to undo nothing. Running as root
	// hid this — root is never asked.
	dnsSet bool

	peer *config.Peer
	psk  []byte

	// notify carries what the tunnel has to say. Five sentences over the life of
	// a session, and every one of them is something a window would show
	// differently — a status line, a toast, a coloured dot — so the tunnel
	// states the fact and lets whoever is watching decide how it appears.
	notify func(string)

	// selectNext is asked for another peer when the current one never answers.
	//
	// A function rather than a call to the prompt: choosing is the one part of
	// failover that belongs to whoever is watching. A terminal asks and reads a
	// line; a window will put up a dialogue, or try the next peer itself and say
	// so afterwards. The tunnel does not need to know which, and the moment it
	// does it can only ever be driven from a terminal.
	selectNext func(tree *config.Tree, failed *config.Peer) (*config.Peer, error)

	// hemInside is whether the current peer's AllowedIPs cover the HEM. The
	// probe that acts on it waits until the routes are actually in.
	hemInside bool
	hemHost   string
}

// run brings the interface up on peer and holds it until something ends it,
// offering another peer whenever the current one never answers (§6.4).
func (t *tunnel) run(peer *config.Peer) error {
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

	st := &state{
		PID: os.Getpid(), Interface: t.ifname, IfKID: t.tree.IfKID,
		PeerKID: peer.KID, PeerLabel: peer.Label, Endpoint: peer.Endpoint.String(),
		HEMURL: t.hemURL, Started: time.Now(),
		TokenExpiry: hem.TokenExpiry(t.useTok),
	}
	if err := st.Save(); err != nil {
		t.teardown()
		return failf(exitDevice, "recording the interface state: %w", err)
	}

	uapi, err := rt.UAPIListen(t.ifname)
	if err != nil {
		t.teardown()
		return failf(exitDevice, "opening the UAPI socket: %w", err)
	}
	defer uapi.Close()
	uapiErr := make(chan error, 1)
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
		case <-t.hsm.Dead():
			endMsg = "The HEM is gone or the token has expired — bringing the interface down."
		}
		close(ending)
	}()

	t.notify(fmt.Sprintf("Interface %s is up.", t.ifname))

	if err := t.hold(st, ending); err != nil {
		t.teardown()
		return err
	}
	if endMsg != "" {
		t.notify(endMsg)
	}
	t.teardown()
	t.notify(fmt.Sprintf("Interface %s is down.", t.ifname))
	return nil
}

// hold waits for the current peer to answer, and offers another when it does
// not (§6.4). Once a handshake has happened it just waits for the end: a peer
// that answers and later stops is v2's problem, with the health check and the
// hysteresis that telling a quiet tunnel from a dead one actually needs.
func (t *tunnel) hold(st *state, ending <-chan struct{}) error {
	for {
		if awaitHandshake(t.ifname, ending) {
			t.notify(fmt.Sprintf("Handshake with %q completed.", t.peer.Label))
			<-ending
			return nil
		}
		select {
		case <-ending:
			return nil
		default:
		}

		next, err := t.selectNext(t.tree, t.peer)
		if err != nil {
			return err
		}
		if err := t.usePeer(next); err != nil {
			return err
		}
		st.PeerKID, st.PeerLabel, st.Endpoint = next.KID, next.Label, next.Endpoint.String()
		if err := st.Save(); err != nil {
			t.notify(fmt.Sprintf("WARNING: the state file no longer names the active peer: %v", err))
		}
	}
}

// openDevice reads the interface's public key, binds the handshake path to the
// HEM, and creates the tunnel device. None of it depends on which peer is
// chosen, so failover leaves all of it alone.
func (t *tunnel) openDevice() error {
	ifPub, err := t.client.GetPubKey(t.ctx, t.useTok, t.tree.IfKID)
	if err != nil {
		return classify(err, exitDevice, "reading the interface public key")
	}
	var ifPubKey device.NoisePublicKey
	copy(ifPubKey[:], ifPub.PubKey)

	// The private key never enters this process, so every handshake is a live
	// call into the device.
	t.hsm = rt.NewHSM(t.client, t.useTok, t.tree.IfKID, ifPubKey)
	t.hsm.Inject()

	tdev, err := tun.CreateTUN(t.ifname, int(t.tree.MTU()))
	if err != nil {
		return failf(exitDevice, "creating the tunnel interface: %w", err)
	}
	if name, err := tdev.Name(); err == nil && name != "" {
		t.ifname = name
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", t.ifname))
	t.dev = device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	_ = os.MkdirAll(runDir, 0755)
	_ = os.WriteFile(t.pubPath(), []byte(base64.StdEncoding.EncodeToString(ifPub.PubKey)+"\n"), 0644)
	return nil
}

// usePeer points the interface at a peer: its pre-shared key out of the device,
// its endpoint pinned outside the tunnel, and the peer itself into wireguard-go
// — which precomputes the static-static DH as it goes in, one more call the
// device answers.
func (t *tunnel) usePeer(peer *config.Peer) error {
	psk, err := t.tree.UnwrapPSK(t.ctx, t.client, t.useTok, *peer)
	if err != nil {
		return classify(err, exitDevice, "pre-shared key")
	}
	fail := func(err error) error {
		zero(psk)
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
	}}, t.hemURL)
	if err != nil {
		return fail(failf(exitNetwork, "%w", err))
	}
	if err := t.pins.Add(plan.Endpoints); err != nil {
		return fail(failf(exitDevice, "%w", err))
	}

	uapi := uapiConfig(t.tree, peer, psk)
	if t.peer != nil {
		warnAllowedIPsDiffer(t.peer, peer)
		uapi = uapiReplacePeer(peer, psk)
		// Routes are added, never withdrawn: traffic is using the ones already
		// there, and taking them back mid-flight is the more dangerous mistake.
		if err := rt.AddRoutes(t.ifname, peer.AllowedIPs); err != nil {
			return fail(failf(exitDevice, "installing routes: %w", err))
		}
	}
	if err := t.dev.IpcSet(uapi); err != nil {
		return fail(failf(exitDevice, "configuring the tunnel: %w", err))
	}

	zero(t.psk)
	t.peer, t.psk = peer, psk
	t.hemInside, t.hemHost = plan.HEMInside, plan.HEMHost
	return nil
}

// configureInterface does the interface-level work: address, MTU, routes, DNS,
// and the check that the HEM survived them.
func (t *tunnel) configureInterface() error {
	if err := rt.Up(t.ifname, t.tree.Iface.Addrs); err != nil {
		return failf(exitDevice, "bringing %s up: %w", t.ifname, err)
	}
	if err := rt.SetMTU(t.ifname, int(t.tree.MTU())); err != nil {
		return failf(exitDevice, "setting the MTU: %w", err)
	}
	if err := rt.AddRoutes(t.ifname, t.peer.AllowedIPs); err != nil {
		return failf(exitDevice, "installing routes: %w", err)
	}
	if servers := dnsServers(t.tree); len(servers) > 0 {
		if err := rt.SetDNS(t.ifname, servers); err != nil {
			return failf(exitDevice, "setting DNS: %w", err)
		}
		t.dnsSet = true
	}
	// With the routes in place, confirm the HEM is still there. It is consulted
	// at every handshake, so losing it is not a degraded tunnel — it is one that
	// stops at the first rekey, roughly two minutes in.
	if t.hemInside {
		if err := rt.ProbeHEM(t.client, t.hemHost); err != nil {
			return failf(exitNetwork, "%w", err)
		}
	}
	return nil
}

func (t *tunnel) pubPath() string { return runDir + "/" + t.ifname + ".pub" }

// teardown undoes everything this process created, in the order that leaves the
// host as it was found. Every way out goes through it, so the abort path cannot
// drift from the one that runs on Ctrl+C.
func (t *tunnel) teardown() {
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
	zero(t.psk)
	_ = os.Remove(t.pubPath())
	removeState(t.ifname)
}

// selectPeer implements §6.2 step 5. WireGuard's cryptokey routing gives one
// peer the AllowedIPs at a time, so exactly one is chosen; the stored order is
// the failover priority and therefore the suggestion.
func selectPeer(tree *config.Tree, index int, keyPrefix string) (*config.Peer, error) {
	switch {
	case len(tree.Peers) == 0:
		return nil, failf(exitIntegrit, "the configuration has no peers")

	case index != 0:
		if index < 1 || index > len(tree.Peers) {
			return nil, failf(exitUsage, "--peer %d: the configuration has %d peers", index, len(tree.Peers))
		}
		return &tree.Peers[index-1], nil

	case keyPrefix != "":
		var found *config.Peer
		for i := range tree.Peers {
			b64 := base64.StdEncoding.EncodeToString(tree.Peers[i].PubKey[:])
			if !strings.HasPrefix(b64, keyPrefix) {
				continue
			}
			if found != nil {
				return nil, failf(exitUsage, "--peer-pubkey %q matches more than one peer", keyPrefix)
			}
			found = &tree.Peers[i]
		}
		if found == nil {
			return nil, failf(exitUsage, "--peer-pubkey %q matches no peer in the configuration", keyPrefix)
		}
		return found, nil

	case len(tree.Peers) == 1:
		return &tree.Peers[0], nil
	}

	return promptForPeer(tree)
}

// promptForPeer asks which peer to connect to, defaulting to the first — which
// is the head of the stored failover order.
func promptForPeer(tree *config.Tree) (*config.Peer, error) {
	fmt.Fprintln(os.Stderr, "Peers in this configuration:")
	for i, p := range tree.Peers {
		fmt.Fprintf(os.Stderr, "  %d) %-20s %s\n", i+1, p.Label, p.Endpoint.String())
	}
	fmt.Fprintf(os.Stderr, "Connect to [1]: ")

	line, err := readLine()
	if err != nil && err != io.EOF {
		return nil, failf(exitUsage, "reading the peer selection: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return &tree.Peers[0], nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(tree.Peers) {
		return nil, failf(exitUsage, "%q is not one of the %d peers offered", line, len(tree.Peers))
	}
	return &tree.Peers[n-1], nil
}

// readLine is a variable so tests can drive the selection without a terminal.
var readLine = func() (string, error) {
	return bufio.NewReader(os.Stdin).ReadString('\n')
}

// uapiConfig renders the set-operation wireguard-go is configured with.
//
// private_key is 64 zeros: the fork's SetPrivateKey intercepts it and takes the
// public key from the injected session instead, because the real private key is
// in the device and stays there.
func uapiConfig(tree *config.Tree, peer *config.Peer, psk []byte) string {
	var sb strings.Builder

	sb.WriteString("private_key=" + strings.Repeat("0", 64) + "\n")
	if tree.Iface.ListenPort != 0 {
		fmt.Fprintf(&sb, "listen_port=%d\n", tree.Iface.ListenPort)
	}
	writePeer(&sb, peer, psk)

	sb.WriteString("\n")
	return sb.String()
}

// uapiReplacePeer swaps the active peer for another and leaves the interface's
// own settings alone. replace_peers drops the previous one, which is the point:
// two peers claiming the same AllowedIPs is not something WireGuard can route.
func uapiReplacePeer(peer *config.Peer, psk []byte) string {
	var sb strings.Builder
	sb.WriteString("replace_peers=true\n")
	writePeer(&sb, peer, psk)
	sb.WriteString("\n")
	return sb.String()
}

func writePeer(sb *strings.Builder, peer *config.Peer, psk []byte) {
	fmt.Fprintf(sb, "public_key=%s\n", hex.EncodeToString(peer.PubKey[:]))
	if !peer.Endpoint.IsZero() {
		fmt.Fprintf(sb, "endpoint=%s\n", peer.Endpoint.String())
	}
	for _, a := range peer.AllowedIPs {
		fmt.Fprintf(sb, "allowed_ip=%s\n", a)
	}
	if peer.Keepalive != 0 {
		fmt.Fprintf(sb, "persistent_keepalive_interval=%d\n", peer.Keepalive)
	}
	if len(psk) != 0 {
		fmt.Fprintf(sb, "preshared_key=%s\n", hex.EncodeToString(psk))
	}
}

func dnsServers(tree *config.Tree) []string {
	out := make([]string, 0, len(tree.Iface.DNS))
	for _, d := range tree.Iface.DNS {
		out = append(out, d.String())
	}
	return out
}
