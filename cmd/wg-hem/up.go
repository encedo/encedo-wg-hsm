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

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
)

// runDir is where the interface's public key is left while it is up, so `wg
// show` and `wg-hem status` have something to read. The private key is not there
// and never will be — `wg` cannot derive the public one from the zeroed private
// key the device is configured with.
const runDir = "/var/run/wireguard"

// cmdUp brings the tunnel up from the configuration in the device (§6.2). No
// file is read and nothing is written to disk beyond the public key.
func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	dev := addDeviceFlags(fs)
	ifname := fs.String("interface", "wg0", "name of the tunnel interface")
	peerIndex := fs.Int("peer", 0, "connect to peer N as numbered by `wg-hem verify` (1-based)")
	peerKey := fs.String("peer-pubkey", "", "connect to the peer whose base64 public key starts with this prefix")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wg-hem up — bring the tunnel up from the configuration in the device

  wg-hem up [--interface wg0] [--peer N | --peer-pubkey PREFIX] [device flags]

With more than one peer and neither selection flag, the peer is asked for; the
order is the one the interface record stores, which is the failover priority.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return failf(exitUsage, "%w", err)
	}
	if *peerIndex != 0 && *peerKey != "" {
		return failf(exitUsage, "--peer and --peer-pubkey select the same thing; pass one")
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
	fmt.Fprintf(os.Stderr, "Peer %q at %s.\n", peer.Label, peer.Endpoint.String())

	// One scope covers the rest of the run: the ECDH at every handshake, the
	// unwrap of the pre-shared key, and reading the interface's own public key.
	useTok, err := auth.token(ctx, "keymgmt:use:"+tree.IfKID)
	if err != nil {
		return err
	}

	psk, err := tree.UnwrapPSK(ctx, client, useTok, *peer)
	if err != nil {
		return classify(err, exitDevice, "pre-shared key")
	}
	defer zero(psk)

	// Resolve while the host's resolver is still the host's own: once AllowedIPs
	// owns the default route, a lookup may be travelling through the tunnel that
	// the answer is needed to build.
	//
	// Only the selected peer is planned for. Cryptokey routing gives one peer
	// the AllowedIPs at a time, so the others' endpoints are not reachable
	// through this interface and have nothing to be pinned against.
	plan, err := rt.PlanRouting([]rt.Peer{{
		Endpoint:   peer.Endpoint.String(),
		AllowedIPs: peer.AllowedIPs,
	}}, dev.url())
	if err != nil {
		return failf(exitNetwork, "%w", err)
	}

	return bringUp(ctx, client, tree, peer, psk, useTok, plan, *ifname)
}

// bringUp is everything from "the configuration is known" onwards: the device,
// the interface, the routing, and the wait. It is separate from cmdUp so the
// part that talks to the HEM and the part that talks to the kernel stay legible
// apart from each other.
func bringUp(ctx context.Context, client *hem.Client, tree *config.Tree, peer *config.Peer,
	psk []byte, useTok string, plan *rt.Plan, ifname string) error {

	ifPub, err := client.GetPubKey(ctx, useTok, tree.IfKID)
	if err != nil {
		return classify(err, exitDevice, "reading the interface public key")
	}
	var ifPubKey device.NoisePublicKey
	copy(ifPubKey[:], ifPub.PubKey)

	// The private key never enters this process, so the tunnel's every handshake
	// is a live call into the device.
	hsm := rt.NewHSM(client, useTok, tree.IfKID, ifPubKey)
	var peerPub device.NoisePublicKey
	copy(peerPub[:], peer.PubKey[:])
	hsm.AddPeerKID(peerPub, peer.KID)
	hsm.Inject()

	tdev, err := tun.CreateTUN(ifname, int(tree.MTU()))
	if err != nil {
		return failf(exitDevice, "creating the tunnel interface: %w", err)
	}
	if name, err := tdev.Name(); err == nil && name != "" {
		ifname = name
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", ifname))
	wgdev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	if err := wgdev.IpcSet(uapiConfig(tree, peer, psk)); err != nil {
		wgdev.Close()
		return failf(exitDevice, "configuring the tunnel: %w", err)
	}

	_ = os.MkdirAll(runDir, 0755)
	pubPath := runDir + "/" + ifname + ".pub"
	_ = os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(ifPub.PubKey)+"\n"), 0644)

	if err := rt.Up(ifname, tree.Iface.Addrs); err != nil {
		wgdev.Close()
		_ = os.Remove(pubPath)
		return failf(exitDevice, "bringing %s up: %w", ifname, err)
	}
	if err := rt.SetMTU(ifname, int(tree.MTU())); err != nil {
		wgdev.Close()
		_ = rt.Down(ifname)
		_ = os.Remove(pubPath)
		return failf(exitDevice, "setting the MTU: %w", err)
	}

	// From here the routing table has been touched, so every way out goes
	// through one teardown — the abort path cannot then drift from the one that
	// runs on Ctrl+C.
	pins := &rt.Pins{}
	teardown := func() {
		wgdev.Close()
		rt.RevertDNS(ifname)
		_ = rt.Down(ifname)
		pins.Restore()
		_ = os.Remove(pubPath)
	}

	if err := pins.Add(plan.Endpoints); err != nil {
		teardown()
		return failf(exitDevice, "%w", err)
	}
	if err := rt.AddRoutes(ifname, peer.AllowedIPs); err != nil {
		teardown()
		return failf(exitDevice, "installing routes: %w", err)
	}
	if err := rt.SetDNS(ifname, dnsServers(tree)); err != nil {
		teardown()
		return failf(exitDevice, "setting DNS: %w", err)
	}
	if plan.HEMInside {
		if err := rt.ProbeHEM(client, plan.HEMHost); err != nil {
			teardown()
			return failf(exitNetwork, "%w", err)
		}
	}

	uapi, err := rt.UAPIListen(ifname)
	if err != nil {
		teardown()
		return failf(exitDevice, "opening the UAPI socket: %w", err)
	}
	uapiErr := make(chan error, 1)
	go func() {
		for {
			c, err := uapi.Accept()
			if err != nil {
				uapiErr <- err
				return
			}
			go wgdev.IpcHandle(c)
		}
	}()

	fmt.Fprintf(os.Stderr, "Interface %s is up.\n", ifname)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case <-stop:
	case <-uapiErr:
	case <-wgdev.Wait():
	case <-hsm.Dead():
		fmt.Fprintln(os.Stderr, "The HEM is gone or the token has expired — bringing the interface down.")
	}

	uapi.Close()
	teardown()
	fmt.Fprintf(os.Stderr, "Interface %s is down.\n", ifname)
	return nil
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

	fmt.Fprintf(&sb, "public_key=%s\n", hex.EncodeToString(peer.PubKey[:]))
	if !peer.Endpoint.IsZero() {
		fmt.Fprintf(&sb, "endpoint=%s\n", peer.Endpoint.String())
	}
	for _, a := range peer.AllowedIPs {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", a)
	}
	if peer.Keepalive != 0 {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", peer.Keepalive)
	}
	if len(psk) != 0 {
		fmt.Fprintf(&sb, "preshared_key=%s\n", hex.EncodeToString(psk))
	}

	sb.WriteString("\n")
	return sb.String()
}

func dnsServers(tree *config.Tree) []string {
	out := make([]string, 0, len(tree.Iface.DNS))
	for _, d := range tree.Iface.DNS {
		out = append(out, d.String())
	}
	return out
}
