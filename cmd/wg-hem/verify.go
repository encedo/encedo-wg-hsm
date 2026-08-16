package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/mac"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// cmdVerify is the "has anyone touched the configuration" diagnostic (section 10.3).
// It performs exactly what `up` performs before it brings an interface up -
// find, resolve, authenticate - and then prints what it found instead of acting
// on it, so the check can be run at any time without disturbing a live tunnel.
func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dev := addDeviceFlags(fs)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: wg-hem verify [flags]

Reads the configuration out of the HEM and checks its MAC, then prints it.
Exit code 4 means the stored configuration is not the one that was provisioned.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return &exitError{code: exitUsage, err: err}
	}

	ctx := context.Background()
	_, auth, tree, err := dev.load(ctx)
	if err != nil {
		return err
	}
	defer auth.Wipe()

	fmt.Fprintln(os.Stderr, "Configuration verified: the stored records are the ones that were provisioned.")
	dumpTree(tree)
	reportRunningPeer(tree)
	return nil
}

// reportRunningPeer says when a tunnel is running through a peer this
// configuration no longer names.
//
// The configuration authenticates and the tunnel works, and they can still
// disagree: `peer update` re-signs the tree without touching a running
// interface, so an authentic tree and a stale interface look alike from the MAC
// alone. It lives here rather than in `status` because answering it needs the
// tree, and reading the tree is this command's job - `status` reports what is
// running and asks nobody for anything.
func reportRunningPeer(tree *config.Tree) {
	names, err := session.Running()
	if err != nil {
		return
	}
	for _, name := range names {
		st, err := session.Load(name)
		if err != nil || st.IfKID != tree.IfKID {
			continue
		}
		if treeHasPeer(tree, st.PeerKID) {
			fmt.Printf("running.%s.peer-present true\n", name)
			continue
		}
		fmt.Printf("running.%s.peer-present false\n", name)
		fmt.Fprintf(os.Stderr,
			"NOTE: %s is running peer %s, which this configuration no longer names;\n"+
				"      restart it to pick up the current one.\n", name, st.PeerKID)
	}
}

// treeHasPeer reports whether the configuration still carries the peer an
// interface is running.
func treeHasPeer(tree *config.Tree, kid string) bool {
	for _, p := range tree.Peers {
		if p.KID == kid {
			return true
		}
	}
	return false
}

// dumpTree writes the parsed configuration to stdout in a stable, greppable
// form. Human commentary belongs on stderr (section 10.4), so this is only the data.
func dumpTree(t *config.Tree) {
	fmt.Printf("interface.kid %s\n", t.IfKID)
	fmt.Printf("interface.label %s\n", t.IfLabel)
	fmt.Printf("interface.pubkey %s\n", base64.StdEncoding.EncodeToString(t.IfPubKey[:]))
	for _, a := range t.Iface.Addrs {
		fmt.Printf("interface.address %s\n", a)
	}
	fmt.Printf("interface.mtu %d\n", t.MTU())
	for _, d := range t.Iface.DNS {
		fmt.Printf("interface.dns %s\n", d)
	}
	if t.Iface.ListenPort != 0 {
		fmt.Printf("interface.listen-port %d\n", t.Iface.ListenPort)
	}
	fmt.Printf("interface.mac %x\n", t.Iface.MAC)

	for i, p := range t.Peers {
		// The index is the failover priority, which is what the reference order
		// in the interface record encodes.
		fmt.Printf("peer.%d.kid %s\n", i, p.KID)
		fmt.Printf("peer.%d.label %s\n", i, p.Label)
		fmt.Printf("peer.%d.pubkey %s\n", i, base64.StdEncoding.EncodeToString(p.PubKey[:]))
		fmt.Printf("peer.%d.endpoint %s\n", i, p.Endpoint.String())
		for _, a := range p.AllowedIPs {
			fmt.Printf("peer.%d.allowed-ips %s\n", i, a)
		}
		if p.Keepalive != 0 {
			fmt.Printf("peer.%d.keepalive %d\n", i, p.Keepalive)
		}
		fmt.Printf("peer.%d.psk %t\n", i, len(p.PSKWrapped) > 0)
	}
}

// classifyLoad separates "the configuration failed authentication" from every
// other reason loading can fail. The first has its own exit code because it is
// the one that means someone changed something.
func classifyLoad(err error) error {
	if errors.Is(err, mac.ErrNotAuthentic) {
		return failf(exitIntegrit, "%w", err)
	}
	var he *hem.HemError
	if errors.As(err, &he) {
		return classify(he, exitDevice, "reading the configuration")
	}
	return failf(exitDevice, "reading the configuration: %w", err)
}
