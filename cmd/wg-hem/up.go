package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
	"github.com/encedo/encedo-wg-hsm/internal/tunnel"
)

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
	defer auth.Wipe()

	peer, err := selectPeer(tree, *peerIndex, *peerKey)
	if err != nil {
		return err
	}

	// One scope covers the rest of the run: the ECDH at every handshake, the
	// unwrap of each pre-shared key, and reading the interface's own public key.
	useTok, err := auth.Token(ctx, "keymgmt:use:"+tree.IfKID)
	if err != nil {
		return err
	}

	t := tunnel.New(ctx, tunnel.Opts{
		Client: client, Tree: tree,
		UseTok: useTok, HEMURL: dev.url(), Ifname: *ifname,
		SelectNext: repromptPeer,
		Notify:     func(line string) { fmt.Fprintln(os.Stderr, line) },
	})
	if err := t.Run(peer); err != nil {
		return exitFrom(err)
	}
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
