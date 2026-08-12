package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
)

// cmdStatus reports what a running interface is doing (§10.2): which peer is
// active, when it last handshook, what it has carried, and whether the stored
// configuration still authenticates.
//
// The last of those is the point. A tunnel can be up and carrying traffic while
// the configuration behind it has been edited underneath — the MAC is what
// notices, and asking here means not waiting for the next startup to find out.
func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	dev := addDeviceFlags(fs)
	ifname := fs.String("interface", "wg0", "name of the tunnel interface")
	noVerify := fs.Bool("no-verify", false, "skip the configuration check, and with it the device round trip")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wg-hem status — report on a running interface

  wg-hem status [--interface wg0] [--no-verify] [device flags]

Without --no-verify the stored configuration is re-authenticated against the
device, which needs a token and therefore the passphrase.

`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return failf(exitUsage, "%w", err)
	}

	st, err := resolveState(*ifname, flagGiven(fs, "interface"))
	if err != nil {
		return err
	}

	// The device is spoken to first, though what it says is printed last.
	//
	// It is the only step here that asks for anything, and asked in the place
	// its answer belongs — under the live figures — the passphrase prompt
	// arrived at the foot of a screenful of output, where it reads as a program
	// that has finished rather than one waiting for a person. The report keeps
	// the order it had; only the question moved.
	var (
		tree    *config.Tree
		loadErr error
	)
	if !*noVerify {
		if *dev.hem == "" {
			*dev.hem = st.HEMURL
		}
		var auth *authenticator
		_, auth, tree, loadErr = dev.load(context.Background())
		if auth != nil {
			defer auth.wipe()
		}
	}

	fmt.Printf("interface %s\n", st.Interface)
	fmt.Printf("pid %d\n", st.PID)
	fmt.Printf("uptime %s\n", time.Since(st.Started).Truncate(time.Second))
	if !st.TokenExpiry.IsZero() {
		// Both forms: the instant is what a person plans around, the remaining
		// time is what they act on. Past the expiry the tunnel is already gone or
		// about to be, so say so rather than print a negative duration.
		left := time.Until(st.TokenExpiry).Truncate(time.Second)
		if left <= 0 {
			fmt.Printf("session.expired %s\n", st.TokenExpiry.UTC().Format(time.RFC3339))
		} else {
			fmt.Printf("session.ends %s\n", st.TokenExpiry.UTC().Format(time.RFC3339))
			fmt.Printf("session.ends-in %s\n", left)
		}
	}
	fmt.Printf("hem %s\n", st.HEMURL)
	fmt.Printf("if-kid %s\n", st.IfKID)
	fmt.Printf("peer.kid %s\n", st.PeerKID)
	fmt.Printf("peer.label %s\n", st.PeerLabel)
	fmt.Printf("peer.endpoint %s\n", st.Endpoint)

	live, err := rt.Status(st.Interface)
	if err != nil {
		// The state file says a tunnel should be here and the socket says
		// otherwise. That is worth reporting as a failure, not as a blank.
		return failf(exitDevice, "%w", err)
	}
	if live.ListenPort != 0 {
		fmt.Printf("listen-port %d\n", live.ListenPort)
	}
	for _, p := range live.Peers {
		fmt.Printf("live.pubkey %s\n", base64.StdEncoding.EncodeToString(p.PublicKey[:]))
		if p.Endpoint != "" {
			fmt.Printf("live.endpoint %s\n", p.Endpoint)
		}
		if p.LastHandshake.IsZero() {
			// With the private key in the device, a tunnel whose HEM is
			// unreachable comes up and simply never completes a handshake.
			fmt.Printf("live.last-handshake never\n")
		} else {
			fmt.Printf("live.last-handshake %s\n", p.LastHandshake.UTC().Format(time.RFC3339))
			fmt.Printf("live.last-handshake-ago %s\n", time.Since(p.LastHandshake).Truncate(time.Second))
		}
		fmt.Printf("live.rx-bytes %d\n", p.RxBytes)
		fmt.Printf("live.tx-bytes %d\n", p.TxBytes)
		fmt.Printf("live.psk %t\n", p.HasPSK)
		if p.Keepalive != 0 {
			fmt.Printf("live.keepalive %d\n", p.Keepalive)
		}
	}

	if *noVerify {
		fmt.Printf("config.verified skipped\n")
		return nil
	}
	if loadErr != nil {
		fmt.Printf("config.verified false\n")
		return loadErr
	}

	fmt.Printf("config.verified true\n")
	fmt.Printf("config.peers %d\n", len(tree.Peers))

	// The configuration authenticates, but it may no longer be the one this
	// interface came up with — `peer update` re-MACs the tree without touching a
	// running tunnel, so an authentic tree and a stale interface look alike from
	// the MAC alone.
	if !treeHasPeer(tree, st.PeerKID) {
		fmt.Printf("config.active-peer-present false\n")
		fmt.Fprintf(os.Stderr,
			"NOTE: the peer this interface is running is no longer in the stored configuration;\n"+
				"      restart it to pick up the current one.\n")
	} else {
		fmt.Printf("config.active-peer-present true\n")
	}
	return nil
}

// treeHasPeer reports whether the configuration still carries the peer the
// interface is running.
func treeHasPeer(tree *config.Tree, kid string) bool {
	for _, p := range tree.Peers {
		if p.KID == kid {
			return true
		}
	}
	return false
}
