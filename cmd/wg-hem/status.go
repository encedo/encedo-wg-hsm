package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"time"

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
	ifname := fs.String("interface", "wg0", "name of the tunnel interface")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `wg-hem status — report on a running interface

  wg-hem status [--interface wg0]

Reads the state file this process left and the interface itself. It does not
reach the device and does not ask for anything: whether the stored configuration
still authenticates is what `+"`wg-hem verify`"+` answers.

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
	if errors.Is(err, iofs.ErrPermission) {
		// A tunnel the service started leaves a socket the service owns, and
		// that socket is how an interface is *configured* — group access to it
		// would let anybody in the group replace the endpoint and the routes
		// that the configuration MAC exists to protect. So it stays private, and
		// reading the live half of a service-run tunnel wants root.
		//
		// Everything above this line came from the state file and is still true,
		// so this is a gap in the report rather than a failed command.
		fmt.Printf("live.unreadable permission\n")
		fmt.Fprintf(os.Stderr,
			"NOTE: %s belongs to the service that started it. Its counters and last\n"+
				"      handshake are readable with `sudo wg show %s`; the window shows them\n"+
				"      without either, over its own channel.\n", st.Interface, st.Interface)
		return nil
	}
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

	return nil
}
