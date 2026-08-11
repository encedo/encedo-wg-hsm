package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"

	"github.com/encedo/encedo-wg-hsm/internal/config"
)

// failoverTimeout is how long a freshly configured peer has to complete a
// handshake before it is treated as not answering (§6.4).
//
// WireGuard retransmits its first handshake message every 5 s, so fifteen
// seconds is three attempts. It is long enough that a slow path is not mistaken
// for a dead one, and short enough that an operator watching the terminal has
// not yet started wondering.
var failoverTimeout = 15 * time.Second

// handshakePoll is how often the interface is asked whether it has handshaken.
// The question is answered locally over a unix socket, so the cost is nil.
var handshakePoll = 500 * time.Millisecond

// awaitHandshake waits for the current peer to complete a handshake, or for
// failoverTimeout to pass without one, or for the tunnel to end.
//
// The wait is only for the first handshake after a peer is configured. A peer
// that answers and later stops is v2's problem — automatic failover with a
// health check — and pretending otherwise here would mean guessing at the
// difference between a quiet tunnel and a dead one.
func awaitHandshake(ifname string, ending <-chan struct{}) (handshook bool) {
	deadline := time.After(failoverTimeout)
	tick := time.NewTicker(handshakePoll)
	defer tick.Stop()

	for {
		select {
		case <-ending:
			return false
		case <-deadline:
			return false
		case <-tick.C:
			st, err := rt.Status(ifname)
			if err != nil {
				// The interface answering is the precondition for everything
				// here; if it has stopped, the ending channel will say so.
				continue
			}
			for _, p := range st.Peers {
				if !p.LastHandshake.IsZero() {
					return true
				}
			}
		}
	}
}

// repromptPeer asks which peer to try next after one stopped answering (§6.4).
// The failed peer stays on the list — an endpoint can come back, and the
// operator may know something this process does not — but it is marked, and the
// suggestion moves on to the next one in the stored order.
func repromptPeer(tree *config.Tree, failed *config.Peer) (*config.Peer, error) {
	suggestion := 1
	for i := range tree.Peers {
		if tree.Peers[i].KID == failed.KID {
			suggestion = (i+1)%len(tree.Peers) + 1
			break
		}
	}

	fmt.Fprintf(os.Stderr, "\nPeer %q (%s) is not responding after %s.\n",
		failed.Label, failed.Endpoint.String(), failoverTimeout)
	fmt.Fprintln(os.Stderr, "Peers in this configuration:")
	for i, p := range tree.Peers {
		mark := " "
		if p.KID == failed.KID {
			mark = "!"
		}
		fmt.Fprintf(os.Stderr, "  %s %d) %-20s %s\n", mark, i+1, p.Label, p.Endpoint.String())
	}
	fmt.Fprintf(os.Stderr, "Connect to [%d]: ", suggestion)

	line, err := readLine()
	if err != nil {
		// No terminal to ask, or the operator closed it. There is no answer to
		// guess at here: a wrong peer is a tunnel to the wrong place.
		return nil, failf(exitNetwork, "peer %q is not responding and there is nobody to ask: %w",
			failed.Label, err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return &tree.Peers[suggestion-1], nil
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(tree.Peers) {
		return nil, failf(exitUsage, "%q is not one of the %d peers offered", line, len(tree.Peers))
	}
	return &tree.Peers[n-1], nil
}

// warnAllowedIPsDiffer reports ranges that the interface routes but the peer
// about to take over does not claim.
//
// §6.4 replaces the peer and leaves the routing alone: the routes are in the
// table and traffic is using them, so withdrawing them mid-flight is the more
// dangerous of the two mistakes. The cheaper one is a range that now routes into
// the interface and finds no peer willing to carry it, and that is worth naming
// rather than leaving to be discovered as packet loss.
func warnAllowedIPsDiffer(from, to *config.Peer) {
	claimed := make(map[string]bool, len(to.AllowedIPs))
	for _, a := range to.AllowedIPs {
		claimed[a.String()] = true
	}
	var orphaned []string
	for _, a := range from.AllowedIPs {
		if !claimed[a.String()] {
			orphaned = append(orphaned, a.String())
		}
	}
	if len(orphaned) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"WARNING: %s does not claim %s; that range stays routed into the interface\n"+
			"         and will be dropped until a peer that claims it is selected.\n",
		to.Label, strings.Join(orphaned, ", "))
}
