package tunnel

import (
	"fmt"
	"strings"
	"time"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
)

// FailoverTimeout is how long a freshly configured peer has to complete a
// handshake before it is treated as not answering (§6.4).
//
// WireGuard retransmits its first handshake message every 5 s, so fifteen
// seconds is three attempts. It is long enough that a slow path is not mistaken
// for a dead one, and short enough that an operator watching the terminal has
// not yet started wondering.
//
// Exported because whoever answers SelectNext wants to say how long it waited,
// and a second copy of the number in the message would be a second thing to keep
// in step.
var FailoverTimeout = 15 * time.Second

// handshakePoll is how often the interface is asked whether it has handshaken.
// The question is answered locally over a unix socket, so the cost is nil.
var handshakePoll = 500 * time.Millisecond

// awaitHandshake waits for the current peer to complete a handshake, or for
// FailoverTimeout to pass without one, or for the tunnel to end.
//
// The wait is only for the first handshake after a peer is configured. A peer
// that answers and later stops is v2's problem — automatic failover with a
// health check — and pretending otherwise here would mean guessing at the
// difference between a quiet tunnel and a dead one.
func awaitHandshake(ifname string, ending <-chan struct{}) (handshook bool) {
	deadline := time.After(FailoverTimeout)
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

// allowedIPsDiffer reports ranges that the interface routes but the peer about
// to take over does not claim, or "" when there are none.
//
// §6.4 replaces the peer and leaves the routing alone: the routes are in the
// table and traffic is using them, so withdrawing them mid-flight is the more
// dangerous of the two mistakes. The cheaper one is a range that now routes into
// the interface and finds no peer willing to carry it, and that is worth naming
// rather than leaving to be discovered as packet loss.
//
// It returns the sentence rather than printing it, because where a warning goes
// is not the tunnel's business — a terminal has stderr and a window has neither.
func allowedIPsDiffer(from, to *config.Peer) string {
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
		return ""
	}
	return fmt.Sprintf(
		"WARNING: %s does not claim %s; that range stays routed into the interface\n"+
			"         and will be dropped until a peer that claims it is selected.",
		to.Label, strings.Join(orphaned, ", "))
}
