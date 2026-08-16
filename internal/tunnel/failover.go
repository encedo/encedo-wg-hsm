package tunnel

import (
	"fmt"
	"strings"
	"time"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// FailoverTimeout is how long a freshly configured peer has to complete a
// handshake before it is treated as not answering (section 6.4).
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
// that answers and later stops is v2's problem - automatic failover with a
// health check - and pretending otherwise here would mean guessing at the
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

// WalkPeers answers failover without asking anybody, by walking the stored order
// (section 6.4 v2). It is what a component with nobody in front of it passes as
// SelectNext.
//
// The stored order *is* the priority - section 3.1 says so of PEER_REF, and it is
// covered by the configuration MAC - so there is nothing to decide here beyond
// keeping track of what has already been tried. The interactive prompt exists
// because a terminal had a human in front of it, not because failover needs one.
//
// It gives up after every peer has had its turn rather than cycling. Cycling
// would never report that nothing works, and each attempt is not free: pointing
// the interface at a peer unwraps that peer's pre-shared key, which is a call
// into the device. A tunnel that quietly asked the appliance something every
// fifteen seconds for the rest of the afternoon would be a worse failure than
// the one it was papering over.
//
// Stateful, therefore a closure: one walk belongs to one tunnel, and "have we
// tried this one" cannot be answered from the arguments alone.
func WalkPeers() func(tree *config.Tree, failed *config.Peer) (*config.Peer, error) {
	tried := map[string]bool{}
	return func(tree *config.Tree, failed *config.Peer) (*config.Peer, error) {
		if failed != nil {
			tried[failed.KID] = true
		}
		for i := range tree.Peers {
			if !tried[tree.Peers[i].KID] {
				return &tree.Peers[i], nil
			}
		}

		names := make([]string, 0, len(tree.Peers))
		for _, p := range tree.Peers {
			names = append(names, p.Label)
		}
		return nil, session.Fail(session.KindNetwork,
			"no peer answered: %s, each given %s", strings.Join(names, ", "), FailoverTimeout)
	}
}

// allowedIPsDiffer reports ranges that the interface routes but the peer about
// to take over does not claim, or "" when there are none.
//
// section 6.4 replaces the peer and leaves the routing alone: the routes are in the
// table and traffic is using them, so withdrawing them mid-flight is the more
// dangerous of the two mistakes. The cheaper one is a range that now routes into
// the interface and finds no peer willing to carry it, and that is worth naming
// rather than leaving to be discovered as packet loss.
//
// It returns the sentence rather than printing it, because where a warning goes
// is not the tunnel's business - a terminal has stderr and a window has neither.
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
