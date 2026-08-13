package tunnel

import (
	"strings"
	"testing"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

func threePeers(t *testing.T) *config.Tree {
	t.Helper()
	return treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
		testPeer("spare", 3, "192.0.2.1:51820", "0.0.0.0/0"),
	)
}

// The stored order is the priority — §3.1 says so of PEER_REF, and the
// configuration MAC covers it — so the walk follows it rather than inventing
// one.
func TestWalkFollowsTheStoredOrder(t *testing.T) {
	tree := threePeers(t)
	walk := WalkPeers()

	next, err := walk(tree, &tree.Peers[0])
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if next.Label != "backup" {
		t.Errorf("after hq the walk chose %q, want backup", next.Label)
	}

	next, err = walk(tree, next)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if next.Label != "spare" {
		t.Errorf("after backup the walk chose %q, want spare", next.Label)
	}
}

// A peer that has already failed must not come round again. Without this the
// walk is a loop, and a loop here is a call into the device every fifteen
// seconds for as long as nobody is watching.
func TestWalkNeverReturnsAPeerTwice(t *testing.T) {
	tree := threePeers(t)
	walk := WalkPeers()

	seen := map[string]bool{}
	failed := &tree.Peers[0]
	for range tree.Peers {
		next, err := walk(tree, failed)
		if err != nil {
			break
		}
		if seen[next.KID] {
			t.Fatalf("the walk offered %q a second time", next.Label)
		}
		seen[next.KID] = true
		failed = next
	}
}

func TestWalkGivesUpWhenEveryPeerHasHadATurn(t *testing.T) {
	tree := threePeers(t)
	walk := WalkPeers()

	failed := &tree.Peers[0]
	var err error
	for i := 0; i < len(tree.Peers)+1; i++ {
		var next *config.Peer
		next, err = walk(tree, failed)
		if err != nil {
			break
		}
		failed = next
	}
	if err == nil {
		t.Fatal("the walk kept offering peers after every one had failed")
	}
	for _, label := range []string{"hq", "backup", "spare"} {
		if !strings.Contains(err.Error(), label) {
			t.Errorf("the refusal does not name %s:\n%s", label, err)
		}
	}
	if !strings.Contains(err.Error(), FailoverTimeout.String()) {
		t.Errorf("the refusal does not say how long each was given:\n%s", err)
	}
}

// Nothing answering is a network fault. It decides the exit code a script sees
// and, for a window, which screen somebody is shown — an appliance problem sends
// them to the module, and this is not one.
func TestExhaustionIsANetworkFault(t *testing.T) {
	tree := treeWith(t, testPeer("only", 1, "203.0.113.1:51820", "0.0.0.0/0"))
	walk := WalkPeers()

	_, err := walk(tree, &tree.Peers[0])
	if err == nil {
		t.Fatal("the only peer failed and the walk offered something anyway")
	}
	if got := session.KindOf(err); got != session.KindNetwork {
		t.Errorf("kind = %v, want %v", got, session.KindNetwork)
	}
}

// The first call may arrive with nothing having failed yet — a caller that walks
// from the start rather than after a failure — and must not be a crash.
func TestWalkStartsFromNothing(t *testing.T) {
	tree := threePeers(t)
	next, err := WalkPeers()(tree, nil)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if next.Label != "hq" {
		t.Errorf("the walk started at %q, want the head of the stored order", next.Label)
	}
}
