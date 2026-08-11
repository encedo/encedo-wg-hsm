package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/encedo/encedo-wg-hsm/internal/config"
)

// captureStderr collects what a prompt or a warning wrote, so the message an
// operator has to act on can be checked rather than assumed.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	prev := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	w.Close()
	os.Stderr = prev
	return <-done
}

// The suggestion moves on: the peer that just failed is not the one to try next.
func TestRepromptSuggestsTheNextPeer(t *testing.T) {
	withReadLine(t, "\n")
	tree := treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
	)

	var got *config.Peer
	out := captureStderr(t, func() {
		p, err := repromptPeer(tree, &tree.Peers[0])
		if err != nil {
			t.Errorf("repromptPeer: %v", err)
			return
		}
		got = p
	})
	if got == nil {
		t.Fatal("no peer returned")
	}
	if got.Label != "backup" {
		t.Errorf("suggested %q, want backup", got.Label)
	}
	if !strings.Contains(out, "Connect to [2]") {
		t.Errorf("the prompt did not offer peer 2:\n%s", out)
	}
}

// The failed peer stays selectable — an endpoint can come back, and the operator
// may know something this process does not — but it is marked.
func TestRepromptMarksTheFailedPeerAndKeepsIt(t *testing.T) {
	withReadLine(t, "1\n")
	tree := treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
	)

	var got *config.Peer
	out := captureStderr(t, func() {
		p, err := repromptPeer(tree, &tree.Peers[0])
		if err != nil {
			t.Errorf("repromptPeer: %v", err)
			return
		}
		got = p
	})
	if got == nil || got.Label != "hq" {
		t.Fatal("the failed peer could not be chosen again")
	}
	if !strings.Contains(out, "! 1) hq") {
		t.Errorf("the failed peer was not marked:\n%s", out)
	}
	if !strings.Contains(out, "is not responding") {
		t.Errorf("the prompt did not say why it appeared:\n%s", out)
	}
}

// With a single peer the suggestion wraps back to it: there is nothing else to
// offer, and refusing to offer anything would end the tunnel over a slow start.
func TestRepromptWithOnePeerOffersItAgain(t *testing.T) {
	withReadLine(t, "\n")
	tree := treeWith(t, testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"))

	var got *config.Peer
	captureStderr(t, func() {
		p, err := repromptPeer(tree, &tree.Peers[0])
		if err != nil {
			t.Errorf("repromptPeer: %v", err)
			return
		}
		got = p
	})
	if got == nil || got.Label != "hq" {
		t.Fatal("the only peer was not offered again")
	}
}

// Nobody to ask is not a reason to guess: a wrong peer is a tunnel to the wrong
// place, so it ends with a network failure instead.
func TestRepromptWithNoTerminalFails(t *testing.T) {
	prev := readLine
	t.Cleanup(func() { readLine = prev })
	readLine = func() (string, error) { return "", os.ErrClosed }

	tree := treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
	)

	var err error
	captureStderr(t, func() { _, err = repromptPeer(tree, &tree.Peers[0]) })
	if err == nil {
		t.Fatal("repromptPeer guessed a peer with nobody to ask")
	}
	assertExit(t, err, exitNetwork)
}

// A range the interface routes and the incoming peer does not claim becomes a
// black hole. §6.4 keeps the routes on purpose, so the least this can do is say
// which ones are now going nowhere.
func TestWarnsAboutRangesTheNewPeerDoesNotClaim(t *testing.T) {
	from := testPeer("hq", 1, "203.0.113.1:51820", "10.0.0.0/24", "192.168.0.0/16")
	to := testPeer("backup", 2, "198.51.100.1:51820", "10.0.0.0/24")

	out := captureStderr(t, func() { warnAllowedIPsDiffer(&from, &to) })
	if !strings.Contains(out, "192.168.0.0/16") {
		t.Errorf("the orphaned range was not named:\n%s", out)
	}
	if strings.Contains(out, "10.0.0.0/24") {
		t.Errorf("a range the new peer does claim was reported as orphaned:\n%s", out)
	}
}

func TestNoWarningWhenTheNewPeerClaimsEverything(t *testing.T) {
	from := testPeer("hq", 1, "203.0.113.1:51820", "10.0.0.0/24")
	to := testPeer("backup", 2, "198.51.100.1:51820", "10.0.0.0/24", "192.168.0.0/16")

	if out := captureStderr(t, func() { warnAllowedIPsDiffer(&from, &to) }); out != "" {
		t.Errorf("warned about nothing:\n%s", out)
	}
}

// awaitHandshake must not outlive the tunnel: when the interface ends for a
// reason no peer would fix, the wait stops rather than running its timeout out.
func TestAwaitHandshakeStopsWhenTheTunnelEnds(t *testing.T) {
	prev := failoverTimeout
	failoverTimeout = 10 * time.Second
	t.Cleanup(func() { failoverTimeout = prev })

	ending := make(chan struct{})
	close(ending)

	start := time.Now()
	if awaitHandshake("nosuchiface", ending) {
		t.Error("awaitHandshake claimed a handshake on an interface that is not up")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("awaitHandshake waited %s past the end of the tunnel", elapsed)
	}
}

// An interface that never answers is reported as not having handshaken, after
// the timeout and not before.
func TestAwaitHandshakeGivesUpAfterTheTimeout(t *testing.T) {
	prevTimeout, prevPoll := failoverTimeout, handshakePoll
	failoverTimeout, handshakePoll = 200*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { failoverTimeout, handshakePoll = prevTimeout, prevPoll })

	start := time.Now()
	if awaitHandshake("nosuchiface", make(chan struct{})) {
		t.Error("awaitHandshake claimed a handshake on an interface that is not up")
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("awaitHandshake gave up after %s, before its timeout", elapsed)
	}
}

func TestUAPIReplacePeerDropsThePrevious(t *testing.T) {
	peer := testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0")
	peer.Keepalive = 25

	got := uapiReplacePeer(&peer, nil)
	if !strings.HasPrefix(got, "replace_peers=true\n") {
		t.Errorf("replace_peers is not the first instruction:\n%s", got)
	}
	if strings.Contains(got, "private_key=") {
		t.Errorf("a replacement rewrote the interface's identity:\n%s", got)
	}
	if !strings.Contains(got, "endpoint=198.51.100.1:51820\n") {
		t.Errorf("the new endpoint is missing:\n%s", got)
	}
	if !strings.Contains(got, "persistent_keepalive_interval=25\n") {
		t.Errorf("keepalive is missing:\n%s", got)
	}
}

func TestUAPIReplacePeerCarriesThePSK(t *testing.T) {
	peer := testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0")
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 0x5A
	}

	if got := uapiReplacePeer(&peer, psk); !strings.Contains(got, "preshared_key=") {
		t.Errorf("the incoming peer lost its pre-shared key:\n%s", got)
	}
}

// A peer whose record has no AllowedIPs at all would silently route nothing;
// the warning is the only thing that would say so.
func TestWarnsWhenTheNewPeerClaimsNothing(t *testing.T) {
	from := testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0")
	to := config.Peer{Label: "empty"}
	to.Endpoint = from.Endpoint
	to.AllowedIPs = nil

	out := captureStderr(t, func() { warnAllowedIPsDiffer(&from, &to) })
	if !strings.Contains(out, "0.0.0.0/0") {
		t.Errorf("an incoming peer claiming nothing went unreported:\n%s", out)
	}
}
