package main

import (
	"os"
	"strings"
	"testing"

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

// The failed peer stays selectable - an endpoint can come back, and the operator
// may know something this process does not - but it is marked.
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
