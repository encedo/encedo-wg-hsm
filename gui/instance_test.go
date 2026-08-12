package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestClaimInstanceHandsOver is the whole point of the mechanism: the second
// launch must not become a second window, and must reach the first rather than
// merely refusing.
func TestClaimInstanceHandsOver(t *testing.T) {
	dir := t.TempDir()

	ln, handedOver, err := claimInstance(dir)
	if err != nil || handedOver || ln == nil {
		t.Fatalf("first claim: ln=%v handedOver=%v err=%v; want a listener", ln, handedOver, err)
	}
	defer ln.Close()

	shown := make(chan struct{}, 1)
	go serveInstance(ln, func() { shown <- struct{}{} })

	second, handedOver, err := claimInstance(dir)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if !handedOver {
		t.Error("the second claim took a listener of its own; two windows would run")
	}
	if second != nil {
		second.Close()
		t.Error("the second claim returned a listener as well as handing over")
	}

	select {
	case <-shown:
	case <-time.After(2 * time.Second):
		t.Error("the first window was never asked to show itself; a second launch would look like nothing happened")
	}
}

// TestClaimInstanceTakesOverStale covers the crash: the address is still on
// disk and nothing is behind it. Refusing to start then would need somebody to
// find and delete a file they have never heard of.
func TestClaimInstanceTakesOverStale(t *testing.T) {
	dir := t.TempDir()

	// A port that was listening and is not any more, so the address is real and
	// the connection is refused rather than left hanging.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := dead.Addr().String()
	dead.Close()

	if err := os.WriteFile(filepath.Join(dir, instanceFile), []byte(addr+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	ln, handedOver, err := claimInstance(dir)
	if err != nil {
		t.Fatalf("claim over stale: %v", err)
	}
	if handedOver {
		t.Fatal("handed over to a port nothing is listening on; the window would never open")
	}
	defer ln.Close()

	// And the file now names this instance, not the dead one.
	raw, err := os.ReadFile(filepath.Join(dir, instanceFile))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := string(raw); got == addr+"\n" {
		t.Error("the stale address was left in place; the next launch would try it again")
	}
}

// TestClaimInstanceIsLoopbackOnly checks where the doorbell is offered. This is
// a channel between two copies of one program on one machine; a bind on any
// other address would put it on the network.
func TestClaimInstanceIsLoopbackOnly(t *testing.T) {
	ln, _, err := claimInstance(t.TempDir())
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	defer ln.Close()

	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("address %q: %v", ln.Addr(), err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Errorf("listening on %s, want loopback", host)
	}
}
