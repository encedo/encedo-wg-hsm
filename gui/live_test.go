package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/ipc"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// The live session satisfies the same interface the stand-in does. If it stops,
// the window has two shapes to drive and the interface has stopped earning its
// keep.
var _ Session = (*liveSession)(nil)

func TestOneIdentityIsNotWorthAsking(t *testing.T) {
	ids := []config.Identity{{KID: "aa", Label: "only"}}
	got, err := pickIdentity(ids, func([]config.Identity) (string, error) {
		t.Fatal("a single identity was put to a choice")
		return "", nil
	})
	if err != nil {
		t.Fatalf("pickIdentity: %v", err)
	}
	if got != "aa" {
		t.Errorf("chose %q, want aa", got)
	}
}

// An unprovisioned module is not a device fault or a network one - it is a
// configuration that is not there, and the window shows a different thing for
// each.
func TestNoIdentityIsAnIntegrityFault(t *testing.T) {
	_, err := pickIdentity(nil, nil)
	if err == nil {
		t.Fatal("a module with no configuration was accepted")
	}
	if got := session.KindOf(err); got != session.KindIntegrity {
		t.Errorf("kind = %v, want %v", got, session.KindIntegrity)
	}
	if !strings.Contains(err.Error(), "provision") {
		t.Errorf("error %q does not say what to do about it", err)
	}
}

// Until the window can offer the choice, several identities must refuse rather
// than pick one. Connecting as an identity nobody named is the mistake that does
// not announce itself.
func TestSeveralIdentitiesWithNoChooserRefuse(t *testing.T) {
	ids := []config.Identity{{KID: "aa"}, {KID: "bb"}}
	if _, err := pickIdentity(ids, nil); err == nil {
		t.Fatal("one of two identities was picked with nobody asked")
	}
}

// The stored order is the failover priority - somebody wrote it down - so the
// first peer is an answer rather than a guess.
func TestTheFirstPeerIsTheStoredPriority(t *testing.T) {
	peers := []config.Peer{{KID: "aa", Label: "hq"}, {KID: "bb", Label: "backup"}}
	got, err := pickPeer(peers, nil)
	if err != nil {
		t.Fatalf("pickPeer: %v", err)
	}
	if got != "aa" {
		t.Errorf("chose %q, want the head of the stored order", got)
	}
}

func TestNoPeersIsAnIntegrityFault(t *testing.T) {
	_, err := pickPeer(nil, nil)
	if err == nil {
		t.Fatal("a configuration naming no peers was accepted")
	}
	if got := session.KindOf(err); got != session.KindIntegrity {
		t.Errorf("kind = %v, want %v", got, session.KindIntegrity)
	}
}

func TestTheComponentsStatesBecomeTheWindows(t *testing.T) {
	when := time.Now()
	cases := []struct {
		from string
		want State
	}{
		{"connecting", Connecting},
		{"connected", Connected},
		{"ended", Ended},
		{"something new", Ready},
	}
	for _, c := range cases {
		got := fromIPC(ipc.Event{State: c.from}, "https://my.ence.do")
		if got.State != c.want {
			t.Errorf("%q became %v, want %v", c.from, got.State, c.want)
		}
	}

	// The countdown is drawn from this, and it comes from the token rather than
	// from the length anybody asked for.
	full := fromIPC(ipc.Event{State: "connected", ExpiresAt: when, Peer: "blbx", Rx: 8, Tx: 9}, "u")
	if !full.ExpiresAt.Equal(when) || full.Peer != "blbx" || full.Rx != 8 || full.Tx != 9 {
		t.Errorf("fields did not survive the translation: %+v", full)
	}
}

// A window that is not reading its events - mid-redraw, or wedged - must not be
// able to block the side that is running a tunnel.
func TestASlowWindowDoesNotBlockTheSession(t *testing.T) {
	s := newLiveSession("https://my.ence.do", "/nowhere")
	defer s.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < cap(s.events)*4; i++ {
			s.emit(Event{State: Connected})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("emitting blocked on a window that was not reading")
	}
}

func TestEmittingAfterCloseIsSafe(t *testing.T) {
	s := newLiveSession("https://my.ence.do", "/nowhere")
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s.emit(Event{State: Connected, Err: errors.New("late")}) // must not send on a closed channel
	if err := s.Close(); err != nil {
		t.Errorf("closing twice: %v", err)
	}
}

// Reaching a component that is not there is the first thing anybody will do, so
// it has to say what is missing rather than name a syscall.
func TestAMissingComponentSaysSo(t *testing.T) {
	// A port nothing listens on, so this fails at once and without a network.
	s := newLiveSession("https://127.0.0.1:1", "/nonexistent/wg-hem.sock")
	defer s.Close()

	err := s.Connect(t.Context(), []byte("passphrase"))
	if err == nil {
		t.Fatal("connecting with no device and no component succeeded")
	}
	// It fails at the device, before the socket, since there is no appliance
	// here either - what matters is that it is legible and not a panic.
	if err.Error() == "" {
		t.Error("the failure had nothing to say")
	}
}
