package main

import (
	"os"

	"github.com/encedo/encedo-wg-hsm/internal/session"
	"strings"
	"syscall"
	"testing"
	"time"
)

// withRunDir points the state and public-key files at a directory the test is
// allowed to write to.
func withRunDir(t *testing.T) {
	t.Helper()
	prevRun, prevDir := runDir, session.Dir
	t.Cleanup(func() { runDir, session.Dir = prevRun, prevDir })
	dir := t.TempDir()
	// Both, because the two are the same directory seen from either side of the
	// move: the command writes public keys through runDir and the state through
	// the package. Setting one and not the other passes the tests it happens to
	// touch and leaves the rest writing to /var/run.
	runDir, session.Dir = dir, dir
}

func writeState(t *testing.T, ifname string, pid int) *state {
	t.Helper()
	st := &state{
		PID: pid, Interface: ifname, IfKID: "if-kid", PeerKID: "peer-kid",
		PeerLabel: "hq", Endpoint: "203.0.113.1:51820",
		HEMURL: "https://192.168.7.1", Started: time.Now().Add(-time.Minute),
	}
	if err := st.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	return st
}

func TestStateRoundTrips(t *testing.T) {
	withRunDir(t)
	want := writeState(t, "wg0", 4242)

	got, err := loadState("wg0")
	if err != nil {
		t.Fatalf("loadState: %v", err)
	}
	if got.PID != want.PID || got.PeerKID != want.PeerKID || got.HEMURL != want.HEMURL {
		t.Errorf("loadState = %+v, want %+v", got, want)
	}
	if !got.Started.Equal(want.Started) {
		t.Errorf("Started = %v, want %v", got.Started, want.Started)
	}
}

// Nothing running is the ordinary case, not a broken installation, so it is a
// usage answer rather than a device one.
func TestDownWithoutAStateFileSaysSo(t *testing.T) {
	withRunDir(t)

	err := cmdDown([]string{"--interface", "wg0"})
	if err == nil {
		t.Fatal("down succeeded with nothing running")
	}
	assertExit(t, err, exitUsage)
}

// The point of `down`: the owning process is asked to undo its own work, and
// when it does, this command does not touch the interface at all. Removing it
// here would strand the pinned routes and the DNS the owner still holds.
func TestDownLetsTheOwnerTearItselfDown(t *testing.T) {
	withRunDir(t)
	writeState(t, "wg0", 4242)

	var sent []syscall.Signal
	restore := stubProcess(t, func(pid int, sig syscall.Signal) error {
		sent = append(sent, sig)
		if sig == syscall.SIGTERM {
			// A well-behaved owner tears down and removes its state file.
			removeState("wg0")
		}
		return nil
	}, func(string) error {
		t.Fatal("the interface was removed even though its owner tore it down")
		return nil
	})
	defer restore()

	if err := cmdDown([]string{"--interface", "wg0"}); err != nil {
		t.Fatalf("cmdDown: %v", err)
	}
	if len(sent) == 0 || sent[0] != syscall.SIGTERM {
		t.Errorf("signals sent = %v, want SIGTERM first", sent)
	}
}

// A state file left by a process that is no longer there: the interface may well
// still exist, so it is removed, and the report says what could not be undone.
func TestDownRemovesTheInterfaceWhenTheOwnerIsGone(t *testing.T) {
	withRunDir(t)
	writeState(t, "wg0", 4242)

	removed := ""
	restore := stubProcess(t,
		func(pid int, sig syscall.Signal) error { return os.ErrProcessDone },
		func(ifname string) error { removed = ifname; return nil },
	)
	defer restore()

	if err := cmdDown([]string{"--interface", "wg0"}); err != nil {
		t.Fatalf("cmdDown: %v", err)
	}
	if removed != "wg0" {
		t.Errorf("removed %q, want wg0", removed)
	}
	if _, err := os.Stat(statePath("wg0")); !os.IsNotExist(err) {
		t.Error("the stale state file was left behind")
	}
}

// An owner that takes the signal and then sits there must not hold `down`
// forever. After the timeout the interface comes down from here.
func TestDownGivesUpOnAnUnresponsiveOwner(t *testing.T) {
	withRunDir(t)
	writeState(t, "wg0", 4242)

	prevTimeout := downTimeout
	downTimeout = 150 * time.Millisecond
	t.Cleanup(func() { downTimeout = prevTimeout })

	removed := ""
	restore := stubProcess(t,
		func(pid int, sig syscall.Signal) error { return nil }, // alive, ignores it
		func(ifname string) error { removed = ifname; return nil },
	)
	defer restore()

	if err := cmdDown([]string{"--interface", "wg0"}); err != nil {
		t.Fatalf("cmdDown: %v", err)
	}
	if removed != "wg0" {
		t.Errorf("removed %q, want wg0 after the timeout", removed)
	}
}

func TestDownReportsAFailureToRemoveTheInterface(t *testing.T) {
	withRunDir(t)
	writeState(t, "wg0", 4242)

	restore := stubProcess(t,
		func(pid int, sig syscall.Signal) error { return os.ErrProcessDone },
		func(string) error { return os.ErrPermission },
	)
	defer restore()

	err := cmdDown([]string{"--interface", "wg0"})
	if err == nil {
		t.Fatal("cmdDown reported success over an interface it could not remove")
	}
	assertExit(t, err, exitDevice)
}

func stubProcess(t *testing.T, signal func(int, syscall.Signal) error, down func(string) error) func() {
	t.Helper()
	prevSignal, prevDown := signalProcess, takeDownInterface
	signalProcess, takeDownInterface = signal, down
	return func() { signalProcess, takeDownInterface = prevSignal, prevDown }
}

// On macOS `up` asks for wg0 and the kernel hands back utunN, so the state file
// is never under the name a later command would guess. Left at its default, the
// name is a guess and may be corrected.
func TestResolveStateFindsTheOnlyRunningInterface(t *testing.T) {
	withRunDir(t)
	writeState(t, "utun5", 4242)

	got, err := resolveState("wg0", false)
	if err != nil {
		t.Fatalf("resolveState: %v", err)
	}
	if got.Interface != "utun5" {
		t.Errorf("resolved %q, want utun5", got.Interface)
	}
}

// A name the caller typed is not a guess. Acting on some other interface
// because this one is absent would take down something nobody named.
func TestResolveStateHonoursAnExplicitName(t *testing.T) {
	withRunDir(t)
	writeState(t, "utun5", 4242)

	if _, err := resolveState("wg7", true); err == nil {
		t.Fatal("an explicitly named interface that is not running must fail")
	}
}

// With more than one candidate only the caller knows which was meant, and the
// refusal has to name them or it is not actionable.
func TestResolveStateRefusesToChooseBetweenSeveral(t *testing.T) {
	withRunDir(t)
	writeState(t, "utun5", 4242)
	writeState(t, "utun6", 4243)

	_, err := resolveState("wg0", false)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, want := range []string{"utun5", "utun6", "--interface"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// Nothing running at all is the ordinary case, and it must still read as
// "nothing is running" rather than as a directory listing failure.
func TestResolveStateReportsNothingRunning(t *testing.T) {
	withRunDir(t)

	_, err := resolveState("wg0", false)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "wg0") {
		t.Errorf("error should name the interface asked for, got: %v", err)
	}
}
