package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheSocketIsReachableOnlyByItsGroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg-hem.sock")
	ln, err := listenOn(path, "")
	if err != nil {
		t.Fatalf("listenOn: %v", err)
	}
	defer ln.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o660 {
		t.Errorf("the socket is %o, want 660: the filesystem is what decides who may connect", perm)
	}
}

// After a crash there is always a socket file left behind, and somebody having
// to delete a file they have never heard of is not a recovery procedure.
func TestAStaleSocketIsTakenOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg-hem.sock")

	// A socket that was listening and is not any more, with the file left behind
	// as a killed process leaves it. Go tidies up after itself on Close, which is
	// exactly what a crash does not do, so that has to be turned off to
	// reproduce the case at all.
	dead, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead.(*net.UnixListener).SetUnlinkOnClose(false)
	dead.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the leftover socket file is not there, so this tests nothing: %v", err)
	}

	ln, err := listenOn(path, "")
	if err != nil {
		t.Fatalf("a leftover socket stopped the daemon starting: %v", err)
	}
	defer ln.Close()

	if _, err := net.Dial("unix", path); err != nil {
		t.Errorf("the socket was taken over but nothing answers on it: %v", err)
	}
}

// Two daemons on one socket is the one case where refusing is right: the second
// would silently take the first one's callers.
func TestALiveSocketIsNotStolen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wg-hem.sock")
	first, err := listenOn(path, "")
	if err != nil {
		t.Fatalf("listenOn: %v", err)
	}
	defer first.Close()

	_, err = listenOn(path, "")
	if err == nil {
		t.Fatal("a second daemon took over a socket that was still being served")
	}
	if !strings.Contains(err.Error(), "already listening") {
		t.Errorf("refusal is %q; it should say what is in the way", err)
	}
}
