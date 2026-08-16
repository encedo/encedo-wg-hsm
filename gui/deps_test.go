package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTheWindowStaysUnprivileged is a layering rule with teeth, and the reason
// the daemon exists at all.
//
// This window authenticates a person and hands over a token. It must not be able
// to run a tunnel even by accident, and the way to keep that true in Go is to
// keep the code that could out of the build. Two things must never appear here:
//
//   - the patched wireguard-go, which build.sh generates into a directory this
//     repository does not contain, so importing it also ends the window's
//     ability to be built on its own;
//   - netlink and the platform layer, which is the half that needs privilege.
//
// Nothing fails when this drifts. The window keeps working, the tests keep
// passing, and one day somebody notices that the unprivileged half is carrying a
// tunnel implementation and asks how long that has been true.
func TestTheWindowStaysUnprivileged(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	forbidden := []string{
		"golang.zx2c4.com/wireguard",
		"github.com/vishvananda/netlink",
		"github.com/encedo/encedo-wg-hsm/internal/runtime",
		"github.com/encedo/encedo-wg-hsm/internal/tunnel",
		"github.com/encedo/encedo-wg-hsm/internal/daemon",
	}
	for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, bad := range forbidden {
			if dep == bad || strings.HasPrefix(dep, bad+"/") {
				t.Errorf("the window depends on %s.\n"+
					"That is the privileged half. What it needed belongs behind the socket,\n"+
					"or in a package light enough for both sides - internal/session and\n"+
					"internal/ipc are that, by the same rule enforced there.", dep)
			}
		}
	}
}
