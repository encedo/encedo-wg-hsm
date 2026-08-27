package main

import (
	"net/netip"
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"

	"github.com/encedo/encedo-wg-hsm/internal/config"
)

func ident(t *testing.T, kid, label string, addrs ...string) config.Identity {
	t.Helper()
	id := config.Identity{KID: kid, Label: label}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", a, err)
		}
		id.Addrs = append(id.Addrs, p)
	}
	return id
}

// A radio group is identified by the text it shows, so two profiles that look
// alike would silently become one. They look alike more often than not: every
// identity provision writes carries the same default label.
func TestIdentityChoicesAreUniqueWhenLabelsAndAddressesMatch(t *testing.T) {
	ids := []config.Identity{
		ident(t, "aaaa1111bbbb2222", "wg-hem identity", "10.99.0.7/32"),
		ident(t, "cccc3333dddd4444", "wg-hem identity", "10.99.0.7/32"),
	}
	got := identityChoices(ids)
	if len(got) != 2 {
		t.Fatalf("identityChoices returned %d lines, want 2", len(got))
	}
	if got[0] == got[1] {
		t.Fatalf("two identities render as the same line: %q", got[0])
	}
	// Every line still has to map back to exactly the identity it came from.
	for i, line := range got {
		if kid := kidFor(ids, line); kid != ids[i].KID {
			t.Errorf("line %d (%q) maps to %q, want %q", i, line, kid, ids[i].KID)
		}
	}
}

func TestIdentityChoicesShowLabelAndAddress(t *testing.T) {
	ids := []config.Identity{ident(t, "aaaa1111", "head office", "10.99.0.7/32")}
	line := identityChoices(ids)[0]
	if !strings.Contains(line, "head office") {
		t.Errorf("line does not name the profile: %q", line)
	}
	if !strings.Contains(line, "10.99.0.7/32") {
		t.Errorf("line does not show the address: %q", line)
	}
}

// An identity whose record does not decode is still offered - hiding it would
// produce a list that disagrees with the device - but it has to say so, because
// a blank where an address goes reads as a rendering fault.
func TestIdentityChoicesSayWhenTheRecordIsUnreadable(t *testing.T) {
	ids := []config.Identity{ident(t, "aaaa1111", "somewhere")}
	if line := identityChoices(ids)[0]; !strings.Contains(line, "unreadable") {
		t.Errorf("unreadable record is not marked: %q", line)
	}
}

func TestIdentityChoicesNameAnUnlabelledIdentity(t *testing.T) {
	ids := []config.Identity{ident(t, "aaaa1111", "  ", "10.0.0.1/32")}
	if line := identityChoices(ids)[0]; !strings.Contains(line, "(unnamed)") {
		t.Errorf("an empty label leaves the line starting with a dash: %q", line)
	}
}

func TestKidForRejectsALineItNeverProduced(t *testing.T) {
	ids := []config.Identity{ident(t, "aaaa1111", "head office", "10.99.0.7/32")}
	if kid := kidFor(ids, "something else"); kid != "" {
		t.Errorf("kidFor invented %q for a line it never rendered", kid)
	}
}

// Cancelling has to reach the window as something other than a fault, or
// pressing Cancel reports that the module is broken.
func TestNoProfileChosenReadsAsAChoice(t *testing.T) {
	msg := humanError(errNoProfileChosen)
	if strings.Contains(strings.ToLower(msg), "error") || strings.Contains(msg, "no profile chosen") {
		t.Errorf("the cancel message is the raw error: %q", msg)
	}
	if !strings.Contains(msg, "Connect again") {
		t.Errorf("the cancel message does not say what to do next: %q", msg)
	}
}

// The window does not resize, and a dialogue is drawn inside it. Content wider
// than the window is cut off rather than wrapped or scrolled, and what gets cut
// is the end of every line - which is exactly where the addresses are, the only
// part that tells two profiles apart. So this measures.
//
// The case is the worst realistic one: several identities carrying the label
// provision writes by default, so the lines are identical and each has to be
// disambiguated by a key identifier, with two addresses apiece.
func TestIdentityChooserFits(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	ids := []config.Identity{
		ident(t, "aaaa1111bbbb2222", "wg-hem identity", "10.99.0.7/32", "fd00::7/128"),
		ident(t, "cccc3333dddd4444", "wg-hem identity", "10.99.0.7/32", "fd00::7/128"),
		ident(t, "eeee5555ffff6666", "wg-hem identity", "10.99.0.7/32", "fd00::7/128"),
	}

	body, _ := identityChooser(ids)
	w := test.NewWindow(body)
	defer w.Close()

	// Not the whole window: a dialogue is inset in it and draws a border of its
	// own, so the content has less room than the window is wide. Measuring
	// against the full width passes a line that is still cut in practice.
	need := body.MinSize()
	if room := float32(windowWidth) - dialogInset; need.Width > room {
		t.Errorf("the chooser needs %.1f of width and a dialogue in this window has about %.1f - the addresses will be cut off",
			need.Width, room)
	}
	// A dialogue is inset in the window and carries a title bar and a row of
	// buttons of its own, so it cannot have the whole height to itself.
	if room := float32(compactHeight) - dialogChrome; need.Height > room {
		t.Errorf("the chooser needs %.1f of height and a dialogue in this window has about %.1f",
			need.Height, room)
	}
}

// However many identities a module holds, the dialogue is the same size: the
// list scrolls instead of growing. A module with eight profiles must not push
// the buttons off the bottom of a window that cannot grow to meet them.
func TestIdentityChooserDoesNotGrowWithTheList(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	small, _ := identityChooser([]config.Identity{
		ident(t, "aaaa1111", "one", "10.0.0.1/32"),
		ident(t, "bbbb2222", "two", "10.0.0.2/32"),
	})
	var many []config.Identity
	for _, kid := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		many = append(many, ident(t, kid+"0000000", "profile "+kid, "10.0.0.1/32"))
	}
	big, _ := identityChooser(many)

	if big.MinSize().Height > small.MinSize().Height {
		t.Errorf("eight identities make the dialogue %.1f tall against %.1f for two - it grows with the list",
			big.MinSize().Height, small.MinSize().Height)
	}
}

// dialogInset and dialogChrome are what a dialogue costs inside this window:
// padding either side, and a title bar plus a row of buttons above and below.
// Approximate on purpose - the point is to measure against less than the whole
// window rather than to predict the toolkit to the point.
const (
	dialogInset  = 40 * uiScale
	dialogChrome = 120 * uiScale
)
