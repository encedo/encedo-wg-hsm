package main

import (
	"net/netip"
	"strings"
	"testing"

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
