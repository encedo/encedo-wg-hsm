package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/encedo/encedo-wg-hsm/internal/config"
)

func ids() []config.Identity {
	return []config.Identity{
		{KID: "aa11bb22", Label: "home", Addrs: []netip.Prefix{netip.MustParsePrefix("10.1.1.5/24")}},
		{KID: "aa99cc33", Label: "work", Addrs: []netip.Prefix{netip.MustParsePrefix("10.99.0.7/32")}},
	}
}

func TestIdentityMatchesAFullKID(t *testing.T) {
	got, err := matchIdentity(ids(), "aa99cc33")
	if err != nil {
		t.Fatalf("matchIdentity: %v", err)
	}
	if got != "aa99cc33" {
		t.Errorf("got %q, want aa99cc33", got)
	}
}

func TestIdentityMatchesAUniquePrefix(t *testing.T) {
	got, err := matchIdentity(ids(), "aa9")
	if err != nil {
		t.Fatalf("matchIdentity: %v", err)
	}
	if got != "aa99cc33" {
		t.Errorf("got %q, want aa99cc33", got)
	}
}

// Key identifiers are lowercase hex, and somebody pasting from a device that
// prints them in upper case is not making a mistake.
func TestIdentityMatchIgnoresCase(t *testing.T) {
	got, err := matchIdentity(ids(), "AA99")
	if err != nil {
		t.Fatalf("matchIdentity: %v", err)
	}
	if got != "aa99cc33" {
		t.Errorf("got %q, want aa99cc33", got)
	}
}

// Resolving an ambiguous prefix either way would connect as an identity nobody
// named, and nothing afterwards would look wrong.
func TestAnAmbiguousIdentityPrefixIsRefused(t *testing.T) {
	_, err := matchIdentity(ids(), "aa")
	if err == nil {
		t.Fatal("a prefix matching both identities was accepted")
	}
	for _, kid := range []string{"aa11bb22", "aa99cc33"} {
		if !strings.Contains(err.Error(), kid) {
			t.Errorf("error %q does not name %s, so there is nothing to disambiguate with", err, kid)
		}
	}
}

func TestAnUnknownIdentityIsRefused(t *testing.T) {
	_, err := matchIdentity(ids(), "ffff")
	if err == nil {
		t.Fatal("an identity the device does not hold was accepted")
	}
	if !strings.Contains(err.Error(), "aa11bb22") {
		t.Errorf("error %q does not list what the device does hold", err)
	}
}

func TestAnsweredIdentityPromptSelects(t *testing.T) {
	restore := readLine
	readLine = func() (string, error) { return "2\n", nil }
	defer func() { readLine = restore }()

	got, err := promptForIdentity(ids())
	if err != nil {
		t.Fatalf("promptForIdentity: %v", err)
	}
	if got != "aa99cc33" {
		t.Errorf("got %q, want the second identity", got)
	}
}

// Unlike the peer prompt, this one has no default: the peer order is the
// failover priority and means something, while identities are sorted for
// stability alone. Pressing return would otherwise connect as whichever key
// sorted first.
func TestAnUnansweredIdentityPromptRefuses(t *testing.T) {
	restore := readLine
	readLine = func() (string, error) { return "\n", nil }
	defer func() { readLine = restore }()

	_, err := promptForIdentity(ids())
	if err == nil {
		t.Fatal("an empty answer picked an identity")
	}
	if !strings.Contains(err.Error(), "--identity") {
		t.Errorf("error %q does not mention the flag that avoids the prompt", err)
	}
}

func TestAnIdentityAnswerOutsideTheListIsRefused(t *testing.T) {
	restore := readLine
	readLine = func() (string, error) { return "3\n", nil }
	defer func() { readLine = restore }()

	if _, err := promptForIdentity(ids()); err == nil {
		t.Fatal("an answer past the end of the list was accepted")
	}
}

func TestANonNumericIdentityAnswerIsRefused(t *testing.T) {
	restore := readLine
	readLine = func() (string, error) { return "work\n", nil }
	defer func() { readLine = restore }()

	if _, err := promptForIdentity(ids()); err == nil {
		t.Fatal("a label was accepted where a number was asked for")
	}
}

// The flag skips the prompt entirely; a terminal is not always there.
func TestTheFlagAnswersInsteadOfThePrompt(t *testing.T) {
	restore := readLine
	readLine = func() (string, error) {
		t.Fatal("the prompt was reached although --identity was given")
		return "", nil
	}
	defer func() { readLine = restore }()

	want := "aa11bb22"
	d := &deviceFlags{identity: &want}
	got, err := d.chooseIdentity(ids())
	if err != nil {
		t.Fatalf("chooseIdentity: %v", err)
	}
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAddrListSaysWhenTheRecordIsUnreadable(t *testing.T) {
	if got := addrList(nil); !strings.Contains(got, "unreadable") {
		t.Errorf("addrList(nil) = %q; a record that did not decode should say so in the list", got)
	}
}
