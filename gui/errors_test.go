package main

import (
	"errors"
	"strings"
	"testing"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// TestHumanErrorHidesTheJargon pins the two translations and, more importantly,
// pins that everything else is left alone. The temptation with a function like
// this is to keep adding cases until every error is a reassuring sentence, at
// which point a configuration that does not authenticate reads like a hiccup.
func TestHumanErrorHidesTheJargon(t *testing.T) {
	// What the device actually produces for a wrong passphrase, wrapped the way
	// Auth.Token wraps it.
	refused := session.Classify(
		&hem.HemError{Message: "auth failed", Status: 401},
		session.KindDevice, "authorizing %s", "keymgmt:get")

	got := humanError(refused)
	for _, jargon := range []string{"keymgmt", "401", "authorizing"} {
		if strings.Contains(got, jargon) {
			t.Errorf("a person is being shown %q: %s", jargon, got)
		}
	}
	if !strings.Contains(got, "passphrase") {
		t.Errorf("says nothing about the passphrase: %s", got)
	}

	unreachable := session.Classify(
		&hem.HemError{Message: "dial tcp: i/o timeout", Code: "timeout"},
		session.KindDevice, "checkin")
	if got := humanError(unreachable); strings.Contains(got, "i/o timeout") {
		t.Errorf("a person is being shown the dial error: %s", got)
	}

	// The sentences this repository writes for the occasion have to survive. A
	// module holding no configuration is the case that matters: it is not a
	// hiccup, and "check it and try again" would be the wrong advice.
	ours := session.Fail(session.KindIntegrity,
		"this module holds no configuration — provision it first")
	if got := humanError(ours); got != ours.Error() {
		t.Errorf("our own wording was replaced:\n got  %s\n want %s", got, ours.Error())
	}

	// An error with no kind at all is a device fault by default, and its text is
	// the only thing anybody has to go on.
	plain := errors.New("the privileged component is not answering")
	if got := humanError(plain); got != plain.Error() {
		t.Errorf("an unclassified error was replaced: %s", got)
	}
}
