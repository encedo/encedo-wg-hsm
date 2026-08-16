package session

import (
	"bytes"
	"context"
	"errors"
	"testing"

	hem "github.com/encedo/hem-sdk-go"
)

// deadURL is a port nothing listens on, so every call fails at the transport
// and the tests below observe what happens around the call rather than in it.
const deadURL = "https://127.0.0.1:1"

func deadAuth(dev Device) *Auth {
	return &Auth{client: hem.NewClient(deadURL, hem.Config{}), dev: dev, expSecs: 3600}
}

// The SDK caches the key derived from the passphrase, and a second prompt would
// mean that cache had stopped working - four scopes into provisioning, that is
// four passphrase prompts for one session.
func TestThePassphraseIsAskedForOnce(t *testing.T) {
	asked := 0
	a := deadAuth(Device{Passphrase: func() ([]byte, error) {
		asked++
		return []byte("secret"), nil
	}})

	ctx := context.Background()
	_, _ = a.Token(ctx, "keymgmt:get")
	_, _ = a.Token(ctx, "keymgmt:gen")

	if asked != 1 {
		t.Errorf("the passphrase was asked for %d times, want 1", asked)
	}
}

// The buffer the passphrase arrived in must not outlive the call. CLAUDE.md
// documents the zeroing order and this is the step at the top of it.
func TestThePassphraseBufferIsZeroed(t *testing.T) {
	pass := []byte("correct horse battery staple")
	a := deadAuth(Device{Passphrase: func() ([]byte, error) { return pass, nil }})

	_, _ = a.Token(context.Background(), "keymgmt:get")

	if !bytes.Equal(pass, make([]byte, len(pass))) {
		t.Errorf("the passphrase buffer still holds %q after the token call", pass)
	}
}

// A window that has not been given a way to ask is a bug in the window, and it
// must not present as a device or network fault - those send somebody looking at
// their appliance.
func TestNoWayToAskIsAnAuthenticationFault(t *testing.T) {
	a := deadAuth(Device{})
	_, err := a.Token(context.Background(), "keymgmt:get")
	if err == nil {
		t.Fatal("a token was issued with no way to ask for the passphrase")
	}
	if got := KindOf(err); got != KindAuth {
		t.Errorf("kind = %v, want %v", got, KindAuth)
	}
}

func TestARefusedPassphraseIsAnAuthenticationFault(t *testing.T) {
	want := errors.New("no terminal")
	a := deadAuth(Device{Passphrase: func() ([]byte, error) { return nil, want }})

	_, err := a.Token(context.Background(), "keymgmt:get")
	if err == nil {
		t.Fatal("a token was issued although the passphrase could not be read")
	}
	if got := KindOf(err); got != KindAuth {
		t.Errorf("kind = %v, want %v", got, KindAuth)
	}
}

// Notify is optional: a daemon has nowhere to print and must not have to supply
// a sink to avoid a crash.
func TestNotifyIsOptional(t *testing.T) {
	_, _, err := Device{URL: deadURL}.Connect(context.Background())
	if err == nil {
		t.Fatal("connecting to a dead address succeeded")
	}
}

func TestConnectSaysWhatItIsDoing(t *testing.T) {
	var said []string
	_, _, _ = Device{URL: deadURL, Notify: func(m string) { said = append(said, m) }}.Connect(context.Background())

	if len(said) == 0 {
		t.Fatal("nothing was said while reaching the device")
	}
	if !bytes.Contains([]byte(said[0]), []byte(deadURL)) {
		t.Errorf("first notice is %q; it should name where it is going", said[0])
	}
}

// A device that cannot be reached is a network fault, not an authentication one:
// the two send a person to entirely different places.
func TestAnUnreachableDeviceIsANetworkFault(t *testing.T) {
	_, _, err := Device{URL: deadURL}.Connect(context.Background())
	if err == nil {
		t.Fatal("connecting to a dead address succeeded")
	}
	if got := KindOf(err); got != KindNetwork {
		t.Errorf("kind = %v, want %v", got, KindNetwork)
	}
}

func TestWipeSurvivesNothingToWipe(t *testing.T) {
	var a *Auth
	a.Wipe() // must not panic: teardown runs on paths where connecting never happened
	(&Auth{}).Wipe()
}
