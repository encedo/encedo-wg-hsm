package main

import (
	"context"
	"fmt"
	"os"
	"time"

	hem "github.com/encedo/hem-sdk-go"
	"golang.org/x/term"
)

// authenticator hands out scoped tokens, asking for the passphrase once.
//
// Provisioning needs four different scopes, and the device issues one token per
// scope. The SDK caches the key derived from the passphrase, so only the first
// call pays for the passphrase and for PBKDF2; the rest are a single round trip
// each. Wipe releases that cached key, which is why provisioning defers it.
type authenticator struct {
	client  *hem.Client
	mobile  bool
	expSecs int
	asked   bool
}

func (a *authenticator) token(ctx context.Context, scope string) (string, error) {
	if a.mobile {
		fmt.Fprintf(os.Stderr, "Approve on your phone: %s\n", scope)
		tok, err := a.client.AuthRemote(ctx, scope, hem.RemoteOpts{
			PollInterval: 2 * time.Second,
			PollTimeout:  60 * time.Second,
			OnPending:    func() { fmt.Fprint(os.Stderr, ".") },
		})
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", failf(exitAuth, "authorizing %s: %w", scope, err)
		}
		return tok, nil
	}

	var pass []byte
	if !a.asked {
		p, err := readPassphrase()
		if err != nil {
			return "", failf(exitAuth, "reading passphrase: %w", err)
		}
		defer zero(p)
		pass = p
		a.asked = true
	}

	// A nil passphrase on later calls reuses the key derived for the first one.
	tok, err := a.client.AuthPassword(ctx, pass, scope, a.expSecs)
	if err != nil {
		return "", failf(exitAuth, "authorizing %s: %w", scope, err)
	}
	return tok, nil
}

// wipe drops the derived key. Provisioning is short-lived, but it holds the key
// only for as long as it is still asking for tokens.
func (a *authenticator) wipe() {
	if a.client != nil {
		a.client.ClearKeys()
	}
}

// readPassphrase reads the passphrase from the terminal with echo off. It is a
// variable so tests can drive provisioning without a tty; nothing else replaces it.
var readPassphrase = func() ([]byte, error) {
	fmt.Fprint(os.Stderr, "HEM passphrase: ")
	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return p, err
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// classify maps an SDK error onto the exit code that describes it, so a script
// can distinguish "wrong passphrase" from "no device on that address".
func classify(err error, fallback int, format string, args ...any) error {
	if err == nil {
		return nil
	}
	code := fallback
	if he, ok := err.(*hem.HemError); ok {
		switch {
		case he.Code == "network" || he.Code == "timeout" || he.Code == "aborted":
			code = exitNetwork
		case he.Status == 401 || he.Status == 403:
			code = exitAuth
		}
	}
	args = append(args, err)
	return failf(code, format+": %w", args...)
}
