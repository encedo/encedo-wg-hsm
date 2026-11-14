package main

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/term"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/session"
	"github.com/encedo/encedo-wg-hsm/internal/tunnel"
)

// startRenewal asks the person again a few minutes before the session ends -
// the phone, or the passphrase at this terminal - and hands the new token to
// the running tunnel. See session.Renewal for why this is not the refresh
// CLAUDE.md rules out: nothing is kept, a person answers every time.
//
// It returns what has to run when the command ends. A passphrase prompt left
// waiting when the tunnel closes has echo turned off, and a process that exits
// in the middle of term.ReadPassword leaves the terminal that way.
func startRenewal(ctx context.Context, auth *session.Auth, t *tunnel.Tunnel, scope, token string) func() {
	say := func(s string) { fmt.Fprintln(os.Stderr, s) }
	r := session.Renewal{
		Ask:   func(ctx context.Context) (string, error) { return auth.Renew(ctx, scope) },
		Apply: t.Refresh,
		Say:   say,
	}
	restore := func() {}
	if !auth.Mobile() {
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			if exp := hem.TokenExpiry(token); !exp.IsZero() {
				say(fmt.Sprintf("No terminal to ask for the passphrase again, so the session ends at %s.",
					exp.Local().Format("15:04:05")))
			}
			return restore
		}
		if st, err := term.GetState(fd); err == nil {
			restore = func() { _ = term.Restore(fd, st) }
		}
		r.Before = "\aType the passphrase to renew it (Ctrl+C ends the tunnel)."
	}
	go r.Run(ctx, token)
	return restore
}
