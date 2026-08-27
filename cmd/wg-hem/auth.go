package main

import (
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// Reaching the device lives in internal/session now, because a window needs the
// same thing and has neither a terminal to read a passphrase from nor stderr to
// print progress on. What is left here is what only a command has: a way to read
// a passphrase from a tty, and the exit code a failure should carry.

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

// classify names what went wrong and gives it this command's exit code.
//
// The naming lives in internal/session, because a window needs the same
// distinction and has no exit codes to express it with; the numbering stays
// here, because it is the only part that is genuinely a command's.
func classify(err error, fallback int, format string, args ...any) error {
	if err == nil {
		return nil
	}
	e := session.Classify(err, kindFor(fallback), format, args...)
	return failf(exitFor(session.KindOf(e)), "%w", e)
}

// exitFrom gives an error that already knows its kind the matching exit code.
// Errors from internal/session arrive named - the command's part is only to
// number them.
func exitFrom(err error) error {
	if err == nil {
		return nil
	}
	return failf(exitFor(session.KindOf(err)), "%w", err)
}

// kindFor and exitFor are the two directions of the same small table. Keeping
// them adjacent is the only guard against them drifting apart.
func kindFor(code int) session.Kind {
	switch code {
	case exitNetwork:
		return session.KindNetwork
	case exitAuth:
		return session.KindAuth
	case exitIntegrit:
		return session.KindIntegrity
	case exitUsage:
		return session.KindUsage
	default:
		return session.KindDevice
	}
}

func exitFor(k session.Kind) int {
	switch k {
	case session.KindNetwork:
		return exitNetwork
	case session.KindAuth:
		return exitAuth
	case session.KindIntegrity:
		return exitIntegrit
	case session.KindUsage:
		return exitUsage
	default:
		return exitDevice
	}
}
