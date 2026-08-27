package session

import (
	"errors"
	"fmt"

	hem "github.com/encedo/hem-sdk-go"
)

// Kind says what sort of thing went wrong, in terms both callers understand.
//
// A command turns these into exit codes so a script can tell a wrong passphrase
// from an unreachable device. A window turns the same distinction into different
// screens: authentication is somebody typing again, a network fault is somebody
// waiting, and a failed integrity check is neither - it is a configuration that
// must not be used and a person who has to be told so.
//
// Both need the distinction; only one of them has exit codes. So the kind lives
// here and the numbering stays in the command.
type Kind int

const (
	KindDevice    Kind = iota // the module refused, or answered something impossible
	KindNetwork               // it could not be reached at all
	KindAuth                  // it would not accept the credential
	KindIntegrity             // what came back does not authenticate
	KindUsage                 // what was asked for does not make sense
)

func (k Kind) String() string {
	switch k {
	case KindNetwork:
		return "network"
	case KindAuth:
		return "authentication"
	case KindIntegrity:
		return "integrity"
	case KindUsage:
		return "usage"
	default:
		return "device"
	}
}

// Error carries a kind alongside the message. Callers match with errors.As, so
// wrapping it further does not lose the distinction.
type Error struct {
	Kind Kind
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Fail builds an error of a given kind.
func Fail(kind Kind, format string, args ...any) error {
	return &Error{Kind: kind, Err: fmt.Errorf(format, args...)}
}

// Classify reads what the SDK reports and names it. The device says "401" or
// "timeout" and the caller needs "your passphrase was refused" or "it could not
// be reached" - a distinction worth keeping because the two ask entirely
// different things of whoever is watching.
//
// fallback is what to call anything the SDK does not distinguish, which is most
// of it: a device that answers and dislikes the request is a device problem.
func Classify(err error, fallback Kind, format string, args ...any) error {
	if err == nil {
		return nil
	}
	kind := fallback
	var he *hem.HemError
	if errors.As(err, &he) {
		switch {
		case he.Code == "network" || he.Code == "timeout" || he.Code == "aborted":
			kind = KindNetwork
		case he.Status == 401 || he.Status == 403:
			kind = KindAuth
		}
	}
	args = append(args, err)
	return &Error{Kind: kind, Err: fmt.Errorf(format+": %w", args...)}
}

// KindOf reports how to treat an error, defaulting to a device fault for
// anything that never said. Callers use it to choose an exit code or a screen.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindDevice
}
