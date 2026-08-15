package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"

	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// The state itself lives in internal/session, because a window needs the same
// answers a terminal does. What stays here is the part that is only true of a
// command: turning a failure into an exit code a script can test, and saying so
// on stderr.

type state = session.State

func statePath(ifname string) string { return session.Path(ifname) }

// loadState maps the package's errors onto this command's exit codes. Nothing
// running is a usage error — the caller asked about something that is not there
// — while a file that exists and will not parse is the device's problem.
func loadState(ifname string) (*state, error) {
	s, err := session.Load(ifname)
	if err != nil {
		return nil, stateExit(err)
	}
	return s, nil
}

func resolveState(ifname string, explicit bool) (*state, error) {
	s, err := session.Resolve(ifname, explicit, func(asked, using string) {
		fmt.Fprintf(os.Stderr, "No interface named %s; using %s, the only one running.\n", asked, using)
	})
	if err != nil {
		return nil, stateExit(err)
	}
	return s, nil
}

func stateExit(err error) error {
	switch {
	case errors.Is(err, fs.ErrPermission):
		// A bare "permission denied" sends people looking at the file, and the
		// answer is never the file. What it is instead differs by platform, so
		// the remedy is written where the platform is — see state_unix.go and
		// state_windows.go. Getting this wrong is not cosmetic: this branch used
		// to offer `sudo adduser` on Windows, where there is no sudo, no adduser
		// and no such group.
		return failf(exitUsage, "%w\n%s", err, stateDeniedAdvice)
	case errors.Is(err, session.ErrNotRunning):
		return failf(exitUsage, "%w", err)
	case errors.Is(err, session.ErrAmbiguous):
		// The package says what is wrong; naming the flag that settles it is
		// this command's business, and no other caller's.
		return failf(exitUsage, "%w — name one with --interface", err)
	default:
		return failf(exitDevice, "%w", err)
	}
}

func removeState(ifname string) {
	session.Remove(ifname, func(msg string) {
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", msg)
	})
}

// flagGiven reports whether a flag was typed rather than left at its default.
func flagGiven(fs *flag.FlagSet, name string) bool {
	given := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	return given
}
