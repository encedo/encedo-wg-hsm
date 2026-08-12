package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// stateSuffix names a state file. Writing it and finding it again are in
// different places now, so the two agree through this rather than by eye.
const stateSuffix = ".wg-hem.json"

// state is what a running `wg-hem up` leaves behind so another invocation can
// find it. The UAPI socket says what the tunnel is doing; it does not say which
// peer of which stored configuration was chosen, or which process owns the
// routes and the DNS — and that is exactly what `down` and `status` need.
//
// It holds no secrets. Key identifiers are not key material, and §8 treats the
// stored configuration as public; the pre-shared key exists only in memory,
// between the unwrap and the moment the interface is configured.
type state struct {
	PID       int       `json:"pid"`
	Interface string    `json:"interface"`
	IfKID     string    `json:"if_kid"`
	PeerKID   string    `json:"peer_kid"`
	PeerLabel string    `json:"peer_label"`
	Endpoint  string    `json:"endpoint"`
	HEMURL    string    `json:"hem_url"`
	Started   time.Time `json:"started"`

	// TokenExpiry is when the session ends, read from the token rather than
	// computed from the lifetime asked for. The device issues what it chooses:
	// a run on 2026-08-11 requested eight hours and ended after seven and a
	// half, so anything derived from the request would have been half an hour
	// optimistic about when somebody loses their tunnel.
	TokenExpiry time.Time `json:"token_expiry,omitempty"`
}

func statePath(ifname string) string {
	return runDir + "/" + ifname + stateSuffix
}

func (s *state) save() error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(statePath(s.Interface), append(raw, '\n'), 0644)
}

// loadState reads what `up` left. A missing file is reported as such rather than
// as an error about JSON: the ordinary reason for it is that nothing is running.
func loadState(ifname string) (*state, error) {
	raw, err := os.ReadFile(statePath(ifname))
	if os.IsNotExist(err) {
		return nil, failf(exitUsage, "no wg-hem interface named %s is running", ifname)
	}
	if err != nil {
		return nil, failf(exitDevice, "reading the state of %s: %w", ifname, err)
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, failf(exitDevice, "the state file of %s is unreadable: %w", ifname, err)
	}
	return &s, nil
}

// resolveState finds the interface a command should act on.
//
// A name the caller typed is used as given: guessing past an explicit argument
// would act on an interface nobody named. A name left at its default may be
// corrected, and on macOS it usually has to be — `up` asks for wg0, the kernel
// hands back utunN, and the state file is written under the name that came
// back, so the default names a file that was never going to exist. When exactly
// one interface is running, that is the one meant; when several are, only the
// caller knows which.
func resolveState(ifname string, explicit bool) (*state, error) {
	s, err := loadState(ifname)
	if err == nil || explicit {
		return s, err
	}

	running, lerr := runningInterfaces()
	if lerr != nil || len(running) == 0 {
		return nil, err // the original "nothing by that name is running"
	}
	if len(running) > 1 {
		return nil, failf(exitUsage,
			"no interface named %s, and %d others are running (%s) — name one with --interface",
			ifname, len(running), strings.Join(running, ", "))
	}
	fmt.Fprintf(os.Stderr, "No interface named %s; using %s, the only one running.\n", ifname, running[0])
	return loadState(running[0])
}

// runningInterfaces lists the interfaces that left a state file behind. A file
// here is not proof the process is alive — `down` deals with that — only that
// this is a name `up` used.
func runningInterfaces() ([]string, error) {
	entries, err := os.ReadDir(runDir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if name, ok := strings.CutSuffix(e.Name(), stateSuffix); ok {
			names = append(names, name)
		}
	}
	return names, nil
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

func removeState(ifname string) {
	if err := os.Remove(statePath(ifname)); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "WARNING: leaving %s behind: %v\n", statePath(ifname), err)
	}
}
