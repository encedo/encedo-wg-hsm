// Package session holds what a running tunnel is, apart from the interface that
// started it.
//
// It exists because two very different things need the same answers. A terminal
// asks "what is running" by printing a state file; a window asks the same
// question to draw a status. While the answer lives in `package main` of one
// command, only that command can ask — which is why this package is being grown
// rather than designed: pieces move here as they are needed, and each move is
// the smallest thing that leaves both callers working.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/encedo/encedo-wg-hsm/internal/paths"
)

// stateSuffix names a state file. Writing it and finding it again are in
// different places, so the two agree through this rather than by eye.
const stateSuffix = ".wg-hem.json"

// ErrNotRunning says no tunnel answers to that name. It is a sentinel rather
// than a message because callers act on it differently: a command turns it into
// an exit code a script can test, and a window turns it into a state with a
// button in it. Neither should be matching on prose.
var ErrNotRunning = errors.New("no tunnel is running under that name")

// ErrAmbiguous says several tunnels are running and none was named. The package
// stops there: which flag or which control resolves it is the caller's
// vocabulary, not this one's.
var ErrAmbiguous = errors.New("several tunnels are running")

// Dir is where state files live. A variable so tests can write somewhere they
// are allowed to; everything else takes it from the platform.
//
// It comes from internal/paths rather than internal/runtime, and that is the
// difference between this package being importable by a window and not: the run
// directory is a string, while the package it used to live in carries netlink,
// the tunnel device and the whole platform layer with it.
var Dir = paths.RunDir

// State is what a running tunnel leaves behind so another invocation can find
// it. The UAPI socket says what the tunnel is doing; it does not say which peer
// of which stored configuration was chosen, or which process owns the routes and
// the DNS — and that is exactly what stopping and reporting need.
//
// It holds no secrets. Key identifiers are not key material, and §8 treats the
// stored configuration as public; the pre-shared key exists only in memory,
// between the unwrap and the moment the interface is configured.
type State struct {
	PID       int       `json:"pid"`
	Interface string    `json:"interface"`
	IfKID     string    `json:"if_kid"`
	PeerKID   string    `json:"peer_kid"`
	PeerLabel string    `json:"peer_label"`
	Endpoint  string    `json:"endpoint"`
	HEMURL    string    `json:"hem_url"`
	Started   time.Time `json:"started"`

	// TokenExpiry is when the session ends, read from the token rather than
	// computed from the lifetime asked for. The device issues what it chooses: a
	// run on 2026-08-11 requested eight hours and ended after seven and a half,
	// so anything derived from the request would have been half an hour
	// optimistic about when somebody loses their tunnel.
	TokenExpiry time.Time `json:"token_expiry,omitempty"`
}

func Path(ifname string) string { return Dir + "/" + ifname + stateSuffix }

func (s *State) Save() error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(Dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(Path(s.Interface), append(raw, '\n'), 0o644)
}

// Load reads what a running tunnel left. A missing file is reported as
// ErrNotRunning rather than as an error about JSON: the ordinary reason for it
// is that nothing is running, which is not a fault.
func Load(ifname string) (*State, error) {
	raw, err := os.ReadFile(Path(ifname))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("%w: %s", ErrNotRunning, ifname)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the state of %s: %w", ifname, err)
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("the state file of %s is unreadable: %w", ifname, err)
	}
	return &s, nil
}

// Resolve finds the tunnel a caller means.
//
// A name that was typed is used as given: guessing past an explicit argument
// would act on a tunnel nobody named. A name left at its default may be
// corrected, and on macOS it usually has to be — the caller asks for wg0, the
// kernel hands back utunN, and the state file is written under the name that
// came back, so the default names a file that was never going to exist. When
// exactly one tunnel is running, that is the one meant; when several are, only
// the caller knows which.
//
// found, when set, is told which tunnel was chosen in place of the name asked
// for. Silently acting on a different interface would be worse than refusing.
func Resolve(ifname string, explicit bool, found func(asked, using string)) (*State, error) {
	s, err := Load(ifname)
	if err == nil || explicit {
		return s, err
	}

	running, lerr := Running()
	if lerr != nil || len(running) == 0 {
		return nil, err // the original "nothing by that name"
	}
	if len(running) > 1 {
		return nil, fmt.Errorf("%w: no tunnel named %s, and %d others are running (%s)",
			ErrAmbiguous, ifname, len(running), strings.Join(running, ", "))
	}
	if found != nil {
		found(ifname, running[0])
	}
	return Load(running[0])
}

// Running lists the tunnels that left a state file behind. A file here is not
// proof the process is alive — stopping deals with that — only that this is a
// name something used.
func Running() ([]string, error) {
	entries, err := os.ReadDir(Dir)
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

// Remove deletes a state file. A failure is reported rather than returned: it
// happens while a tunnel is being taken down, where there is nothing useful left
// to do about it and stopping would leave more behind than carrying on.
func Remove(ifname string, warn func(string)) {
	if err := os.Remove(Path(ifname)); err != nil && !os.IsNotExist(err) && warn != nil {
		warn(fmt.Sprintf("leaving %s behind: %v", Path(ifname), err))
	}
}
