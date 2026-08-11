package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

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
}

func statePath(ifname string) string {
	return runDir + "/" + ifname + ".wg-hem.json"
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

func removeState(ifname string) {
	if err := os.Remove(statePath(ifname)); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "WARNING: leaving %s behind: %v\n", statePath(ifname), err)
	}
}
