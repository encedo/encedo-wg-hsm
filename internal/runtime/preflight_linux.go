//go:build linux

package runtime

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// capNetAdmin is the capability every privileged thing this client does on Linux
// actually needs: creating the interface, assigning addresses, adding routes,
// setting the MTU. Nothing here wants root — root is merely the usual way to get
// this one bit, and a coarse one.
const capNetAdmin = 12

// Preflight reports what would stop the tunnel coming up, before anything has
// been created and before the passphrase has been asked for.
//
// It exists because the failures it replaces are unhelpful in a specific way:
// netlink returns "operation not permitted" from somewhere three layers down,
// after the device has been authenticated and half the work is done, and the
// message says nothing about which permission or how to grant it. A person then
// reaches for sudo, which works, and never learns that a capability would have
// done — or that running the whole client as root was never the intent.
//
// Both conditions are fixable without root at run time, which is the point:
//
//	sudo setcap cap_net_admin=eip /usr/local/bin/wg-hem
//	echo 'd /var/run/wireguard 0770 root <group> -' | sudo tee /etc/tmpfiles.d/wireguard.conf
func Preflight() error {
	var missing []string

	if !hasCapNetAdmin() {
		missing = append(missing, "cap_net_admin — the interface, its addresses and its routes all need it\n"+
			"    grant it once with:  sudo setcap cap_net_admin=eip $(command -v wg-hem)")
	}
	if err := writable(RunDir); err != nil {
		missing = append(missing, fmt.Sprintf("%s is not writable (%v) — the UAPI socket and the state file live there\n"+
			"    make it so with:  printf 'd %s 0770 root %s -\\n' | sudo tee /etc/tmpfiles.d/wireguard.conf && sudo systemd-tmpfiles --create",
			RunDir, err, RunDir, currentGroup()))
	}

	switch len(missing) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("this needs one thing it does not have:\n  %s", missing[0])
	default:
		return fmt.Errorf("this needs two things it does not have:\n  %s\n  %s", missing[0], missing[1])
	}
}

// hasCapNetAdmin reads the effective capability set rather than testing for
// root. They are not the same question, and the difference is the whole reason
// this file exists: a binary with the capability and no privilege is the goal.
func hasCapNetAdmin() bool {
	if os.Geteuid() == 0 {
		return true
	}
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		if err != nil {
			return false
		}
		return v&(1<<capNetAdmin) != 0
	}
	return false
}

// writable reports whether the directory can be written to, creating it when the
// parent allows. Testing the mode bits would be a guess; creating and removing a
// file is the question actually being asked.
func writable(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".preflight-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// currentGroup names the caller's primary group, for the tmpfiles line the error
// suggests. A wrong guess here costs nothing — the line is a suggestion a person
// reads before running it.
func currentGroup() string {
	gid := syscall.Getgid()
	f, err := os.Open("/etc/group")
	if err != nil {
		return strconv.Itoa(gid)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) >= 3 && parts[2] == strconv.Itoa(gid) {
			return parts[0]
		}
	}
	return strconv.Itoa(gid)
}
