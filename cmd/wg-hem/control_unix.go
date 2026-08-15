//go:build !windows

package main

import (
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

const (
	controlFlagUsage       = "unix socket to listen on"
	controlAccessFlagUsage = "group allowed to reach the socket (default: whoever the directory allows)"
)

// defaultSocket is where the service's own runtime directory is.
//
// Deliberately not /var/run/wireguard: that directory belongs to the
// command-line client, which an administrator sets up for themselves, and two
// entry points writing one root-owned directory under different owners is the
// fight the rule about not changing the CLI exists to avoid.
func defaultSocket() string {
	if dir := os.Getenv("RUNTIME_DIRECTORY"); dir != "" {
		return filepath.Join(dir, "wg-hem.sock")
	}
	return "/run/encedo-wg/wg-hem.sock"
}

// listenOn opens the socket the window will find, and settles who may reach it.
//
// A leftover socket from a process that is gone is not a reason to refuse to
// start — after a crash there is always one, and somebody having to delete a
// file they have never heard of is not a recovery procedure. One that something
// is still listening on is a different matter, and is refused.
//
// The mode is the primary access control: who may connect at all is decided by
// the filesystem, and SO_PEERCRED then says which of them it is, so a tunnel can
// belong to the person who started it.
func listenOn(path, group string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, failf(exitDevice, "the socket directory: %w", err)
	}
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return nil, failf(exitUsage, "something is already listening on %s", path)
	}
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, failf(exitDevice, "listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, failf(exitDevice, "setting permissions on %s: %w", path, err)
	}

	// The service runs as its own user and the people using it do not. Without a
	// group they share, a socket the service owns is a socket nobody can reach —
	// which is what happened: the window said the component was not answering,
	// and the component was answering to nobody.
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			ln.Close()
			return nil, failf(exitUsage, "no group %q to give the socket to: %w", group, err)
		}
		gid, _ := strconv.Atoi(g.Gid)
		if err := os.Chown(path, -1, gid); err != nil {
			ln.Close()
			return nil, failf(exitDevice, "giving %s to group %s: %w", path, group, err)
		}
	}
	return ln, nil
}

// dialControl opens the channel to a running component, for the diagnostic that
// asks it who is calling. Nothing else in this command talks to it: running a
// tunnel from here does not go through the component at all.
func dialControl(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, 3*time.Second)
}
