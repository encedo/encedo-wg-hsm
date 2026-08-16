package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// One window per machine, because one window is one tunnel.
//
// A second copy is not a cosmetic duplicate. Each holds its own token and
// configures the same interface, and the last one to do so wins - so the window
// somebody is looking at can be reporting a session that no longer owns
// anything, with a countdown for a token that is not the one keeping the tunnel
// alive. Closing that window then takes down a tunnel it did not create. The
// architecture has always been one process per tunnel; nothing was holding it to
// that.

// instanceFile holds the address the running window listens on. A file rather
// than a fixed port: a port compiled in is a port something else may hold.
const instanceFile = "instance.port"

// pokeTimeout bounds the wait for the other window to answer. It is a loopback
// connection to a process on the same machine - if that has not connected in
// this long, there is nothing there and the file is left over from a crash.
const pokeTimeout = 300 * time.Millisecond

// claimInstance makes this process the window, or hands the request to the
// window that already exists.
//
// Handing over rather than merely refusing is the part that matters: the window
// may be hidden in the tray, so a second launch that quietly exited would look
// like an application that does not start. The listener returned is how it will
// be asked, in turn, to show itself.
//
// A stale address fails to connect and is taken over, which is what should
// happen after a crash. Two launches racing each other could still both claim
// it; for something started by hand that is a smaller cost than the
// platform-specific locking needed to close it, and it is a race between two
// copies of the same intention.
func claimInstance(dir string) (ln net.Listener, handedOver bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	path := filepath.Join(dir, instanceFile)

	if raw, rerr := os.ReadFile(path); rerr == nil {
		if addr := strings.TrimSpace(string(raw)); addr != "" {
			if c, derr := net.DialTimeout("tcp", addr, pokeTimeout); derr == nil {
				// The message is the connection. Anything the other side reads
				// means the same thing, so there is nothing to agree on.
				c.Close()
				return nil, true, nil
			}
		}
	}

	// Loopback only. This is a doorbell between two copies of one program on one
	// machine, and binding anywhere else would be offering it to the network.
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, []byte(ln.Addr().String()+"\n"), 0o600); err != nil {
		ln.Close()
		return nil, false, err
	}
	return ln, false, nil
}

// serveInstance answers later launches by showing the window this one owns.
func serveInstance(ln net.Listener, show func()) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
		show()
	}
}

// instanceDir is where the address is kept: beside this application's own
// settings, so it is per-user. Two people logged into one machine are two
// desktops and two modules, and neither should be handing windows to the other.
func instanceDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("finding the configuration directory: %w", err)
	}
	return filepath.Join(base, appID), nil
}
