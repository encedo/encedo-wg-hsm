//go:build !linux && !windows

package daemon

import (
	"fmt"
	"net"
)

// peerPrincipal has no answer on these platforms yet, and says so rather than
// guessing.
//
// The daemon refuses a connection whose owner it cannot determine, so this
// compiles everywhere and runs nowhere - which is the honest state of it. macOS
// does not need a daemon of ours at all: the tunnel lives in a system extension,
// and the channel to it is authenticated by code signature. Windows had the same
// note until the named pipe existed - see peercred_windows.go, which answers it
// by impersonating the caller rather than by asking.
func peerPrincipal(c net.Conn) (Principal, error) {
	return Anonymous, fmt.Errorf("this platform has no way to identify the peer of a local connection yet")
}
