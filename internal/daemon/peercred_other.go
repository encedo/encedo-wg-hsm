//go:build !linux && !windows && !darwin

package daemon

import (
	"fmt"
	"net"
)

// peerPrincipal has no answer on these platforms yet, and says so rather than
// guessing.
//
// The daemon refuses a connection whose owner it cannot determine, so this
// compiles everywhere and runs nowhere - which is the honest state of it. Linux,
// macOS and Windows each have their own file; this is for whatever is left.
func peerPrincipal(c net.Conn) (Principal, error) {
	return Anonymous, fmt.Errorf("this platform has no way to identify the peer of a local connection yet")
}
