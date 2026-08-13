//go:build !linux

package daemon

import (
	"fmt"
	"net"
)

// peerUID has no answer on these platforms yet, and says so rather than
// guessing.
//
// The daemon refuses a connection whose owner it cannot determine, so this
// compiles everywhere and runs nowhere — which is the honest state of it. macOS
// does not need a daemon of ours at all (the tunnel lives in a system extension,
// and the channel to it is authenticated by code signature). Windows needs one,
// and the equivalent there is the client's token off the named pipe, which is a
// different call and belongs with the pipe that has not been written yet.
func peerUID(c net.Conn) (uint32, error) {
	return 0, fmt.Errorf("this platform has no way to identify the peer of a local connection yet")
}
