//go:build !windows

package main

import (
	"context"
	"fmt"
	"net"
)

// defaultControl is where the privileged component listens, and it is only a
// default: -live takes a path, because a person debugging a component they
// started by hand needs to point the window at it.
const defaultControl = "/run/encedo-wg/wg-hem.sock"

// Built from the constant rather than repeating it, so the help text cannot
// come to name a path the window would not dial.
var controlFlagUsage = fmt.Sprintf(
	"drive a real appliance: the `socket` the privileged component listens on\n(try %s)", defaultControl)

// dialControl opens the channel to the privileged component.
//
// A plain dial here, because a unix socket that nothing is listening on fails
// immediately and says so. See control_windows.go for why the same call needs a
// timeout there.
func dialControl(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}
