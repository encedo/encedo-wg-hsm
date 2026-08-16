package main

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// defaultControl is the pipe the service listens on. It has to agree with
// defaultSocket in cmd/wg-hem/control_windows.go, and the two are apart because
// the window may not import anything the privileged half does - see
// deps_test.go, which is the rule and the reason.
const defaultControl = `\\.\pipe\encedo-wg`

// Built from the constant rather than repeating it, so the help text cannot
// come to name a pipe the window would not dial.
var controlFlagUsage = fmt.Sprintf(
	"drive a real appliance: the `pipe` the privileged component listens on\n(try %s)", defaultControl)

// dialControl opens the channel to the privileged component.
//
// go-winio rather than the namedpipe package the component uses: that one comes
// from wireguard-go, and the window is forbidden to depend on wireguard-go by a
// test that exists to keep a tunnel implementation out of the unprivileged half.
// The two are the same code - upstream's namedpipe is derived from this library
// - so the rule costs a module and no behaviour.
//
// The impersonation level is the part that has to be spelled out, and getting it
// wrong is silent. winio's DialPipe, DialPipeContext and DialPipeAccess all
// connect at PipeImpLevelAnonymous - its own documented default - and a pipe
// opened that way gives the server an anonymous token when it impersonates. The
// component would then read S-1-5-7, ANONYMOUS LOGON, for every caller: one
// principal shared by everybody, so anybody could stop anybody's tunnel, and
// nothing would look wrong from either end.
//
// Identification, not Impersonation: the component reads the token and never
// acts as the caller, so the level that permits acting is more than it needs.
// The component refuses the anonymous SID as well, because a client chooses this
// level and a caller that picks anonymity should be told rather than accommodated.
//
// The timeout is the difference from the Unix side and is not a precaution. A
// named pipe that exists but has no free instance fails with ERROR_PIPE_BUSY
// rather than with "nothing there", and the documented way to wait for one is
// WaitNamedPipe, which is what a timeout here becomes. Zero would mean the
// default, which is the pipe's own and could be anything; a dial that hangs is
// how a window comes to look like it has stopped responding.
func dialControl(ctx context.Context, path string) (net.Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dialTimeout)
		defer cancel()
	}
	return winio.DialPipeAccessImpLevel(ctx, path,
		windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}

// dialTimeout is long enough for a busy service to free an instance and short
// enough that somebody clicking Connect is told rather than left waiting.
const dialTimeout = 5 * time.Second
