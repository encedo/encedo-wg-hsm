package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerPrincipal asks the kernel who is on the other end.
//
// This is the part of the access control that cannot be forged. The socket's
// permissions decide who may connect at all — that is the primary control, set
// by the package and not by this code — and SO_PEERCRED answers the question
// that remains once somebody has: which user, so that a tunnel can belong to the
// person who started it and nobody else can stop or renew it.
//
// The kernel fills this in at connect time from the peer's real credentials.
// Nothing the peer sends is involved, which is why it is worth having rather
// than asking politely in the protocol.
func peerPrincipal(c net.Conn) (Principal, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Anonymous, fmt.Errorf("not a unix socket: %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Anonymous, err
	}
	var cred *unix.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return Anonymous, err
	}
	if credErr != nil {
		return Anonymous, credErr
	}
	return Principal(fmt.Sprintf("uid:%d", cred.Uid)), nil
}
