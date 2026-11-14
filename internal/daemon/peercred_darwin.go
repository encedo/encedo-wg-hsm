package daemon

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerPrincipal asks the kernel who is on the other end - the macOS spelling
// of what SO_PEERCRED answers on Linux.
//
// LOCAL_PEERCRED returns the peer's credentials as they were when it
// connected, filled in by the kernel; nothing the peer sends is involved. The
// uid is the same kind of answer Linux gives, so the principal has the same
// prefix and the rules - a tunnel belongs to whoever started it - read the
// same on both.
func peerPrincipal(c net.Conn) (Principal, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Anonymous, fmt.Errorf("not a unix socket: %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Anonymous, err
	}
	var cred *unix.Xucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if err != nil {
		return Anonymous, err
	}
	if credErr != nil {
		return Anonymous, credErr
	}
	return Principal(fmt.Sprintf("uid:%d", cred.Uid)), nil
}
