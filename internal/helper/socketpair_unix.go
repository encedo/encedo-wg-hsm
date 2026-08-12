//go:build !windows

package helper

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// unixSocketPair returns the two ends of a connected socket. The helper is
// started with one end already open rather than being told where to listen: a
// socket nobody else can reach cannot be reached by anybody else, which is a
// stronger statement than any permission on a path.
func unixSocketPair() (*net.UnixConn, *net.UnixConn, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	conn := func(fd int, name string) (*net.UnixConn, error) {
		f := os.NewFile(uintptr(fd), name)
		defer f.Close()
		c, err := net.FileConn(f)
		if err != nil {
			return nil, err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			c.Close()
			return nil, fmt.Errorf("%s is not a unix connection", name)
		}
		return uc, nil
	}
	a, err := conn(fds[0], "helper-a")
	if err != nil {
		syscall.Close(fds[1])
		return nil, nil, err
	}
	b, err := conn(fds[1], "helper-b")
	if err != nil {
		a.Close()
		return nil, nil, err
	}
	return a, b, nil
}
