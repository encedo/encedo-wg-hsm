//go:build !windows

package helper

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

// The transport is a length-prefixed message on a unix socket, with one
// exception: the answer to OpCreateTUN carries a file descriptor.
//
// It has to. wireguard-go reads and writes the tunnel through a descriptor, and
// only the privileged side can create one — so the descriptor itself must cross
// the boundary. SCM_RIGHTS is how a unix socket does that: the kernel installs a
// copy in the receiving process and it arrives as a real descriptor rather than
// a number that would mean nothing on the other side.
//
// This is the whole reason the helper cannot be a command invoked with sudo and
// its output parsed. A descriptor is not text.

const maxMessage = 64 << 10 // far more than any request here; a bound, not a target

// WriteMessage frames a message so the reader knows where it ends. A socket is a
// stream and JSON is not self-delimiting for a reader that must not block.
func WriteMessage(c *net.UnixConn, v any) error {
	b, err := Encode(v)
	if err != nil {
		return err
	}
	if len(b) > maxMessage {
		return fmt.Errorf("message of %d bytes exceeds the limit", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := c.Write(hdr[:]); err != nil {
		return err
	}
	_, err = c.Write(b)
	return err
}

// ReadMessage reads one framed message. The length is checked before allocating:
// a helper listening on a socket should not be persuadable into a large
// allocation by whatever can reach it.
func ReadMessage(c *net.UnixConn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxMessage {
		return nil, fmt.Errorf("message of %d bytes exceeds the limit", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, err
}

// SendFD writes a response, passing a descriptor with it when there is one to
// pass. The response travels in the ordinary payload so the receiver learns
// whether to expect a descriptor before it tries to take one.
//
// A negative descriptor means there is none — a refusal, most often. Attaching
// rights for one anyway is not a harmless no-op: the kernel rejects the control
// message, the write fails after the header has already gone, and the reader
// waits for a body that will never arrive. A refusal that hangs the caller is a
// worse failure than whatever was being refused.
func SendFD(c *net.UnixConn, resp Response, fd int) error {
	if fd < 0 {
		resp.HasFD = false
	}
	b, err := Encode(resp)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := c.Write(hdr[:]); err != nil {
		return err
	}
	if fd < 0 {
		_, err = c.Write(b)
		return err
	}
	_, _, err = c.WriteMsgUnix(b, syscall.UnixRights(fd), nil)
	return err
}

// RecvFD reads a response and, when it says one is coming, the descriptor with
// it. The returned file owns the descriptor: the caller closes it, and until
// they do it is a live handle on a tunnel interface.
func RecvFD(c *net.UnixConn) (Response, *os.File, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return Response{}, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxMessage {
		return Response{}, nil, fmt.Errorf("message of %d bytes exceeds the limit", n)
	}

	buf := make([]byte, n)
	oob := make([]byte, syscall.CmsgSpace(4)) // room for exactly one descriptor
	bn, on, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil {
		return Response{}, nil, err
	}
	resp, err := DecodeResponse(buf[:bn])
	if err != nil {
		return Response{}, nil, err
	}
	if !resp.HasFD {
		return resp, nil, resp.error()
	}

	f, err := fileFromOOB(oob[:on])
	if err != nil {
		return resp, nil, err
	}
	return resp, f, resp.error()
}

// fileFromOOB extracts the single descriptor a create carries. More than one
// would mean the two sides disagree about the protocol, and the extra ones would
// leak, so they are closed rather than ignored.
func fileFromOOB(oob []byte) (*os.File, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("reading the descriptor: %w", err)
	}
	var fds []int
	for _, m := range msgs {
		got, err := syscall.ParseUnixRights(&m)
		if err != nil {
			continue
		}
		fds = append(fds, got...)
	}
	if len(fds) == 0 {
		return nil, fmt.Errorf("the helper said a descriptor was coming and sent none")
	}
	for _, extra := range fds[1:] {
		syscall.Close(extra)
	}
	return os.NewFile(uintptr(fds[0]), "tun"), nil
}
