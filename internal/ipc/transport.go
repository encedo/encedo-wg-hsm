package ipc

import (
	"encoding/binary"
	"fmt"
	"io"
)

// maxMessage bounds one framed message. Far more than anything here needs; a
// limit, not a target.
const maxMessage = 64 << 10

// The framing is a four-byte length and then JSON, over anything that reads and
// writes bytes.
//
// It works on io.Reader and io.Writer rather than a socket type, and that is
// what the previous arrangement could not do: it had to hand a file descriptor
// across, which is a unix socket's trick and has no Windows equivalent. Here the
// component creates the descriptor and never parts with it, so the same code
// runs over a unix socket on Linux and a named pipe on Windows without knowing
// which it is under.

// WriteMsg frames a value so the reader knows where it ends. A stream is a
// stream, and JSON is not self-delimiting for a reader that must not block.
func WriteMsg(w io.Writer, v any) error {
	b, err := Encode(v)
	if err != nil {
		return err
	}
	if len(b) > maxMessage {
		return fmt.Errorf("message of %d bytes exceeds the limit", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadMsg reads one framed message. The length is checked before anything is
// allocated: a component listening on a socket must not be persuadable into a
// large allocation by whatever can reach it.
func ReadMsg(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxMessage {
		return nil, fmt.Errorf("message of %d bytes exceeds the limit", n)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
