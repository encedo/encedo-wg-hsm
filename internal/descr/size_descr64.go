//go:build descr64

package descr

// Size is 64 bytes on firmware whose descr field predates the 128-byte one.
// Build with -tags descr64 to talk to such a device.
//
// The budget gets tight enough to change what is expressible. A peer record is
// 7 bytes of header plus 8 for an IPv4 endpoint, 7 per allowed-ip range, 3 for
// keepalive and 42 for a wrapped PSK: a peer with a PSK therefore fits only
// with a literal IPv4 endpoint, exactly one allowed-ip range and no keepalive,
// landing on 64 bytes exactly. A hostname endpoint and a PSK cannot coexist at
// all. An interface record spends 7 on the header and 34 on the MAC, leaving
// room for an address, one option and two peer references.
//
// See the comment in size_default.go: a tree written by this build is not
// readable by a default one.
const Size = 64
