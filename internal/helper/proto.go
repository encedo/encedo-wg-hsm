// Package helper is the boundary between the part of this client that needs
// privilege and the part that holds secrets. They are deliberately not the same
// part.
//
// Everything that requires elevation is an operation on the network stack:
// creating the tunnel interface, giving it addresses, routes and an MTU, and
// pointing the resolver at it. None of it involves a key. Everything secret —
// the passphrase, the token, the shared secrets that come back from the device —
// stays in the unprivileged process, which is where the person typing is.
//
// So the helper is small, and its request types are the proof: nothing in this
// file has a field that could carry key material. A test asserts that, because
// the property is easy to lose one convenient field at a time.
//
// Linux does not strictly need this — one capability on the binary covers every
// operation here, and the command-line client uses exactly that. A graphical
// client is a different matter: granting CAP_NET_ADMIN to a process that also
// contains a rendering stack and a webview is a much larger promise than the
// same grant to a few hundred lines of netlink calls.
package helper

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

// Op names what the caller is asking for. Strings rather than integers so a
// mismatched helper and client fail loudly and legibly, rather than performing
// the wrong operation because the numbering drifted.
type Op string

const (
	OpCreateTUN Op = "create-tun" // answered with a file descriptor, not a value
	OpUp        Op = "up"
	OpDown      Op = "down"
	OpAddRoutes Op = "add-routes"
	OpSetMTU    Op = "set-mtu"
	OpSetDNS    Op = "set-dns"
	OpRevertDNS Op = "revert-dns"
	OpPin       Op = "pin"   // hold an endpoint on the pre-tunnel gateway
	OpUnpin     Op = "unpin" // and let go of it
)

// Request is everything the privileged side is ever told. Every field is public
// information: an interface name, an address, a route, a resolver. If a change
// to this struct ever wants to carry something secret, the boundary is in the
// wrong place and the change is the bug.
type Request struct {
	Op   Op     `json:"op"`
	Name string `json:"name,omitempty"` // interface

	Addrs  []netip.Prefix `json:"addrs,omitempty"`
	Routes []netip.Prefix `json:"routes,omitempty"`
	Hosts  []netip.Addr   `json:"hosts,omitempty"` // endpoints to pin
	DNS    []string       `json:"dns,omitempty"`
	MTU    int            `json:"mtu,omitempty"`
}

// Response says whether it worked and, when it did not, why in words the caller
// can show somebody. The privileged side never returns a value: it acts, or it
// explains itself.
type Response struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`

	// HasFD reports that a file descriptor accompanies this response out of
	// band. Only OpCreateTUN sets it. The descriptor cannot travel in JSON, so
	// the transport carries it alongside and this says to expect it — without
	// which a caller would have to infer from the op it sent, and inference is
	// how a descriptor gets leaked or lost.
	HasFD bool `json:"has_fd,omitempty"`
}

func (r Response) error() error {
	if r.OK {
		return nil
	}
	if r.Err == "" {
		return fmt.Errorf("the helper refused without saying why")
	}
	return fmt.Errorf("%s", r.Err)
}

// Encode and Decode are here rather than inlined so both ends share one
// definition of the wire format, and so a test can round-trip it without a
// socket.
func Encode(v any) ([]byte, error) { return json.Marshal(v) }

func DecodeRequest(b []byte) (Request, error) {
	var r Request
	err := json.Unmarshal(b, &r)
	return r, err
}

func DecodeResponse(b []byte) (Response, error) {
	var r Response
	err := json.Unmarshal(b, &r)
	return r, err
}

// Validate rejects a request the privileged side should not act on. It runs
// there, not here: the unprivileged side asking nicely is not a control, and a
// helper that trusts its caller is only as safe as whatever can reach its
// socket.
func (r Request) Validate() error {
	switch r.Op {
	case OpCreateTUN, OpUp, OpDown, OpAddRoutes, OpSetMTU, OpSetDNS, OpRevertDNS:
		if r.Name == "" {
			return fmt.Errorf("%s needs an interface name", r.Op)
		}
	case OpPin, OpUnpin:
		if len(r.Hosts) == 0 {
			return fmt.Errorf("%s needs at least one address", r.Op)
		}
	default:
		return fmt.Errorf("unknown operation %q", r.Op)
	}

	if r.MTU < 0 || r.MTU > 65535 {
		return fmt.Errorf("mtu %d out of range", r.MTU)
	}
	for _, p := range r.Addrs {
		if !p.IsValid() {
			return fmt.Errorf("invalid address")
		}
	}
	for _, p := range r.Routes {
		if !p.IsValid() {
			return fmt.Errorf("invalid route")
		}
	}
	for _, a := range r.Hosts {
		if !a.IsValid() {
			return fmt.Errorf("invalid host address")
		}
	}
	return nil
}
