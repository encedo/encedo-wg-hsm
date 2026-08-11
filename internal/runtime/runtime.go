// Package runtime carries the part of bringing a WireGuard interface up that is
// the operating system's business rather than WireGuard's: addresses, routes,
// DNS, the UAPI socket, and the routing exceptions a tunnel needs in order to
// carry its own transport.
//
// Both clients drive it. wg-quick-encedo fills its input from wg1.conf,
// wg-hem from the descr records it reads out of the device, and neither of them
// knows how a route is installed on the host it happens to be running on.
package runtime

import (
	"net/netip"
	"os"
	"os/exec"
)

// Peer is what this package needs to know about one peer: where its transport
// lives, and what the interface will claim on its behalf. It is deliberately
// smaller than either client's notion of a peer — no keys, no labels, nothing
// that would tie the routing decision to where the configuration came from.
type Peer struct {
	// Endpoint is host:port as configured. It may be a name; resolving it is
	// this package's job, and the timing of that matters — see PlanRouting.
	Endpoint string

	// AllowedIPs are the prefixes the interface will route.
	AllowedIPs []netip.Prefix
}

// run executes a command, letting its output through to stderr. stdout is the
// machine-readable channel in both clients, so nothing a helper prints may
// land there.
func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// hostPrefix is the single-address prefix for addr — /32 or /128, whichever
// family it belongs to.
func hostPrefix(addr netip.Addr) netip.Prefix {
	return netip.PrefixFrom(addr, addr.BitLen())
}
