// Package handoff renders the one thing this client cannot do for itself: the
// entry an administrator has to add on the server.
//
// Everything else in a provisioning run happens inside the module or against
// it. The far end is somebody else's machine, so the run ends with two values -
// a public key and an address - that have to travel to a person and be typed
// into a file. That last step is the only place in the whole flow where a typo
// passes unnoticed: a mistyped key produces a tunnel that never completes a
// handshake, with nothing anywhere saying why. Printing the block that person
// needs, ready to paste, removes the retyping and with it the entire class of
// report.
//
// Two forms, because servers are administered two ways. A [Peer] section is
// what goes into wg0.conf and survives a reboot; `wg set` is what somebody with
// a running interface types to add a peer without restarting it. They describe
// the same peer and it is deliberate that both are offered rather than one
// chosen: a client that guesses which style a server uses guesses wrong half
// the time.
package handoff

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Peer is this client as the server has to describe it.
//
// The fields are what the far end needs and nothing else. In particular there
// is no endpoint: a client behind NAT has no address the server can dial, and
// offering a field for one would invite somebody to fill it in.
type Peer struct {
	// PublicKey is the interface key, base64, exactly as the module reported
	// it. This is the value that changes on the server, and the only one.
	PublicKey string

	// Addresses are the client's own addresses, with their prefixes as
	// configured on this side - 10.99.0.7/32, or 10.1.1.5/24.
	Addresses []netip.Prefix

	// Label names the peer for whoever reads the server's configuration later.
	// Optional; an empty label simply produces no comment.
	Label string

	// PresharedKey is base64 and set only when there is one to hand over -
	// that is, when this run generated it. A pre-shared key that came from the
	// infrastructure is already known to the far end, and one that was stored
	// earlier cannot be read back out of the module.
	PresharedKey string
}

// AllowedIPs is what the server must route to this client, and it is not the
// same thing as the client's own address.
//
// A client configured as 10.1.1.5/24 holds one address on a network of 254; the
// prefix says where its neighbours are, not what it owns. Copied verbatim into
// the server's AllowedIPs it would claim the whole /24 for this one peer, which
// silently steals the other 253 - traffic for any of them is encrypted to this
// client and dropped there. So every address is narrowed to the single host it
// actually is.
//
// The narrowing is the reason this package exists rather than a printf at each
// call site. It is exactly the step a person doing this by hand gets wrong, and
// it fails in the direction that looks like it worked: the tunnel comes up, and
// something unrelated stops reaching a machine it used to reach.
func (p Peer) AllowedIPs() []string {
	seen := make(map[string]bool, len(p.Addresses))
	out := make([]string, 0, len(p.Addresses))
	for _, a := range p.Addresses {
		host := netip.PrefixFrom(a.Addr(), a.Addr().BitLen()).String()
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}
	// v4 before v6, and stable within each, so two runs of the same
	// configuration produce the same text and a diff of them is empty.
	sort.SliceStable(out, func(i, j int) bool {
		return strings.Contains(out[i], ".") && !strings.Contains(out[j], ".")
	})
	return out
}

// ConfBlock is the section to paste into the server's wg0.conf.
func (p Peer) ConfBlock() string {
	var b strings.Builder
	b.WriteString("[Peer]\n")
	if p.Label != "" {
		fmt.Fprintf(&b, "# %s\n", p.Label)
	}
	fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
	if p.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs(), ", "))
	return b.String()
}

// SetCommand is the same peer as a command for a running interface, which is
// how it is added without taking the server down.
//
// The pre-shared key is named as a file rather than given as a value, because
// `wg set` reads it from one and there is nowhere on a command line to put a
// secret that does not also put it in the process list and the shell history.
// The line is left for the administrator to fill in, deliberately: this is the
// one place where a copyable block should stop being copyable.
func (p Peer) SetCommand(iface string) string {
	if iface == "" {
		iface = "wg0"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "wg set %s peer %s \\\n", iface, p.PublicKey)
	if p.PresharedKey != "" {
		b.WriteString("  preshared-key /path/to/psk \\\n")
	}
	fmt.Fprintf(&b, "  allowed-ips %s\n", strings.Join(p.AllowedIPs(), ","))
	if p.PresharedKey != "" {
		fmt.Fprintf(&b, "\n# The pre-shared key is read from a file, not from this line:\n")
		fmt.Fprintf(&b, "#   umask 077; printf %%s '%s' > /path/to/psk\n", p.PresharedKey)
	}
	return b.String()
}
