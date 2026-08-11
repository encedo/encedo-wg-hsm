package runtime

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	hem "github.com/encedo/hem-sdk-go"
)

// hemProbeTimeout bounds the one unauthenticated call that decides whether the
// routes just installed have cut the HEM off. It is the same order as the
// handshake budget: a device that needs longer than this to answer will not
// survive a rekey either.
const hemProbeTimeout = 3 * time.Second

// A tunnel carries its own transport, and AllowedIPs decides what the tunnel
// carries. With 0.0.0.0/0 the default route moves onto the interface and the UDP
// to the peer's endpoint is routed by the same table as everything else — handed
// to the tunnel it is supposed to carry, so the handshake can never complete and
// the interface comes up dead.
//
// The fix is a host route per endpoint address through the gateway that was
// default before the interface existed. A /32 beats a /0 whatever order the two
// are installed in, so the endpoint keeps its physical path while everything
// else goes through the tunnel.
//
// The HEM is a second address with the same exposure and a different answer —
// see ProbeHEM.

// resolveHost turns a host name or literal address into addresses. It is a
// variable so tests can plan routing without a resolver.
var resolveHost = func(host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{addr}, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, addr.Unmap())
		}
	}
	return out, nil
}

// Plan is everything about the routing decision that has to be settled before
// the interface exists, because it depends on name resolution.
type Plan struct {
	// Endpoints are peer endpoint addresses that AllowedIPs would otherwise
	// capture. Each needs a host route around the tunnel.
	Endpoints []netip.Addr

	// HEMHost is the HEM's host as configured, for messages.
	HEMHost string

	// HEMInside records that AllowedIPs covers the HEM as well. Unlike an
	// endpoint this is not automatically routed around the tunnel: it may be a
	// deliberate choice to protect HEM traffic, and it works — see ProbeHEM.
	HEMInside bool
}

// PlanRouting resolves the endpoints and the HEM against the peers' AllowedIPs.
//
// Call it before the interface exists. Afterwards the resolver may be behind the
// tunnel whose construction depends on the answer, and a name that does not
// resolve now will not resolve better once the default route has moved — so this
// fails rather than guessing.
func PlanRouting(peers []Peer, hemURL string) (*Plan, error) {
	p := &Plan{}
	for _, peer := range peers {
		if peer.Endpoint == "" {
			continue
		}
		host := HostOf(peer.Endpoint)
		addrs, err := resolveHost(host)
		if err != nil {
			return nil, fmt.Errorf("resolving the endpoint %s: %w", host, err)
		}
		for _, a := range addrs {
			if covered(a, peers) && !containsAddr(p.Endpoints, a) {
				p.Endpoints = append(p.Endpoints, a)
			}
		}
	}

	var err error
	p.HEMHost, err = HEMHost(hemURL)
	if err != nil {
		return nil, err
	}
	hemAddrs, err := resolveHost(p.HEMHost)
	if err != nil {
		return nil, fmt.Errorf("resolving the HEM address %s: %w", p.HEMHost, err)
	}
	for _, a := range hemAddrs {
		if covered(a, peers) {
			p.HEMInside = true
			break
		}
	}
	return p, nil
}

// ProbeHEM applies the HEM half of the routing decision once the routes are in
// place. Every handshake is a live HEM call, so an interface that has routed its
// own HEM into the dark is an interface that dies at the first rekey.
//
// A HEM that still answers from inside the tunnel is fine and is left alone.
// Rekeying starts at ~120 s while the previous session stays valid to 180 s, so
// the call travels over the live session; sending the first handshake message
// does not need the HEM at all, only consuming the reply does.
func ProbeHEM(client *hem.Client, host string) error {
	ctx, cancel := context.WithTimeout(context.Background(), hemProbeTimeout)
	defer cancel()
	if _, err := client.GetVersion(ctx); err != nil {
		return fmt.Errorf("the HEM at %s is inside the tunnel and no longer answers (%w); "+
			"refusing to leave an interface up that cannot rekey", host, err)
	}
	fmt.Fprintf(os.Stderr, "NOTE: the HEM at %s is routed through the tunnel and still answers.\n", host)
	fmt.Fprintln(os.Stderr, "      Rekeying overlaps the live session, so this works; if the peer stays")
	fmt.Fprintln(os.Stderr, "      unreachable past that overlap, restart to rebuild the tunnel.")
	return nil
}

// pinnedRoute is one exception this process installed and therefore owns.
type pinnedRoute struct {
	addr  netip.Addr
	gw    netip.Addr
	iface string
}

// Pins remembers the host routes installed so teardown leaves the table as it
// was found. Routes on the tunnel link go away with the link; these sit on the
// physical one and would outlive it.
type Pins struct {
	routes []pinnedRoute
}

// Add installs a host route for each address, through whatever gateway is
// default for that family right now. Call it before the tunnel's own routes go
// in, so there is no window in which the endpoint has no path.
func (p *Pins) Add(addrs []netip.Addr) error {
	for _, addr := range addrs {
		gw, iface, err := defaultGateway(addr.Is6())
		if err != nil {
			return fmt.Errorf("finding the current route to %s: %w", addr, err)
		}
		if err := addHostRoute(addr, gw, iface); err != nil {
			return fmt.Errorf("pinning %s to %s via %s: %w", addr, iface, gw, err)
		}
		p.routes = append(p.routes, pinnedRoute{addr: addr, gw: gw, iface: iface})
		fmt.Fprintf(os.Stderr, "Endpoint %s pinned to %s via %s (outside the tunnel).\n", addr, iface, gw)
	}
	return nil
}

// Restore removes the pins. A failure here is reported rather than returned: it
// happens on the way down, where there is nothing left to abort.
func (p *Pins) Restore() {
	for _, r := range p.routes {
		if err := delHostRoute(r.addr, r.gw, r.iface); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: leaving a host route to %s via %s behind: %v\n", r.addr, r.gw, err)
		}
	}
	p.routes = nil
}

// AllowedPrefixes collects every AllowedIPs entry across the peers — what the
// interface will claim, and so also what may capture an address the tunnel
// itself depends on.
func AllowedPrefixes(peers []Peer) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range peers {
		out = append(out, p.AllowedIPs...)
	}
	return out
}

// covered reports whether an address falls inside any peer's AllowedIPs. A v4
// address is never covered by a v6 prefix: ::/0 does not route 203.0.113.1.
func covered(addr netip.Addr, peers []Peer) bool {
	for _, p := range peers {
		for _, prefix := range p.AllowedIPs {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func containsAddr(list []netip.Addr, addr netip.Addr) bool {
	for _, a := range list {
		if a == addr {
			return true
		}
	}
	return false
}

// HostOf strips the port from a WireGuard endpoint. An endpoint without a port
// is not valid for WireGuard, but parsing is not the place to say so.
func HostOf(endpoint string) string {
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return host
	}
	return strings.Trim(endpoint, "[]")
}

// HEMHost extracts the host from a HEM base URL. The scheme is optional in
// practice — the SDK accepts a bare host — so a missing one is not an error.
func HEMHost(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("the HEM URL is empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("HEM URL %q: %w", raw, err)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("HEM URL %q has no host", raw)
	}
	return u.Hostname(), nil
}
