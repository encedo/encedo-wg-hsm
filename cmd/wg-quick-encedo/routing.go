package main

import (
	"context"
	"fmt"
	"net"
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
// see probeHEM.

// resolveHost turns a host name or literal address into addresses. It is a
// variable so tests can plan routing without a resolver, and it is called before
// the interface exists: afterwards the tunnel may own the path to the resolver.
var resolveHost = func(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	return net.LookupIP(host)
}

// tunnelRouting is everything about the routing decision that has to be settled
// before the interface exists, because it depends on name resolution.
type tunnelRouting struct {
	// endpoints are peer endpoint addresses that AllowedIPs would otherwise
	// capture. Each needs a host route around the tunnel.
	endpoints []net.IP

	// hemHost is the HEM's host as written in the configuration, for messages.
	hemHost string

	// hemInside records that AllowedIPs covers the HEM as well. Unlike an
	// endpoint this is not automatically routed around the tunnel: it may be a
	// deliberate choice to protect HEM traffic, and it works — see probeHEM.
	hemInside bool
}

// planRouting resolves the endpoints and the HEM against the configuration's
// AllowedIPs. It fails rather than guessing: a name that does not resolve now
// will not resolve better once the default route has moved.
func planRouting(cfg *Config) (*tunnelRouting, error) {
	prefixes, err := allowedPrefixes(cfg.Peers)
	if err != nil {
		return nil, err
	}

	r := &tunnelRouting{}
	for _, p := range cfg.Peers {
		if p.Endpoint == "" {
			continue
		}
		host := hostOf(p.Endpoint)
		ips, err := resolveHost(host)
		if err != nil {
			return nil, fmt.Errorf("resolving the endpoint %s: %w", host, err)
		}
		for _, ip := range ips {
			if covered(ip, prefixes) && !containsIP(r.endpoints, ip) {
				r.endpoints = append(r.endpoints, ip)
			}
		}
	}

	r.hemHost, err = hemHost(cfg.Interface.HEMURL)
	if err != nil {
		return nil, err
	}
	hemIPs, err := resolveHost(r.hemHost)
	if err != nil {
		return nil, fmt.Errorf("resolving the HEM address %s: %w", r.hemHost, err)
	}
	for _, ip := range hemIPs {
		if covered(ip, prefixes) {
			r.hemInside = true
			break
		}
	}
	return r, nil
}

// probeHEM applies the HEM half of the routing decision once the routes are in
// place. Every handshake is a live HEM call, so an interface that has routed its
// own HEM into the dark is an interface that dies at the first rekey.
//
// A HEM that still answers from inside the tunnel is fine and is left alone.
// Rekeying starts at ~120 s while the previous session stays valid to 180 s, so
// the call travels over the live session; sending the first handshake message
// does not need the HEM at all, only consuming the reply does.
func probeHEM(client *hem.Client, host string) error {
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
	ip    net.IP
	gw    net.IP
	iface string
}

// routeExceptions remembers what was pinned so teardown leaves the table as it
// was found. Routes on the tunnel link go away with the link; these sit on the
// physical one and would outlive it.
type routeExceptions struct {
	routes []pinnedRoute
}

// pin installs a host route for each address, through whatever gateway is
// default for that family right now. Call it before the tunnel's own routes go
// in, so there is no window in which the endpoint has no path.
func (r *routeExceptions) pin(ips []net.IP) error {
	for _, ip := range ips {
		gw, iface, err := defaultGateway(ip.To4() == nil)
		if err != nil {
			return fmt.Errorf("finding the current route to %s: %w", ip, err)
		}
		if err := addHostRoute(ip, gw, iface); err != nil {
			return fmt.Errorf("pinning %s to %s via %s: %w", ip, iface, gw, err)
		}
		r.routes = append(r.routes, pinnedRoute{ip: ip, gw: gw, iface: iface})
		fmt.Fprintf(os.Stderr, "Endpoint %s pinned to %s via %s (outside the tunnel).\n", ip, iface, gw)
	}
	return nil
}

// restore removes the pins. A failure here is reported rather than returned:
// it happens on the way down, where there is nothing left to abort.
func (r *routeExceptions) restore() {
	for _, p := range r.routes {
		if err := delHostRoute(p.ip, p.gw, p.iface); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: leaving a host route to %s via %s behind: %v\n", p.ip, p.gw, err)
		}
	}
	r.routes = nil
}

// allowedPrefixes collects every AllowedIPs entry in the configuration. They are
// what the interface will claim, so they are also what may capture an address
// the tunnel itself depends on.
func allowedPrefixes(peers []Peer) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, p := range peers {
		for _, cidr := range p.AllowedIPs {
			_, n, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("AllowedIPs %q: %w", cidr, err)
			}
			out = append(out, n)
		}
	}
	return out, nil
}

// covered reports whether an address falls inside any of the prefixes. A v4
// address is tested against v4 prefixes only: ::/0 does not route 203.0.113.1.
func covered(ip net.IP, prefixes []*net.IPNet) bool {
	for _, n := range prefixes {
		if (n.IP.To4() != nil) != (ip.To4() != nil) {
			continue
		}
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func containsIP(list []net.IP, ip net.IP) bool {
	for _, e := range list {
		if e.Equal(ip) {
			return true
		}
	}
	return false
}

// hostOf strips the port from a WireGuard endpoint. An endpoint without a port
// is not valid for WireGuard, but parsing is not the place to say so.
func hostOf(endpoint string) string {
	if host, _, err := net.SplitHostPort(endpoint); err == nil {
		return host
	}
	return strings.Trim(endpoint, "[]")
}

// hemHost extracts the host from a HEM base URL. The scheme is optional in
// practice — the SDK accepts a bare host — so a missing one is not an error.
func hemHost(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("HEM_URL is empty")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("HEM_URL %q: %w", raw, err)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("HEM_URL %q has no host", raw)
	}
	return u.Hostname(), nil
}

// hostNet is the single-address prefix for ip — /32 or /128, whichever family
// it belongs to.
func hostNet(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}
