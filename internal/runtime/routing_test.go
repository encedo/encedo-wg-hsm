package runtime

import (
	"errors"
	"net/netip"
	"testing"
)

// withResolver swaps the resolver for one that answers from a table, so the
// routing decision can be tested without a network or a name server.
func withResolver(t *testing.T, table map[string][]string) {
	t.Helper()
	prev := resolveHost
	t.Cleanup(func() { resolveHost = prev })
	resolveHost = func(host string) ([]netip.Addr, error) {
		if addr, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{addr}, nil
		}
		addrs, ok := table[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

func peer(endpoint string, allowed ...string) Peer {
	p := Peer{Endpoint: endpoint}
	for _, a := range allowed {
		p.AllowedIPs = append(p.AllowedIPs, netip.MustParsePrefix(a))
	}
	return p
}

func TestFullTunnelPinsTheEndpoint(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{peer("203.0.113.1:51820", "0.0.0.0/0")}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if len(plan.Endpoints) != 1 || plan.Endpoints[0] != netip.MustParseAddr("203.0.113.1") {
		t.Fatalf("Endpoints = %v, want [203.0.113.1] — without the pin the tunnel routes its own transport", plan.Endpoints)
	}
}

func TestSplitTunnelPinsNothing(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{peer("203.0.113.1:51820", "10.1.1.0/24")}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if len(plan.Endpoints) != 0 {
		t.Errorf("Endpoints = %v, want none: AllowedIPs does not cover the endpoint", plan.Endpoints)
	}
	if plan.HEMInside {
		t.Error("HEMInside = true, want false: 10.1.1.0/24 does not cover 192.168.7.1")
	}
}

// An AllowedIPs that is not the default route can still capture the endpoint,
// which is why the condition is coverage and not a literal check for 0.0.0.0/0.
func TestANarrowPrefixCoveringTheEndpointStillPins(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{peer("203.0.113.1:51820", "203.0.113.0/24")}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if len(plan.Endpoints) != 1 {
		t.Fatalf("Endpoints = %v, want the endpoint pinned", plan.Endpoints)
	}
}

func TestEndpointNamesResolveBeforeTheTunnel(t *testing.T) {
	withResolver(t, map[string][]string{
		"vpn.example.com": {"198.51.100.7", "198.51.100.8"},
		"my.ence.do":      {"198.51.100.9"},
	})

	plan, err := PlanRouting([]Peer{peer("vpn.example.com:51820", "0.0.0.0/0")}, "https://my.ence.do")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if len(plan.Endpoints) != 2 {
		t.Fatalf("Endpoints = %v, want both addresses of the name pinned", plan.Endpoints)
	}
}

func TestAnUnresolvableEndpointStopsBeforeAnythingIsTouched(t *testing.T) {
	withResolver(t, nil)

	if _, err := PlanRouting([]Peer{peer("nowhere.invalid:51820", "0.0.0.0/0")}, "https://192.168.7.1"); err == nil {
		t.Fatal("PlanRouting succeeded; a name that does not resolve now will not resolve once the default route has moved")
	}
}

func TestHEMInsideTheTunnelIsReported(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{peer("203.0.113.1:51820", "0.0.0.0/0")}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if !plan.HEMInside {
		t.Error("HEMInside = false: 0.0.0.0/0 covers the HEM, and every handshake needs it")
	}
	if plan.HEMHost != "192.168.7.1" {
		t.Errorf("HEMHost = %q, want 192.168.7.1", plan.HEMHost)
	}
}

// The endpoint is pinned automatically; the HEM is not. Routing HEM traffic
// through the tunnel can be deliberate, and it works — so the plan records it
// rather than adding an exception behind the operator's back.
func TestTheHEMIsNotPinnedWithTheEndpoints(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{peer("203.0.113.1:51820", "0.0.0.0/0")}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if containsAddr(plan.Endpoints, netip.MustParseAddr("192.168.7.1")) {
		t.Error("the HEM address was pinned with the endpoints")
	}
}

func TestIPv6DefaultDoesNotCaptureIPv4(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{peer("203.0.113.1:51820", "::/0")}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if len(plan.Endpoints) != 0 {
		t.Errorf("Endpoints = %v: ::/0 does not route a v4 address", plan.Endpoints)
	}
}

func TestIPv6EndpointUnderAnIPv6Default(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{peer("[2001:db8::1]:51820", "::/0")}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if len(plan.Endpoints) != 1 || plan.Endpoints[0] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("Endpoints = %v, want [2001:db8::1]", plan.Endpoints)
	}
}

func TestSeveralPeersOnOneAddressPinItOnce(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{
		peer("203.0.113.1:51820", "0.0.0.0/0"),
		peer("203.0.113.1:51821", "0.0.0.0/0"),
	}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if len(plan.Endpoints) != 1 {
		t.Fatalf("Endpoints = %v, want one entry for one address", plan.Endpoints)
	}
}

// Cryptokey routing is per-interface: one peer's endpoint can be captured by a
// different peer's AllowedIPs, and the pin has to follow the table, not the peer.
func TestAPeersEndpointCapturedByAnotherPeersAllowedIPs(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{
		peer("203.0.113.1:51820", "10.1.1.0/24"),
		peer("198.51.100.1:51820", "203.0.113.0/24"),
	}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if !containsAddr(plan.Endpoints, netip.MustParseAddr("203.0.113.1")) {
		t.Errorf("Endpoints = %v, want the first peer's endpoint pinned: the second peer's AllowedIPs covers it", plan.Endpoints)
	}
}

func TestAPeerWithoutAnEndpointIsSkipped(t *testing.T) {
	withResolver(t, nil)

	plan, err := PlanRouting([]Peer{peer("", "0.0.0.0/0")}, "https://192.168.7.1")
	if err != nil {
		t.Fatalf("PlanRouting: %v", err)
	}
	if len(plan.Endpoints) != 0 {
		t.Errorf("Endpoints = %v, want none", plan.Endpoints)
	}
}

func TestHostOf(t *testing.T) {
	cases := map[string]string{
		"203.0.113.1:51820":     "203.0.113.1",
		"vpn.example.com:51820": "vpn.example.com",
		"[2001:db8::1]:51820":   "2001:db8::1",
		"vpn.example.com":       "vpn.example.com",
	}
	for in, want := range cases {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHEMHost(t *testing.T) {
	cases := map[string]string{
		"https://my.ence.do":        "my.ence.do",
		"https://192.168.7.1":       "192.168.7.1",
		"https://epa.acme.com:8443": "epa.acme.com",
		"192.168.7.1":               "192.168.7.1",
	}
	for in, want := range cases {
		got, err := HEMHost(in)
		if err != nil {
			t.Errorf("HEMHost(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("HEMHost(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := HEMHost(""); err == nil {
		t.Error("HEMHost accepted an empty URL")
	}
}

func TestHostPrefix(t *testing.T) {
	if got := hostPrefix(netip.MustParseAddr("203.0.113.1")).String(); got != "203.0.113.1/32" {
		t.Errorf("hostPrefix(v4) = %s, want 203.0.113.1/32", got)
	}
	if got := hostPrefix(netip.MustParseAddr("2001:db8::1")).String(); got != "2001:db8::1/128" {
		t.Errorf("hostPrefix(v6) = %s, want 2001:db8::1/128", got)
	}
}
