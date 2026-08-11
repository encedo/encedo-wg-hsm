package main

import (
	"errors"
	"net"
	"testing"
)

// withResolver swaps the resolver for one that answers from a table, so the
// routing decision can be tested without a network or a name server.
func withResolver(t *testing.T, table map[string][]string) {
	t.Helper()
	prev := resolveHost
	t.Cleanup(func() { resolveHost = prev })
	resolveHost = func(host string) ([]net.IP, error) {
		if ip := net.ParseIP(host); ip != nil {
			return []net.IP{ip}, nil
		}
		addrs, ok := table[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		out := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, net.ParseIP(a))
		}
		return out, nil
	}
}

func cfgWith(hemURL string, peers ...Peer) *Config {
	c := &Config{Peers: peers}
	c.Interface.HEMURL = hemURL
	return c
}

func TestFullTunnelPinsTheEndpoint(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{"0.0.0.0/0"},
	})

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	if len(r.endpoints) != 1 || !r.endpoints[0].Equal(net.ParseIP("203.0.113.1")) {
		t.Fatalf("endpoints = %v, want [203.0.113.1] — without the pin the tunnel routes its own transport", r.endpoints)
	}
}

func TestSplitTunnelPinsNothing(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{"10.1.1.0/24"},
	})

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	if len(r.endpoints) != 0 {
		t.Errorf("endpoints = %v, want none: AllowedIPs does not cover the endpoint", r.endpoints)
	}
	if r.hemInside {
		t.Error("hemInside = true, want false: 10.1.1.0/24 does not cover 192.168.7.1")
	}
}

// An AllowedIPs that is not the default route can still capture the endpoint,
// which is why the test is coverage and not a literal check for 0.0.0.0/0.
func TestANarrowPrefixCoveringTheEndpointStillPins(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{"203.0.113.0/24"},
	})

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	if len(r.endpoints) != 1 {
		t.Fatalf("endpoints = %v, want the endpoint pinned", r.endpoints)
	}
}

func TestEndpointNamesResolveBeforeTheTunnel(t *testing.T) {
	withResolver(t, map[string][]string{
		"vpn.example.com": {"198.51.100.7", "198.51.100.8"},
		"my.ence.do":      {"198.51.100.9"},
	})
	cfg := cfgWith("https://my.ence.do", Peer{
		Endpoint:   "vpn.example.com:51820",
		AllowedIPs: []string{"0.0.0.0/0"},
	})

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	if len(r.endpoints) != 2 {
		t.Fatalf("endpoints = %v, want both addresses of the name pinned", r.endpoints)
	}
}

func TestAnUnresolvableEndpointStopsBeforeAnythingIsTouched(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{
		Endpoint:   "nowhere.invalid:51820",
		AllowedIPs: []string{"0.0.0.0/0"},
	})

	if _, err := planRouting(cfg); err == nil {
		t.Fatal("planRouting succeeded; a name that does not resolve now will not resolve once the default route has moved")
	}
}

func TestHEMInsideTheTunnelIsReported(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{"0.0.0.0/0"},
	})

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	if !r.hemInside {
		t.Error("hemInside = false: 0.0.0.0/0 covers the HEM, and every handshake needs it")
	}
	if r.hemHost != "192.168.7.1" {
		t.Errorf("hemHost = %q, want 192.168.7.1", r.hemHost)
	}
}

// The endpoint is pinned automatically; the HEM is not. Routing HEM traffic
// through the tunnel can be deliberate, and it works — so the plan records it
// rather than adding an exception behind the operator's back.
func TestTheHEMIsNotPinnedWithTheEndpoints(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{"0.0.0.0/0"},
	})

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	for _, ip := range r.endpoints {
		if ip.Equal(net.ParseIP("192.168.7.1")) {
			t.Error("the HEM address was pinned with the endpoints")
		}
	}
}

func TestIPv6DefaultDoesNotCaptureIPv4(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{"::/0"},
	})

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	if len(r.endpoints) != 0 {
		t.Errorf("endpoints = %v: ::/0 does not route a v4 address", r.endpoints)
	}
}

func TestIPv6EndpointUnderAnIPv6Default(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{
		Endpoint:   "[2001:db8::1]:51820",
		AllowedIPs: []string{"::/0"},
	})

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	if len(r.endpoints) != 1 || !r.endpoints[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("endpoints = %v, want [2001:db8::1]", r.endpoints)
	}
}

func TestSeveralPeersOnOneAddressPinItOnce(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1",
		Peer{Endpoint: "203.0.113.1:51820", AllowedIPs: []string{"0.0.0.0/0"}},
		Peer{Endpoint: "203.0.113.1:51821", AllowedIPs: []string{"0.0.0.0/0"}},
	)

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	if len(r.endpoints) != 1 {
		t.Fatalf("endpoints = %v, want one entry for one address", r.endpoints)
	}
}

func TestAPeerWithoutAnEndpointIsSkipped(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{AllowedIPs: []string{"0.0.0.0/0"}})

	r, err := planRouting(cfg)
	if err != nil {
		t.Fatalf("planRouting: %v", err)
	}
	if len(r.endpoints) != 0 {
		t.Errorf("endpoints = %v, want none", r.endpoints)
	}
}

func TestMalformedAllowedIPsIsAnError(t *testing.T) {
	withResolver(t, nil)
	cfg := cfgWith("https://192.168.7.1", Peer{
		Endpoint:   "203.0.113.1:51820",
		AllowedIPs: []string{"10.1.1.0/33"},
	})

	if _, err := planRouting(cfg); err == nil {
		t.Fatal("planRouting accepted a /33 prefix")
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
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHemHost(t *testing.T) {
	cases := map[string]string{
		"https://my.ence.do":        "my.ence.do",
		"https://192.168.7.1":       "192.168.7.1",
		"https://epa.acme.com:8443": "epa.acme.com",
		"192.168.7.1":               "192.168.7.1",
	}
	for in, want := range cases {
		got, err := hemHost(in)
		if err != nil {
			t.Errorf("hemHost(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("hemHost(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := hemHost(""); err == nil {
		t.Error("hemHost accepted an empty URL")
	}
}

func TestHostNet(t *testing.T) {
	if got := hostNet(net.ParseIP("203.0.113.1")).String(); got != "203.0.113.1/32" {
		t.Errorf("hostNet(v4) = %s, want 203.0.113.1/32", got)
	}
	if got := hostNet(net.ParseIP("2001:db8::1")).String(); got != "2001:db8::1/128" {
		t.Errorf("hostNet(v6) = %s, want 2001:db8::1/128", got)
	}
}
