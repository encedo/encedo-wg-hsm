package handoff

import (
	"net/netip"
	"strings"
	"testing"
)

func prefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

// The narrowing is the whole point of the package, so it is the first test: a
// /24 on this side is one host on the server's side, and copying the prefix
// across would hand this peer the other 253 addresses.
func TestAllowedIPsNarrowsToTheHost(t *testing.T) {
	p := Peer{Addresses: prefixes(t, "10.1.1.5/24")}
	got := p.AllowedIPs()
	if len(got) != 1 || got[0] != "10.1.1.5/32" {
		t.Fatalf("AllowedIPs = %v, want [10.1.1.5/32]", got)
	}
}

func TestAllowedIPsHandlesV6AndOrdersV4First(t *testing.T) {
	p := Peer{Addresses: prefixes(t, "fd00::7/64", "10.99.0.7/32")}
	got := p.AllowedIPs()
	want := []string{"10.99.0.7/32", "fd00::7/128"}
	if len(got) != len(want) {
		t.Fatalf("AllowedIPs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AllowedIPs = %v, want %v", got, want)
		}
	}
}

// Two addresses that differ only in prefix length are one host, and listing it
// twice would be a peer entry an administrator has to think about.
func TestAllowedIPsDeduplicates(t *testing.T) {
	p := Peer{Addresses: prefixes(t, "10.1.1.5/24", "10.1.1.5/32")}
	if got := p.AllowedIPs(); len(got) != 1 {
		t.Fatalf("AllowedIPs = %v, want one entry", got)
	}
}

func TestConfBlock(t *testing.T) {
	p := Peer{
		PublicKey: "abc123=",
		Addresses: prefixes(t, "10.99.0.7/32"),
		Label:     "chris laptop",
	}
	got := p.ConfBlock()
	for _, want := range []string{
		"[Peer]\n",
		"# chris laptop\n",
		"PublicKey = abc123=\n",
		"AllowedIPs = 10.99.0.7/32\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ConfBlock missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "PresharedKey") {
		t.Errorf("ConfBlock names a pre-shared key that does not exist:\n%s", got)
	}
	if strings.Contains(got, "Endpoint") {
		t.Errorf("ConfBlock offers an endpoint for a client behind NAT:\n%s", got)
	}
}

func TestConfBlockCarriesAGeneratedPresharedKey(t *testing.T) {
	p := Peer{
		PublicKey:    "abc123=",
		Addresses:    prefixes(t, "10.99.0.7/32"),
		PresharedKey: "psk456=",
	}
	if got := p.ConfBlock(); !strings.Contains(got, "PresharedKey = psk456=\n") {
		t.Errorf("ConfBlock dropped the pre-shared key:\n%s", got)
	}
}

// A label is a comment, so no label means no empty comment line left behind.
func TestConfBlockWithoutALabel(t *testing.T) {
	p := Peer{PublicKey: "abc123=", Addresses: prefixes(t, "10.99.0.7/32")}
	if got := p.ConfBlock(); strings.Contains(got, "#") {
		t.Errorf("ConfBlock left a comment with nothing in it:\n%s", got)
	}
}

func TestSetCommand(t *testing.T) {
	p := Peer{PublicKey: "abc123=", Addresses: prefixes(t, "10.99.0.7/32")}
	got := p.SetCommand("wg0")
	if !strings.Contains(got, "wg set wg0 peer abc123=") {
		t.Errorf("SetCommand:\n%s", got)
	}
	if !strings.Contains(got, "allowed-ips 10.99.0.7/32") {
		t.Errorf("SetCommand:\n%s", got)
	}
}

// The one thing that must not be copyable is the secret on a command line: it
// would land in the process list and in shell history.
func TestSetCommandKeepsThePresharedKeyOffTheCommandLine(t *testing.T) {
	p := Peer{
		PublicKey:    "abc123=",
		Addresses:    prefixes(t, "10.99.0.7/32"),
		PresharedKey: "psk456=",
	}
	got := p.SetCommand("wg0")
	cmd, _, _ := strings.Cut(got, "\n\n")
	if strings.Contains(cmd, "psk456=") {
		t.Errorf("the pre-shared key is on the command line:\n%s", got)
	}
	if !strings.Contains(cmd, "preshared-key /path/to/psk") {
		t.Errorf("SetCommand does not name a file for the pre-shared key:\n%s", got)
	}
}

func TestSetCommandDefaultsTheInterface(t *testing.T) {
	p := Peer{PublicKey: "abc123=", Addresses: prefixes(t, "10.99.0.7/32")}
	if got := p.SetCommand(""); !strings.Contains(got, "wg set wg0 peer") {
		t.Errorf("SetCommand(\"\"):\n%s", got)
	}
}
