package provision

import (
	"fmt"
	"strings"
	"testing"

	"github.com/encedo/encedo-wg-hsm/internal/wgconf"
)

// The file a person is actually handed, in the one test here that needs a whole
// one: the rest of the parsing is wgconf's own business and is tested there.
const demoConf = `[Interface]
PrivateKey = kOk30xyXpohscPIXf1WuFquKdgd1pWeJrsdTsXs50XQ=
Address = 192.168.2.2/32
DNS = 8.8.8.8

[Peer]
PublicKey = o98XCmRcyP+by2GUzpPkPD+6HtNQkCl7qRmXZlizsDA=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 95.50.164.18:51820
PersistentKeepalive = 25
`

// TestImportProducesFlagsProvisionAccepts holds the two halves of an import
// together. wgconf turns a file into flags; provision parses them. Neither
// package can see the other's idea of what a peer specification is, so a change
// to either side would otherwise be found by somebody importing a real file.
func TestImportProducesFlagsProvisionAccepts(t *testing.T) {
	c, err := wgconf.Parse(strings.NewReader(demoConf))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	argv, err := c.ProvisionArgs("grota-gw")
	if err != nil {
		t.Fatalf("ProvisionArgs: %v", err)
	}

	seen := false
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] != "-peer" {
			continue
		}
		seen = true
		p, err := ParsePeerSpec(argv[i+1])
		if err != nil {
			t.Fatalf("provision would reject the peer this produced: %v", err)
		}
		if p.Label != "grota-gw" {
			t.Errorf("label = %q", p.Label)
		}
		if len(p.AllowedIPs) != 2 {
			t.Errorf("allowed-ips = %v, want both halves of a full tunnel", p.AllowedIPs)
		}
	}
	if !seen {
		t.Fatal("no -peer flag was produced at all")
	}
}

// TestFromConfAgreesWithTheFlags holds the window's path and the command's
// together. `wg-hem import` goes file -> flags -> PeerSpec, so that provision's
// own flags can be appended after a --; the window goes file -> PeerSpec
// directly, having no flags to append. Two paths to one value is two places for
// it to be wrong, so this checks they produce the same peer.
func TestFromConfAgreesWithTheFlags(t *testing.T) {
	c, err := wgconf.Parse(strings.NewReader(demoConf))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	direct, err := FromConf(c, "grota-gw")
	if err != nil {
		t.Fatalf("FromConf: %v", err)
	}

	argv, err := c.ProvisionArgs("grota-gw")
	if err != nil {
		t.Fatalf("ProvisionArgs: %v", err)
	}
	var viaFlags PeerSpec
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "-peer" {
			if viaFlags, err = ParsePeerSpec(argv[i+1]); err != nil {
				t.Fatalf("ParsePeerSpec: %v", err)
			}
		}
	}

	if len(direct.Peers) != 1 {
		t.Fatalf("FromConf produced %d peers, want 1", len(direct.Peers))
	}
	got := direct.Peers[0]
	if got.Label != viaFlags.Label {
		t.Errorf("label: direct %q, via flags %q", got.Label, viaFlags.Label)
	}
	if string(got.PubKey) != string(viaFlags.PubKey) {
		t.Error("the two paths produced different public keys")
	}
	if got.Endpoint.String() != viaFlags.Endpoint.String() {
		t.Errorf("endpoint: direct %q, via flags %q", got.Endpoint, viaFlags.Endpoint)
	}
	if fmt.Sprint(got.AllowedIPs) != fmt.Sprint(viaFlags.AllowedIPs) {
		t.Errorf("allowed-ips: direct %v, via flags %v", got.AllowedIPs, viaFlags.AllowedIPs)
	}
	if got.Keepalive != viaFlags.Keepalive {
		t.Errorf("keepalive: direct %d, via flags %d", got.Keepalive, viaFlags.Keepalive)
	}

	// And the rest of the configuration, which the flags path carries as
	// separate flags and this one carries as fields.
	if len(direct.Addrs) != len(c.Addresses) {
		t.Errorf("addresses = %v, want %v", direct.Addrs, c.Addresses)
	}
	if len(direct.DNS) != len(c.DNS) {
		t.Errorf("dns = %v, want %v", direct.DNS, c.DNS)
	}
}

// A peer with no name cannot be stored usefully, and the refusal has to arrive
// before a passphrase is asked for rather than after.
func TestFromConfNeedsAName(t *testing.T) {
	c, err := wgconf.Parse(strings.NewReader(demoConf))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FromConf(c, "   "); err == nil {
		t.Fatal("accepted a peer with no name")
	}
}
