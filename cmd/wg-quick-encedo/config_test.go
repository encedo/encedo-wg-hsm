package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validKID = "0123456789abcdef0123456789abcdef"

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg1.conf")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig(writeConfig(t, `
[Interface]
Address = 10.1.1.5/24
HEM_URL = https://my.ence.do
HEM_KID = `+validKID+`
DNS = 10.1.1.1, 10.1.1.2
MTU = 1380

[Peer]
PublicKey = i14L0qgxykUZL7GVV2x/hBXwuvbcXbcv+TIEp60Pk0M=
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.1.1.0/24, 192.168.0.0/16
PersistentKeepalive = 25
`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	if got := cfg.Interface.Address.String(); got != "10.1.1.5/24" {
		t.Errorf("Address = %s, want 10.1.1.5/24", got)
	}
	if cfg.Interface.MTU != 1380 {
		t.Errorf("MTU = %d, want 1380", cfg.Interface.MTU)
	}
	if len(cfg.Interface.DNS) != 2 {
		t.Errorf("DNS = %v, want two servers", cfg.Interface.DNS)
	}
	if len(cfg.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(cfg.Peers))
	}
	if len(cfg.Peers[0].AllowedIPs) != 2 {
		t.Fatalf("AllowedIPs = %v, want two prefixes", cfg.Peers[0].AllowedIPs)
	}
	if got := cfg.Peers[0].AllowedIPs[1].String(); got != "192.168.0.0/16" {
		t.Errorf("AllowedIPs[1] = %s, want 192.168.0.0/16", got)
	}
	if cfg.Peers[0].PersistentKeepalive != 25 {
		t.Errorf("PersistentKeepalive = %d, want 25", cfg.Peers[0].PersistentKeepalive)
	}
}

// A prefix is parsed here rather than at route-installation time: the failure
// otherwise arrives with the interface half up and the routes partly written.
func TestParseConfigRejectsMalformedPrefixes(t *testing.T) {
	cases := map[string]string{
		"AllowedIPs out of range": "AllowedIPs = 10.1.1.0/33",
		"AllowedIPs not a prefix": "AllowedIPs = 10.1.1.0",
		"AllowedIPs nonsense":     "AllowedIPs = lan",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig(writeConfig(t, `
[Interface]
Address = 10.1.1.5/24
HEM_URL = https://my.ence.do
HEM_KID = `+validKID+`

[Peer]
PublicKey = i14L0qgxykUZL7GVV2x/hBXwuvbcXbcv+TIEp60Pk0M=
`+line+`
`))
			if err == nil {
				t.Fatalf("%q was accepted", line)
			}
			if !strings.Contains(err.Error(), "AllowedIPs") {
				t.Errorf("error does not name the offending field: %v", err)
			}
		})
	}
}

func TestParseConfigRejectsAMalformedAddress(t *testing.T) {
	_, err := ParseConfig(writeConfig(t, `
[Interface]
Address = 10.1.1.5
HEM_URL = https://my.ence.do
HEM_KID = `+validKID+`
`))
	if err == nil {
		t.Fatal("an address without a prefix length was accepted")
	}
}

// The whole point of the client is that no key material sits in the file, so a
// PrivateKey is not ignored — it is refused.
func TestParseConfigRefusesAPrivateKey(t *testing.T) {
	_, err := ParseConfig(writeConfig(t, `
[Interface]
Address = 10.1.1.5/24
PrivateKey = 6HqPBqBLKRKS7ZbcuC7HRhsQx5N0kaMBiZQMHIQtOFo=
HEM_URL = https://my.ence.do
HEM_KID = `+validKID+`
`))
	if err == nil {
		t.Fatal("a config carrying a PrivateKey was accepted")
	}
	if !strings.Contains(err.Error(), "PrivateKey") {
		t.Errorf("error does not name PrivateKey: %v", err)
	}
}

func TestParseConfigRequiresTheHEMFields(t *testing.T) {
	cases := map[string]string{
		"no HEM_URL": "[Interface]\nAddress = 10.1.1.5/24\nHEM_KID = " + validKID + "\n",
		"no HEM_KID": "[Interface]\nAddress = 10.1.1.5/24\nHEM_URL = https://my.ence.do\n",
		"short KID":  "[Interface]\nAddress = 10.1.1.5/24\nHEM_URL = https://my.ence.do\nHEM_KID = abcd\n",
		"KID not hex": "[Interface]\nAddress = 10.1.1.5/24\nHEM_URL = https://my.ence.do\nHEM_KID = " +
			strings.Repeat("z", 32) + "\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig(writeConfig(t, body)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestParseConfigRequiresAKeyForEachPeer(t *testing.T) {
	_, err := ParseConfig(writeConfig(t, `
[Interface]
Address = 10.1.1.5/24
HEM_URL = https://my.ence.do
HEM_KID = `+validKID+`

[Peer]
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.1.1.0/24
`))
	if err == nil {
		t.Fatal("a peer with neither PublicKey nor HEM_KID was accepted")
	}
}

// runtimePeers is the seam between the parsed file and the routing decision;
// everything else about a peer stays on this side of it.
func TestRuntimePeersCarriesEndpointAndPrefixes(t *testing.T) {
	cfg, err := ParseConfig(writeConfig(t, `
[Interface]
Address = 10.1.1.5/24
HEM_URL = https://my.ence.do
HEM_KID = `+validKID+`

[Peer]
HEM_KID = `+validKID+`
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	peers := runtimePeers(cfg.Peers)
	if len(peers) != 1 {
		t.Fatalf("runtimePeers = %v, want one", peers)
	}
	if peers[0].Endpoint != "203.0.113.1:51820" {
		t.Errorf("Endpoint = %q", peers[0].Endpoint)
	}
	if len(peers[0].AllowedIPs) != 1 || peers[0].AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Errorf("AllowedIPs = %v, want [0.0.0.0/0]", peers[0].AllowedIPs)
	}
}
