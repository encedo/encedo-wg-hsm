package wgconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The file a person is actually handed. Kept verbatim rather than reduced,
// because what is being tested is that an ordinary client configuration goes in
// without anybody editing it first.
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

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTranslatesADemoConfiguration(t *testing.T) {
	c, err := ParseFile(write(t, demoConf))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	argv, err := c.ProvisionArgs("grota-gw")
	if err != nil {
		t.Fatalf("provisionArgs: %v", err)
	}
	got := strings.Join(argv, " ")
	want := "-address 192.168.2.2/32 -dns 8.8.8.8 -peer " +
		"label=grota-gw,pubkey=o98XCmRcyP+by2GUzpPkPD+6HtNQkCl7qRmXZlizsDA=," +
		"endpoint=95.50.164.18:51820,allowed-ips=0.0.0.0/0,allowed-ips=::/0,keepalive=25"
	if got != want {
		t.Errorf("translated to:\n  %s\nwant:\n  %s", got, want)
	}

	// Whether provision actually accepts these flags is checked where provision
	// is - see TestImportProducesFlagsProvisionAccepts. It cannot be checked
	// here without this package knowing about that one, and the direction of
	// that dependency is the whole reason this package exists.
}

// TestImportDiscardsThePrivateKey is the guarantee the command exists to make.
// A key that has been in a text file is already out, and the device cannot
// accept one anyway - so it must not appear in what is sent onward, and nothing
// downstream should ever have the chance to use it.
func TestDiscardsThePrivateKey(t *testing.T) {
	c, err := ParseFile(write(t, demoConf))
	if err != nil {
		t.Fatal(err)
	}
	argv, err := c.ProvisionArgs("peer")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range argv {
		if strings.Contains(a, "kOk30xyXpohscPIXf1WuFquKdgd1pWeJrsdTsXs50XQ=") {
			t.Fatalf("the private key from the file reached provision: %q", a)
		}
		if strings.Contains(strings.ToLower(a), "privatekey") {
			t.Fatalf("the private key was carried across: %q", a)
		}
	}
}

// TestRefusesWhatItCannotHonour. Each of these could be dropped silently
// and each would change what the tunnel does, which is the one thing an import
// must not do quietly.
func TestRefusesWhatItCannotHonour(t *testing.T) {
	cases := []struct {
		name, body, wants string
	}{
		{
			"a pre-shared key",
			demoConf + "PresharedKey = uZ3xY1n1p8sVUj6b2b2vTf1ZQ2m0Q5oQ3n8oV1sO1cE=\n",
			"psk generate",
		},
		{
			"a second peer",
			demoConf + "\n[Peer]\nPublicKey = o98XCmRcyP+by2GUzpPkPD+6HtNQkCl7qRmXZlizsDA=\n",
			"2 [Peer] sections",
		},
		{
			"a wg-quick hook",
			demoConf + "\n[Interface]\nPostUp = iptables -A FORWARD -j ACCEPT\n",
			"wg-quick directive",
		},
		{
			"a search domain in DNS",
			strings.Replace(demoConf, "DNS = 8.8.8.8", "DNS = example.com", 1),
			"search domains",
		},
		{
			"no address",
			strings.Replace(demoConf, "Address = 192.168.2.2/32\n", "", 1),
			"no Address",
		},
		{
			"no peer key",
			strings.Replace(demoConf, "PublicKey = o98XCmRcyP+by2GUzpPkPD+6HtNQkCl7qRmXZlizsDA=\n", "", 1),
			"no PublicKey",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFile(write(t, tc.body))
			if err == nil {
				t.Fatalf("accepted %s without a word", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refused, but not legibly: %v", err)
			}
		})
	}
}
