package main

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

func TestImportTranslatesADemoConfiguration(t *testing.T) {
	c, err := parseWireGuardConf(write(t, demoConf))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	argv, err := c.provisionArgs("grota-gw")
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

	// The flags it produces have to be the flags provision accepts, or the
	// translation is only correct against a reading of the other file. Parsing
	// the peer specification back is the cheapest way to hold the two together.
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] != "-peer" {
			continue
		}
		p, err := parsePeerSpec(argv[i+1])
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
}

// TestImportDiscardsThePrivateKey is the guarantee the command exists to make.
// A key that has been in a text file is already out, and the device cannot
// accept one anyway - so it must not appear in what is sent onward, and nothing
// downstream should ever have the chance to use it.
func TestImportDiscardsThePrivateKey(t *testing.T) {
	c, err := parseWireGuardConf(write(t, demoConf))
	if err != nil {
		t.Fatal(err)
	}
	argv, err := c.provisionArgs("peer")
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

// TestImportRefusesWhatItCannotHonour. Each of these could be dropped silently
// and each would change what the tunnel does, which is the one thing an import
// must not do quietly.
func TestImportRefusesWhatItCannotHonour(t *testing.T) {
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
			_, err := parseWireGuardConf(write(t, tc.body))
			if err == nil {
				t.Fatalf("accepted %s without a word", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refused, but not legibly: %v", err)
			}
		})
	}
}

// TestImportTakesTheFileInEitherPosition. Go's flag package stops at the first
// argument that is not a flag, so a file written before the flags left them
// unparsed - and the command then asked for a name it had already been given.
func TestImportTakesTheFileInEitherPosition(t *testing.T) {
	cases := [][]string{
		{"client.conf", "-name", "x", "-dry-run"},
		{"-name", "x", "client.conf", "-dry-run"},
		{"-dry-run", "client.conf", "-name", "x"},
		{"-name=x", "client.conf"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			ours, _ := splitAtDoubleDash(args)
			path, rest := takeFirstBareArg(ours)
			if path != "client.conf" {
				t.Fatalf("found the file as %q", path)
			}
			for _, r := range rest {
				if r == "client.conf" {
					t.Fatal("the file was left in the flags as well")
				}
			}
		})
	}
}

func TestImportPassesTheRestToProvision(t *testing.T) {
	ours, theirs := splitAtDoubleDash(
		[]string{"client.conf", "-name", "x", "--", "-session", "8", "-label", "laptop"})
	if got := strings.Join(theirs, " "); got != "-session 8 -label laptop" {
		t.Errorf("passthrough = %q", got)
	}
	if path, _ := takeFirstBareArg(ours); path != "client.conf" {
		t.Errorf("file = %q", path)
	}
}
