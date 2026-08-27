package main

import (
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
	if !seen {
		t.Fatal("no -peer flag was produced at all")
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
