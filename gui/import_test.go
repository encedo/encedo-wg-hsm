package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"

	"github.com/encedo/encedo-wg-hsm/internal/wgconf"
)

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

func parseDemo(t *testing.T) *wgconf.Conf {
	t.Helper()
	c, err := wgconf.Parse(strings.NewReader(demoConf))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return c
}

// The preview is the screen that makes the import believable, and the sentence
// it must not omit is the one about the key it is leaving behind. A tool that
// discards a private key silently looks exactly like a tool that kept it.
func TestImportSummarySaysWhatBecomesOfThePrivateKey(t *testing.T) {
	got := importSummary(parseDemo(t))
	if !strings.Contains(got, "NOT imported") {
		t.Errorf("the summary does not say the private key is left behind:\n%s", got)
	}
	if !strings.Contains(got, "delete the file") {
		t.Errorf("the summary does not say the old key is still live:\n%s", got)
	}
	// And it must not print the key itself. It is a secret that is already
	// compromised, which is not a reason to put it on a screen.
	if strings.Contains(got, "kOk30xyXpohscPIXf1WuFquKdgd1pWeJrsdTsXs50XQ=") {
		t.Errorf("the summary prints the private key:\n%s", got)
	}
}

// A file with no private key in it - somebody's already-migrated config, or one
// written by hand - must not be told that a key was discarded.
func TestImportSummaryIsSilentWhenThereWasNoPrivateKey(t *testing.T) {
	body := strings.Replace(demoConf, "PrivateKey = kOk30xyXpohscPIXf1WuFquKdgd1pWeJrsdTsXs50XQ=\n", "", 1)
	c, err := wgconf.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if got := importSummary(c); strings.Contains(got, "NOT imported") {
		t.Errorf("claimed to have discarded a key that was never there:\n%s", got)
	}
}

func TestImportSummaryShowsWhatWillBeStored(t *testing.T) {
	got := importSummary(parseDemo(t))
	for _, want := range []string{
		"192.168.2.2/32",
		"8.8.8.8",
		"o98XCmRcyP+by2GUzpPkPD+6HtNQkCl7qRmXZlizsDA=",
		"95.50.164.18:51820",
		"0.0.0.0/0",
		"25s",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary does not mention %q:\n%s", want, got)
		}
	}
}

func TestPeerNameFromAFileName(t *testing.T) {
	cases := map[string]string{
		"head-office.conf": "head-office",
		"wg0.conf":         "wg0",
		"vpn":              "vpn",
		// The peer specification is comma-separated key=value, so either
		// character in a name would split it into something else further down.
		"hq,backup.conf": "hq backup",
		"a=b.conf":       "a b",
		".conf":          ".conf",
	}
	for file, want := range cases {
		if got := peerNameFrom(file); got != want {
			t.Errorf("peerNameFrom(%q) = %q, want %q", file, got, want)
		}
	}
}

func TestValidPeerName(t *testing.T) {
	if err := validPeerName("head office"); err != nil {
		t.Errorf("refused an ordinary name: %v", err)
	}
	for _, bad := range []string{"", "   ", "a,b", "a=b"} {
		if err := validPeerName(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// The window does not resize, and these dialogues are drawn inside it. The
// preview is the widest of them because it lists addresses and a base64 key.
func TestImportPreviewFits(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	// A conf with everything filled in, which is the widest the summary gets.
	c := parseDemo(t)
	summary := importSummary(c)

	for _, line := range strings.Split(summary, "\n") {
		// The base64 peer key is 44 characters and cannot be shortened without
		// making it useless to compare against a server, so it sets the floor.
		// What must not happen is a line materially longer than that one.
		if len(line) > 62 {
			t.Errorf("summary line is %d characters and will be cut:\n  %s", len(line), line)
		}
	}
}
