package main

import (
	"net/netip"
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
func TestImportWarningSaysWhatBecomesOfThePrivateKey(t *testing.T) {
	c := parseDemo(t)
	got := importWarning(c)
	if !strings.Contains(got, "not imported") {
		t.Errorf("the warning does not say the private key is left behind:\n%s", got)
	}
	if !strings.Contains(got, "delete the file") {
		t.Errorf("the warning does not say the old key is still live:\n%s", got)
	}
	// And nothing on the screen prints the key itself. It is a secret that is
	// already compromised, which is not a reason to put it on a screen.
	if strings.Contains(importSummary(c)+got, "kOk30xyXpohscPIXf1WuFquKdgd1pWeJrsdTsXs50XQ=") {
		t.Errorf("the preview prints the private key")
	}
}

// A file with no private key in it - somebody's already-migrated config, or one
// written by hand - must not be told that a key was discarded.
func TestImportWarningIsSilentWhenThereWasNoPrivateKey(t *testing.T) {
	body := strings.Replace(demoConf, "PrivateKey = kOk30xyXpohscPIXf1WuFquKdgd1pWeJrsdTsXs50XQ=\n", "", 1)
	c, err := wgconf.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if got := importWarning(c); strings.Contains(got, "not imported") {
		t.Errorf("claimed to have discarded a key that was never there:\n%s", got)
	}
}

func TestImportSummarySaysWhereAndHowMuch(t *testing.T) {
	got := importSummary(parseDemo(t))
	for _, want := range []string{
		"Connects to 95.50.164.18.",
		"Your address in the tunnel: 192.168.2.2.",
		"All your traffic goes through the tunnel.",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary does not say %q:\n%s", want, got)
		}
	}
}

func TestRoutesSentence(t *testing.T) {
	p := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	cases := []struct {
		in   []netip.Prefix
		want string
	}{
		{p("0.0.0.0/0", "::/0"), "All your traffic"},
		{p("::/0"), "All your traffic"},
		{p("10.0.0.0/24"), "Only 10.0.0.0/24 goes"},
		{p("10.0.0.0/24", "10.1.0.0/24"), "Only 10.0.0.0/24 and 10.1.0.0/24 go"},
		{p("10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24"), "Only 10.0.0.0/24 and 2 more networks"},
		{nil, "No traffic"},
	}
	for _, tc := range cases {
		if got := routesSentence(tc.in); !strings.HasPrefix(got, tc.want) {
			t.Errorf("%v: %q, want it to start %q", tc.in, got, tc.want)
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

// The window does not resize, and the preview is drawn inside it. It was a
// monospace block wider than the dialogue, cut off at the right; now it is
// sentences that wrap, and this holds the dialogue to the window.
func TestImportPreviewFits(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	u := &ui{app: a, sess: newFakeSession()}
	defer u.sess.Close()
	u.win = test.NewWindow(nil)
	defer u.win.Close()
	u.build()
	u.resizeForContent()

	u.previewImport("a-rather-long-name-for-a-head-office-tunnel.conf", strings.NewReader(demoConf))

	top := u.win.Canvas().Overlays().Top()
	if top == nil {
		t.Fatal("the preview did not open")
	}
	if need := top.MinSize().Width; need > windowWidth {
		t.Errorf("the preview needs %.1f of width and the window is %d", need, windowWidth)
	}
}
