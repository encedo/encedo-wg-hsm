package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

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

// newImportUI is a window with the stand-in behind it, at its compact height.
func newImportUI(t *testing.T) *ui {
	t.Helper()
	a := test.NewApp()
	t.Cleanup(a.Quit)
	u := &ui{app: a, sess: newFakeSession()}
	t.Cleanup(func() { u.sess.Close() })
	u.win = test.NewWindow(nil)
	t.Cleanup(u.win.Close)
	u.build()
	u.resizeForContent()
	return u
}

// fits fails when the dialogue on top needs more than the window has, in
// either direction. The window does not resize, and a dialogue is drawn
// inside it: too wide is cut off at the right, too tall draws rows over each
// other.
func fits(t *testing.T, u *ui, what string) {
	t.Helper()
	top := u.win.Canvas().Overlays().Top()
	if top == nil {
		t.Fatalf("%s did not open", what)
	}
	need, have := top.MinSize(), u.win.Canvas().Size()
	if need.Width > windowWidth {
		t.Errorf("%s needs %.1f of width and the window is %d", what, need.Width, windowWidth)
	}
	if need.Height > have.Height {
		t.Errorf("%s needs %.1f of height and the window is %.1f", what, need.Height, have.Height)
	}
}

// The preview was a monospace block wider than the dialogue, cut off at the
// right; now it is sentences that wrap. Measured with the longest status line
// it can show, since that is the row that arrives while somebody is watching.
func TestImportPreviewFits(t *testing.T) {
	u := newImportUI(t)
	p := u.previewImport("a-rather-long-name-for-a-head-office-tunnel.conf", strings.NewReader(demoConf))
	p.status.SetText("That passphrase was not accepted - check it and try again.")
	fits(t, u, "the preview")
}

// Pressing Import with no passphrase used to close the preview and leave a
// sentence on the main screen, which read as nothing having happened. It has to
// stay open and say what is missing.
func TestImportWithoutAPassphraseStaysOpenAndSaysSo(t *testing.T) {
	u := newImportUI(t)
	p := u.previewImport("office.conf", strings.NewReader(demoConf))

	test.Tap(p.importBtn)

	if !strings.Contains(p.status.Text, "passphrase") {
		t.Errorf("the preview says %q, not that the passphrase is missing", p.status.Text)
	}
	if top := u.win.Canvas().Overlays().Top(); top == nil || !top.Visible() {
		t.Error("the preview closed")
	}
}

// A successful import ends on the key and nothing else: the server already has
// this peer, and the key is the one thing in its entry that moved.
func TestImportEndsOnTheNewKeyAlone(t *testing.T) {
	u := newImportUI(t)
	p := u.previewImport("office.conf", strings.NewReader(demoConf))
	p.pass.SetText("secret")

	test.Tap(p.importBtn)

	// The import runs off the drawing goroutine and comes back through fyne.Do;
	// the test app runs that immediately, but the goroutine has to get there.
	deadline := time.Now().Add(2 * time.Second)
	var top fyne.CanvasObject
	for time.Now().Before(deadline) {
		if top = u.win.Canvas().Overlays().Top(); top != nil && hasText(top, "Tell the server") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if top == nil || !hasText(top, "Tell the server") {
		t.Fatalf("no handoff after a successful import; status says %q", p.status.Text)
	}
	if !hasText(top, "0000stand-in-public-key-not-a-real-one0000=") {
		t.Error("the handoff does not show the new public key")
	}
	for _, gone := range []string{"[Peer]", "AllowedIPs"} {
		if hasText(top, gone) {
			t.Errorf("the handoff still shows %q", gone)
		}
	}
	fits(t, u, "the handoff")
}

// hasText says whether any label under o reads s.
func hasText(o fyne.CanvasObject, s string) bool {
	found := false
	var walk func(fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if found || o == nil {
			return
		}
		switch v := o.(type) {
		case *canvas.Text:
			found = strings.Contains(v.Text, s)
		case *widget.Label:
			found = strings.Contains(v.Text, s)
		}
		if c, ok := o.(*fyne.Container); ok {
			for _, child := range c.Objects {
				walk(child)
			}
		}
		if w, ok := o.(fyne.Widget); ok {
			for _, child := range test.WidgetRenderer(w).Objects() {
				walk(child)
			}
		}
	}
	walk(o)
	return found
}
