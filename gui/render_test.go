package main

import (
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/test"
)

// TestRenderStates draws each state to a PNG through Fyne's test driver, which
// rasterises a canvas with no display attached. It is here so the interface can
// be looked at while it is being designed, rather than only run — the states
// that matter are awkward to reach by hand, and comparing them side by side is
// the only way to see whether the hierarchy holds across all of them.
//
// Set WG_GUI_SHOTS to a directory to keep the images:
//
//	WG_GUI_SHOTS=/tmp/shots go test -run TestRenderStates ./...
//
// scales are the ones a real display asks for: unscaled, the fractional step
// GNOME offers, and the doubling a 4K panel uses.
var scales = []float32{1, 1.5, 2}

// shotTheme picks the scheme to render in. The test driver has one variant and
// it is not a choice anybody makes, so without this only half the palette is
// ever looked at — and the half that goes unseen is the one somebody eventually
// runs into by accident:
//
//	WG_GUI_SHOTS=/tmp/shots WG_GUI_THEME=light go test -run TestRenderStates
func shotTheme(t *testing.T) encedoTheme {
	t.Helper()
	th, err := themeFor(os.Getenv("WG_GUI_THEME"))
	if err != nil {
		t.Fatalf("WG_GUI_THEME: %v", err)
	}
	return th
}

// shotDir is where images go, or "" to skip. Creating the directory belongs
// here rather than in one of the three tests that write into it — it was in one,
// and the other two failed on a path nobody had made yet.
func shotDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("WG_GUI_SHOTS")
	if dir == "" {
		return ""
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("shot directory: %v", err)
	}
	return dir
}

func writeShot(t *testing.T, dir, name string, scale float32, img image.Image) {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("%s@%gx.png", name, scale))
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
}

func TestRenderStates(t *testing.T) {
	dir := shotDir(t)
	if dir == "" {
		t.Skip("set WG_GUI_SHOTS to a directory to render the interface")
	}

	now := time.Now()
	cases := []struct {
		name     string
		event    Event
		advanced bool
	}{
		{"1-no-module", Event{State: NoModule, HEM: "https://my.ence.do"}, false},
		{"2-ready", Event{State: Ready}, false},
		{"3-connecting", Event{State: Connecting}, false},
		{"4-connected", Event{
			State: Connected, Peer: "head office",
			ExpiresAt:     now.Add(7*time.Hour + 32*time.Minute),
			LastHandshake: now.Add(-41 * time.Second),
			Rx:            4_812_310, Tx: 1_204_770,
		}, false},
		{"5-failover", Event{
			State: Connected, Peer: "backup site",
			ExpiresAt:     now.Add(6*time.Hour + 5*time.Minute),
			LastHandshake: now,
			Rx:            5_1290, Tx: 33_400,
			Notice: `Moved to "backup site" — "head office" stopped answering`,
		}, false},
		{"6-expired", Event{
			State:  Ready,
			Notice: "the session has expired — connect again to continue",
		}, false},
		{"8-expiring", Event{
			State: Connected, Peer: "head office",
			ExpiresAt:     now.Add(3 * time.Minute),
			LastHandshake: now.Add(-12 * time.Second),
			Rx:            9_112_004, Tx: 2_004_881,
		}, false},
		{"7-advanced", Event{
			State: Connected, Peer: "head office", HEM: "https://epa.acme.example",
			ExpiresAt:     now.Add(58 * time.Minute),
			LastHandshake: now.Add(-9 * time.Second),
			Rx:            902_144, Tx: 331_008,
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := test.NewApp()
			defer a.Quit()
			a.Settings().SetTheme(shotTheme(t))

			u := &ui{app: a, sess: newFakeSession()}
			defer u.sess.Close()

			u.win = test.NewWindow(nil)
			defer u.win.Close()
			u.build()

			if tc.advanced {
				u.advBox.SetChecked(true)
			}
			u.render(tc.event)
			u.resizeForContent()

			// Render at each scale a real display might ask for. Nothing here
			// is in pixels, so this should change the size of the image and
			// nothing else — if a layout breaks at 2x, it breaks because
			// something was measured in the wrong units.
			for _, scale := range scales {
				if c, ok := u.win.Canvas().(test.WindowlessCanvas); ok {
					c.SetScale(scale)
				}
				// Resize to a different size first: the driver lays out on a
				// size change, and asking for the size it already has is a
				// no-op, so a window whose children changed visibility would be
				// captured with the layout it had before they did.
				u.resizeForContent()
				writeShot(t, dir, tc.name, scale, u.win.Canvas().Capture())
			}
			t.Logf("wrote %s at %v", tc.name, scales)
		})
	}
}

// TestRenderIcon draws the application mark at the sizes a dock, a task bar and
// a tray actually ask for. A mark that only works at 64 px is a mark nobody sees
// working, since every place it appears is smaller than that.
func TestRenderIcon(t *testing.T) {
	dir := shotDir(t)
	if dir == "" {
		t.Skip("set WG_GUI_SHOTS to a directory to render the icon")
	}
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(shotTheme(t))

	for _, px := range []float32{128, 64, 32, 16} {
		img := canvas.NewImageFromResource(appIcon)
		img.FillMode = canvas.ImageFillContain
		w := test.NewWindow(img)
		// Without this the window pads the image, and at 16 px the padding is
		// most of the icon — measuring the padding rather than the mark.
		w.SetPadded(false)
		w.Resize(fyne.NewSize(px, px))
		writeShot(t, dir, fmt.Sprintf("icon-%gpx", px), 1, w.Canvas().Capture())
		w.Close()
	}
}

// TestRenderScenario walks the same scenario the -scenario flag plays and
// captures a frame per step. It is the flow rather than the states: a set of
// screens each of which is fine on its own can still be a sequence that makes
// no sense, and that is not visible one screen at a time.
func TestRenderScenario(t *testing.T) {
	dir := shotDir(t)
	if dir == "" {
		t.Skip("set WG_GUI_SHOTS to a directory to render the scenario")
	}
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(shotTheme(t))

	u := &ui{app: a, sess: newFakeSession()}
	defer u.sess.Close()
	u.win = test.NewWindow(nil)
	defer u.win.Close()
	u.build()
	u.resizeForContent()

	for i, s := range scenario {
		s.do(u.sess)

		// Drain for a fixed window rather than waiting for quiet: a connected
		// session emits continuously, so quiescence never arrives. The last
		// event in the window is the settled state.
		deadline := time.After(1600 * time.Millisecond)
		var last Event
		draining := true
		for draining {
			select {
			case e, ok := <-u.sess.Events():
				if !ok {
					draining = false
					break
				}
				last = e
			case <-deadline:
				draining = false
			}
		}
		u.render(last)
		u.renderCountdown(last)
		writeShot(t, dir, fmt.Sprintf("flow-%d", i), 1, u.win.Canvas().Capture())
		t.Logf("step %d: %s -> %s", i, s.what, last.State)
	}
}
