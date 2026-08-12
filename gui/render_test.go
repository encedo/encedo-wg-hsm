package main

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fyne.io/fyne/v2"
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
func TestRenderStates(t *testing.T) {
	dir := os.Getenv("WG_GUI_SHOTS")
	if dir == "" {
		t.Skip("set WG_GUI_SHOTS to a directory to render the interface")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("shot directory: %v", err)
	}

	now := time.Now()
	cases := []struct {
		name     string
		event    Event
		advanced bool
	}{
		{"1-no-module", Event{State: NoModule}, false},
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
			State: Connected, Peer: "head office",
			ExpiresAt:     now.Add(58 * time.Minute),
			LastHandshake: now.Add(-9 * time.Second),
			Rx:            902_144, Tx: 331_008,
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := test.NewApp()
			defer a.Quit()

			u := &ui{app: a, sess: newFakeSession()}
			defer u.sess.Close()

			u.win = test.NewWindow(nil)
			defer u.win.Close()
			u.build()

			if tc.advanced {
				u.advBox.SetChecked(true)
			}
			u.render(tc.event)
			u.win.Resize(fyne.NewSize(420, 400))

			img := u.win.Canvas().Capture()
			path := filepath.Join(dir, tc.name+".png")
			f, err := os.Create(path)
			if err != nil {
				t.Fatalf("create %s: %v", path, err)
			}
			defer f.Close()
			if err := png.Encode(f, img); err != nil {
				t.Fatalf("encode %s: %v", path, err)
			}
			t.Logf("wrote %s (%v)", path, img.Bounds().Size())
		})
	}
}
