package main

import (
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
)

// TestCompactHeightFits is the guard on the one number in this window that has
// been wrong twice.
//
// The window is a fixed height by choice - it must not move while somebody is
// reading it - and a border layout asked for the impossible does not complain.
// It gives the header its minimum, places the footer against it, and draws the
// rows that do not fit over the top of each other. So a row added anywhere, or
// a font that measures differently, silently produces overlapping text rather
// than a failure, and it is found by looking rather than by testing.
//
// This measures instead. Every state the window can be in with the panel closed
// has to fit in compactHeight, including the notice, since a notice arrives
// unannounced and the window will not grow to meet it.
func TestCompactHeightFits(t *testing.T) {
	now := time.Now()
	long := `Moved to "backup site" - "head office" stopped answering`

	// Each state, and each state that can carry a notice carrying one, because
	// the notice is the row that pushes a state over the edge.
	cases := []struct {
		name  string
		event Event
	}{
		{"no module", Event{State: NoModule, HEM: "https://my.ence.do"}},
		{"ready", Event{State: Ready}},
		{"ready with a notice", Event{State: Ready, Notice: "the session has expired - connect again to continue"}},
		{"connecting", Event{State: Connecting}},
		{"connecting with a notice", Event{State: Connecting, Notice: "Connecting to https://my.ence.do..."}},
		{"connected", Event{
			State: Connected, Peer: "head office",
			Addrs:         []string{"10.99.0.7/32"},
			ExpiresAt:     now.Add(7 * time.Hour),
			LastHandshake: now,
			Rx:            4_812_310, Tx: 1_204_770,
		}},
		{"connected with a notice", Event{
			State: Connected, Peer: "backup site",
			Addrs:         []string{"10.99.0.7/32"},
			ExpiresAt:     now.Add(7 * time.Hour),
			LastHandshake: now,
			Rx:            4_812_310, Tx: 1_204_770,
			Notice: long,
		}},
		{"connected with several addresses", Event{
			State: Connected, Peer: "head office",
			Addrs:         []string{"10.99.0.7/32", "fd00::7/128"},
			ExpiresAt:     now.Add(7 * time.Hour),
			LastHandshake: now,
		}},
		{"disconnecting", Event{State: Disconnecting}},
		{"closed", Event{State: Ended}},
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

			u.render(tc.event)
			u.resizeForContent()

			if need := u.win.Content().MinSize().Height; need > compactHeight {
				t.Errorf("needs %.1f but compactHeight is %d - rows will be drawn over each other",
					need, compactHeight)
			}
		})
	}
}

// TestAdvancedHeightFits is the same guard on the open panel, which is measured
// rather than constant - the check is that the measurement is actually applied,
// so a panel that grows takes the window with it.
func TestAdvancedHeightFits(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	u := &ui{app: a, sess: newFakeSession()}
	defer u.sess.Close()
	u.win = test.NewWindow(nil)
	defer u.win.Close()
	u.build()

	u.advBox.SetChecked(true)
	u.render(Event{State: Connected, Peer: "head office", Addrs: []string{"10.99.0.7/32"}})
	u.resizeForContent()

	need := u.win.Content().MinSize().Height
	if got := u.win.Canvas().Size().Height; need > got {
		t.Errorf("panel needs %.1f and the window is %.1f", need, got)
	}
}

// Renewing asks in a dialogue rather than on the main screen, and this is why.
// The connected screen is already the tallest this window gets; the window
// cannot grow past compactHeight, so anything that does not fit is drawn over
// something else. Measured: a "Stay connected" button alone put it forty points
// over, and a passphrase field beside it ninety.
//
// The guard is that the connected screen stays the size it is. If somebody
// later moves the renewal controls back onto it, TestCompactHeightFits is what
// catches them - this test records the measurement that sent them to a dialogue
// in the first place.
func TestRenewingDoesNotGrowTheConnectedScreen(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	u := &ui{app: a, sess: newFakeSession()}
	defer u.sess.Close()
	u.win = test.NewWindow(nil)
	defer u.win.Close()
	u.build()

	now := time.Now()
	e := Event{
		State: Connected, Peer: "head office",
		Addrs:         []string{"10.99.0.7/32", "fd00::7/128"},
		ExpiresAt:     now.Add(7 * time.Hour),
		LastHandshake: now,
		Rx:            9_112_004, Tx: 2_004_881,
		Notice: "The session is ending. Renew it, or the tunnel closes.",
	}
	u.render(e)
	u.resizeForContent()
	before := u.win.Content().MinSize().Height

	// The state the warning puts the window in. Nothing about it may change the
	// screen's size: the offer is in a dialogue, not in the footer.
	u.warned = true
	u.compose(e)
	u.resizeForContent()

	if after := u.win.Content().MinSize().Height; after != before {
		t.Errorf("warning about the session changed the screen from %.1f to %.1f", before, after)
	}
	if before > compactHeight {
		t.Errorf("the connected screen needs %.1f and compactHeight is %d", before, compactHeight)
	}
}
