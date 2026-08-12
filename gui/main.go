// Command gui is the skeleton of the graphical client: the flow, on a fake
// session, so it can be run on all three platforms before any of it touches a
// device. Nothing here talks to a HEM. See ../TODO.md, "A graphical client".
package main

import (
	_ "embed"

	"context"
	"flag"
	"fmt"
	"image/color"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type ui struct {
	app    fyne.App
	win    fyne.Window
	sess   *fakeSession
	hasTr  bool
	latest Event

	dot    *canvas.Circle
	status *widget.Label
	detail *widget.Label

	// fields is the middle of the window: what the tunnel is doing, as label
	// and value. It fills space that was empty with something true, and the
	// values are monospaced because that is the vernacular of the subject —
	// endpoints, byte counts, key identifiers — and the typeface the product
	// page uses for exactly the same reason.
	head     *fyne.Container
	fields   *fyne.Container
	fPeer    *widget.Label
	fMoved   *widget.Label
	fShake   *widget.Label
	fExpires *widget.Label

	noticeText *widget.Label
	warned     bool
	noticeBG   *canvas.Rectangle
	noticeBox  *fyne.Container

	pass    *widget.Entry
	action  *widget.Button
	adv     *fyne.Container
	advBox  *widget.Check
	advText *widget.Label
}

//go:embed icon.svg
var iconSVG []byte

// appIcon is the mark in the dock, the task bar and the tray. SVG rather than a
// bitmap so it is drawn at whatever size each of those asks for.
var appIcon = fyne.NewStaticResource("encedo-wg.svg", iconSVG)

func main() {
	// -scenario plays the life of a session end to end so somebody can watch it
	// once rather than learn which debug button produces which state.
	auto := flag.Bool("scenario", false, "play a scripted session instead of waiting for input")
	flag.Parse()

	a := app.New()
	a.SetIcon(appIcon)
	a.Settings().SetTheme(encedoTheme{})
	u := &ui{app: a, win: a.NewWindow("encedo-wg"), sess: newFakeSession()}
	u.build()
	u.installTray()
	u.installCloseIntercept()

	go u.consume()
	go u.tickCountdown()
	if *auto {
		go u.sess.play(func(what string) {
			fyne.Do(func() { u.status.SetText(u.status.Text) })
			println("scenario:", what)
		})
	}

	// Fixed: there is nothing here that benefits from more room, and a window
	// of three states stretched across a large display reads as a mistake. It
	// also removes the maximise button, which is the honest signal — a control
	// that does nothing useful is worse than no control.
	//
	// The size accommodates the advanced panel with its debug rows open, so
	// nothing is clipped when it is; the alternative, sizing to content, would
	// make the window jump every time the state changed.
	u.win.SetFixedSize(true)
	u.win.Resize(fyne.NewSize(630, 600))
	u.win.ShowAndRun()
}

func (u *ui) build() {
	// The dot carries the state before any word is read. That is the one thing
	// this interface has to do well: somebody restoring the window from the tray
	// should know where they stand without parsing a sentence.
	u.dot = canvas.NewCircle(color.Transparent)
	u.status = widget.NewLabel("")
	u.status.TextStyle = fyne.TextStyle{Bold: true}
	u.detail = widget.NewLabel("")
	u.detail.Wrapping = fyne.TextWrapWord

	mono := func() *widget.Label {
		l := widget.NewLabel("")
		l.TextStyle = fyne.TextStyle{Monospace: true}
		return l
	}
	u.fPeer, u.fMoved, u.fShake, u.fExpires = mono(), mono(), mono(), mono()
	u.fields = container.New(layout.NewFormLayout(),
		widget.NewLabel("peer"), u.fPeer,
		widget.NewLabel("transferred"), u.fMoved,
		widget.NewLabel("last handshake"), u.fShake,
		widget.NewLabel("session ends"), u.fExpires,
	)
	u.fields.Hide()

	// One line, ellipsised. A wrapping label inside a background box cannot be
	// sized reliably — the height is computed before the width is known, so long
	// text is clipped rather than wrapped. Deciding that the in-window notice is
	// a single line removes the gamble, and it is better as an alert anyway: the
	// full text goes to the system notification, which is where prose belongs.
	u.noticeText = widget.NewLabel("")
	u.noticeText.Wrapping = fyne.TextWrapOff
	u.noticeText.Truncation = fyne.TextTruncateEllipsis
	u.noticeBG = canvas.NewRectangle(color.Transparent)
	u.noticeBG.CornerRadius = 4
	u.noticeBox = container.NewStack(u.noticeBG, container.NewPadded(u.noticeText))
	u.noticeBox.Hide()

	u.head = container.NewVBox(
		container.NewBorder(nil, nil,
			container.NewCenter(container.NewGridWrap(fyne.NewSize(16, 16), u.dot)),
			nil, u.status),
		u.detail,
		u.fields,
		u.noticeBox,
	)

	u.pass = widget.NewPasswordEntry()
	u.pass.SetPlaceHolder("HEM passphrase")
	u.pass.OnSubmitted = func(string) { u.onAction() }

	u.action = widget.NewButton("Connect", u.onAction)

	// The debug panel drives the fake into states that are awkward to reach on
	// real hardware — a peer going quiet, a token running out — which is the
	// point of having a fake at all.
	u.advText = widget.NewLabel("")
	u.advText.TextStyle = fyne.TextStyle{Monospace: true}
	u.adv = container.NewVBox(
		widget.NewSeparator(),
		u.advText,
		container.NewGridWithColumns(3,
			widget.NewButton("Module in", func() { u.sess.setModulePresent(true) }),
			widget.NewButton("Module out", func() { u.sess.setModulePresent(false) }),
			widget.NewButton("Peer fails", func() { u.sess.triggerFailover() }),
		),
		widget.NewButton("Expire the session now", func() { u.sess.expireNow() }),
	)
	u.adv.Hide()

	u.advBox = widget.NewCheck("Advanced", func(on bool) {
		if on {
			u.adv.Show()
		} else {
			u.adv.Hide()
		}
	})

	foot := container.NewVBox(u.pass, u.action, u.advBox, u.adv)

	// Border rather than a plain column: the controls sit at the bottom and the
	// state keeps the top, so the window does not read as half-finished with a
	// void beneath it.
	u.win.SetContent(container.NewPadded(
		container.NewBorder(u.head, foot, nil, nil, nil),
	))
	u.render(u.sess.snapshot())
}

// onAction is the single button: what it does depends on the state, so the user
// never has to decide which of several controls applies.
func (u *ui) onAction() {
	switch u.latest.State {
	case Ready:
		pass := []byte(u.pass.Text)
		u.pass.SetText("")
		if err := u.sess.Connect(context.Background(), pass); err != nil {
			u.showNotice(err.Error(), true)
		}
	case Connected:
		_ = u.sess.Disconnect()
	}
}

// consume is the only writer of interface state. Fyne requires updates to come
// through fyne.Do when they originate off the main goroutine.
func (u *ui) consume() {
	for e := range u.sess.Events() {
		e := e
		fyne.Do(func() { u.render(e) })
	}
}

// tickCountdown redraws the remaining time once a second. The value comes from
// the session's ExpiresAt and is never computed from a requested duration —
// see the comment on Event.ExpiresAt.
func (u *ui) tickCountdown() {
	for range time.Tick(time.Second) {
		fyne.Do(func() { u.renderCountdown(u.latest) })
	}
}

func (u *ui) render(e Event) {
	prev := u.latest
	u.latest = e

	switch e.State {
	case NoModule:
		u.fields.Hide()
		u.setDot(theme.ColorNameDisabled)
		u.status.SetText("Plug in your key")
		u.detail.SetText("The tunnel needs the module that holds its identity.")
	case Ready:
		u.fields.Hide()
		u.setDot(theme.ColorNameForeground)
		u.status.SetText("Ready")
		u.detail.SetText("Module present.")
	case Connecting:
		u.fields.Hide()
		u.setDot(theme.ColorNameWarning)
		u.status.SetText("Connecting…")
		u.detail.SetText("Waiting for the first handshake.")
	case Connected:
		u.setDot(theme.ColorNameSuccess)
		u.status.SetText("Connected")
		u.detail.SetText("")
		u.fPeer.SetText(dash(e.Peer))
		u.fMoved.SetText(human(e.Rx) + " in / " + human(e.Tx) + " out")
		u.fShake.SetText(ago(e.LastHandshake))
		u.fields.Show()
	case Disconnecting:
		u.fields.Hide()
		u.setDot(theme.ColorNameWarning)
		u.status.SetText("Disconnecting…")
		u.detail.SetText("")
	case Ended:
		u.fields.Hide()
		u.setDot(theme.ColorNameDisabled)
		u.status.SetText("Closed")
		u.detail.SetText("")
	}

	// Show/Hide rather than setting Hidden: assigning the field does not tell
	// the layout to recompute, so the field left a hole where it used to be.
	if e.State == Ready {
		u.pass.Show()
	} else {
		u.pass.Hide()
	}

	// Emphasis follows what the user is likely to want next. Connecting is the
	// act worth highlighting; disconnecting is not something to invite, so the
	// button goes quiet once there is a tunnel to lose.
	switch e.State {
	case Ready:
		u.action.SetText("Connect")
		u.action.Importance = widget.HighImportance
		u.action.Enable()
	case Connected:
		u.action.SetText("Disconnect")
		u.action.Importance = widget.MediumImportance
		u.action.Enable()
	default:
		u.action.Importance = widget.MediumImportance
		u.action.Disable()
	}
	u.action.Refresh()

	if e.Notice != "" && e.Notice != prev.Notice {
		u.showNotice(e.Notice, e.Err != nil)
		u.app.SendNotification(fyne.NewNotification("encedo-wg", e.Notice))
	} else if e.Notice == "" && prev.Notice != "" {
		u.noticeBox.Hide()
	}

	// An empty label still occupies a row, which left a hole between the status
	// and whatever followed it.
	if u.detail.Text == "" {
		u.detail.Hide()
	} else {
		u.detail.Show()
	}

	u.renderCountdown(e)
	u.advText.SetText(fmt.Sprintf(
		"state          %s\npeer           %s\nlast handshake %s\nexpires        %s\ntray           %v",
		e.State, dash(e.Peer), stamp(e.LastHandshake), stamp(e.ExpiresAt), u.hasTr))

	// Last, because everything above can change which rows are visible — and
	// renderCountdown is one of them, since the expiry warning appears from
	// there. Showing or hiding a child changes what the column has to lay out
	// and the container does not work that out by itself, so without this the
	// rows keep their old positions and the next state draws over the last.
	// Invisible when each state is rendered into a fresh window; plain the
	// moment one window is driven through a sequence.
	u.head.Refresh()
}

// showNotice gives the one line worth reading a ground of its own. Failover and
// expiry both arrive as prose in the middle of other prose otherwise, which is
// how a person misses the only sentence that changed.
func (u *ui) showNotice(text string, bad bool) {
	name := theme.ColorNameWarning
	if bad {
		name = theme.ColorNameError
	}
	c := theme.Color(name)
	r, g, b, _ := c.RGBA()
	u.noticeBG.FillColor = color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: 40}
	u.noticeBG.StrokeColor = c
	u.noticeBG.StrokeWidth = 1
	u.noticeBG.Refresh()
	u.noticeText.SetText(text)
	u.noticeBox.Show()
}

func (u *ui) setDot(name fyne.ThemeColorName) {
	u.dot.FillColor = theme.Color(name)
	u.dot.Refresh()
}

func (u *ui) renderCountdown(e Event) {
	if e.State != Connected || e.ExpiresAt.IsZero() {
		u.fExpires.SetText("—")
		return
	}
	left := time.Until(e.ExpiresAt)
	// Named as an ending rather than a duration: the session does not renew
	// itself, and a countdown that does not say so invites the assumption.
	u.fExpires.SetText(fmtLeft(left))

	// The tunnel does not renew itself, so the end of the session arrives as a
	// disconnection in the middle of somebody's afternoon unless they are told
	// while there is still time to act. Once, not every second.
	if left > 0 && left <= warnBefore && !u.warned {
		u.warned = true
		// The countdown above already says how long. This says the part it
		// cannot: that nothing will renew it.
		u.showNotice("Reconnect before it ends — the session does not renew itself", false)
		u.app.SendNotification(fyne.NewNotification("encedo-wg",
			"The tunnel will disconnect in "+fmtLeft(left)+"."))
	}
	if left > warnBefore {
		u.warned = false
	}
}

// installCloseIntercept makes the architecture visible at the one moment it
// matters. Closing the window ends the tunnel, because the process holding the
// token is this one; minimising keeps it, where there is a tray to minimise to.
func (u *ui) installCloseIntercept() {
	u.win.SetCloseIntercept(func() {
		if u.latest.State != Connected {
			_ = u.sess.Close()
			u.win.Close()
			return
		}
		msg := "Closing this window disconnects the tunnel."
		if u.hasTr {
			msg += "\n\nTo keep it running, minimise to the tray instead."
		}
		// A dialogue over the window, not a replacement for it. Rebuilding the
		// content to ask a question threw away everything the window was
		// showing — the notice, the advanced panel, whether it was open — and
		// answering "stay" rebuilt it from scratch rather than returning to it.
		d := dialog.NewConfirm("Disconnect?", msg, func(leave bool) {
			if !leave {
				return
			}
			_ = u.sess.Close()
			u.win.Close()
		}, u.win)
		d.SetConfirmText("Disconnect and close")
		d.SetDismissText("Stay connected")
		d.Show()
	})
}

// installTray records whether a tray exists rather than assuming one. Stock
// GNOME has none, and on such a desktop the gesture that means "keep the
// session" does not exist — so the close dialogue above stops offering it
// instead of promising something the desktop will not honour.
func (u *ui) installTray() {
	desk, ok := u.app.(desktop.App)
	if !ok {
		return
	}
	desk.SetSystemTrayMenu(fyne.NewMenu("encedo-wg",
		fyne.NewMenuItem("Show", func() { u.win.Show() }),
		fyne.NewMenuItem("Disconnect", func() { _ = u.sess.Disconnect() }),
	))
	u.hasTr = true
}

// fmtLeft renders a remaining time the way somebody reads a clock, not the way
// Go prints a duration: "7h 32m", not "7h32m0s".
// warnBefore is how much of the session is left when the warning appears. Long
// enough to finish a call and reconnect; short enough not to nag.
const warnBefore = 5 * time.Minute

func fmtLeft(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d >= time.Hour:
		return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}

func human(n uint64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1024*1024))
	}
}

// ago renders a moment as distance from now, which is how a person reads a
// handshake: "41s ago" answers the question, an absolute timestamp makes them
// do arithmetic first.
func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return fmtLeft(time.Since(t)) + " ago"
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("15:04:05")
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
