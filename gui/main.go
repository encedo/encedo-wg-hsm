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
	"strings"
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

// defaultHEM is where a personal appliance answers: a fixed address on its own
// USB link, the same constant the command-line client uses. An enterprise
// appliance sits somewhere on the network instead, which is why the window has
// to let somebody say where.
const defaultHEM = "https://192.168.7.1"

// prefHEM is the key the address is remembered under. It is set once per machine
// and never again, so remembering it is kinder than asking every launch.
const prefHEM = "hem-url"

// guiVersion is this interface's own number, not the client's. They are separate
// artifacts built differently — the command-line client is static and
// cross-compiled from one machine, this one needs cgo and a build per platform —
// and they will not move in step, so pretending they share a version would be a
// claim neither of them keeps.
const guiVersion = "0.9"

// warnBefore is how much of the session is left when the warning appears. Long
// enough to finish a call and reconnect; short enough not to nag.
const warnBefore = 5 * time.Minute

//go:embed icon.svg
var iconSVG []byte

// appIcon is the mark in the dock, the task bar and the tray. SVG rather than a
// bitmap so it is drawn at whatever size each of them asks for.
var appIcon = fyne.NewStaticResource("encedo-wg.svg", iconSVG)

type ui struct {
	app    fyne.App
	win    fyne.Window
	sess   *fakeSession
	hasTr  bool
	latest Event

	// The two columns are rebuilt from the state rather than having their rows
	// shown and hidden. See compose.
	head, foot *fyne.Container
	body       *fyne.Container

	statusRow *fyne.Container
	rule      *widget.Separator
	topRule   *widget.Separator
	advRule   *widget.Separator
	dot       *canvas.Circle
	status    *widget.Label
	detail    *widget.Label

	// hemRow says which address the module is being looked for at. Offered on
	// the one screen where the question arises, because "no module" and "wrong
	// address" are indistinguishable from the outside.
	hem    *widget.Entry
	hemRow *fyne.Container

	// fields is the middle of the window: what the tunnel is doing, as label and
	// value. Values are monospaced because that is the vernacular of the subject
	// — endpoints, byte counts, key identifiers — and the typeface the product
	// page uses for the same reason.
	fields   *fyne.Container
	fPeer    *widget.Label
	fMoved   *widget.Label
	fShake   *widget.Label
	fExpires *widget.Label

	noticeText *widget.Label
	noticeBG   *canvas.Rectangle
	noticeBox  *fyne.Container
	warned     bool

	pass      *widget.Entry
	action    *widget.Button
	actionBox fyne.CanvasObject
	advBox    *widget.Check
	adv       *fyne.Container
	advText   *widget.Label
}

func main() {
	// -scenario plays the life of a session end to end so somebody can watch it
	// once rather than learn which debug button produces which state.
	auto := flag.Bool("scenario", false, "play a scripted session instead of waiting for input")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("encedo-wg-gui", guiVersion)
		return
	}

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
		go u.sess.play(func(what string) { println("scenario:", what) })
	}

	// Fixed: nothing here benefits from more room, and three states stretched
	// across a large display read as a mistake. It also removes the maximise
	// button, which is the honest signal — a control that does nothing useful is
	// worse than no control. The size accommodates the advanced panel with its
	// debug rows open, so nothing is clipped when somebody opens it.
	u.win.SetFixedSize(true)
	u.resizeForContent()
	u.win.ShowAndRun()
}

func (u *ui) build() {
	// The dot carries the state before any word is read: somebody restoring the
	// window from the tray should know where they stand without parsing a
	// sentence.
	u.dot = canvas.NewCircle(color.Transparent)
	u.status = widget.NewLabel("")
	u.status.TextStyle = fyne.TextStyle{Bold: true}
	u.statusRow = container.NewBorder(nil, nil,
		container.NewCenter(container.NewGridWrap(fyne.NewSize(16, 16), u.dot)),
		nil, u.status)

	u.detail = widget.NewLabel("")
	u.detail.Wrapping = fyne.TextWrapWord

	u.hem = widget.NewEntry()
	u.hem.SetText(u.app.Preferences().StringWithFallback(prefHEM, defaultHEM))
	u.hem.OnSubmitted = u.applyHEM
	u.hemRow = container.New(layout.NewFormLayout(), widget.NewLabel("looking at"), u.hem)

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

	// One line, ellipsised. A wrapping label inside a background box cannot be
	// sized reliably — its height is computed before its width is known, so long
	// text is clipped rather than wrapped. A single line removes the gamble and
	// is the better alert anyway; the full text goes to the system notification.
	u.noticeText = widget.NewLabel("")
	u.noticeText.Wrapping = fyne.TextWrapOff
	u.noticeText.Truncation = fyne.TextTruncateEllipsis
	u.noticeBG = canvas.NewRectangle(color.Transparent)
	u.noticeBG.CornerRadius = 4
	u.noticeBox = container.NewStack(u.noticeBG, container.NewPadded(u.noticeText))

	u.pass = widget.NewPasswordEntry()
	u.pass.SetPlaceHolder("HEM passphrase")
	u.pass.OnSubmitted = func(string) { u.onAction() }
	u.action = widget.NewButton("Connect", u.onAction)
	u.actionBox = outlined(u.action)

	// The debug panel drives the fake into states that are awkward to reach on
	// real hardware — a peer going quiet, a token running out — which is the
	// point of having a fake at all.
	u.advText = widget.NewLabel("")
	u.advText.TextStyle = fyne.TextStyle{Monospace: true}
	u.adv = container.NewVBox(
		widget.NewSeparator(),
		u.advText,
		container.NewGridWithColumns(3,
			outlined(widget.NewButton("Module in", func() { u.sess.setModulePresent(true) })),
			outlined(widget.NewButton("Module out", func() { u.sess.setModulePresent(false) })),
			outlined(widget.NewButton("Peer fails", func() { u.sess.triggerFailover() })),
		),
		outlined(widget.NewButton("Expire the session now", func() { u.sess.expireNow() })),
	)
	u.advBox = widget.NewCheck("Advanced", func(bool) { u.compose(u.latest) })

	// A rule between what the tunnel is and what you can do about it. Without
	// one the two run together, and the eye has to work out from wording alone
	// where reading stops and acting starts.
	u.rule = widget.NewSeparator()
	u.topRule = widget.NewSeparator()
	u.advRule = widget.NewSeparator()
	u.head, u.foot = container.NewVBox(), container.NewVBox()

	// Border rather than a plain column: the controls keep the bottom and the
	// state keeps the top, so the window does not read as half-drawn.
	u.body = container.NewBorder(u.head, u.foot, nil, nil, nil)
	u.win.SetContent(container.NewPadded(u.body))
	u.render(u.sess.snapshot())
}

// compose rebuilds both columns from what the state says belongs in them.
//
// The alternative — keeping every row in place and calling Show and Hide — is
// what this replaces, and it did not work. A hidden container still claimed its
// row, so the footer drew through the middle of the header; and one Hide that
// was never wired left a field on screen in every state. Rebuilding the object
// list is declarative, has one path per state, and cannot leave a stale row
// behind because nothing is left over to go stale.
func (u *ui) compose(e Event) {
	// The status row is closed on both sides rather than only underneath, so it
	// reads as a header rather than as the first of a list of lines. The rule
	// appears only when something follows it — a line under the last thing on
	// screen is a line to nowhere.
	head := []fyne.CanvasObject{u.statusRow, u.topRule}
	if u.detail.Text != "" {
		head = append(head, u.detail)
	}
	if e.State == Connected {
		head = append(head, u.fields)
	}
	if e.State == NoModule {
		head = append(head, u.hemRow)
	}
	if u.noticeText.Text != "" {
		head = append(head, u.noticeBox)
	}

	foot := []fyne.CanvasObject{u.rule}
	if e.State == Ready {
		foot = append(foot, u.pass)
	}
	// The action and the advanced toggle are not the same kind of thing: one is
	// what this window is for, the other is a way in to what it is hiding.
	// A rule between them says so, and gives the button its own ground rather
	// than leaving it stacked against a checkbox.
	foot = append(foot, u.actionBox, u.advRule, u.advBox)
	if u.advBox.Checked {
		foot = append(foot, u.adv)
	}

	if len(head) == 2 {
		head = head[:1]
	}
	u.head.Objects, u.foot.Objects = head, foot
	u.head.Refresh()
	u.foot.Refresh()
	u.body.Refresh()
	u.resizeForContent()
}

// Window heights. Fixed size stops somebody dragging the window about, but the
// program may still choose one — and it has to, because the advanced panel adds
// more than the compact height can hold. Squeezing it instead is what a border
// layout does when asked for the impossible: the header keeps its minimum, the
// footer is placed against it, and the rows that do not fit are drawn over the
// top of each other. That is what this replaces.
const (
	compactHeight  = 480
	noticeHeight   = 60 // a notice is one more row, and it arrives unannounced
	advancedHeight = 860
	windowWidth    = 630
)

// resizeForContent gives the window the height the current content needs. Two
// sizes rather than a measurement: the difference is a panel that is either open
// or closed, and a window that changes size by a few pixels as text changes
// would be worse than one that changes by a lot when a panel does.
func (u *ui) resizeForContent() {
	h := float32(compactHeight)
	if u.noticeText != nil && u.noticeText.Text != "" {
		h += noticeHeight
	}
	if u.advBox != nil && u.advBox.Checked {
		h = advancedHeight
	}
	u.win.Resize(fyne.NewSize(windowWidth, h))
}

// outlined gives a button an edge. Fyne draws a filled rectangle and no border,
// which on a ground this dark leaves a control that has to be inferred from its
// label rather than seen as a control.
//
// The rule goes behind, with the button inset over it, rather than on top: an
// overlay would sit between the pointer and the thing it is outlining, and a
// button that looks right and does not respond is worse than one that looks
// flat.
func outlined(b *widget.Button) fyne.CanvasObject {
	r := canvas.NewRectangle(color.Transparent)
	r.StrokeColor = theme.Color(theme.ColorNameInputBorder)
	r.StrokeWidth = 1
	r.CornerRadius = 4
	return container.NewStack(r, b)
}

// onAction is the single button: what it does depends on the state, so nobody
// has to decide which of several controls applies.
func (u *ui) onAction() {
	switch u.latest.State {
	case Ready:
		pass := []byte(u.pass.Text)
		u.pass.SetText("")
		if err := u.sess.Connect(context.Background(), pass); err != nil {
			u.showNotice(err.Error(), true)
			u.compose(u.latest)
		}
	case Connected:
		_ = u.sess.Disconnect()
	}
}

// applyHEM remembers the address and points the session at it. Remembered
// because it is set once per machine: asking again every launch would be asking
// somebody to retype a constant.
func (u *ui) applyHEM(url string) {
	url = strings.TrimSpace(url)
	if url == "" {
		url = defaultHEM
		u.hem.SetText(url)
	}
	u.app.Preferences().SetString(prefHEM, url)
	u.sess.setHEM(url)
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
// the session's ExpiresAt and is never computed from a requested duration — see
// the comment on Event.ExpiresAt.
func (u *ui) tickCountdown() {
	for range time.Tick(time.Second) {
		fyne.Do(func() {
			u.renderCountdown(u.latest)
			u.compose(u.latest)
		})
	}
}

func (u *ui) render(e Event) {
	prev := u.latest
	u.latest = e

	switch e.State {
	case NoModule:
		u.setDot(theme.ColorNameDisabled)
		u.status.SetText("Plug in your key")
		u.detail.SetText("The tunnel needs the module that holds its identity.")
	case Ready:
		u.setDot(theme.ColorNameForeground)
		u.status.SetText("Ready")
		u.detail.SetText("Module present.")
	case Connecting:
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
	case Disconnecting:
		u.setDot(theme.ColorNameWarning)
		u.status.SetText("Disconnecting…")
		u.detail.SetText("")
	case Ended:
		u.setDot(theme.ColorNameDisabled)
		u.status.SetText("Closed")
		u.detail.SetText("")
	}

	// Emphasis follows what somebody is likely to want next. Connecting is the
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
		// Naming the action that will be available, not the one that was. Left
		// alone, the button still said "Disconnect" after the module was pulled
		// out — offering, in disabled grey, something it could no longer do.
		u.action.SetText("Connect")
		u.action.Importance = widget.MediumImportance
		u.action.Disable()
	}
	u.action.Refresh()

	if e.Notice != "" && e.Notice != prev.Notice {
		u.showNotice(e.Notice, e.Err != nil)
		u.app.SendNotification(fyne.NewNotification("encedo-wg", e.Notice))
	} else if e.Notice == "" && prev.Notice != "" {
		u.noticeText.SetText("")
	}

	u.renderCountdown(e)
	u.advText.SetText(fmt.Sprintf(
		"version        %s\nstate          %s\nhem            %s\npeer           %s\nlast handshake %s\nexpires        %s\ntray           %v",
		guiVersion, e.State, dash(e.HEM), dash(e.Peer), stamp(e.LastHandshake), stamp(e.ExpiresAt), u.hasTr))

	u.compose(e)
}

// showNotice gives the one line worth reading a ground of its own. Failover and
// expiry both arrive as prose among other prose otherwise, which is how a person
// misses the only sentence that changed.
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
	u.fExpires.SetText(fmtLeft(left))

	// The tunnel does not renew itself, so the end of a session arrives as a
	// disconnection in the middle of an afternoon unless somebody is told while
	// there is still time to act. Once, not every second.
	if left > 0 && left <= warnBefore && !u.warned {
		u.warned = true
		// The countdown above already says how long; this says the part it
		// cannot, which is that nothing will renew it.
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
			u.quit()
			return
		}
		msg := "Closing this window disconnects the tunnel."
		if u.hasTr {
			msg += "\n\nTo keep it running, minimise to the tray instead."
		}
		d := dialog.NewConfirm("Disconnect?", msg, func(leave bool) {
			if !leave {
				return
			}
			u.quit()
		}, u.win)
		d.SetConfirmText("Disconnect and close")
		d.SetDismissText("Stay connected")
		d.Show()
	})
}

// quit ends the session and the process together.
//
// Closing the window is not enough and the tray is why: a tray icon tells the
// toolkit the application is meant to outlive its windows, so closing the last
// one left the process running with nothing on screen. For most applications
// that is the point of a tray. Here it contradicts the arrangement the whole
// design rests on — the window is the session, and a process that survives it
// is one holding a credential nobody is watching, which is the thing this
// client exists not to do.
func (u *ui) quit() {
	_ = u.sess.Close()
	u.app.Quit()
}

// installTray records whether a tray exists rather than assuming one. Stock
// GNOME has none, and on such a desktop the gesture that means "keep the
// session" does not exist — so the close dialogue stops offering it instead of
// promising what the desktop will not honour.
func (u *ui) installTray() {
	desk, ok := u.app.(desktop.App)
	if !ok {
		return
	}
	desk.SetSystemTrayMenu(fyne.NewMenu("encedo-wg",
		fyne.NewMenuItem("Show", func() { u.win.Show() }),
		fyne.NewMenuItem("Disconnect", func() { _ = u.sess.Disconnect() }),
		// A tray with no way out is a trap: minimising to it is what keeps the
		// session, so it has to offer the other thing too.
		fyne.NewMenuItem("Quit", u.quit),
	))
	u.hasTr = true
}

// fmtLeft renders a remaining time the way somebody reads a clock, not the way
// Go prints a duration: "7h 32m", not "7h32m0s".
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

// ago renders a moment as distance from now, which is how a person reads a
// handshake: "41s ago" answers the question, a timestamp makes them do
// arithmetic first.
func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return fmtLeft(time.Since(t)) + " ago"
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
