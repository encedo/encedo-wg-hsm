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
	"net"
	"os"
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

	"github.com/encedo/encedo-wg-hsm/internal/ipc"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// defaultHEM is where a personal appliance answers, the same constant the
// command-line client uses. A name rather than the address behind it, because
// the connection is TLS and certificates are issued for names. An enterprise
// appliance sits somewhere else on the network entirely, which is why the window
// has to let somebody say where.
const defaultHEM = "https://my.ence.do"

// prefHEM is the key the address is remembered under. It is set once per machine
// and never again, so remembering it is kinder than asking every launch.
const prefHEM = "hem-url"

// legacyHEM is what the default used to be, before the appliance was reached by
// name. Finding it stored is not somebody's choice — it is the old default,
// written the first time the window was opened — so it is read as unset rather
// than carried forward into a certificate that was never issued for it. Anything
// else stored is a decision and is left alone.
const legacyHEM = "https://192.168.7.1"

// appID identifies the application to the desktop it runs on, and it is not
// decoration. Without it the toolkit refuses to load or save preferences at all
// — the address typed into the window was written nowhere and read back never —
// and it is the name under which the settings of this application, and no other,
// are kept.
const appID = "com.encedo.wg"

// wmClass is what the window announces itself as, and what a desktop entry has
// to name in StartupWMClass for the two to be recognised as the same thing.
// Measured rather than assumed: GLFW takes both parts of WM_CLASS from the
// window title when nothing else sets them, so a window titled encedo-wg
// announces ("encedo-wg", "encedo-wg"). It follows windowTitle, which is why
// they are one constant apart.
const windowTitle = "encedo-wg"

// The window used to carry a number of its own, 0.9, on the grounds that the two
// halves are built differently — the command-line client is static and
// cross-compiled from one machine, this one needs cgo and a build per platform —
// and so would not move in step.
//
// They do move in step, and not by convention: ipc.Build.Matches compares the
// release and the record length, and the component refuses to take instructions
// from a window that does not agree with it. Two artifacts that must agree to
// work at all do not have two versions. So the window reports what the check
// reports, in the shape `wg-hem version` uses, and the number nobody compared
// against anything is gone — it was a second answer to a question with one, and
// the wrong one to read out when the two halves refuse each other.

// warnBefore is how much of the session is left when the warning appears. Long
// enough to finish a call and reconnect; short enough not to nag.
const warnBefore = 5 * time.Minute

//go:embed icon.svg
var iconSVG []byte

// appIcon is the mark in the dock, the task bar and the tray. SVG rather than a
// bitmap so it is drawn at whatever size each of them asks for.
var appIcon = fyne.NewStaticResource("encedo-wg.svg", iconSVG)

type ui struct {
	app fyne.App
	win fyne.Window
	// sess is the interface rather than the fake, which is what the interface
	// was written for: the window drives one shape, and what is behind it is a
	// scripted stand-in or a real appliance and a privileged component.
	sess Session
	// faked is set when the session behind this window is the scripted stand-in.
	// It is not a debug detail: a stand-in draws "Connected", a byte counter, a
	// countdown and a desktop notification, and none of it is a tunnel. Somebody
	// who believes that has no VPN and thinks they do.
	faked  bool
	hasTr  bool
	latest Event
	// heard records whether the session has ever reported. Without it the first
	// frame and a broken reporter look identical, which cost an evening: the
	// advanced panel said "not asked yet" and that was true of one of them.
	heard bool

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
	fAddr    *widget.Label
	fPeer    *widget.Label
	fMoved   *widget.Label
	fShake   *widget.Label
	fExpires *widget.Label

	// A notice is the one sentence worth reading, and it is drawn in the detail
	// line rather than in a panel of its own. baseDetail is what that line says
	// when nothing has happened, kept so the notice can stand in its place and
	// the sentence can come back when the notice goes.
	baseDetail string
	notice     string
	noticeBad  bool
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
	// -theme exists because the desktop's answer is not always the right one:
	// under sudo the appearance setting consulted is root's, not the one whose
	// desktop this is. See variantChoice.
	themeName := flag.String("theme", "auto", "colour scheme: auto, dark or light (auto follows the desktop, which under sudo is root's)")
	// -live drives a real appliance through the privileged component. It is opt
	// in for now, so that -scenario and the render tests keep working on a
	// machine with neither a device nor a service, and so that the first person
	// to try it does so deliberately.
	live := flag.String("live", "", controlFlagUsage)
	flag.Parse()
	if *showVersion {
		// One line, the same shape `wg-hem version` prints, because the two are
		// meant to be compared and the comparison used to need somebody to know
		// which of two lines was the one that mattered.
		fmt.Println("encedo-wg-gui", ipc.Current())
		return
	}
	// Before the toolkit starts, because that is when it reads the variable. It
	// says nothing about it: this is a correction for a display that will not
	// describe itself, and a person opening a VPN client has no use for that.
	alignScaleWithDesktop()

	th, err := themeFor(*themeName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// Before anything is drawn: a window that appears and vanishes is worse than
	// no window. A failure to tell either way is not a reason to refuse to
	// start — it leaves the rule unenforced, which is where this began.
	var ln net.Listener
	if dir, derr := instanceDir(); derr != nil {
		fmt.Fprintf(os.Stderr, "WARNING: cannot tell whether another window is open: %v\n", derr)
	} else {
		var handedOver bool
		ln, handedOver, err = claimInstance(dir)
		if handedOver {
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: cannot tell whether another window is open: %v\n", err)
		}
	}

	// Metadata before the application exists, because it is read while it is
	// being built. Declaring the fyneDo migration is not a formality either: the
	// toolkit otherwise prints three lines of warning to the terminal at every
	// launch, about a threading model this program already follows.
	app.SetMetadata(fyne.AppMetadata{
		ID:         appID,
		Name:       windowTitle,
		Version:    ipc.Current().Release,
		Migrations: map[string]bool{"fyneDo": true},
	})

	a := app.NewWithID(appID)
	a.SetIcon(appIcon)
	a.Settings().SetTheme(th)

	u := &ui{app: a, win: a.NewWindow(windowTitle)}
	if *live != "" {
		ls := newLiveSession(rememberedHEM(a.Preferences().StringWithFallback(prefHEM, defaultHEM)), *live)
		go ls.watch(context.Background())
		u.sess = ls
	} else {
		u.sess = newFakeSession()
	}
	u.build()
	// Now that there is a window to show, start answering the launches that ask
	// for it. Through fyne.Do: the request arrives on the listener's goroutine.
	if ln != nil {
		go serveInstance(ln, func() { fyne.Do(u.present) })
	}
	u.installTray()
	u.installCloseIntercept()

	go u.consume()
	go u.tickCountdown()
	if *auto {
		u.onFake(func(f *fakeSession) { go f.play(func(what string) { println("scenario:", what) }) })
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
	u.hem.SetText(rememberedHEM(u.app.Preferences().StringWithFallback(prefHEM, defaultHEM)))
	u.hem.OnSubmitted = u.applyHEM
	u.hemRow = container.New(layout.NewFormLayout(), widget.NewLabel("looking at"), u.hem)

	mono := func() *widget.Label {
		l := widget.NewLabel("")
		l.TextStyle = fyne.TextStyle{Monospace: true}
		return l
	}
	u.fAddr, u.fPeer, u.fMoved, u.fShake, u.fExpires = mono(), mono(), mono(), mono(), mono()
	// Address before peer: this row is who you are on the tunnel, the next is
	// who is at the other end, and the ones after are what has passed between
	// them. It is also the row somebody reads out to a colleague, which is the
	// reason it is here at all rather than behind Advanced.
	u.fields = container.New(layout.NewFormLayout(),
		widget.NewLabel("address"), u.fAddr,
		widget.NewLabel("peer"), u.fPeer,
		widget.NewLabel("transferred"), u.fMoved,
		widget.NewLabel("last handshake"), u.fShake,
		widget.NewLabel("session ends"), u.fExpires,
	)

	u.pass = widget.NewPasswordEntry()
	u.pass.SetPlaceHolder("HEM passphrase")
	u.pass.OnSubmitted = func(string) { u.onAction() }
	u.action = widget.NewButton("Connect", u.onAction)
	u.actionBox = outlined(u.action)

	// The debug panel drives the fake into states that are awkward to reach on
	// real hardware — a peer going quiet, a token running out — which is the
	// point of having a fake at all.
	// From the session, not from whoever constructed the window. Set in main()
	// it was missed by every other caller — the render tests among them, which
	// is how a marker meant to stop a stand-in passing for a tunnel came to be
	// absent from the pictures of the stand-in. It is the same condition that
	// decides whether the debug buttons exist, and now it is asked once.
	_, u.faked = u.sess.(*fakeSession)

	u.advText = widget.NewLabel("")
	u.advText.TextStyle = fyne.TextStyle{Monospace: true}
	// The buttons drive states that are awkward to reach on real hardware — a
	// module pulled out, a peer going quiet, a token running out — which is the
	// point of having a stand-in. Against a real appliance there is nothing for
	// them to do, and a control that does nothing is worse than no control.
	u.adv = container.NewVBox(widget.NewSeparator(), u.advText)
	if _, scripted := u.sess.(*fakeSession); scripted {
		u.adv.Add(container.NewGridWithColumns(3,
			outlined(widget.NewButton("Module in", func() { u.onFake(func(f *fakeSession) { f.setModulePresent(true) }) })),
			outlined(widget.NewButton("Module out", func() { u.onFake(func(f *fakeSession) { f.setModulePresent(false) }) })),
			outlined(widget.NewButton("Peer fails", func() { u.onFake(func(f *fakeSession) { f.triggerFailover() }) })),
		))
		u.adv.Add(outlined(widget.NewButton("Expire the session now", func() { u.onFake(func(f *fakeSession) { f.expireNow() }) })))
	}
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
	if f, ok := u.sess.(*fakeSession); ok {
		u.render(f.snapshot())
	}
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
// Each is a multiple of uiScale rather than a number, because that is what they
// are: every metric inside the window is scaled by it, so the window that holds
// them has to be. Written as constants they drift apart at exactly the moment
// nobody is looking — changing the density and not the window is how the rows
// came to be drawn over each other once already.
const (
	// Measured, not chosen: the tallest the window gets with the panel closed is
	// connected with a notice — five rows, a status line and a footer — which
	// comes to 376. TestCompactHeightFits is what keeps this honest, because
	// this number has been wrong twice, both times by somebody adding a row.
	compactHeight = 384 * uiScale
	windowWidth   = 420 * uiScale
)

// resizeForContent gives the window the height the current content needs.
//
// Closed, that is one height whatever is on screen — the window must not move
// while somebody is reading it, and a notice arrives unannounced, which is the
// worst possible moment. The compact height has room for one either way.
//
// Open, it is that height plus whatever the panel actually measures. It used to
// be a second constant, 590, taken from the panel at its tallest: the four
// buttons that only exist in front of the scripted stand-in. Against a real
// appliance the panel is a few lines of text and the rest was an empty gap
// above the button — which is what the constant bought, and it was not worth it.
// Measuring is safe here for the reason a constant was chosen elsewhere: this
// changes only when somebody ticks the box, never underneath them.
func (u *ui) resizeForContent() {
	h := float32(compactHeight)
	if u.advBox != nil && u.advBox.Checked {
		h += u.adv.MinSize().Height + theme.Padding()
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

		// Off this goroutine, because connecting takes seconds and this one is
		// drawing. Deriving the key from the passphrase alone is 600,000 rounds
		// of PBKDF2, and running it here froze the window hard enough that the
		// desktop offered to kill the application.
		//
		// The state does not change here either: the session emits Connecting
		// when it starts, and everything after that arrives the same way — so
		// there is no path where the window believes something the session has
		// not said.
		go func() {
			if err := u.sess.Connect(context.Background(), pass); err != nil {
				fyne.Do(func() { u.setNotice(humanError(err), true) })
			}
		}()
	case Connected:
		_ = u.sess.Disconnect()
	}
}

// rememberedHEM is what was stored, unless what was stored is the address the
// default used to be. See legacyHEM.
func rememberedHEM(stored string) string {
	if strings.TrimSpace(stored) == legacyHEM {
		return defaultHEM
	}
	return stored
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
	// Only something that has not connected yet can be pointed elsewhere, and
	// both implementations happen to offer it.
	if h, ok := u.sess.(interface{ setHEM(string) }); ok {
		h.setHEM(url)
	}
}

// consume is the only writer of interface state. Fyne requires updates to come
// through fyne.Do when they originate off the main goroutine.
func (u *ui) consume() {
	for e := range u.sess.Events() {
		e := e
		fyne.Do(func() { u.heard = true; u.render(e) })
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
		u.baseDetail = "The tunnel needs the module that holds its identity."
	case Ready:
		u.setDot(theme.ColorNameForeground)
		u.status.SetText("Ready")
		u.baseDetail = "Module present."
	case Connecting:
		u.setDot(theme.ColorNameWarning)
		u.status.SetText("Connecting…")
		u.baseDetail = "Waiting for the first handshake."
	case Connected:
		u.setDot(theme.ColorNameSuccess)
		u.status.SetText("Connected")
		u.baseDetail = ""
		u.fAddr.SetText(addrs(e.Addrs))
		u.fPeer.SetText(dash(e.Peer))
		u.fMoved.SetText(human(e.Rx) + " in / " + human(e.Tx) + " out")
		u.fShake.SetText(ago(e.LastHandshake))
	case Disconnecting:
		u.setDot(theme.ColorNameWarning)
		u.status.SetText("Disconnecting…")
		u.baseDetail = ""
	case Ended:
		u.setDot(theme.ColorNameDisabled)
		u.status.SetText("Closed")
		u.baseDetail = ""
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
	// Said on the line that is read rather than only in the panel that is
	// opened. The status word is where somebody looks to learn whether they are
	// protected, so it is where a stand-in has to admit it.
	if u.faked {
		u.status.SetText(u.status.Text + " (stand-in)")
	}

	u.action.Refresh()

	// A notice outlives the events around it but not the state it belongs to.
	// Clearing it on the next event carrying none made every notice flash and
	// vanish, since the component reports once a second; never clearing it left
	// "Connecting to …" sitting in front of a tunnel that had been up for an
	// hour. The state it arrived in is the thing it is about, so that is what it
	// lasts for: failover and expiry both hold while the tunnel does, and the
	// narration of connecting goes when connecting does.
	if e.State != prev.State {
		u.notice, u.noticeBad = "", false
	}
	if e.Notice != "" && e.Notice != prev.Notice {
		u.notice, u.noticeBad = e.Notice, e.Err != nil
	}
	u.applyDetail()

	// Notifications only where the state changed, and only for the two changes
	// worth interrupting somebody over. The tunnel says five sentences over a
	// session — up, handshake, moved, expired, down — and a popup for each is
	// four too many for something whose whole job is to be unremarkable.
	if e.State != prev.State {
		switch e.State {
		case Connected:
			u.app.SendNotification(fyne.NewNotification("encedo-wg", "Connected."))
		case Ended:
			u.app.SendNotification(fyne.NewNotification("encedo-wg", "Disconnected."))
		}
	}

	u.renderCountdown(e)
	// The build, not a number of the window's own: this is the line somebody
	// reads out when the component has refused the window, and it has to be the
	// one the component compared against — the same text `wg-hem version` prints
	// after the program name.
	u.advText.SetText(fmt.Sprintf(
		"version        %s\nsession        %s\nstate          %s\nhem            %s\nreach          %s\npeer           %s\nlast handshake %s\nexpires        %s\ntray           %v",
		ipc.Current(), u.sessionKind(), e.State, dash(e.HEM), u.reach(e), dash(e.Peer),
		stamp(e.LastHandshake), stamp(e.ExpiresAt), u.hasTr))

	u.compose(e)
}

// setNotice puts a sentence in front of somebody from outside render, which the
// expiry warning is: it comes off a timer rather than off an event.
func (u *ui) setNotice(text string, bad bool) {
	u.notice, u.noticeBad = text, bad
	u.applyDetail()
	u.compose(u.latest)
}

// applyDetail draws the detail line, which is the notice when there is one and
// the state's own sentence otherwise.
//
// A panel with a coloured ground used to carry this. It was designed against the
// scripted stand-in, where a box was the only way to show that anything had
// happened; with a real component the word, the dot and the fields already carry
// the state, and what was left was one sentence being shouted. Colour says the
// same thing more quietly, and the line wraps — the panel could not, because a
// wrapping label inside a background box has its height computed before its
// width is known, so the failover message was cut off mid-word.
func (u *ui) applyDetail() {
	text, importance := u.baseDetail, widget.MediumImportance
	if u.notice != "" {
		text = u.notice
		importance = widget.WarningImportance
		if u.noticeBad {
			importance = widget.DangerImportance
		}
	}
	u.detail.Importance = importance
	u.detail.SetText(text)
	u.detail.Refresh()
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
		u.setNotice("Reconnect before it ends — the session does not renew itself", false)
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
	u.win.SetCloseIntercept(u.askToClose)
}

// askToClose is the single place that decides what leaving means, because there
// is more than one way to ask for it and they were not agreeing: the window made
// somebody confirm, and the tray's Quit — the same decision, two clicks away —
// ended the tunnel without a word.
func (u *ui) askToClose() {
	if u.latest.State != Connected {
		u.quit()
		return
	}
	// The question needs a window to be asked in. Reached from the tray the
	// window may be hidden, and a dialogue drawn on a hidden window is, from the
	// outside, an application that has stopped responding.
	u.present()

	msg := "Closing this window disconnects the tunnel."
	dismiss := "Stay connected"
	if u.hasTr {
		msg = "Closing this window disconnects the tunnel. It can wait in the tray instead, with the tunnel up."
		dismiss = "Keep it in the tray"
	}
	d := dialog.NewConfirm("Disconnect?", msg, func(leave bool) {
		if leave {
			u.quit()
			return
		}
		// Declining is not cancelling, where there is a tray: what was offered
		// was to put the window away and keep the tunnel, so put it away.
		// Hiding and not minimising is the difference somebody actually sees —
		// a minimised window keeps its place in the task bar, so it looks as
		// though nothing was sent anywhere.
		if u.hasTr {
			u.win.Hide()
		}
	}, u.win)
	d.SetConfirmText("Disconnect and close")
	d.SetDismissText(dismiss)
	d.Show()
}

// present brings the window back from wherever it went.
//
// Show on its own is not enough, and Windows is where that shows: a window put
// down by the task bar is minimised rather than hidden, and showing something
// already shown does nothing at all — the task bar entry blinks and the window
// stays where it was. Asking for focus is what raises it.
func (u *ui) present() {
	u.win.Show()
	u.win.RequestFocus()
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
	// Asked before anything is offered. The toolkit accepts a tray menu on any
	// desktop and finds out later whether one exists — see tray_linux.go — and
	// a window that hides itself into a tray that is not there is a live tunnel
	// nobody can reach.
	if !trayAvailable() {
		return
	}
	desk.SetSystemTrayMenu(fyne.NewMenu(windowTitle,
		fyne.NewMenuItem("Show", u.present),
		fyne.NewMenuItem("Disconnect", func() { _ = u.sess.Disconnect() }),
		// A tray with no way out is a trap: minimising to it is what keeps the
		// session, so it has to offer the other thing too — and it asks the
		// same question the window asks, rather than ending a live tunnel from
		// a menu without one.
		fyne.NewMenuItem("Quit", u.askToClose),
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

// humanError is what the window says instead of what the error says.
//
// The command line prints the error as it came, and should: somebody at a
// terminal is debugging, and "authorizing keymgmt:get: auth failed: invalid
// credentials" names the scope, the call and the device's own words. In a window
// it is four pieces of jargon in front of somebody who mistyped a passphrase,
// and none of the four changes what they do next.
//
// So the kind is translated and the text is dropped, for the two kinds where the
// person can act and the wording is the SDK's rather than ours. A refused
// credential and an unreachable device are the whole of what a connect attempt
// does wrong from a window; everything else — a configuration that does not
// authenticate, a module holding no identity — this repository already words
// itself, and passing those through keeps the sentence somebody wrote for the
// occasion.
func humanError(err error) string {
	switch session.KindOf(err) {
	case session.KindAuth:
		return "That passphrase was not accepted — check it and try again."
	case session.KindNetwork:
		return "The module did not answer. Check that it is plugged in."
	default:
		return err.Error()
	}
}

// reach says why the device did not answer, for the advanced panel.
//
// "no module" is four facts wearing one word — nothing plugged in, no route to
// it, a name that does not resolve, a certificate the system will not accept —
// and on Windows they are especially easy to confuse, because the adapter, the
// name and the certificate store are all different from the machine this was
// written on. The main screen keeps its one friendly sentence; this line is for
// the person who has opened the panel because that sentence was not true.
// sessionKind names what is behind the window, because the two look alike and
// only one of them is a VPN. -live is opt-in, so the stand-in is what a person
// gets by double-clicking, and it was mistaken for the real thing.
func (u *ui) sessionKind() string {
	if u.faked {
		return "stand-in — nothing here reaches a device"
	}
	return "live"
}

func (u *ui) reach(e Event) string {
	switch {
	case e.Reach != "":
		return e.Reach
	case !u.heard:
		// Nothing has arrived from the session at all. The presence check runs
		// every three seconds, so this is either the first second of the
		// window's life or something is wrong upstream of the check.
		return "waiting for the first report"
	case e.State == NoModule:
		// The session said the device is absent and gave no reason, which the
		// presence check cannot do: every failure it reports carries the error
		// it got. Saying so plainly beats a placeholder that reads like a
		// normal state.
		return "reported absent with no reason — that is a bug, please report it"
	default:
		return "answering"
	}
}

// addrs draws the interface's addresses in one row. Every configuration written
// so far has one, so the row is built for that and does not lie when there are
// more: the second and later are counted rather than listed, because a row that
// grows with the configuration is a row that eventually overruns the window.
func addrs(list []string) string {
	switch len(list) {
	case 0:
		return "—"
	case 1:
		return list[0]
	default:
		return fmt.Sprintf("%s  +%d more", list[0], len(list)-1)
	}
}

// onFake runs something only the scripted stand-in can do.
//
// The debug panel drives states that are awkward to reach on real hardware — a
// module pulled out, a peer going quiet, a token running out — which is the
// point of having a stand-in at all. Against a real appliance those buttons have
// nothing to do, and doing nothing quietly is better than offering a control
// that would have to lie about what it did.
func (u *ui) onFake(fn func(*fakeSession)) {
	if f, ok := u.sess.(*fakeSession); ok {
		fn(f)
	}
}
