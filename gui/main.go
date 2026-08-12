// Command gui is the skeleton of the graphical client: the flow, on a fake
// session, so it can be run on all three platforms before any of it touches a
// device. Nothing here talks to a HEM. See ../TODO.md, "A graphical client".
package main

import (
	"context"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

type ui struct {
	app    fyne.App
	win    fyne.Window
	sess   *fakeSession
	hasTr  bool
	latest Event

	status   *widget.Label
	detail   *widget.Label
	pass     *widget.Entry
	action   *widget.Button
	notice   *widget.Label
	adv      *fyne.Container
	advBox   *widget.Check
	advText  *widget.Label
	countLbl *widget.Label
}

func main() {
	a := app.New()
	u := &ui{app: a, win: a.NewWindow("encedo-wg"), sess: newFakeSession()}
	u.build()
	u.installTray()
	u.installCloseIntercept()

	go u.consume()
	go u.tickCountdown()

	u.win.Resize(fyne.NewSize(420, 380))
	u.win.ShowAndRun()
}

func (u *ui) build() {
	u.status = widget.NewLabel("")
	u.status.TextStyle = fyne.TextStyle{Bold: true}
	u.detail = widget.NewLabel("")
	u.countLbl = widget.NewLabel("")
	u.notice = widget.NewLabel("")
	u.notice.Wrapping = fyne.TextWrapWord

	u.pass = widget.NewPasswordEntry()
	u.pass.SetPlaceHolder("HEM passphrase")
	u.pass.OnSubmitted = func(string) { u.onAction() }

	u.action = widget.NewButton("Connect", u.onAction)
	u.action.Importance = widget.HighImportance

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

	u.win.SetContent(container.NewVBox(
		u.status,
		u.detail,
		u.countLbl,
		u.notice,
		widget.NewSeparator(),
		u.pass,
		u.action,
		u.advBox,
		u.adv,
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
			u.notice.SetText(err.Error())
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
		u.status.SetText("Plug in your key")
		u.detail.SetText("The tunnel needs the module that holds its identity.")
	case Ready:
		u.status.SetText("Ready")
		u.detail.SetText("Module present.")
	case Connecting:
		u.status.SetText("Connecting…")
		u.detail.SetText("Waiting for the first handshake.")
	case Connected:
		u.status.SetText("Connected")
		u.detail.SetText(fmt.Sprintf("%s · %s in, %s out",
			e.Peer, human(e.Rx), human(e.Tx)))
	case Disconnecting:
		u.status.SetText("Disconnecting…")
		u.detail.SetText("")
	case Ended:
		u.status.SetText("Closed")
		u.detail.SetText("")
	}

	u.pass.Hidden = e.State != Ready
	switch e.State {
	case Ready:
		u.action.SetText("Connect")
		u.action.Enable()
	case Connected:
		u.action.SetText("Disconnect")
		u.action.Enable()
	default:
		u.action.Disable()
	}

	if e.Notice != "" && e.Notice != prev.Notice {
		u.notice.SetText(e.Notice)
		u.app.SendNotification(fyne.NewNotification("encedo-wg", e.Notice))
	} else if e.State == Connecting || e.State == Ready && prev.State == NoModule {
		u.notice.SetText("")
	}

	u.renderCountdown(e)
	u.advText.SetText(fmt.Sprintf(
		"state          %s\npeer           %s\nlast handshake %s\nexpires        %s\ntray           %v",
		e.State, dash(e.Peer), stamp(e.LastHandshake), stamp(e.ExpiresAt), u.hasTr))
}

func (u *ui) renderCountdown(e Event) {
	if e.State != Connected || e.ExpiresAt.IsZero() {
		u.countLbl.SetText("")
		return
	}
	left := time.Until(e.ExpiresAt).Round(time.Second)
	if left < 0 {
		left = 0
	}
	// Named as an ending rather than a duration: the session does not renew
	// itself, and a countdown that does not say so invites the assumption.
	u.countLbl.SetText(fmt.Sprintf("Session ends in %s", left))
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
		d := widget.NewLabel(msg)
		d.Wrapping = fyne.TextWrapWord
		popup := widget.NewButton("Disconnect and close", func() {
			_ = u.sess.Close()
			u.win.Close()
		})
		popup.Importance = widget.DangerImportance
		u.win.SetContent(container.NewVBox(
			d, popup,
			widget.NewButton("Stay connected", func() { u.build() }),
		))
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
