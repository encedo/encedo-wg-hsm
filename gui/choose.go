package main

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/encedo/encedo-wg-hsm/internal/config"
)

// errNoProfileChosen is what a dismissed dialogue means.
//
// Not an error in the sense of something going wrong: somebody was asked a
// question and declined to answer it, which is a legitimate way to end a
// connection attempt. It is an error only because that is how a decision
// travels back up a call that was waiting for one.
var errNoProfileChosen = errors.New("no profile chosen")

// chooseIdentity is what the window puts up when the module holds more than one
// identity. Until it existed, that module simply refused - see pickIdentity -
// which made a second imported configuration a wall rather than a choice.
//
// It is called from the goroutine running Connect, not from the one drawing, so
// everything here is in two halves: build and show the dialogue through fyne.Do,
// then block on a channel until somebody answers it. Showing a dialogue from the
// connecting goroutine directly is the toolkit's one unforgivable sin, and the
// symptom is not a crash but a window that stops painting.
//
// There is deliberately no default and no preselection. The command line makes
// the same choice for a reason worth repeating here: the list is ordered oldest
// first, which is a fact about history rather than about intent, so preselecting
// the first would let a distracted return connect as whichever key has been
// around longest. Peers are different and are not asked about at all - their
// stored order is the failover priority somebody wrote down when provisioning,
// so taking the first honours a decision instead of inventing one.
func (u *ui) chooseIdentity(ids []config.Identity) (string, error) {
	answer := make(chan string, 1)

	fyne.Do(func() {
		// The dialogue needs a window that is actually on screen. Reached from
		// the tray with the window hidden, it would otherwise be an application
		// that has stopped responding, with the question drawn somewhere nobody
		// can see.
		u.present()

		var chosen string
		list := widget.NewRadioGroup(identityChoices(ids), func(s string) { chosen = s })
		list.Required = true

		body := container.NewVBox(
			widget.NewLabel("This module holds more than one configuration.\nWhich one should this tunnel use?"),
			list,
		)

		d := dialog.NewCustomConfirm("Choose a profile", "Use this one", "Cancel", body,
			func(ok bool) {
				if !ok || chosen == "" {
					answer <- ""
					return
				}
				answer <- kidFor(ids, chosen)
			}, u.win)
		d.Show()
	})

	kid := <-answer
	if kid == "" {
		return "", errNoProfileChosen
	}
	return kid, nil
}

// identityChoices renders one line per identity, in the order the device
// reported them.
//
// A radio group identifies its selection by the string it displays, so these
// have to be unique or two profiles become one. Uniqueness cannot come from the
// label: `provision` defaults every identity to "wg-hem identity", so a module
// with two imported configurations has two of them, and that is the common case
// rather than a corner. The addresses usually separate them; when they do not,
// the key identifier does, and it is the only thing here guaranteed to.
func identityChoices(ids []config.Identity) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		s := identityLine(id)
		if seen[s] {
			s = fmt.Sprintf("%s  ·  %s", s, shortKID(id.KID))
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// kidFor maps a displayed line back to the identity it came from.
func kidFor(ids []config.Identity, line string) string {
	for i, s := range identityChoices(ids) {
		if s == line {
			return ids[i].KID
		}
	}
	return ""
}

// identityLine is one identity as a person recognises it: what it was called,
// and where it puts them.
func identityLine(id config.Identity) string {
	label := strings.TrimSpace(id.Label)
	if label == "" {
		label = "(unnamed)"
	}
	return fmt.Sprintf("%s  —  %s", label, addrSummary(id.Addrs))
}

// addrSummary is the addresses a record claims. Decoded locally, with nothing
// vouching for it, and shown for recognition only - see config.Identity.Addrs.
func addrSummary(addrs []netip.Prefix) string {
	if len(addrs) == 0 {
		return "unreadable record"
	}
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

// shortKID is enough of a key identifier to tell two apart without filling a
// line with hex nobody reads.
func shortKID(kid string) string {
	if len(kid) <= 8 {
		return kid
	}
	return kid[:8] + "…"
}

// installChoosers gives a live session the window's way of asking.
//
// A method on ui rather than a field set at construction, because the session is
// built before the window is: main creates it, starts it watching, and only then
// calls build. Wiring the chooser at construction time is what left the field nil
// through every path except the one test that set it by hand.
func (u *ui) installChoosers() {
	ls, ok := u.sess.(*liveSession)
	if !ok {
		return
	}
	ls.ChooseIdentity = u.chooseIdentity
}
