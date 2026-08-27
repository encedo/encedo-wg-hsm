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

		body, chosen := identityChooser(ids)

		d := dialog.NewCustomConfirm("Choose a profile", "Use this one", "Cancel", body,
			func(ok bool) {
				if !ok || chosen() == "" {
					answer <- ""
					return
				}
				answer <- kidFor(ids, chosen())
			}, u.win)
		d.Show()
	})

	kid := <-answer
	if kid == "" {
		return "", errNoProfileChosen
	}
	return kid, nil
}

// identityChooser builds what the dialogue shows, and a way to read back what
// was picked.
//
// Separate from showing it so the thing can be measured. The window is a fixed
// size by choice, and a dialogue is drawn inside it: content wider than the
// window is not scrolled or wrapped, it is simply cut off, and the half of a
// line that survives is the half that says "wg-hem identity" on every entry.
// The addresses - the part that tells two profiles apart - are at the end.
// TestIdentityChooserFits is what stops that happening silently.
//
// The list is scrolled rather than stacked, because the number of identities is
// somebody else's decision. Three fit; a module with eight would otherwise push
// the buttons off the bottom of a window that cannot grow.
func identityChooser(ids []config.Identity) (fyne.CanvasObject, func() string) {
	var chosen string
	list := widget.NewRadioGroup(identityChoices(ids), func(s string) { chosen = s })
	list.Required = true

	scroll := container.NewVScroll(list)
	scroll.SetMinSize(fyne.NewSize(0, chooserListHeight))

	body := container.NewBorder(
		widget.NewLabel("This module holds more than one configuration.\nWhich one should this tunnel use?"),
		nil, nil, nil,
		scroll,
	)
	return body, func() string { return chosen }
}

// chooserListHeight is how much of the list is on screen before it scrolls. It
// is three rows: enough that the common case - a second configuration imported
// beside the first - never scrolls at all, and small enough that the dialogue
// fits a window which does not resize.
const chooserListHeight = 3 * 34 * uiScale

// identityChoices renders one line per identity, in the order the device
// reported them.
//
// A radio group identifies its selection by the string it displays, so these
// have to be unique or two profiles become one. Uniqueness cannot come from the
// label: `provision` defaults every identity to "wg-hem identity", so a module
// with two imported configurations has two of them, and that is the common case
// rather than a corner. The addresses usually separate them; when they do not,
// the key identifier does, and it is the only thing here guaranteed to.
//
// A duplicate has its label replaced by that identifier rather than extended
// with it. Appending was the obvious thing and it did not fit - measured at
// 430 points against a window of 420, and a line too wide is not wrapped or
// scrolled but cut, taking the addresses with it. Substituting keeps the line
// the length it already was, and loses only a label that had told nobody
// anything: every entry it appears on says the same word.
func identityChoices(ids []config.Identity) []string {
	out := make([]string, 0, len(ids))
	count := make(map[string]int, len(ids))
	for _, id := range ids {
		count[identityLine(id, "")]++
	}
	for _, id := range ids {
		line := identityLine(id, "")
		if count[line] > 1 {
			line = identityLine(id, shortKID(id.KID))
		}
		out = append(out, line)
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
// and where it puts them. instead, when not empty, stands in for the label.
func identityLine(id config.Identity, instead string) string {
	label := instead
	if label == "" {
		label = truncate(strings.TrimSpace(id.Label), labelRunes)
	}
	if label == "" {
		label = "(unnamed)"
	}
	return fmt.Sprintf("%s  —  %s", label, addrSummary(id.Addrs))
}

// labelRunes is how much of a label survives. A name long enough to push the
// addresses off the end costs more than it carries.
const labelRunes = 18

// addrSummary is the addresses a record claims. Decoded locally, with nothing
// vouching for it, and shown for recognition only - see config.Identity.Addrs.
//
// One address, and a count of the rest. An identity with a v4 and a v6 address
// is one machine in one place, and spelling out both doubles the length of the
// line to say so twice.
func addrSummary(addrs []netip.Prefix) string {
	switch len(addrs) {
	case 0:
		return "unreadable record"
	case 1:
		return addrs[0].String()
	default:
		return fmt.Sprintf("%s  +%d", addrs[0], len(addrs)-1)
	}
}

// truncate keeps a string to n runes, marking where it was cut. Runes and not
// bytes: a label may be in any script somebody names a laptop in.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
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
