package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/encedo/encedo-wg-hsm/internal/provision"
	"github.com/encedo/encedo-wg-hsm/internal/wgconf"
)

// The import flow, which is the shortest way in for the person this client is
// for: somebody who already has a WireGuard tunnel and a file describing it.
//
// It is three screens rather than one, and the middle one is the point. A
// migration tool has to be believed at the moment it runs, because what it does
// is irreversible on the far side - somebody has to change a line on a server
// afterwards - and because the file it reads holds a private key that this
// client is about to leave behind on purpose. Showing what will be stored, what
// will not be carried, and what becomes of that key, before asking for a
// passphrase, is the difference between a tool that is trusted and one that is
// merely used.
//
// Nothing here needs the privileged component. Provisioning writes to the
// module over its own API and touches no interface, no route and no file, which
// is why the window can do it itself.

// onImport is the whole flow, from a file dialogue to a block somebody can
// paste into a server.
//
// The file comes from the system's own chooser where there is one. Fyne draws
// its own otherwise - a grid of folder icons with none of the places somebody
// keeps things, no search and no recent files - and a person who has just been
// emailed a .conf file is looking for it in the chooser they know. Fyne asks the
// system only in a Flatpak build, and the tag that turns that on also moves the
// notifications and link opening onto the portal with no fallback, so the
// chooser is asked for here instead, and Fyne's is what is left when there is no
// system chooser to ask.
func (u *ui) onImport() {
	// The owner is read here, on the main goroutine, because the chooser blocks
	// until somebody answers it and so is run off it.
	owner := nativeOwner(u.win)
	go func() {
		path, handled, err := nativeOpen(owner, "Import a WireGuard configuration")
		fyne.Do(func() {
			switch {
			case !handled:
				u.fyneOpen()
			case err != nil:
				dialog.ShowError(fmt.Errorf("The file chooser failed: %w", err), u.win)
			case path != "":
				u.previewPath(path)
			}
		})
	}()
}

// previewPath opens a file the system chooser named.
func (u *ui) previewPath(path string) {
	f, err := os.Open(path)
	if err != nil {
		dialog.ShowError(err, u.win)
		return
	}
	defer f.Close()
	u.previewImport(filepath.Base(path), f)
}

// fyneOpen is Fyne's own chooser, for a system that offers none.
func (u *ui) fyneOpen() {
	d := dialog.NewFileOpen(func(rc fyne.URIReadCloser, err error) {
		if err != nil || rc == nil {
			return
		}
		defer rc.Close()
		u.previewImport(rc.URI().Name(), rc)
	}, u.win)
	// wg-quick's own extension. Filtering to it is a suggestion rather than a
	// rule - the dialogue still allows anything, because a file somebody was
	// emailed is as likely to be called vpn.txt.
	d.SetFilter(storage.NewExtensionFileFilter([]string{".conf"}))
	d.Show()
}

// previewImport reads the file and says what an import would do with it.
//
// The parse happens here and not after the passphrase, so a file this client
// cannot honour is refused while somebody is still choosing files - and the
// refusal names what it could not carry rather than failing halfway through
// writing a configuration.
//
// It returns the controls it drew, which only the tests use.
func (u *ui) previewImport(name string, r io.Reader) *importPreview {
	conf, err := wgconf.Parse(r)
	if err != nil {
		dialog.ShowError(fmt.Errorf("%s cannot be imported as it is.\n\n%w", name, err), u.win)
		return nil
	}

	// A peer needs a name, and a .conf file has nowhere to carry one. The file
	// name is the best guess available and is usually right - people call these
	// after the place they connect to - so it is offered filled in rather than
	// asked for blank.
	label := widget.NewEntry()
	label.SetText(peerNameFrom(name))
	label.Validator = validPeerName

	summary := widget.NewLabel(importSummary(conf))
	summary.Wrapping = fyne.TextWrapWord
	warning := widget.NewLabel(importWarning(conf))
	warning.Wrapping = fyne.TextWrapWord
	warning.Importance = widget.WarningImportance

	// The passphrase is asked for here, not taken from the field on the main
	// screen. It used to be: pressing Import with that field empty closed this
	// dialogue and put a sentence on the main screen, which read as nothing
	// having happened at all - and whether it had was exactly the question.
	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("HEM passphrase")

	// Progress and failure are said in the dialogue that caused them, which
	// stays open until the module has answered.
	// Hidden until it has something to say, so the row it takes goes to the
	// summary instead.
	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord
	status.Hide()

	body := container.NewBorder(
		nil,
		container.NewVBox(
			container.New(layout.NewFormLayout(),
				widget.NewLabel("call this peer"), label,
				widget.NewLabel("passphrase"), pass),
			status),
		nil, nil,
		container.NewVScroll(container.NewVBox(summary, warning)),
	)

	d := dialog.NewCustomWithoutButtons("Import a tunnel", body, u.win)
	cancel := widget.NewButton("Cancel", d.Hide)
	importBtn := widget.NewButton("Import", nil)
	importBtn.Importance = widget.HighImportance

	say := func(text string, importance widget.Importance) {
		status.Importance = importance
		status.SetText(text)
		status.Show()
	}
	busy := func(on bool) {
		for _, w := range []fyne.Disableable{label, pass, importBtn, cancel} {
			if on {
				w.Disable()
			} else {
				w.Enable()
			}
		}
	}

	importBtn.OnTapped = func() {
		if err := validPeerName(label.Text); err != nil {
			say(err.Error(), widget.DangerImportance)
			return
		}
		if pass.Text == "" {
			say("Type the module passphrase - importing writes to it.", widget.WarningImportance)
			u.win.Canvas().Focus(pass)
			return
		}
		params, err := provision.FromConf(conf, strings.TrimSpace(label.Text))
		if err != nil {
			say(humanError(err), widget.DangerImportance)
			return
		}
		secret := []byte(pass.Text)
		pass.SetText("")

		// Cancel goes too. The write cannot be taken back once it has started,
		// and a dialogue dismissed halfway would leave somebody with a new key
		// in the module and nobody told what to send the server.
		busy(true)
		say("Importing - this takes a few seconds while the module works.", widget.MediumImportance)

		// Off this goroutine for the same reason connecting is: deriving the key
		// from the passphrase is 600,000 rounds of PBKDF2, and doing that here
		// freezes the window hard enough that the desktop offers to kill it.
		go func() {
			res, err := u.sess.Import(context.Background(), secret, params)
			fyne.Do(func() {
				busy(false)
				if err != nil {
					say(humanError(err), widget.DangerImportance)
					return
				}
				d.Hide()
				u.showHandoff(res)
			})
		}()
	}
	pass.OnSubmitted = func(string) { importBtn.OnTapped() }

	d.SetButtons([]fyne.CanvasObject{cancel, importBtn})
	d.Resize(fyne.NewSize(windowWidth-dialogInset, compactHeight-40*uiScale))
	d.Show()
	return &importPreview{pass: pass, status: status, importBtn: importBtn}
}

// importPreview is what previewImport drew, so a test can press its buttons.
type importPreview struct {
	pass      *widget.Entry
	status    *widget.Label
	importBtn *widget.Button
}

// importSummary is the middle screen: where the tunnel goes and what it
// carries, in sentences.
//
// It used to be the whole configuration in a monospace block - addresses, DNS,
// MTU, the peer's base64 key - under a paragraph about the private key, and in
// a dialogue inside a window this narrow every line was cut off at the right
// and the rest scrolled. None of those fields changes whether somebody presses
// Import: they came from the file somebody chose, and they go into the module
// unchanged. What does change it is where the tunnel leads and whether it takes
// all their traffic, so that is what is said.
func importSummary(c *wgconf.Conf) string {
	var lines []string
	if c.PeerEndpoint != "" {
		host := c.PeerEndpoint
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		lines = append(lines, "Connects to "+host+".")
	} else {
		lines = append(lines, "Waits for the server to connect - the file names no address for it.")
	}
	if len(c.Addresses) > 0 {
		var addrs []string
		for _, a := range c.Addresses {
			addrs = append(addrs, hostAddr(a))
		}
		lines = append(lines, "Your address in the tunnel: "+strings.Join(addrs, ", ")+".")
	}
	lines = append(lines, routesSentence(c.PeerAllowed))
	return strings.Join(lines, "\n")
}

// importWarning is the two things that happen whether or not anybody reads the
// rest, which is why they are the ones in colour.
//
// The private key is named because it is what somebody is most likely to be
// uneasy about, and the unease is the correct instinct - a key that has sat in
// a text file is already out. Saying so plainly is worth more than saying it
// quietly.
func importWarning(c *wgconf.Conf) string {
	s := "The server has to be given a new key - the next screen shows it."
	if c.HadPrivateKey {
		s += "\nThe private key in this file is not imported, but it still works: " +
			"delete the file once the tunnel is up."
	}
	return s
}

// hostAddr drops the prefix length from a single-host address, which is what
// every client address is and what nobody needs to read "/32" after.
func hostAddr(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

// routesSentence says how much traffic the tunnel takes, which is the one fact
// in AllowedIPs somebody importing a file cares about.
func routesSentence(allowed []netip.Prefix) string {
	var nets []string
	for _, p := range allowed {
		if p.Bits() == 0 {
			return "All your traffic goes through the tunnel."
		}
		nets = append(nets, p.String())
	}
	switch len(nets) {
	case 0:
		return "No traffic is routed through the tunnel - the file lists no networks."
	case 1, 2:
		return "Only " + strings.Join(nets, " and ") + " goes through the tunnel."
	default:
		return fmt.Sprintf("Only %s and %d more networks go through the tunnel.", nets[0], len(nets)-1)
	}
}

// showHandoff is the last screen: the one line the server has to change, and a
// button that copies it.
//
// Only the public key. It used to be the whole [Peer] block, but an import
// replaces a tunnel the server already has: the address, the routes and the
// endpoint are the ones it was configured with, and the key is the one thing
// that moved. A block invited somebody to paste an entry beside the old one,
// which leaves two peers claiming the same address.
//
// The copy button is the reason this screen exists rather than a sentence
// saying "run wg-hem status". Retyping a public key is the one step in the
// whole flow where a mistake passes unnoticed - the tunnel simply never
// completes a handshake, and nothing anywhere says why.
func (u *ui) showHandoff(res provision.Result) {
	key := res.Server.PublicKey

	head := widget.NewLabel("Imported. On the server, this peer's PublicKey changes to:")
	head.Wrapping = fyne.TextWrapWord

	text := widget.NewLabel(key)
	text.Selectable = true

	copied := widget.NewLabel("")
	copyBtn := widget.NewButton("Copy", func() {
		u.win.Clipboard().SetContent(key)
		copied.SetText("Copied.")
	})

	tail := widget.NewLabel("Nothing else in its entry changes. The tunnel connects once the server has the new key.")
	tail.Wrapping = fyne.TextWrapWord

	body := container.NewVBox(head, text,
		container.NewBorder(nil, nil, nil, copyBtn, copied),
		tail)

	d := dialog.NewCustom("Tell the server", "Done", body, u.win)
	d.Resize(fyne.NewSize(windowWidth-dialogInset, compactHeight-40*uiScale))
	d.Show()
}

// peerNameFrom turns a file name into a peer name, since the file has nowhere
// to carry one and its name is usually what somebody would have typed anyway.
func peerNameFrom(file string) string {
	name := file
	if i := strings.LastIndex(name, "."); i > 0 {
		name = name[:i]
	}
	// The characters a peer specification uses as its own punctuation. A file
	// called "hq,backup.conf" would otherwise produce a name that splits into
	// two fields somewhere further down.
	name = strings.NewReplacer(",", " ", "=", " ").Replace(name)
	name = strings.TrimSpace(name)
	if name == "" {
		return "peer"
	}
	return name
}

// validPeerName refuses what the stored form cannot carry, at the moment
// somebody types it rather than after the passphrase.
func validPeerName(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("the peer needs a name - it is what the tunnel screen will show")
	}
	if strings.ContainsAny(s, ",=") {
		return fmt.Errorf("a name cannot contain a comma or an equals sign")
	}
	return nil
}
