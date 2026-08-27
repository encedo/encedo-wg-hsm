package main

import (
	"context"
	"fmt"
	"io"
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
func (u *ui) onImport() {
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
func (u *ui) previewImport(name string, r io.Reader) {
	conf, err := wgconf.Parse(r)
	if err != nil {
		dialog.ShowError(fmt.Errorf("%s cannot be imported as it is.\n\n%w", name, err), u.win)
		return
	}

	// A peer needs a name, and a .conf file has nowhere to carry one. The file
	// name is the best guess available and is usually right - people call these
	// after the place they connect to - so it is offered filled in rather than
	// asked for blank.
	label := widget.NewEntry()
	label.SetText(peerNameFrom(name))
	label.Validator = validPeerName

	summary := widget.NewLabel(importSummary(conf))
	summary.TextStyle = fyne.TextStyle{Monospace: true}

	body := container.NewBorder(
		widget.NewLabel("This is what would be written into the module."),
		container.New(layout.NewFormLayout(), widget.NewLabel("call this peer"), label),
		nil, nil,
		container.NewVScroll(summary),
	)

	d := dialog.NewCustomConfirm("Import "+name, "Import", "Cancel", body, func(ok bool) {
		if !ok {
			return
		}
		if err := validPeerName(label.Text); err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		u.runImport(conf, strings.TrimSpace(label.Text))
	}, u.win)
	d.Resize(fyne.NewSize(windowWidth-dialogInset, compactHeight-40*uiScale))
	d.Show()
}

// importSummary is the middle screen: what lands in the module, and what is
// left behind.
//
// The private key is named first because it is the thing somebody is most
// likely to be uneasy about, and the uneasiness is the correct instinct - a key
// that has sat in a text file is already out. Saying it plainly is worth more
// than saying it quietly.
func importSummary(c *wgconf.Conf) string {
	var b strings.Builder

	if c.HadPrivateKey {
		b.WriteString("The private key in this file is NOT imported.\n")
		b.WriteString("A new one is generated inside the module and never\n")
		b.WriteString("leaves it. The old key stays in the file, and stays\n")
		b.WriteString("as usable as it was - delete the file once this works.\n\n")
	}

	b.WriteString("Stored in the module:\n")
	for _, a := range c.Addresses {
		fmt.Fprintf(&b, "  address       %s\n", a)
	}
	for _, d := range c.DNS {
		fmt.Fprintf(&b, "  dns           %s\n", d)
	}
	if c.MTU != 0 {
		fmt.Fprintf(&b, "  mtu           %d\n", c.MTU)
	}
	if c.ListenPort != 0 {
		fmt.Fprintf(&b, "  listen port   %d\n", c.ListenPort)
	}
	fmt.Fprintf(&b, "  peer key      %s\n", c.PeerPubKey)
	if c.PeerEndpoint != "" {
		fmt.Fprintf(&b, "  peer endpoint %s\n", c.PeerEndpoint)
	}
	for _, p := range c.PeerAllowed {
		fmt.Fprintf(&b, "  routes        %s\n", p)
	}
	if c.PeerKeepalive != 0 {
		fmt.Fprintf(&b, "  keepalive     %ds\n", c.PeerKeepalive)
	}

	b.WriteString("\nAfterwards the tunnel will not come up until the server\n")
	b.WriteString("is told the new public key. The last screen has the exact\n")
	b.WriteString("lines to send.\n")
	return b.String()
}

// runImport does the work, having asked for everything it needs first.
func (u *ui) runImport(c *wgconf.Conf, label string) {
	pass := []byte(u.pass.Text)
	if len(pass) == 0 {
		u.setNotice("Type the module passphrase first - importing writes to it.", false)
		return
	}
	u.pass.SetText("")

	params, err := provision.FromConf(c, label)
	if err != nil {
		dialog.ShowError(err, u.win)
		return
	}

	u.setNotice("Importing - this takes a few seconds while the module works.", false)

	// Off this goroutine for the same reason connecting is: deriving the key
	// from the passphrase is 600,000 rounds of PBKDF2, and doing that here
	// freezes the window hard enough that the desktop offers to kill it.
	go func() {
		res, err := u.sess.Import(context.Background(), pass, params)
		fyne.Do(func() {
			if err != nil {
				u.setNotice(humanError(err), true)
				return
			}
			u.showHandoff(res)
		})
	}()
}

// showHandoff is the last screen: the lines an administrator has to be sent,
// and a button that copies them.
//
// The copy button is the whole reason this screen exists rather than a sentence
// saying "run wg-hem status". Retyping a public key is the one step in the
// entire flow where a mistake passes unnoticed - the tunnel simply never
// completes a handshake, and nothing anywhere says why.
func (u *ui) showHandoff(res provision.Result) {
	block := res.Server.ConfBlock()

	text := widget.NewLabel(block)
	text.TextStyle = fyne.TextStyle{Monospace: true}

	copied := widget.NewLabel("")
	copyBtn := widget.NewButton("Copy", func() {
		u.win.Clipboard().SetContent(block)
		copied.SetText("Copied.")
	})

	head := widget.NewLabel("Imported. Send these lines to whoever runs the server:\n" +
		"they replace the peer entry this machine already has.")
	head.Wrapping = fyne.TextWrapWord

	body := container.NewBorder(head,
		container.NewBorder(nil, nil, nil, copyBtn, copied),
		nil, nil,
		container.NewVScroll(text))

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
