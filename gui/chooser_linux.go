package main

import (
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver"

	"github.com/rymdport/portal"
	"github.com/rymdport/portal/filechooser"
)

// chooserOwner is the portal's name for the window the chooser belongs to:
// "x11:<id>", or empty, which the portal accepts and which leaves the chooser
// unparented.
type chooserOwner = string

// nativeOwner names the window for the portal. Only X11 can be named: under
// Wayland it takes an exported handle through xdg-foreign, which Fyne does not
// expose, so the chooser opens on its own there - still the system's, only not
// attached to the window.
func nativeOwner(w fyne.Window) chooserOwner {
	owner := ""
	if nw, ok := w.(driver.NativeWindow); ok {
		nw.RunNative(func(ctx any) {
			if x, ok := ctx.(driver.X11WindowContext); ok {
				owner = portal.FormatX11WindowHandle(x.WindowHandle)
			}
		})
	}
	return owner
}

// nativeOpen asks xdg-desktop-portal for one file, which draws the desktop's
// own chooser - GNOME's, KDE's, whichever is installed.
//
// Any failure to reach the portal is "not handled" rather than an error. A
// desktop without one - a bare window manager, a minimal install - is a system
// with no chooser to ask, and Fyne's own is the right answer there, not an
// error dialogue.
func nativeOpen(owner chooserOwner, title string) (path string, handled bool, err error) {
	conf := &filechooser.Filter{Name: "WireGuard configuration", Rules: []filechooser.Rule{{Type: filechooser.GlobPattern, Pattern: "*.conf"}}}
	all := &filechooser.Filter{Name: "All files", Rules: []filechooser.Rule{{Type: filechooser.GlobPattern, Pattern: "*"}}}
	uris, err := filechooser.OpenFile(owner, title, &filechooser.OpenFileOptions{
		AcceptLabel:   "Import",
		Filters:       []*filechooser.Filter{conf, all},
		CurrentFilter: conf,
	})
	if err != nil {
		return "", false, nil
	}
	if len(uris) == 0 {
		return "", true, nil
	}
	// A file:// URI, already unescaped by the library. Outside a sandbox it is
	// the file's own path; the portal hands out a document-store path only to
	// sandboxed callers.
	u, err := url.Parse(uris[0])
	if err != nil {
		return "", true, err
	}
	return u.Path, true, nil
}
