package main

import (
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// encedoTheme carries the palette of the product page into the application, so
// the two do not look like different products. The tokens map across almost one
// for one, because the page was built on a token set of the same shape: a ground,
// a surface, three weights of ink, a rule, and two semantic colours.
//
// Those two are the whole argument in both places. "sealed" means inside the
// module; "exposed" means on the host, where anyone with access can read it.
// Nothing else in the palette competes with them, which is why connecting is the
// only thing tinted green and failure the only thing tinted rust.
type encedoTheme struct {
	// variant, when it is not variantAuto, overrides what the toolkit reports
	// the desktop is set to. The zero value follows the desktop, so an
	// encedoTheme{} means what it always meant.
	variant variantChoice
}

// variantChoice is what somebody asked for, which is not always what the desktop
// says.
//
// Two things make the desktop's answer wrong. The one that prompted this: an
// appearance setting belongs to the account a process runs as, so the window run
// under sudo — which it must be until the privileged helper lands — asks root
// and is told light, on a desktop that is set to dark. It comes up as the one
// pale window among dark ones, and there is nothing to say otherwise with. The
// other is simply that some people want one scheme regardless, which is a
// preference and not a bug.
type variantChoice int

const (
	variantAuto variantChoice = iota // follow the desktop
	variantLight
	variantDark
)

// themeFor turns what was typed into a theme, or says what it should have been.
// Refusing an unknown name rather than falling back to the desktop matters
// because the fallback looks exactly like the problem being worked around: a
// mistyped -theme dsrk would silently do nothing and read as the override not
// working.
func themeFor(name string) (encedoTheme, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "auto", "system":
		return encedoTheme{}, nil
	case "dark":
		return encedoTheme{variant: variantDark}, nil
	case "light":
		return encedoTheme{variant: variantLight}, nil
	}
	return encedoTheme{}, fmt.Errorf("unknown theme %q: expected auto, dark or light", name)
}

var _ fyne.Theme = encedoTheme{}

// Light and dark are peers, not an inversion: each was chosen against its own
// ground, as on the page.
var (
	lightPalette = palette{
		ground:  rgb(0xF1, 0xF4, 0xF3),
		surface: rgb(0xFF, 0xFF, 0xFF),
		sunken:  rgb(0xE7, 0xEB, 0xE9),
		ink:     rgb(0x0F, 0x14, 0x14),
		inkSoft: rgb(0x3A, 0x47, 0x46),
		muted:   rgb(0x6A, 0x77, 0x73),
		rule:    rgb(0xD5, 0xDC, 0xD9),
		sealed:  rgb(0x0F, 0x5F, 0x4B),
		exposed: rgb(0x94, 0x42, 0x2A),
		warning: rgb(0x8A, 0x63, 0x20),
		onDark:  rgb(0xF2, 0xF8, 0xF5),
	}
	darkPalette = palette{
		ground:  rgb(0x0A, 0x0E, 0x0E),
		surface: rgb(0x12, 0x19, 0x18),
		sunken:  rgb(0x06, 0x09, 0x09),
		ink:     rgb(0xE8, 0xF0, 0xED),
		inkSoft: rgb(0xAF, 0xBD, 0xB8),
		muted:   rgb(0x7C, 0x8C, 0x87),
		rule:    rgb(0x23, 0x2D, 0x2C),
		sealed:  rgb(0x47, 0xC6, 0xA3),
		exposed: rgb(0xDE, 0x84, 0x67),
		warning: rgb(0xD9, 0xA8, 0x5A),
		onDark:  rgb(0x06, 0x09, 0x09),
	}
)

type palette struct {
	ground, surface, sunken   color.Color
	ink, inkSoft, muted, rule color.Color
	sealed, exposed, warning  color.Color
	onDark                    color.Color
}

func rgb(r, g, b uint8) color.Color { return color.NRGBA{R: r, G: g, B: b, A: 255} }

func alpha(c color.Color, a uint8) color.Color {
	r, g, b, _ := c.RGBA()
	return color.NRGBA{R: uint8(r >> 8), G: uint8(g >> 8), B: uint8(b >> 8), A: a}
}

func (t encedoTheme) Color(name fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	// Every colour in the window arrives through here, including the ones the
	// widgets fetch themselves through theme.Color, so overriding the variant at
	// this one point covers the whole interface.
	switch t.variant {
	case variantLight:
		v = theme.VariantLight
	case variantDark:
		v = theme.VariantDark
	}

	p := darkPalette
	if v == theme.VariantLight {
		p = lightPalette
	}

	switch name {
	case theme.ColorNameBackground:
		return p.ground
	case theme.ColorNameForeground:
		return p.ink
	case theme.ColorNameForegroundOnPrimary, theme.ColorNameForegroundOnSuccess:
		return p.onDark
	case theme.ColorNamePrimary, theme.ColorNameSuccess:
		return p.sealed
	case theme.ColorNameError:
		return p.exposed
	case theme.ColorNameWarning:
		return p.warning
	case theme.ColorNameDisabled, theme.ColorNamePlaceHolder:
		return p.muted
	case theme.ColorNameSeparator:
		return p.rule
	case theme.ColorNameInputBackground, theme.ColorNameOverlayBackground,
		theme.ColorNameMenuBackground:
		return p.surface
	case theme.ColorNameInputBorder, theme.ColorNameDisabledButton:
		return p.rule
	case theme.ColorNameButton:
		return p.sunken
	case theme.ColorNameHover:
		return alpha(p.sealed, 28)
	case theme.ColorNameFocus, theme.ColorNameSelection:
		return alpha(p.sealed, 64)
	case theme.ColorNameScrollBar:
		return alpha(p.muted, 120)
	case theme.ColorNameShadow:
		return color.NRGBA{A: 60}
	}
	return theme.DefaultTheme().Color(name, v)
}

// Font falls through to the default for now. Fyne can embed a face through
// go:embed and return it here, which would carry the page's typography across
// every platform exactly — better than the page manages, since it has to name
// system stacks and hope. That waits on choosing and licensing a face; the
// palette is what makes the two look related, and it does not.
func (encedoTheme) Font(s fyne.TextStyle) fyne.Resource { return theme.DefaultTheme().Font(s) }

func (encedoTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }

// uiScale enlarges every metric uniformly. Fyne's defaults are dense for a
// window somebody glances at rather than works in, and the density was the
// complaint: text, padding and controls all read as too small at 100%.
//
// Multiplying the defaults rather than listing values keeps the proportions the
// toolkit already balanced — headings against body, padding against text — and
// leaves one number to argue about instead of a dozen. It composes with the
// display scale rather than replacing it: this decides how dense the interface
// is, the operating system decides how large a pixel is.
const uiScale = 1.5

func (encedoTheme) Size(n fyne.ThemeSizeName) float32 {
	// Every size here is in device-independent units, so this and the display
	// scale multiply cleanly. There is not a pixel constant in the program.
	return theme.DefaultTheme().Size(n) * uiScale
}
