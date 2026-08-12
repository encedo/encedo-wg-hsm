package main

import (
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// TestThemeOverride checks the one thing that could regress silently: a forced
// scheme has to win over what the toolkit reports, in both directions. If it
// stops winning, the window still draws — in the wrong colours, on the platform
// where nobody is looking, which is exactly how this was noticed in the first
// place.
func TestThemeOverride(t *testing.T) {
	ground := func(th encedoTheme, v fyne.ThemeVariant) interface{} {
		return th.Color(theme.ColorNameBackground, v)
	}
	dark := ground(encedoTheme{}, theme.VariantDark)
	light := ground(encedoTheme{}, theme.VariantLight)
	if dark == light {
		t.Fatal("the two palettes share a ground; the rest of this test proves nothing")
	}

	cases := []struct {
		name string
		th   encedoTheme
		told fyne.ThemeVariant
		want interface{}
	}{
		{"auto follows dark", encedoTheme{}, theme.VariantDark, dark},
		{"auto follows light", encedoTheme{}, theme.VariantLight, light},
		{"forced dark over light", encedoTheme{variant: variantDark}, theme.VariantLight, dark},
		{"forced light over dark", encedoTheme{variant: variantLight}, theme.VariantDark, light},
	}
	for _, tc := range cases {
		if got := ground(tc.th, tc.told); got != tc.want {
			t.Errorf("%s: background = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestThemeFor covers the names accepted on the command line. The unknown case
// is the point: falling back to the desktop would be indistinguishable from the
// override not working, which is why themeFor refuses instead.
func TestThemeFor(t *testing.T) {
	for _, name := range []string{"", "auto", "system", "Dark", " light "} {
		if _, err := themeFor(name); err != nil {
			t.Errorf("themeFor(%q) = %v, want it accepted", name, err)
		}
	}
	if _, err := themeFor("dsrk"); err == nil {
		t.Error("themeFor(\"dsrk\") was accepted; a typo must be reported, not ignored")
	}
}
