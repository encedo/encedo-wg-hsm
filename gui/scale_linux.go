package main

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Fyne works out how large a pixel is from the monitor's physical size — width
// in millimetres against width in pixels — and on Linux that is the only thing
// it looks at. It never reads the desktop's own scaling setting, unlike macOS
// and Windows, where the system answers directly.
//
// Which is fine until something does not know its own size. Measured on
// 2026-08-13, on Ubuntu under VMware Fusion:
//
//	Virtual-1 connected primary 3420x2146+0+0 ... 0mm x 0mm
//	Xft.dpi: 192
//
// The desktop is running at 2×, says so the standard X11 way, and the virtual
// monitor reports no physical size at all — so Fyne falls back to 1.0 and the
// window comes out at half the size of everything around it. A real monitor
// reports millimetres over EDID and none of this applies, which is why the same
// build looks right on hardware.
//
// So: work out what Fyne is about to conclude, work out what the desktop is
// actually doing, and only correct the difference. Where Fyne already agrees
// with the desktop the correction is 1 and nothing is set — this must not
// double-apply on the machines that were never wrong.

// baseDPI is the X11 convention: Xft.dpi of 96 means no scaling. GTK reads it
// the same way, which is what makes matching it the right target — the window
// should be the size of the windows beside it.
const baseDPI = 96.0

// fyneBaselineDPI is Fyne's own, from internal/driver/glfw/scale.go. Repeated
// here because predicting its conclusion is the whole method, and a copy that
// drifts would silently start over-correcting.
const fyneBaselineDPI = 120.0

// alignScaleWithDesktop sets FYNE_SCALE when the toolkit is about to disagree
// with the desktop, and returns what it did for anyone reporting it.
//
// It must run before the toolkit starts, since that is when the variable is
// read; and it never overrides one that is already set, because somebody who
// typed it means it.
func alignScaleWithDesktop() (string, bool) {
	if os.Getenv("FYNE_SCALE") != "" {
		return "", false
	}
	dpi, ok := xftDPI()
	if !ok {
		return "", false
	}
	widthMm, widthPx, ok := primaryMonitor()
	if !ok {
		return "", false
	}

	desired := dpi / baseDPI
	detected := fyneDetectedScale(widthMm, widthPx)
	if detected <= 0 {
		return "", false
	}

	correction := desired / detected
	// A tenth is below what anybody can see and above the rounding in both
	// calculations; correcting inside it would be noise.
	if correction > 0.9 && correction < 1.1 {
		return "", false
	}
	value := strconv.FormatFloat(float64(correction), 'f', 2, 32)
	os.Setenv("FYNE_SCALE", value)
	return value, true
}

// fyneDetectedScale reproduces what the toolkit will conclude from the monitor,
// including its fallback: a physical size that yields an implausible DPI — zero
// millimetres yields infinity — is replaced by its baseline, which is how a
// monitor that does not know its own size ends up at 1.
func fyneDetectedScale(widthMm, widthPx int) float64 {
	dpi := fyneBaselineDPI
	if widthMm > 0 {
		if d := float64(widthPx) / (float64(widthMm) / 25.4); d >= 10 && d <= 1000 {
			dpi = d
		}
	}
	if scale := dpi / fyneBaselineDPI; scale > 1 {
		return scale
	}
	return 1
}

var xftLine = regexp.MustCompile(`(?m)^Xft\.dpi:\s*([0-9.]+)`)

// xftDPI reads what the desktop says a pixel is worth. GNOME sets it, GTK reads
// it, and it is the one number here that reflects a person's choice rather than
// a measurement.
func xftDPI() (float64, bool) {
	out, err := exec.Command("xrdb", "-query").Output()
	if err != nil {
		return 0, false
	}
	m := xftLine.FindSubmatch(out)
	if m == nil {
		return 0, false
	}
	dpi, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil || dpi <= 0 {
		return 0, false
	}
	return dpi, true
}

var connectedLine = regexp.MustCompile(`^\S+ connected (?:primary )?(\d+)x\d+\+\d+\+\d+.*?(\d+)mm x \d+mm`)

// primaryMonitor reports the width the toolkit will measure against, in pixels
// and in millimetres. The primary display when one is marked, otherwise the
// first connected one — the same order the toolkit would arrive at for a window
// that has not been moved anywhere yet.
func primaryMonitor() (widthMm, widthPx int, ok bool) {
	out, err := exec.Command("xrandr", "--query").Output()
	if err != nil {
		return 0, 0, false
	}
	var first [2]int
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		m := connectedLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		px, _ := strconv.Atoi(m[1])
		mm, _ := strconv.Atoi(m[2])
		if strings.Contains(line, " primary ") {
			return mm, px, true
		}
		if !found {
			first, found = [2]int{mm, px}, true
		}
	}
	if !found {
		return 0, 0, false
	}
	return first[0], first[1], true
}
