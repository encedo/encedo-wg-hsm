//go:build linux

package main

import "testing"

// A monitor that does not report its size is the case this exists for. VMware's
// virtual display says 0mm x 0mm, so the toolkit's calculation yields an
// infinite DPI, falls back to its baseline, and concludes 1 - while the desktop
// beside it is running at 2x.
func TestAMonitorWithNoSizeDetectsAsUnscaled(t *testing.T) {
	if got := fyneDetectedScale(0, 3420); got != 1 {
		t.Errorf("detected %v for a monitor reporting no size, want 1", got)
	}
}

// A real monitor reports millimetres over EDID, the toolkit's own calculation
// works, and the correction has to come out as nothing - this must never
// double-apply on the machines that were never wrong.
func TestARealMonitorNeedsNoCorrection(t *testing.T) {
	// A 27-inch 4K panel: 597 mm wide, 3840 px. 163 DPI against a baseline of
	// 120 is about 1.36.
	got := fyneDetectedScale(597, 3840)
	if got < 1.3 || got > 1.4 {
		t.Errorf("detected %v for a 4K 27-inch panel, want about 1.36", got)
	}
}

// An implausible DPI is replaced by the baseline rather than believed, which is
// what the toolkit does and therefore what predicting it has to do.
func TestAnAbsurdPhysicalSizeFallsBackToTheBaseline(t *testing.T) {
	// One millimetre wide would be 86,000 DPI.
	if got := fyneDetectedScale(1, 3420); got != 1 {
		t.Errorf("detected %v for an absurd physical size, want the baseline's 1", got)
	}
}

func TestTheConnectedMonitorLineIsParsed(t *testing.T) {
	line := "Virtual-1 connected primary 3420x2146+0+0 (normal left inverted right x axis y axis) 0mm x 0mm"
	m := connectedLine.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("the line xrandr actually prints did not parse:\n%s", line)
	}
	if m[1] != "3420" || m[2] != "0" {
		t.Errorf("parsed width %q px and %q mm", m[1], m[2])
	}

	real := "eDP-1 connected primary 2560x1600+0+0 (normal left inverted right x axis y axis) 301mm x 188mm"
	m = connectedLine.FindStringSubmatch(real)
	if m == nil || m[1] != "2560" || m[2] != "301" {
		t.Errorf("a monitor that does report its size did not parse: %v", m)
	}
}

func TestTheDPILineIsParsed(t *testing.T) {
	out := []byte("*customization:\t-color\nXft.dpi:\t192\nXft.antialias:\t1\n")
	m := xftLine.FindSubmatch(out)
	if m == nil {
		t.Fatal("Xft.dpi did not parse out of what xrdb prints")
	}
	if string(m[1]) != "192" {
		t.Errorf("read %q, want 192", m[1])
	}
}
