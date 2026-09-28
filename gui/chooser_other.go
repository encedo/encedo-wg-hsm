//go:build !linux && !windows && !darwin

package main

import "fyne.io/fyne/v2"

type chooserOwner = struct{}

func nativeOwner(fyne.Window) chooserOwner { return chooserOwner{} }

// nativeOpen has no system chooser to ask on this platform, so the window draws
// Fyne's. Linux, Windows and macOS each have their own file.
func nativeOpen(chooserOwner, string) (string, bool, error) { return "", false, nil }
