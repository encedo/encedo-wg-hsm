//go:build !linux && !windows

package main

import "fyne.io/fyne/v2"

type chooserOwner = struct{}

func nativeOwner(fyne.Window) chooserOwner { return chooserOwner{} }

// nativeOpen has no system chooser to ask on this platform yet, so the window
// draws Fyne's. macOS has one, and it is part of the macOS plan rather than
// guessed at here without a machine to try it on.
func nativeOpen(chooserOwner, string) (string, bool, error) { return "", false, nil }
