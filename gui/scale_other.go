//go:build !linux

package main

// macOS and Windows are asked directly how large a pixel is and answer
// correctly, so there is nothing to correct. See scale_linux.go for what goes
// wrong on the platform that is not asked.
func alignScaleWithDesktop() (string, bool) { return "", false }
