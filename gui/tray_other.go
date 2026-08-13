//go:build !linux

package main

// macOS and Windows both have a tray, always, and registering with it does not
// depend on anything the user might not have installed. See tray_linux.go for
// the platform where that is not true.
func trayAvailable() bool { return true }
