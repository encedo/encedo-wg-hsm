//go:build !windows

package main

// attachConsole has nothing to do here. Every other platform starts a process
// with its parent's standard handles already attached, whatever subsystem it
// was linked for; the problem it solves is specific to -H=windowsgui.
func attachConsole() {}
