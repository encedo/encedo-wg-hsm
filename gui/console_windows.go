package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// attachConsole gives this program somewhere to print on Windows, without
// taking away somewhere it already had.
//
// The window is linked with -H=windowsgui, which is what stops a black console
// rectangle appearing behind it at every launch. The cost is that a process in
// that subsystem is started with no console, so run from a prompt its output
// went nowhere: `encedo-wg-gui.exe -version` printed silence, and the installer
// comparing the two halves' stamps read an empty string.
//
// The first attempt at this attached and then pointed the standard handles at
// CONOUT$ unconditionally, which fixed the wrong half of the problem. A person
// could see the version; a script still could not read it. PowerShell captures a
// child's output by handing it a pipe, and writing to the console device instead
// walks straight past that pipe - so the text appeared on screen, above the
// installer's complaint that nothing had been printed.
//
// So the handle decides. If this process was given a usable one - a pipe from a
// caller that wants the output, a file it was redirected to - it is left exactly
// as it is, because somebody has already said where the output should go.
// Only when there is none is a console attached and CONOUT$ opened, which is the
// case that was broken: a prompt that redirected nothing.
//
// Launched from the Start menu there is neither a handle nor a parent console,
// both steps fail, and that is correct rather than a fault: a window opened by
// clicking has nobody to print to.
func attachConsole() {
	if usableStdout() {
		return
	}

	// ATTACH_PARENT_PROCESS. Not in x/sys/windows, so it is spelled out: the
	// documented value is (DWORD)-1.
	const attachParentProcess = ^uintptr(0)

	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")
	if r, _, _ := proc.Call(attachParentProcess); r == 0 {
		return
	}

	// Attaching is not enough on its own. The standard handles were bound to
	// nothing when the process started and stay that way, so they are reopened
	// onto the console device by name.
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
		os.Stderr = out
	}
}

// usableStdout reports whether this process was handed somewhere to write.
//
// GetStdHandle answers with a handle that may be nothing at all, and a zero or
// invalid one is what a GUI-subsystem process gets from a caller that did not
// redirect it. GetFileType is the second half of the question: a handle can be
// present and still refer to nothing, and FILE_TYPE_UNKNOWN with an error is how
// that says so.
func usableStdout() bool {
	h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil || h == 0 || h == windows.InvalidHandle {
		return false
	}
	t, err := windows.GetFileType(h)
	return err == nil && t != windows.FILE_TYPE_UNKNOWN
}
