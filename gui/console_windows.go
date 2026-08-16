package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// attachConsole gives this program somewhere to print on Windows.
//
// The window is linked with -H=windowsgui, which is what stops a black console
// rectangle appearing behind it at every launch. The cost is that the process
// starts with no console at all, so os.Stdout and os.Stderr are handles that go
// nowhere: `encedo-wg-gui.exe -version` from a command prompt printed nothing,
// silently, and the installer comparing the two halves' stamps read an empty
// string and refused a pair that matched perfectly well.
//
// AttachConsole joins the console of whoever started us, when there is one. Run
// from a prompt there is; run from the Start menu or a shortcut there is not,
// and the call fails, which is the correct outcome and not an error worth
// reporting - a window launched by clicking has nobody to print to and does not
// want a console conjured for it.
//
// Attaching is not enough on its own. The standard handles were bound to nothing
// when the process started and stay that way, so they are reopened onto the
// console device by name. CONOUT$ is that device, and it is the console we just
// joined rather than any particular file.
func attachConsole() {
	// ATTACH_PARENT_PROCESS. Not in x/sys/windows, so it is spelled out: the
	// documented value is (DWORD)-1.
	const attachParentProcess = ^uintptr(0)

	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")
	if r, _, _ := proc.Call(attachParentProcess); r == 0 {
		return
	}

	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
		os.Stderr = out
	}
}
