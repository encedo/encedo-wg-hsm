package main

import (
	"context"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

const (
	controlFlagUsage = "named pipe to listen on"
	// The Unix flag names a group. There is no group here that means the same
	// thing, and inventing one at install time to imitate Linux would be a local
	// group nobody asked for. What decides access on this platform is the
	// descriptor, so the flag takes one, under the same name so that the two
	// platforms document the same idea in the same place.
	controlAccessFlagUsage = "SDDL security descriptor for the pipe (default: SYSTEM and Administrators in full, authenticated users may connect)"
)

// defaultSocket is where the window will look.
//
// A pipe rather than a path: named pipes live in their own namespace and not on
// a disk, so nothing here is under %ProgramData% alongside the state file. It is
// also why there is no leftover to clean up before listening - a pipe with no
// server ceases to exist, which is the failure mode the Unix side needs a whole
// paragraph about.
func defaultSocket() string { return `\\.\pipe\encedo-wg` }

// defaultPipeSDDL is who may reach the component.
//
// Read as: full control for LocalSystem (SY) and for the Administrators group
// (BA), and generic read and write for Authenticated Users (AU). The DACL is
// protected (P) so that nothing is inherited into it from anywhere.
//
// Authenticated Users is wider than the `wireguard` group the Linux package
// creates, and it is deliberate rather than lazy. Connecting is not itself a
// privilege: every verb that does anything carries a token the caller obtained
// by authenticating to the device, and the component mints nothing of its own.
// What connecting does grant is the ability to *ask*, and the answers to the two
// questions that matter - whose tunnel is this, who may stop it - come from
// impersonating the caller rather than from the fact they got this far.
//
// The mandatory label (S:) is the part that is easy to leave off and worth
// having: no write up from a low integrity level, so a sandboxed process on the
// same account cannot drive a tunnel that the account's own desktop can.
const defaultPipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)S:(ML;;NW;;;LW)"

// listenOn opens the pipe the window will find, and settles who may reach it.
//
// The descriptor is applied at creation, which is the one respect in which this
// is better than the Unix side: there, the socket exists for an instant with
// whatever mode the umask gave it before Chmod runs. Here there is no such
// instant.
func listenOn(path, sddl string) (net.Listener, error) {
	if sddl == "" {
		sddl = defaultPipeSDDL
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, failf(exitUsage, "the pipe's security descriptor (%s): %w", sddl, err)
	}

	ln, err := (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(path)
	if err != nil {
		// A pipe name already in use fails here, which is the equivalent of the
		// Unix side's refusal to take over a live socket - and needs no leftover
		// check, because a pipe nobody is serving does not exist.
		return nil, failf(exitDevice, "listening on %s: %w", path, err)
	}
	return ln, nil
}

// dialControl opens the channel to a running component, for the diagnostic that
// asks it who is calling.
//
// go-winio and not the namedpipe package three lines above, which is the odd
// thing about this file and the reason worth writing down. Upstream's fork of
// that library dropped the knob: tryDialPipe hardcodes
// SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS and DialConfig exposes only
// ExpectedOwner, so every connection made through it is anonymous and there is
// no argument that changes it. The component would identify such a caller as
// S-1-5-7 and refuse it - correctly, and confusingly, since the caller would be
// this program.
//
// Fine for what upstream uses it for: it dials the UAPI pipe, whose descriptor
// admits only SYSTEM and Administrators, so the level never mattered there. It
// matters here, because identity is the authorisation.
func dialControl(path string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return winio.DialPipeAccessImpLevel(ctx, path,
		windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}
