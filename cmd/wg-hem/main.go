// Command wg-hem provisions and runs a WireGuard client that keeps no
// configuration file and no key material on the host. Everything — the identity
// key, the peer keys, the addresses, routes and DNS, and the MAC that
// authenticates all of it — lives inside an Encedo HEM.
//
// See docs/ENCEDO-WG-CONFIGFREE-SPEC.md.
package main

import (
	"errors"
	"fmt"
	"os"
)

// Exit codes are distinct so a script can tell a wrong password from an
// unreachable device from a configuration that failed authentication (§10.4).
const (
	exitOK       = 0
	exitUsage    = 1
	exitAuth     = 2
	exitNetwork  = 3
	exitIntegrit = 4
	exitDevice   = 5
)

// pubKeyLen is the length of a Curve25519 public key.
const pubKeyLen = 32

// defaultHEM is the PPA's fixed address. It is what lets `wg-hem up` run with
// no arguments at all: the device is always at the same place on the USB link.
const defaultHEM = "https://192.168.7.1"

// exitError carries the code a failure should exit with.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func failf(code int, format string, args ...any) error {
	return &exitError{code: code, err: fmt.Errorf(format, args...)}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}

	var err error
	switch os.Args[1] {
	case "provision":
		err = cmdProvision(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		os.Exit(exitOK)
	default:
		fmt.Fprintf(os.Stderr, "wg-hem: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(exitUsage)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "wg-hem: %v\n", err)
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(exitDevice)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `wg-hem — WireGuard with no config file and no keys on disk

Usage:
  wg-hem provision [flags]    write a configuration into the HEM
  wg-hem verify [flags]       check the stored configuration and print it

Run "wg-hem <command> -h" for a command's flags.

Exit codes: 0 ok, 1 usage, 2 authentication, 3 network, 4 integrity, 5 device.
`)
}
