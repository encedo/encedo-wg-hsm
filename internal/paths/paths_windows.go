package paths

import (
	"os"
	"path/filepath"
)

// RunDir is where a running interface leaves its public key and, for wg-hem,
// its state file. The UAPI is a named pipe on this platform and does not live
// here.
//
// %ProgramData% is what /var/run means on Windows: data a service owns, written
// by administrators and readable by everyone. The Unix path the other platforms
// use would not have failed - Go would have rooted it on whichever drive
// happened to be current and made C:\var\run\wireguard, self-consistent and in a
// place no administrator would think to look.
var RunDir = programDataDir()

func programDataDir() string {
	if pd := os.Getenv("ProgramData"); pd != "" {
		return filepath.Join(pd, "WireGuard")
	}
	return `C:\ProgramData\WireGuard`
}
