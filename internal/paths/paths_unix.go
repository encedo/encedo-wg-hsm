//go:build !windows

package paths

// RunDir is where a running interface leaves its UAPI socket, its public key
// and, for wg-hem, its state file. The private key is not there and never will
// be: the device is configured with a zeroed one.
const RunDir = "/var/run/wireguard"
