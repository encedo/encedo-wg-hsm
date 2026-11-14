package runtime

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// macOS has no per-interface resolver a command can hand servers to the way
// resolvectl does on Linux. What wg-quick from wireguard-tools does there, and
// what this follows, is to give every enabled network service the tunnel's
// servers with networksetup and to put back what each one had afterwards.
//
// What each one had is written to a file before anything is changed, so that
// a process killed with the tunnel up does not take the only copy with it: the
// next tunnel to set DNS finds the file and restores from it first. The file
// is one per host, not per interface, because the setting it records is the
// host's: two tunnels cannot both own it.
//
// The parsing lives here, without a build tag, so it is tested on every
// platform; the commands are in platform_darwin.go.

// macDNSSaved is what the services had before a tunnel changed them.
type macDNSSaved struct {
	PID       int           `json:"pid"`
	Interface string        `json:"interface"`
	Services  []macDNSEntry `json:"services"`
}

type macDNSEntry struct {
	Service string   `json:"service"`
	Servers []string `json:"servers,omitempty"` // none: the service had no servers of its own
}

// macDNSFile is where the saved settings go.
var macDNSFile = RunDir + "/macos-dns.json"

// parseServices reads `networksetup -listallnetworkservices`: a header line
// about the asterisk, then one service per line, disabled ones marked with
// "*". Disabled services are left alone - giving them servers would change
// what they get when somebody enables them later.
func parseServices(out string) []string {
	var svcs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "*") ||
			strings.Contains(line, "asterisk (*)") {
			continue
		}
		svcs = append(svcs, line)
	}
	return svcs
}

// parseDNSServers reads `networksetup -getdnsservers <service>`: one address
// per line, or a sentence saying there are none - which is also what a
// service gets back by being set to "Empty".
func parseDNSServers(out string) []string {
	var servers []string
	for _, line := range strings.Split(out, "\n") {
		s := strings.TrimSpace(line)
		if _, err := netip.ParseAddr(s); err == nil {
			servers = append(servers, s)
		}
	}
	return servers
}

// setArgs is the argument list that gives a service these servers, or takes
// its own away when there are none.
func (e macDNSEntry) setArgs() []string {
	args := []string{"networksetup", "-setdnsservers", e.Service}
	if len(e.Servers) == 0 {
		return append(args, "Empty")
	}
	return append(args, e.Servers...)
}

func readMacDNS() (*macDNSSaved, error) {
	b, err := os.ReadFile(macDNSFile)
	if err != nil {
		return nil, err
	}
	var s macDNSSaved
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeMacDNS(s *macDNSSaved) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(macDNSFile), 0o755); err != nil {
		return err
	}
	return os.WriteFile(macDNSFile, append(b, '\n'), 0o600)
}
