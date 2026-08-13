//go:build windows

package runtime

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"

	"github.com/encedo/encedo-wg-hsm/internal/paths"
)

// RunDir is where a running interface leaves its public key and, for wg-hem,
// its state file. Defined in internal/paths, which is a leaf; re-exported here
// because everything on this side of the boundary already says rt.RunDir.
var RunDir = paths.RunDir

func Up(ifname string, addrs []netip.Prefix) error {
	for _, a := range addrs {
		mask := net.IP(net.CIDRMask(a.Bits(), a.Addr().BitLen())).String()
		if err := run("netsh", "interface", ipFamily(a.Addr().Is6()), "add", "address",
			fmt.Sprintf("name=%s", ifname), a.Addr().String(), mask); err != nil {
			return err
		}
	}
	return nil
}

// Down is a no-op on Windows: the Wintun adapter is destroyed automatically when
// the WireGuard device is closed.
func Down(_ string) error {
	return nil
}

func AddRoutes(ifname string, routes []netip.Prefix) error {
	for _, r := range routes {
		// Ignore errors — the route may already exist.
		_ = run("netsh", "interface", ipFamily(r.Addr().Is6()), "add", "route",
			r.Masked().String(), ifname)
	}
	return nil
}

// defaultGateway reports the gateway carrying this family today and the index of
// the interface behind it. netsh prints one row per route; the interesting ones
// are those whose prefix is the default and whose last column parses as an
// address rather than an interface name. Where several compete, the lowest
// metric wins.
//
// The interface is returned as an index, which is what netsh accepts back and
// what stays stable across the localized names of the same adapter.
func defaultGateway(v6 bool) (netip.Addr, string, error) {
	family := ipFamily(v6)
	wantPrefix := "0.0.0.0/0"
	if v6 {
		wantPrefix = "::/0"
	}
	out, err := exec.Command("netsh", "interface", family, "show", "route").Output()
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("netsh interface %s show route: %w", family, err)
	}
	best := -1
	var gw netip.Addr
	var idx string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || f[3] != wantPrefix {
			continue
		}
		metric, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		next, err := netip.ParseAddr(f[5])
		if err != nil {
			continue
		}
		if best < 0 || metric < best {
			best, gw, idx = metric, next.Unmap(), f[4]
		}
	}
	if best < 0 {
		return netip.Addr{}, "", errors.New("no default route with a gateway to pin against")
	}
	return gw, idx, nil
}

func addHostRoute(addr, gw netip.Addr, iface string) error {
	return run("netsh", "interface", ipFamily(addr.Is6()), "add", "route",
		hostPrefix(addr).String(), iface, gw.String())
}

func delHostRoute(addr, gw netip.Addr, iface string) error {
	return run("netsh", "interface", ipFamily(addr.Is6()), "delete", "route",
		hostPrefix(addr).String(), iface, gw.String())
}

func ipFamily(v6 bool) string {
	if v6 {
		return "ipv6"
	}
	return "ipv4"
}

func SetMTU(ifname string, mtu int) error {
	return run("netsh", "interface", "ipv4", "set", "subinterface",
		ifname, fmt.Sprintf("mtu=%s", strconv.Itoa(mtu)), "store=active")
}

func SetDNS(ifname string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	// Set first DNS server (replaces existing static config)
	if err := run("netsh", "interface", "ip", "set", "dns",
		fmt.Sprintf("name=%s", ifname), "static", servers[0]); err != nil {
		return err
	}
	// Add subsequent servers
	for i, s := range servers[1:] {
		if err := run("netsh", "interface", "ip", "add", "dns",
			fmt.Sprintf("name=%s", ifname), s,
			fmt.Sprintf("index=%d", i+2)); err != nil {
			return err
		}
	}
	return nil
}

func RevertDNS(ifname string) {
	_ = run("netsh", "interface", "ip", "set", "dns",
		fmt.Sprintf("name=%s", ifname), "dhcp")
}

func UAPIListen(ifname string) (net.Listener, error) {
	return ipc.UAPIListen(ifname)
}

// UAPIDial opens a connection to a running interface's UAPI pipe — the same one
// `wg` talks to. It fails when nothing is listening, which is the answer to "is
// this interface up".
func UAPIDial(ifname string) (net.Conn, error) {
	return namedpipe.DialTimeout(`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\`+ifname, time.Second)
}
