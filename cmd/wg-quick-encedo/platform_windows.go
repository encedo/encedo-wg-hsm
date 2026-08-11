//go:build windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/ipc"
)

func ifUp(ifname, address string) error {
	ip, ipNet, err := net.ParseCIDR(address)
	if err != nil {
		return err
	}
	mask := net.IP(ipNet.Mask).String()
	return run("netsh", "interface", "ip", "add", "address",
		fmt.Sprintf("name=%s", ifname), ip.String(), mask)
}

// ifDown is a no-op on Windows: Wintun adapter is destroyed automatically
// when the WireGuard device is closed (device.Close()).
func ifDown(_ string) error {
	return nil
}

func addRoutes(ifname string, routes []string) error {
	for _, cidr := range routes {
		// Ignore errors — route may already exist
		_ = run("netsh", "interface", "ipv4", "add", "route", cidr, ifname)
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
func defaultGateway(v6 bool) (net.IP, string, error) {
	family := ipFamily(v6)
	wantPrefix := "0.0.0.0/0"
	if v6 {
		wantPrefix = "::/0"
	}
	out, err := exec.Command("netsh", "interface", family, "show", "route").Output()
	if err != nil {
		return nil, "", fmt.Errorf("netsh interface %s show route: %w", family, err)
	}
	best := -1
	var gw net.IP
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
		next := net.ParseIP(f[5])
		if next == nil {
			continue
		}
		if best < 0 || metric < best {
			best, gw, idx = metric, next, f[4]
		}
	}
	if best < 0 {
		return nil, "", errors.New("no default route with a gateway to pin against")
	}
	return gw, idx, nil
}

func addHostRoute(ip, gw net.IP, iface string) error {
	return run("netsh", "interface", ipFamily(ip.To4() == nil), "add", "route",
		hostNet(ip).String(), iface, gw.String())
}

func delHostRoute(ip, gw net.IP, iface string) error {
	return run("netsh", "interface", ipFamily(ip.To4() == nil), "delete", "route",
		hostNet(ip).String(), iface, gw.String())
}

func ipFamily(v6 bool) string {
	if v6 {
		return "ipv6"
	}
	return "ipv4"
}

func setMTU(ifname string, mtu int) error {
	return run("netsh", "interface", "ipv4", "set", "subinterface",
		ifname, fmt.Sprintf("mtu=%s", strconv.Itoa(mtu)), "store=active")
}

func setDNS(ifname string, servers []string) error {
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

func revertDNS(ifname string) {
	_ = run("netsh", "interface", "ip", "set", "dns",
		fmt.Sprintf("name=%s", ifname), "dhcp")
}

func uapiListen(ifname string) (net.Listener, error) {
	return ipc.UAPIListen(ifname)
}
