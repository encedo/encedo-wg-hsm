//go:build darwin

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
	// Point-to-point: src = dst = our IP
	if err := run("ifconfig", ifname, "inet", ip.String(), ip.String(), "up"); err != nil {
		return err
	}
	// Add route for the interface subnet
	return run("route", "-q", "-n", "add", "-inet", ipNet.String(), "-interface", ifname)
}

func ifDown(ifname string) error {
	return run("ifconfig", ifname, "down")
}

func addRoutes(ifname string, routes []string) error {
	for _, cidr := range routes {
		// Ignore errors — subnet route may already exist from ifUp
		_ = run("route", "-q", "-n", "add", "-inet", cidr, "-interface", ifname)
	}
	return nil
}

// defaultGateway asks the routing table what carries this family today, before
// the tunnel's own default route is in it. `route -n get default` prints the
// answer the kernel would use, which is exactly the one worth pinning to.
func defaultGateway(v6 bool) (net.IP, string, error) {
	out, err := exec.Command("route", "-n", "get", inetFlag(v6), "default").Output()
	if err != nil {
		return nil, "", fmt.Errorf("route -n get default: %w", err)
	}
	var gw net.IP
	var iface string
	for _, line := range strings.Split(string(out), "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch field {
		case "gateway":
			gw = net.ParseIP(value)
		case "interface":
			iface = value
		}
	}
	if gw == nil || iface == "" {
		return nil, "", errors.New("no default route with a gateway to pin against")
	}
	return gw, iface, nil
}

func addHostRoute(ip, gw net.IP, _ string) error {
	return run("route", "-q", "-n", "add", inetFlag(ip.To4() == nil), "-host", ip.String(), gw.String())
}

func delHostRoute(ip, gw net.IP, _ string) error {
	return run("route", "-q", "-n", "delete", inetFlag(ip.To4() == nil), "-host", ip.String(), gw.String())
}

func inetFlag(v6 bool) string {
	if v6 {
		return "-inet6"
	}
	return "-inet"
}

func setMTU(ifname string, mtu int) error {
	return run("ifconfig", ifname, "mtu", strconv.Itoa(mtu))
}

func setDNS(ifname string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	// macOS DNS requires networksetup with a service name, not interface name.
	// Service name lookup from utun interface name is non-trivial — not implemented yet.
	fmt.Printf("WARNING: DNS configuration not supported on macOS yet (servers: %v)\n", servers)
	return nil
}

func revertDNS(_ string) {}

func uapiListen(ifname string) (net.Listener, error) {
	f, err := ipc.UAPIOpen(ifname)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(ifname, f)
}
