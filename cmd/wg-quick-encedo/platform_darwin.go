//go:build darwin

package main

import (
	"fmt"
	"net"
	"strconv"

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
