//go:build windows

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
