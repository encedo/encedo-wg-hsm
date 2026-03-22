//go:build linux

package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/ipc"
)

func ifUp(ifname, address string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func ifDown(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

func addRoutes(ifname string, routes []string) error {
	if len(routes) == 0 {
		return nil
	}
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	for _, cidr := range routes {
		_, dst, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       dst,
		})
		if err != nil && !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	return nil
}

func setMTU(ifname string, mtu int) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(link, mtu)
}

func setDNS(ifname string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		// resolvectl not available — best-effort, skip
		return nil
	}
	if err := run(append([]string{"resolvectl", "dns", ifname}, servers...)...); err != nil {
		return err
	}
	return run("resolvectl", "domain", ifname, "~.")
}

func revertDNS(ifname string) {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return
	}
	_ = run("resolvectl", "revert", ifname)
}

func uapiListen(ifname string) (net.Listener, error) {
	if err := os.MkdirAll("/var/run/wireguard", 0755); err != nil {
		return nil, err
	}
	f, err := ipc.UAPIOpen(ifname)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(ifname, f)
}
