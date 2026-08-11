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

// defaultGateway reports the gateway and interface that carry traffic for this
// family before the tunnel exists. Where several default routes compete the one
// with the lowest metric wins, which is the choice the kernel is making anyway.
//
// Routes without a gateway are skipped: an interface-scoped default is what the
// tunnel itself installs, and pinning an endpoint to it would defeat the point.
func defaultGateway(v6 bool) (net.IP, string, error) {
	family := netlink.FAMILY_V4
	if v6 {
		family = netlink.FAMILY_V6
	}
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return nil, "", err
	}
	best := -1
	var chosen netlink.Route
	for _, r := range routes {
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		if r.Gw == nil {
			continue
		}
		if best < 0 || r.Priority < best {
			best, chosen = r.Priority, r
		}
	}
	if best < 0 {
		return nil, "", errors.New("no default route with a gateway to pin against")
	}
	link, err := netlink.LinkByIndex(chosen.LinkIndex)
	if err != nil {
		return nil, "", err
	}
	return chosen.Gw, link.Attrs().Name, nil
}

func addHostRoute(ip, gw net.IP, iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       hostNet(ip),
		Gw:        gw,
	})
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return nil
}

func delHostRoute(ip, gw net.IP, iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	err = netlink.RouteDel(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       hostNet(ip),
		Gw:        gw,
	})
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
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
