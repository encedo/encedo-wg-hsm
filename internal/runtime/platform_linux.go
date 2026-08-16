//go:build linux

package runtime

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/ipc"

	"github.com/encedo/encedo-wg-hsm/internal/paths"
)

// RunDir is where a running interface leaves its UAPI socket, its public key
// and, for wg-hem, its state file. Defined in internal/paths, which is a leaf:
// knowing where a state file goes must not require importing netlink and a
// tunnel device. Re-exported here because everything on this side of the
// boundary already says rt.RunDir.
const RunDir = paths.RunDir

// Up assigns the interface its addresses and brings it up. Several are allowed:
// one identity may hold an address in more than one family, or more than one
// range of the same.
func Up(ifname string, addrs []netip.Prefix) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		addr, err := netlink.ParseAddr(a.String())
		if err != nil {
			return err
		}
		if err := netlink.AddrAdd(link, addr); err != nil && !errors.Is(err, syscall.EEXIST) {
			return err
		}
	}
	return netlink.LinkSetUp(link)
}

// Down removes the interface. Its routes go with it; the pins installed by Pins
// sit on the physical link and have to be taken back separately.
func Down(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

func AddRoutes(ifname string, routes []netip.Prefix) error {
	if len(routes) == 0 {
		return nil
	}
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	for _, r := range routes {
		err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       ipNet(r),
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
func defaultGateway(v6 bool) (netip.Addr, string, error) {
	family := netlink.FAMILY_V4
	if v6 {
		family = netlink.FAMILY_V6
	}
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return netip.Addr{}, "", err
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
		return netip.Addr{}, "", errors.New("no default route with a gateway to pin against")
	}
	link, err := netlink.LinkByIndex(chosen.LinkIndex)
	if err != nil {
		return netip.Addr{}, "", err
	}
	gw, ok := netip.AddrFromSlice(chosen.Gw)
	if !ok {
		return netip.Addr{}, "", errors.New("the default route's gateway is not an address")
	}
	return gw.Unmap(), link.Attrs().Name, nil
}

func addHostRoute(addr, gw netip.Addr, iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet(hostPrefix(addr)),
		Gw:        net.IP(gw.AsSlice()),
	})
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return nil
}

func delHostRoute(addr, gw netip.Addr, iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	err = netlink.RouteDel(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet(hostPrefix(addr)),
		Gw:        net.IP(gw.AsSlice()),
	})
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

func SetMTU(ifname string, mtu int) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(link, mtu)
}

func SetDNS(ifname string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		// resolvectl not available - best-effort, skip
		return nil
	}
	if err := run(append([]string{"resolvectl", "dns", ifname}, servers...)...); err != nil {
		return err
	}
	return run("resolvectl", "domain", ifname, "~.")
}

// RevertDNS gives the resolver back what it had. It is best-effort by
// construction - it runs while the tunnel is being dismantled, where there is
// nothing useful left to do about a failure.
//
// Its output is captured rather than passed through, which is the difference
// between a clean shutdown and one that appears to have gone wrong. resolvectl
// writes to its own stderr, so `Failed to resolve interface "wg0": No such
// device` used to appear over our shoulder, in systemd's voice, as the last line
// of a normal exit. When the interface is already gone there is nothing left to
// revert and nothing to say; anything else is worth one line, in ours.
func RevertDNS(ifname string) {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return
	}
	out, err := exec.Command("resolvectl", "revert", ifname).CombinedOutput()
	if err == nil || !linkExists(ifname) {
		return
	}
	fmt.Fprintf(os.Stderr, "WARNING: leaving the DNS settings on %s: %s\n",
		ifname, strings.TrimSpace(string(out)))
}

// linkExists reports whether the interface is still there. It separates the two
// reasons a revert fails: one where the settings went with the interface, and
// one where they did not.
func linkExists(ifname string) bool {
	_, err := netlink.LinkByName(ifname)
	return err == nil
}

func UAPIListen(ifname string) (net.Listener, error) {
	if err := os.MkdirAll(RunDir, 0755); err != nil {
		return nil, err
	}
	f, err := ipc.UAPIOpen(ifname)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(ifname, f)
}

// ipNet converts a prefix to the form netlink wants, masked: a route's
// destination is a network, and host bits in AllowedIPs are the operator's
// shorthand rather than an instruction.
func ipNet(p netip.Prefix) *net.IPNet {
	m := p.Masked()
	return &net.IPNet{
		IP:   net.IP(m.Addr().AsSlice()),
		Mask: net.CIDRMask(m.Bits(), m.Addr().BitLen()),
	}
}

// UAPIDial opens a connection to a running interface's UAPI socket - the same
// one `wg` talks to. It fails when nothing is listening, which is the answer to
// "is this interface up".
func UAPIDial(ifname string) (net.Conn, error) {
	return net.Dial("unix", RunDir+"/"+ifname+".sock")
}
