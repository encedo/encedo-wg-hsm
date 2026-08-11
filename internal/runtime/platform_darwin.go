//go:build darwin

package runtime

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/ipc"
)

// Up configures a utun point-to-point interface. The first address is the
// primary one, the rest are aliases; each brings its own subnet route.
func Up(ifname string, addrs []netip.Prefix) error {
	for i, a := range addrs {
		ip := a.Addr().String()
		args := []string{"ifconfig", ifname, inetFlag(a.Addr().Is6()), ip, ip}
		if i == 0 {
			args = append(args, "up")
		} else {
			args = append(args, "alias")
		}
		if err := run(args...); err != nil {
			return err
		}
		if err := run("route", "-q", "-n", "add", inetFlag(a.Addr().Is6()),
			a.Masked().String(), "-interface", ifname); err != nil {
			return err
		}
	}
	return nil
}

func Down(ifname string) error {
	return run("ifconfig", ifname, "down")
}

func AddRoutes(ifname string, routes []netip.Prefix) error {
	for _, r := range routes {
		// Ignore errors — the subnet route may already exist from Up.
		_ = run("route", "-q", "-n", "add", inetFlag(r.Addr().Is6()),
			r.Masked().String(), "-interface", ifname)
	}
	return nil
}

// defaultGateway asks the routing table what carries this family today, before
// the tunnel's own default route is in it. `route -n get default` prints the
// answer the kernel would use, which is exactly the one worth pinning to.
func defaultGateway(v6 bool) (netip.Addr, string, error) {
	out, err := exec.Command("route", "-n", "get", inetFlag(v6), "default").Output()
	if err != nil {
		return netip.Addr{}, "", fmt.Errorf("route -n get default: %w", err)
	}
	var gw netip.Addr
	var iface string
	for _, line := range strings.Split(string(out), "\n") {
		field, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch field {
		case "gateway":
			if a, err := netip.ParseAddr(value); err == nil {
				gw = a.Unmap()
			}
		case "interface":
			iface = value
		}
	}
	if !gw.IsValid() || iface == "" {
		return netip.Addr{}, "", errors.New("no default route with a gateway to pin against")
	}
	return gw, iface, nil
}

func addHostRoute(addr, gw netip.Addr, _ string) error {
	return run("route", "-q", "-n", "add", inetFlag(addr.Is6()), "-host", addr.String(), gw.String())
}

func delHostRoute(addr, gw netip.Addr, _ string) error {
	return run("route", "-q", "-n", "delete", inetFlag(addr.Is6()), "-host", addr.String(), gw.String())
}

func inetFlag(v6 bool) string {
	if v6 {
		return "-inet6"
	}
	return "-inet"
}

func SetMTU(ifname string, mtu int) error {
	return run("ifconfig", ifname, "mtu", strconv.Itoa(mtu))
}

func SetDNS(_ string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	// macOS DNS requires networksetup with a service name, not interface name.
	// Service name lookup from utun interface name is non-trivial — not implemented yet.
	fmt.Printf("WARNING: DNS configuration not supported on macOS yet (servers: %v)\n", servers)
	return nil
}

func RevertDNS(_ string) {}

func UAPIListen(ifname string) (net.Listener, error) {
	f, err := ipc.UAPIOpen(ifname)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(ifname, f)
}

// UAPIDial opens a connection to a running interface's UAPI socket — the same
// one `wg` talks to. It fails when nothing is listening, which is the answer to
// "is this interface up".
func UAPIDial(ifname string) (net.Conn, error) {
	return net.Dial("unix", "/var/run/wireguard/"+ifname+".sock")
}
