//go:build darwin

package runtime

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/ipc"

	"github.com/encedo/encedo-wg-hsm/internal/paths"
)

// RunDir is where a running interface leaves its UAPI socket, its public key
// and, for wg-hem, its state file. Defined in internal/paths, which is a leaf:
// knowing where a state file goes must not require importing netlink and a
// tunnel device. Re-exported here because everything on this side of the
// boundary already says rt.RunDir.
const RunDir = paths.RunDir

// Up configures a utun point-to-point interface: every address as an alias, the
// way wg-quick does it on macOS, then the link up.
//
// ifconfig names the family without a dash (inet, inet6) where route takes one
// (-inet, -inet6). This used inetFlag for both, and the first run on a Mac
// stopped at "ifconfig: -inet: bad value". A point-to-point IPv4 address also
// needs a destination, which is the address itself.
//
// The subnet route an address implies is added best effort and only for a
// prefix wider than one host: the routes that carry traffic are AllowedIPs',
// added by AddRoutes, and a /32 has no subnet to route.
func Up(ifname string, addrs []netip.Prefix) error {
	for _, a := range addrs {
		var args []string
		if a.Addr().Is6() {
			args = []string{"ifconfig", ifname, "inet6", a.String(), "alias"}
		} else {
			args = []string{"ifconfig", ifname, "inet", a.String(), a.Addr().String(), "alias"}
		}
		if err := run(args...); err != nil {
			return err
		}
		if a.Bits() < a.Addr().BitLen() {
			_ = run("route", "-q", "-n", "add", inetFlag(a.Addr().Is6()),
				a.Masked().String(), "-interface", ifname)
		}
	}
	return run("ifconfig", ifname, "up")
}

// Down takes the link down. A utun exists only while the descriptor that
// created it is open, so once the tunnel has closed it there is nothing left to
// take down - and asking printed "interface utun4 does not exist" at every exit.
func Down(ifname string) error {
	if _, err := net.InterfaceByName(ifname); err != nil {
		return nil
	}
	return run("ifconfig", ifname, "down")
}

func AddRoutes(ifname string, routes []netip.Prefix) error {
	for _, r := range routes {
		// Ignore errors - the subnet route may already exist from Up.
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

// SetDNS gives every enabled network service the tunnel's servers, after
// writing down what each had; see macdns.go for why it is done this way and
// why the record is a file.
//
// A record already there is a previous tunnel's. If that process is still
// running it owns the setting and this one does not take it over; if it is
// gone, it died with its DNS in place, and what it wrote down is put back
// before anything else is read - otherwise the tunnel's servers would be
// recorded as the host's own.
func SetDNS(ifname string, servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	if prev, err := readMacDNS(); err == nil {
		if prev.PID != os.Getpid() && processAlive(prev.PID) {
			return fmt.Errorf("DNS is already set by another tunnel (%s, pid %d); if that process is not a tunnel, remove %s",
				prev.Interface, prev.PID, macDNSFile)
		}
		restoreMacDNS(prev)
	}

	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return fmt.Errorf("networksetup -listallnetworkservices: %w", err)
	}
	saved := &macDNSSaved{PID: os.Getpid(), Interface: ifname}
	for _, svc := range parseServices(string(out)) {
		cur, err := exec.Command("networksetup", "-getdnsservers", svc).Output()
		if err != nil {
			return fmt.Errorf("networksetup -getdnsservers %q: %w", svc, err)
		}
		saved.Services = append(saved.Services, macDNSEntry{Service: svc, Servers: parseDNSServers(string(cur))})
	}
	if len(saved.Services) == 0 {
		return errors.New("no enabled network service to give the DNS servers to")
	}
	if err := writeMacDNS(saved); err != nil {
		return fmt.Errorf("recording the DNS settings before changing them: %w", err)
	}
	for _, e := range saved.Services {
		if err := run(macDNSEntry{Service: e.Service, Servers: servers}.setArgs()...); err != nil {
			restoreMacDNS(saved)
			return fmt.Errorf("setting DNS on %q: %w", e.Service, err)
		}
	}
	flushMacDNS()
	return nil
}

// RevertDNS puts back what SetDNS wrote down. Best effort: it runs while the
// tunnel is being dismantled, where a failure has nowhere better to go than
// one line on stderr. The record stays when a service could not be restored,
// so the next tunnel tries again.
func RevertDNS(_ string) {
	saved, err := readMacDNS()
	if err != nil {
		return
	}
	restoreMacDNS(saved)
}

func restoreMacDNS(saved *macDNSSaved) {
	ok := true
	for _, e := range saved.Services {
		if out, err := exec.Command(e.setArgs()[0], e.setArgs()[1:]...).CombinedOutput(); err != nil {
			ok = false
			fmt.Fprintf(os.Stderr, "WARNING: could not give %q its DNS servers back: %s\n",
				e.Service, strings.TrimSpace(string(out)))
		}
	}
	if ok {
		_ = os.Remove(macDNSFile)
	}
	flushMacDNS()
}

// flushMacDNS drops answers cached from the resolver that has just been
// replaced. Best effort.
func flushMacDNS() {
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
}

// processAlive says whether pid is a running process, by the signal-0 probe.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func UAPIListen(ifname string) (net.Listener, error) {
	f, err := ipc.UAPIOpen(ifname)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(ifname, f)
}

// UAPIDial opens a connection to a running interface's UAPI socket - the same
// one `wg` talks to. It fails when nothing is listening, which is the answer to
// "is this interface up".
func UAPIDial(ifname string) (net.Conn, error) {
	return net.Dial("unix", RunDir+"/"+ifname+".sock")
}
