// Package wgconf reads the ordinary WireGuard client configuration somebody is
// handed today - the one with a private key in it - so that both the command
// line and the window can offer to bring it across.
//
// A deliberately separate parser from the one in wg-quick-encedo, which reads
// the same format for the opposite purpose: that one understands HEM_URL and
// HEM_KID and expects no PrivateKey, this one expects a PrivateKey it will throw
// away and would not know what to do with a HEM field. Sharing them would mean
// one parser with two modes, and the modes disagree about what a valid file is.
//
// Nothing here touches a device or a network. That is what lets a window show
// somebody what an import would do before asking for a passphrase, which is the
// difference between a migration tool that is believed and one that is not.
package wgconf

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Conf is as much of a client configuration as this client can use.
type Conf struct {
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	ListenPort int

	PeerPubKey    string
	PeerEndpoint  string
	PeerAllowed   []netip.Prefix
	PeerKeepalive int

	// HadPrivateKey records that the file carried one, which is worth saying
	// out loud rather than merely doing quietly. Somebody importing a file
	// wants to know what became of the key that was in it, and a window that
	// does not mention it is a window that looks like it might have kept it.
	HadPrivateKey bool
}

// pubKeyLen is the length of a Curve25519 public key.
const pubKeyLen = 32

// ParseFile reads a configuration from disk.
func ParseFile(path string) (*Conf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads a configuration from anywhere.
//
// A reader and not a path, because the window is handed a stream by a file
// dialogue and would otherwise have to write it back out to disk to read it -
// which for a file holding a private key is the one thing this whole exercise
// is about not doing.
func Parse(r io.Reader) (*Conf, error) {
	c := &Conf{}
	section := ""
	peers := 0

	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(text, "#;"); i >= 0 {
			text = strings.TrimSpace(text[:i])
		}
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			section = strings.ToLower(strings.Trim(text, "[]"))
			if section == "peer" {
				peers++
			}
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: %q is not key = value", line, text)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if err := c.set(section, key, value); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	switch {
	case len(c.Addresses) == 0:
		return nil, fmt.Errorf("no Address in [Interface]; this client needs to know what to give the tunnel")
	case peers == 0:
		return nil, fmt.Errorf("no [Peer] section")
	case peers > 1:
		// Not a refusal in principle - the device holds several peers and
		// failover walks them - but each one needs a name, and asking for names
		// one at a time from a file somebody was handed is a different command
		// from this one.
		return nil, fmt.Errorf("%d [Peer] sections; this imports one, and provision takes -peer more than once", peers)
	case c.PeerPubKey == "":
		return nil, fmt.Errorf("the [Peer] section has no PublicKey")
	}
	return c, nil
}

func (c *Conf) set(section, key, value string) error {
	switch strings.ToLower(section) {
	case "interface":
		switch strings.ToLower(key) {
		case "privatekey":
			// Read and dropped. Saying so is the point: somebody importing a
			// file wants to know what became of the key that was in it.
			c.HadPrivateKey = true
			return nil
		case "address":
			for _, part := range splitList(value) {
				p, err := netip.ParsePrefix(part)
				if err != nil {
					return fmt.Errorf("Address %q: %w", part, err)
				}
				c.Addresses = append(c.Addresses, p)
			}
		case "dns":
			for _, part := range splitList(value) {
				a, err := netip.ParseAddr(part)
				if err != nil {
					// A DNS name here is legal in wg-quick and means a search
					// domain. This client does not set those, and silently
					// dropping it would change what the tunnel resolves.
					return fmt.Errorf("DNS %q is not an address; search domains are not supported", part)
				}
				c.DNS = append(c.DNS, a)
			}
		case "mtu":
			n, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("MTU %q: %w", value, err)
			}
			c.MTU = n
		case "listenport":
			n, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("ListenPort %q: %w", value, err)
			}
			c.ListenPort = n
		case "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark":
			// wg-quick's own directives. They run commands or drive its routing
			// table handling, and this client does neither - so they are
			// refused rather than ignored, because a file that relies on them
			// does not mean the same thing here.
			return fmt.Errorf("%s is a wg-quick directive this client does not implement", key)
		}
	case "peer":
		switch strings.ToLower(key) {
		case "publickey":
			raw, err := base64.StdEncoding.DecodeString(value)
			if err != nil || len(raw) != pubKeyLen {
				return fmt.Errorf("PublicKey is not a %d-byte base64 key", pubKeyLen)
			}
			c.PeerPubKey = value
		case "endpoint":
			c.PeerEndpoint = value
		case "allowedips":
			for _, part := range splitList(value) {
				p, err := netip.ParsePrefix(part)
				if err != nil {
					return fmt.Errorf("AllowedIPs %q: %w", part, err)
				}
				c.PeerAllowed = append(c.PeerAllowed, p)
			}
		case "persistentkeepalive":
			n, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("PersistentKeepalive %q: %w", value, err)
			}
			c.PeerKeepalive = n
		case "presharedkey":
			return fmt.Errorf("PresharedKey cannot be imported: the device wraps a pre-shared key on the way in " +
				"and one that has been in a file is already out. Provision with -psk generate instead")
		}
	}
	return nil
}

// ProvisionArgs turns the file into the flags provision already understands, so
// that what an import does is exactly what somebody could have typed.
func (c *Conf) ProvisionArgs(peerLabel string) ([]string, error) {
	var argv []string
	for _, a := range c.Addresses {
		argv = append(argv, "-address", a.String())
	}
	for _, d := range c.DNS {
		argv = append(argv, "-dns", d.String())
	}
	if c.MTU != 0 {
		argv = append(argv, "-mtu", strconv.Itoa(c.MTU))
	}
	if c.ListenPort != 0 {
		argv = append(argv, "-listen-port", strconv.Itoa(c.ListenPort))
	}

	fields := []string{"label=" + peerLabel, "pubkey=" + c.PeerPubKey}
	if c.PeerEndpoint != "" {
		fields = append(fields, "endpoint="+c.PeerEndpoint)
	}
	for _, p := range c.PeerAllowed {
		fields = append(fields, "allowed-ips="+p.String())
	}
	if c.PeerKeepalive != 0 {
		fields = append(fields, "keepalive="+strconv.Itoa(c.PeerKeepalive))
	}
	return append(argv, "-peer", strings.Join(fields, ",")), nil
}

// splitList reads the comma-separated lists wg-quick allows, and tolerates the
// spaces people put after the commas.
func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
