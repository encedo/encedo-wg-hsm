package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// cmdImport provisions the device from an ordinary WireGuard client
// configuration - the file somebody is handed today, with a private key in it.
//
// What it does not do is carry that key across, and this is the whole point
// rather than a limitation. The device generates keys and never accepts one; a
// private key that has sat in a text file is already out, and moving it into a
// module afterwards would be pretending otherwise. So the identity is new, and
// the file's own PrivateKey line is read only far enough to be ignored.
//
// The consequence is the thing to be clear about with whoever runs this: the
// tunnel will not come up until the server is told the new public key. That is
// why the address is printed beside it. A server's configuration lists peers by
// key and allowed address, so the address is what an administrator can match a
// person against, and the key is what they replace.
func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	name := fs.String("name", "", "label for the peer, which a .conf file does not carry (prompted for if absent)")
	dryRun := fs.Bool("dry-run", false, "print the equivalent provision command and stop")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: wg-hem import <file.conf> [flags] [-- provision flags]

Reads a WireGuard client configuration and writes it into the HEM as a
configuration of this client's own: the addresses, the DNS servers, the MTU, and
the peer.

The private key in the file is discarded. This client's key is generated inside
the module and cannot leave it, so the imported tunnel has a new identity - and
will not connect until whoever runs the server replaces the old public key with
the one printed here. The address is printed with it, because that is what an
administrator can match a person against.

Anything after -- is passed to provision unchanged, so its flags are available:

  wg-hem import client.conf -- -session 8 -label "laptop"

Flags:
`)
		fs.PrintDefaults()
	}
	// The file is pulled out before the flags are parsed, because Go's flag
	// package stops at the first argument that is not a flag - so
	// `import file.conf -name x` would parse nothing and then ask for a name it
	// had been given. Both orders work now, which is what anybody would expect
	// of a command whose first argument is a file.
	ours, passthrough := splitAtDoubleDash(args)
	path, ours := takeFirstBareArg(ours)
	if path == "" {
		fs.Usage()
		return failf(exitUsage, "which file?")
	}
	if err := fs.Parse(ours); err != nil {
		return &exitError{code: exitUsage, err: err}
	}
	if extra := fs.Args(); len(extra) > 0 {
		return failf(exitUsage, "unexpected argument %q; flags for provision go after --", extra[0])
	}

	conf, err := parseWireGuardConf(path)
	if err != nil {
		return failf(exitUsage, "%s: %w", path, err)
	}

	label := strings.TrimSpace(*name)
	if label == "" {
		// A .conf has nowhere to put a name, and the peer is about to become a
		// record somebody will read back in `wg-hem status` and choose between
		// during failover. "peer 1" would be a name that helps nobody.
		label, err = askPeerName()
		if err != nil {
			return failf(exitUsage, "%w", err)
		}
	}

	argv, err := conf.provisionArgs(label)
	if err != nil {
		return failf(exitUsage, "%s: %w", path, err)
	}
	argv = append(argv, passthrough...)

	if *dryRun {
		fmt.Println("wg-hem provision " + strings.Join(quoteAll(argv), " "))
		return nil
	}

	// Through provision rather than beside it. Everything after this point -
	// validating, generating the identity, importing the peer key, writing the
	// records, the MAC over them, and reading it back to verify - is the same
	// work with the same failure modes, and a second copy of it would be a
	// second thing to keep correct.
	if err := cmdProvision(argv); err != nil {
		return err
	}

	// provision has already printed the block to paste, so this adds only what
	// is true of a migration and not of a first provisioning: there is an entry
	// on the server already, the old key in the file is now dead, and nothing
	// works until somebody changes that one line.
	fmt.Fprintln(os.Stderr, "Imported from "+path+".")
	fmt.Fprintln(os.Stderr, "The peer entry above replaces the one this person already has: same")
	fmt.Fprintln(os.Stderr, "address, new PublicKey. Until the server is changed the tunnel will not")
	fmt.Fprintln(os.Stderr, "come up - the old private key stayed in the file and is not the one in")
	fmt.Fprintln(os.Stderr, "the module.")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "The file itself is untouched. Delete it once the tunnel works: the key")
	fmt.Fprintln(os.Stderr, "in it still opens whatever it opened before this ran.")
	return nil
}

// splitAtDoubleDash separates this command's own arguments from the ones meant
// for provision. Everything after the first -- belongs to provision, untouched.
func splitAtDoubleDash(args []string) (ours, theirs []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// takeFirstBareArg removes and returns the first argument that is not a flag,
// leaving the rest in order.
//
// It does not try to understand which flags take values, because none of this
// command's do: -name is the only one with an argument and it is written
// -name=x or -name x - and in the second form the value would be taken as the
// file. So -name is the one case that is looked for by name.
func takeFirstBareArg(args []string) (string, []string) {
	rest := make([]string, 0, len(args))
	found := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if found == "" && !strings.HasPrefix(a, "-") {
			found = a
			continue
		}
		rest = append(rest, a)
		if a == "-name" || a == "--name" {
			// Its value follows and is not the file.
			if i+1 < len(args) {
				i++
				rest = append(rest, args[i])
			}
		}
	}
	return found, rest
}

// wireguardConf is as much of a client configuration as this client can use.
//
// A deliberately separate parser from the one in wg-quick-encedo, which reads
// the same format for the opposite purpose: that one understands HEM_URL and
// HEM_KID and expects no PrivateKey, this one expects a PrivateKey it will throw
// away and would not know what to do with a HEM field. Sharing them would mean
// one parser with two modes, and the modes disagree about what a valid file is.
type wireguardConf struct {
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	ListenPort int

	PeerPubKey    string
	PeerEndpoint  string
	PeerAllowed   []netip.Prefix
	PeerKeepalive int
}

func parseWireGuardConf(path string) (*wireguardConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	c := &wireguardConf{}
	section := ""
	peers := 0

	sc := bufio.NewScanner(f)
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

func (c *wireguardConf) set(section, key, value string) error {
	switch strings.ToLower(section) {
	case "interface":
		switch strings.ToLower(key) {
		case "privatekey":
			// Read and dropped. Saying so is the point: somebody importing a
			// file wants to know what became of the key that was in it.
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

// provisionArgs turns the file into the flags provision already understands, so
// that what an import does is exactly what somebody could have typed.
func (c *wireguardConf) provisionArgs(peerLabel string) ([]string, error) {
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

// askPeerName reads a name for the peer, since the file has nowhere to carry
// one and the records are read by people afterwards.
func askPeerName() (string, error) {
	fmt.Fprint(os.Stderr, "Name for this peer (it is what `wg-hem status` will show): ")
	sc := bufio.NewScanner(os.Stdin)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("no name given")
	}
	name := strings.TrimSpace(sc.Text())
	if name == "" {
		return "", fmt.Errorf("no name given; pass -name to supply one without being asked")
	}
	if strings.ContainsAny(name, ",=") {
		// The peer specification provision takes is comma-separated key=value,
		// so either character in a name would split it into something else.
		return "", fmt.Errorf("a name cannot contain a comma or an equals sign")
	}
	return name, nil
}

// quoteAll makes the dry run's output something that can be pasted back.
func quoteAll(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsAny(a, " \t\"'") {
			out[i] = strconv.Quote(a)
		} else {
			out[i] = a
		}
	}
	return out
}
