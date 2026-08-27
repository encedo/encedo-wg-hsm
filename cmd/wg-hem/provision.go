package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/handoff"
	"github.com/encedo/encedo-wg-hsm/internal/provision"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// pskLen is the length of a WireGuard pre-shared key.
const pskLen = config.PSKLen

// keyType is the type of the interface identity key.
const keyType = "CURVE25519"

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, " ") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// provisionedKey is where a run leaves the interface public key it created, for
// a caller in this package that needs it as a value rather than as a line on
// stdout. `import` is that caller: it pairs the key with the address so an
// administrator has both together, and reading it back off stdout would mean
// parsing our own output.
//
// A package variable rather than a return value because cmdProvision is a
// command - its signature is the one every command here has, and bending that
// for one caller would be worse than this. Set on success and never read by
// anything that did not just call it.
var provisionedKey string

func cmdProvision(args []string) error {
	fs := flag.NewFlagSet("provision", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var addresses, dnsServers, peerFlags stringList
	fs.Var(&addresses, "address", "interface address with prefix, e.g. 10.0.0.7/32 (repeatable)")
	fs.Var(&dnsServers, "dns", "DNS server for the tunnel (repeatable)")
	fs.Var(&peerFlags, "peer", "peer spec: pubkey=B64,endpoint=host:port,allowed-ips=CIDR[,keepalive=N][,label=NAME] (repeatable; order is failover priority)")
	mtu := fs.Int("mtu", 0, "interface MTU (0 leaves the default of 1420)")
	listenPort := fs.Int("listen-port", 0, "fixed UDP port (0 lets the kernel choose; required behind NAT)")
	hemURL := fs.String("hem", "", "HEM base URL (default "+defaultHEM+", or $WG_HEM_URL)")
	broker := fs.String("broker", "", "notification broker URL (default is the SDK's)")
	label := fs.String("label", "wg-hem identity", "label for the identity key in the HEM")
	kid := fs.String("kid", "", "reuse an existing Curve25519 key instead of creating one")
	psk := fs.String("psk", "", "'-' reads a base64 pre-shared key from stdin; 'generate' makes one locally")
	adoptPeers := fs.Bool("adopt", false, "reuse a peer already in the device even if its stored settings differ from the flags")
	mobile := fs.Bool("mobile", false, "authorize with a mobile push instead of the passphrase")
	insecure := fs.Bool("insecure", false, "skip TLS verification (self-signed PPA certificate)")
	expHours := fs.Int("session", 1, "token lifetime in hours")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: wg-hem provision [flags]

Writes a complete WireGuard configuration into the HEM: an identity key, one
imported key per peer, the addressing and routing in their descr fields, and a
MAC over the whole tree. Nothing is written to disk.

On success stdout carries the interface public key in base64 - hand it to
whoever runs the other end. With -psk generate, a second line "psk=<base64>"
follows it; that value is shown once and is not recoverable afterwards.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return &exitError{code: exitUsage, err: err}
	}

	// -- validate everything before touching the device -----------------------
	//
	// Parsing is the command's own work: these are flags, and what a flag means
	// is a property of the command line rather than of provisioning. What the
	// values then have to satisfy is provision.Params.Validate, which Run calls
	// again - the caller may be a window that never saw a flag.

	if len(addresses) == 0 {
		return failf(exitUsage, "at least one -address is required")
	}
	var addrs []netip.Prefix
	for _, a := range addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return failf(exitUsage, "-address %q: %w", a, err)
		}
		addrs = append(addrs, p)
	}
	var dns []netip.Addr
	for _, d := range dnsServers {
		a, err := netip.ParseAddr(d)
		if err != nil {
			return failf(exitUsage, "-dns %q: %w", d, err)
		}
		dns = append(dns, a)
	}
	if len(peerFlags) == 0 {
		return failf(exitUsage, "at least one -peer is required")
	}
	var peers []provision.PeerSpec
	for i, spec := range peerFlags {
		p, err := provision.ParsePeerSpec(spec)
		if err != nil {
			return failf(exitUsage, "-peer #%d: %w", i+1, err)
		}
		peers = append(peers, p)
	}

	pskBytes, err := readPSK(*psk)
	if err != nil {
		return err
	}
	defer zero(pskBytes)

	params := provision.Params{
		Addrs:        addrs,
		DNS:          dns,
		MTU:          *mtu,
		ListenPort:   *listenPort,
		Label:        *label,
		Peers:        peers,
		KID:          *kid,
		PSK:          pskBytes,
		PSKGenerated: *psk == "generate",
		Adopt:        *adoptPeers,
	}
	// Validated before the device is reached, so a wrong flag costs nothing and
	// asks nobody for a passphrase. Run checks again; that is not redundant, it
	// is the check being where the writing is rather than where the flags were.
	if err := params.Validate(); err != nil {
		return exitFrom(err)
	}

	url := *hemURL
	if url == "" {
		url = os.Getenv("WG_HEM_URL")
	}
	if url == "" {
		url = defaultHEM
	}

	// -- talk to the device ---------------------------------------------------

	ctx := context.Background()
	// Provisioning takes its own flags rather than the shared set, so it builds
	// the same description of the device by hand.
	client, auth, err := session.Device{
		URL: url, Broker: *broker, Mobile: *mobile, Insecure: *insecure,
		ExpSecs:    *expHours * 3600,
		Passphrase: readPassphrase,
		Notify:     func(msg string) { fmt.Fprintln(os.Stderr, msg) },
	}.Connect(ctx)
	if err != nil {
		return exitFrom(err)
	}
	defer auth.Wipe()

	res, cleanup, err := provision.Run(ctx, client, auth, params,
		func(msg string) { fmt.Fprintln(os.Stderr, msg) })
	if err != nil {
		reportCleanup(cleanup, url)
		return exitFrom(err)
	}

	fmt.Fprintf(os.Stderr, "Configuration written and verified (%d peer(s)).\n", res.PeerCount)
	fmt.Fprintln(os.Stderr, "Nothing was written to disk; `wg-hem up` needs only the HEM.")

	provisionedKey = res.PublicKey
	fmt.Println(provisionedKey)
	if res.PSK != "" {
		fmt.Printf("psk=%s\n", res.PSK)
		fmt.Fprintln(os.Stderr, "The pre-shared key above is shown once - the stored copy is wrapped and cannot be read back.")
	}

	// What the far end has to be told, ready to paste. Stderr, like everything
	// else that is for a person: stdout stays the key and nothing but the key,
	// so `wg-hem provision ... | ssh admin@server` keeps working.
	printHandoff(res.Server)
	return nil
}

// reportCleanup says what a failed run left in the device, and what to type
// next. The facts come back from provision.Run; the sentences are the command's,
// because they name flags and a window would have neither.
func reportCleanup(c provision.Cleanup, url string) {
	fmt.Fprintln(os.Stderr)

	switch {
	case c.RemovalErr != nil:
		fmt.Fprintf(os.Stderr, "Provisioning did not finish, and the identity key it created (%s)\n"+
			"could not be removed: %v\n"+
			"It carries no %s record, so `wg-hem wipe` cannot find it; delete it by key id.\n",
			c.IdentityKID, c.RemovalErr, descr.MagicInterface)
	case c.IdentityRemoved:
		fmt.Fprintf(os.Stderr, "Provisioning did not finish; the identity key it created (%s) was removed.\n", c.IdentityKID)
	default:
		fmt.Fprintln(os.Stderr, "Provisioning did not finish.")
	}

	// Peers are named only when some were actually imported: suggesting a wipe
	// for peers that were never written sends the caller looking for something
	// that is not there.
	if c.ImportedPeers > 0 {
		fmt.Fprintf(os.Stderr, "%d peer key(s) were imported before it failed; clear them with:\n", c.ImportedPeers)
		fmt.Fprintf(os.Stderr, "  wg-hem wipe --peers-only --hem %s\n", url)
	}
	if !c.IdentityRemoved && c.IdentityKID != "" {
		fmt.Fprintln(os.Stderr, "Re-run reusing the identity key with:")
		fmt.Fprintf(os.Stderr, "  wg-hem provision --kid %s ...\n", c.IdentityKID)
	}
}

// printHandoff writes the block an administrator pastes, in both the forms a
// server is administered in.
//
// It says which value changes before showing either, because the reader is
// usually editing an entry that already exists rather than adding one: this
// person had a tunnel a minute ago, and exactly one line of it is now wrong.
func printHandoff(p handoff.Peer) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Send this to whoever runs the server. The PublicKey is the only value")
	fmt.Fprintln(os.Stderr, "that changes; the address is what identifies which peer to change it on.")
	fmt.Fprintln(os.Stderr)
	for _, line := range strings.Split(strings.TrimRight(p.ConfBlock(), "\n"), "\n") {
		fmt.Fprintf(os.Stderr, "  %s\n", line)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Or, on a running interface, without restarting it:")
	fmt.Fprintln(os.Stderr)
	for _, line := range strings.Split(strings.TrimRight(p.SetCommand(""), "\n"), "\n") {
		fmt.Fprintf(os.Stderr, "  %s\n", line)
	}
	fmt.Fprintln(os.Stderr)
}

// readPSK resolves the -psk flag. A pre-shared key is a secret, so it is never
// taken from a command-line argument, where it would sit in the process list
// and the shell history (section 10.4).
func readPSK(mode string) ([]byte, error) {
	switch mode {
	case "":
		return nil, nil
	case "generate":
		key := make([]byte, pskLen)
		if _, err := rand.Read(key); err != nil {
			return nil, failf(exitDevice, "generating a pre-shared key: %w", err)
		}
		return key, nil
	case "-":
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, failf(exitUsage, "reading the pre-shared key from stdin: %w", err)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err != nil {
			return nil, failf(exitUsage, "the pre-shared key on stdin is not valid base64: %w", err)
		}
		if len(raw) != pskLen {
			return nil, failf(exitUsage, "the pre-shared key is %d bytes, expected %d", len(raw), pskLen)
		}
		return raw, nil
	default:
		return nil, failf(exitUsage, "-psk takes '-' to read from stdin or 'generate'; a key on the command line would be visible in the process list")
	}
}
