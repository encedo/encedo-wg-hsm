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

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/mac"
)

// pskCtx domain-separates the key that wraps a PSK from any other wrap use of
// the same interface key (§5).
const pskCtx = "ENC-WG-PSK-v1"

// pskLen is the length of a WireGuard pre-shared key.
const pskLen = 32

// wrapAlg selects the size of the derived key-encryption key.
const wrapAlg = "AES256"

// keyType is the type of the interface identity key.
const keyType = "CURVE25519"

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, " ") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdProvision(args []string) (retErr error) {
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
	mobile := fs.Bool("mobile", false, "authorize with a mobile push instead of the passphrase")
	insecure := fs.Bool("insecure", false, "skip TLS verification (self-signed PPA certificate)")
	expHours := fs.Int("session", 1, "token lifetime in hours")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: wg-hem provision [flags]

Writes a complete WireGuard configuration into the HEM: an identity key, one
imported key per peer, the addressing and routing in their descr fields, and a
MAC over the whole tree. Nothing is written to disk.

On success stdout carries the interface public key in base64 — hand it to
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
	if len(peerFlags) > mac.MaxPeers {
		return failf(exitUsage, "%d peers, but the device's message limit allows %d in one authenticated tree",
			len(peerFlags), mac.MaxPeers)
	}
	var peers []peerSpec
	seenKeys := map[string]bool{}
	for i, spec := range peerFlags {
		p, err := parsePeerSpec(spec)
		if err != nil {
			return failf(exitUsage, "-peer #%d: %w", i+1, err)
		}
		fp := string(p.PubKey)
		if seenKeys[fp] {
			return failf(exitUsage, "-peer #%d: duplicate public key", i+1)
		}
		seenKeys[fp] = true
		peers = append(peers, p)
	}
	if *mtu < 0 || *mtu > 65535 {
		return failf(exitUsage, "-mtu out of range")
	}
	if *listenPort < 0 || *listenPort > 65535 {
		return failf(exitUsage, "-listen-port out of range")
	}

	pskBytes, err := readPSK(*psk)
	if err != nil {
		return err
	}
	defer zero(pskBytes)

	// Encoding every record now, before the device is touched, so an
	// over-budget peer cannot leave a half-written configuration behind.
	for i, p := range peers {
		probe := pskBytes
		if probe != nil {
			probe = make([]byte, descr.PSKWrappedLen)
		}
		if _, err := p.record(probe); err != nil {
			return failf(exitUsage, "-peer #%d (%s): %w", i+1, p.Label, err)
		}
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
	client := hem.NewClient(url, hem.Config{Broker: *broker, InsecureSkipVerify: *insecure})

	fmt.Fprintf(os.Stderr, "Connecting to %s...\n", url)
	if err := client.Checkin(ctx); err != nil {
		return classify(err, exitNetwork, "checkin")
	}

	auth := &authenticator{client: client, mobile: *mobile, expSecs: *expHours * 3600}
	defer auth.wipe()

	ifKID := *kid
	createdIdentity := false
	// Anything created before a later step fails would otherwise be invisible:
	// an identity key carries no WG:if: record until the last write, so a prefix
	// search — and therefore `wg-hem wipe` — cannot find it.
	defer func() {
		if retErr == nil {
			return
		}
		fmt.Fprintln(os.Stderr, "\nProvisioning did not finish. The device now holds:")
		if createdIdentity {
			fmt.Fprintf(os.Stderr, "  identity key %s (no WG:if: record yet, so `wipe` cannot see it)\n", ifKID)
		}
		fmt.Fprintln(os.Stderr, "  any peer keys reported as imported above")
		fmt.Fprintln(os.Stderr, "To carry on where this left off, re-run with:")
		fmt.Fprintf(os.Stderr, "  wg-hem wipe --peers-only --hem %s\n", url)
		fmt.Fprintf(os.Stderr, "  wg-hem provision --kid %s ...    # reuses the identity key\n", ifKID)
	}()

	if ifKID == "" {
		tok, err := auth.token(ctx, "keymgmt:gen")
		if err != nil {
			return err
		}
		ifKID, err = client.CreateKey(ctx, tok, *label, keyType, nil, "")
		if err != nil {
			return classify(err, exitDevice, "creating the identity key")
		}
		createdIdentity = true
		fmt.Fprintf(os.Stderr, "Identity key created: %s\n", ifKID)
	} else {
		fmt.Fprintf(os.Stderr, "Reusing identity key %s\n", ifKID)
	}

	useTok, err := auth.token(ctx, "keymgmt:use:"+ifKID)
	if err != nil {
		return err
	}
	ifKey, err := client.GetPubKey(ctx, useTok, ifKID)
	if err != nil {
		return classify(err, exitDevice, "reading the identity public key")
	}
	if ifKey.Type != "" && !strings.Contains(ifKey.Type, keyType) {
		return failf(exitUsage, "key %s is of type %s, expected %s", ifKID, ifKey.Type, keyType)
	}
	if len(ifKey.PubKey) != pubKeyLen {
		return failf(exitDevice, "identity public key is %d bytes, expected %d", len(ifKey.PubKey), pubKeyLen)
	}
	var ifPub [pubKeyLen]byte
	copy(ifPub[:], ifKey.PubKey)

	// The PSK is wrapped under a key that only exists inside the device: the
	// interface key's ECDH against itself. Wrapping under ECDH(interface, peer)
	// would hand the key-encryption key to whoever holds the peer's private key.
	var wrapped []byte
	if pskBytes != nil {
		wrapped, err = client.CipherWrap(ctx, useTok, ifKID, pskBytes, hem.CryptoOpts{
			Alg:    wrapAlg,
			ExtKID: ifKID,
			Ctx:    []byte(pskCtx),
		})
		if err != nil {
			return classify(err, exitDevice, "wrapping the pre-shared key")
		}
		if len(wrapped) != descr.PSKWrappedLen {
			return failf(exitDevice, "wrapped PSK is %d bytes, expected %d", len(wrapped), descr.PSKWrappedLen)
		}
	}

	impTok, err := auth.token(ctx, "keymgmt:imp")
	if err != nil {
		return err
	}

	ifRec := descr.Interface{
		Addrs:      addrs,
		MTU:        uint16(*mtu),
		DNS:        dns,
		ListenPort: uint16(*listenPort),
		HasMAC:     true,
	}
	var peerRecords []mac.PeerRecord
	for _, p := range peers {
		rec, err := p.record(wrapped)
		if err != nil {
			return failf(exitUsage, "peer %s: %w", p.Label, err)
		}
		enc, err := rec.Encode()
		if err != nil {
			return failf(exitUsage, "peer %s: %w", p.Label, err)
		}
		if _, err := client.ImportKey(ctx, impTok, p.Label, keyType, p.PubKey, enc[:], ""); err != nil {
			return classify(err, exitDevice, "importing peer %s", p.Label)
		}
		// Reference order is failover priority, so it follows the flag order.
		ifRec.PeerRefs = append(ifRec.PeerRefs, descr.MakePeerRef(p.PubKey))

		var pr mac.PeerRecord
		copy(pr.PubKey[:], p.PubKey)
		pr.Descr = enc
		peerRecords = append(peerRecords, pr)
		fmt.Fprintf(os.Stderr, "Peer imported: %s (%s)\n", p.Label, p.Endpoint.String())
	}

	// The MAC is computed over the record as it will be stored, with the MAC
	// tag present and zeroed, so signing and verifying see the same bytes.
	unsigned, err := ifRec.Encode()
	if err != nil {
		return failf(exitUsage, "interface record: %w", err)
	}
	sum, err := mac.Sign(ctx, client, useTok, ifKID, ifPub, unsigned, peerRecords)
	if err != nil {
		return classify(err, exitDevice, "authenticating the configuration")
	}
	ifRec.MAC = sum
	signed, err := ifRec.Encode()
	if err != nil {
		return failf(exitUsage, "interface record: %w", err)
	}

	updTok, err := auth.token(ctx, "keymgmt:upd")
	if err != nil {
		return err
	}
	// The label goes with it. The reference suite always sends both, and a
	// device may reject an update carrying only a description.
	if err := client.UpdateKey(ctx, updTok, ifKID, *label, signed[:]); err != nil {
		return classify(err, exitDevice, "writing the interface record")
	}

	// Read it back and verify, so provisioning fails here rather than at the
	// first startup on the machine that will actually use it.
	if err := mac.Verify(ctx, client, useTok, ifKID, ifPub, signed, peerRecords); err != nil {
		return failf(exitIntegrit, "the configuration just written does not verify: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Configuration written and verified (%d peer(s)).\n", len(peers))
	fmt.Fprintln(os.Stderr, "Nothing was written to disk; `wg-hem up` needs only the HEM.")

	fmt.Println(base64.StdEncoding.EncodeToString(ifPub[:]))
	if *psk == "generate" {
		fmt.Printf("psk=%s\n", base64.StdEncoding.EncodeToString(pskBytes))
		fmt.Fprintln(os.Stderr, "The pre-shared key above is shown once — the stored copy is wrapped and cannot be read back.")
	}
	return nil
}

// readPSK resolves the -psk flag. A pre-shared key is a secret, so it is never
// taken from a command-line argument, where it would sit in the process list
// and the shell history (§10.4).
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
