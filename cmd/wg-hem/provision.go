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

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/mac"
)

// pskLen is the length of a WireGuard pre-shared key.
const pskLen = config.PSKLen

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
	adoptPeers := fs.Bool("adopt", false, "reuse a peer already in the device even if its stored settings differ from the flags")
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
	importedPeers := 0
	recordWritten := false
	// A key this run created, which no record yet names, is litter only this run
	// can identify: `wipe` searches by the WG: prefix and a bare key carries
	// none. So it goes back out the way it came in. The condition is narrow on
	// purpose — an adopted key belongs to the caller, and once the interface
	// record is written the tree may be a working configuration, so a failure
	// after that point is not licence to delete anything.
	defer func() {
		if retErr == nil {
			return
		}
		fmt.Fprintln(os.Stderr)

		removed := false
		if createdIdentity && !recordWritten {
			if err := deleteKey(ctx, client, auth, ifKID); err != nil {
				fmt.Fprintf(os.Stderr, "Provisioning did not finish, and the identity key it created (%s)\n"+
					"could not be removed: %v\n"+
					"It carries no %s record, so `wg-hem wipe` cannot find it; delete it by key id.\n",
					ifKID, err, descr.MagicInterface)
			} else {
				fmt.Fprintf(os.Stderr, "Provisioning did not finish; the identity key it created (%s) was removed.\n", ifKID)
				removed = true
			}
		} else {
			fmt.Fprintln(os.Stderr, "Provisioning did not finish.")
		}

		// Peers are named only when some were actually imported: suggesting a
		// wipe for peers that were never written sends the caller looking for
		// something that is not there.
		if importedPeers > 0 {
			fmt.Fprintf(os.Stderr, "%d peer key(s) were imported before it failed; clear them with:\n", importedPeers)
			fmt.Fprintf(os.Stderr, "  wg-hem wipe --peers-only --hem %s\n", url)
		}
		if !removed && ifKID != "" {
			fmt.Fprintln(os.Stderr, "Re-run reusing the identity key with:")
			fmt.Fprintf(os.Stderr, "  wg-hem provision --kid %s ...\n", ifKID)
		}
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

	ifRec := descr.Interface{
		Addrs:      addrs,
		MTU:        uint16(*mtu),
		DNS:        dns,
		ListenPort: uint16(*listenPort),
		HasMAC:     true,
	}
	var peerRecords []mac.PeerRecord
	for _, p := range peers {
		// The pre-shared key is wrapped once per peer, under a key that exists
		// only inside the device — the interface key's ECDH against itself,
		// bound to this peer. Wrapping under ECDH(interface, peer) would instead
		// hand the key-encryption key to whoever holds the peer's private key.
		wrapped, err := wrapPSK(ctx, client, useTok, ifKID, descr.KID(p.PubKey), pskBytes)
		if err != nil {
			return err
		}
		rec, err := p.record(wrapped)
		if err != nil {
			return failf(exitUsage, "peer %s: %w", p.Label, err)
		}
		enc, err := rec.Encode()
		if err != nil {
			return failf(exitUsage, "peer %s: %w", p.Label, err)
		}
		_, adopted, err := placePeer(ctx, client, auth, p, enc, *adoptPeers)
		if err != nil {
			return err
		}
		if adopted {
			// The stored record is what the tree must authenticate, not the one
			// the flags described.
			stored, err := readPeerRecord(ctx, client, auth, descr.KID(p.PubKey))
			if err != nil {
				return err
			}
			enc = *stored
		}
		// Reference order is failover priority, so it follows the flag order.
		ifRec.PeerRefs = append(ifRec.PeerRefs, descr.MakePeerRef(p.PubKey))

		var pr mac.PeerRecord
		copy(pr.PubKey[:], p.PubKey)
		pr.Descr = enc
		peerRecords = append(peerRecords, pr)
		if !adopted {
			importedPeers++
			fmt.Fprintf(os.Stderr, "Peer imported: %s (%s)\n", p.Label, p.Endpoint.String())
		}
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
	// From here the key is named by a record, so a later failure leaves
	// something `wipe` can find — and something that may already be a working
	// configuration. Either way it is no longer this run's to remove.
	recordWritten = true

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

// deleteKey removes a key this run created and then had to abandon. It asks for
// its own token: provisioning holds scopes for generating, reading and updating,
// and a device that grants those does not thereby grant deletion.
func deleteKey(ctx context.Context, client *hem.Client, auth *authenticator, kid string) error {
	tok, err := auth.token(ctx, "keymgmt:del")
	if err != nil {
		return err
	}
	return client.DeleteKey(ctx, tok, kid)
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
