package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/mac"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

func cmdPeer(args []string) error {
	if len(args) == 0 {
		peerUsage()
		return &exitError{code: exitUsage, err: fmt.Errorf("peer needs a subcommand")}
	}
	switch args[0] {
	case "add":
		return peerAdd(args[1:])
	case "remove", "rm":
		return peerRemove(args[1:])
	case "update":
		return peerUpdate(args[1:])
	case "-h", "--help":
		peerUsage()
		return nil
	default:
		peerUsage()
		return failf(exitUsage, "unknown peer subcommand %q", args[0])
	}
}

func peerUsage() {
	fmt.Fprint(os.Stderr, `Usage:
  wg-hem peer add    --peer <spec> [--psk -|generate] [--first]
  wg-hem peer remove --pubkey BASE64 [--delete-key]
  wg-hem peer update --peer <spec> [--psk -|generate|clear]

A <spec> is the same as provision's:
  pubkey=B64,endpoint=host:port,allowed-ips=CIDR[,allowed-ips=CIDR][,keepalive=N][,label=NAME]

Every change re-authenticates the whole configuration, so the MAC stays over
the tree as a whole rather than over its pieces.
`)
}

func peerAdd(args []string) error {
	fs := flag.NewFlagSet("peer add", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dev := addDeviceFlags(fs)
	spec := fs.String("peer", "", "peer spec (see `wg-hem peer -h`)")
	psk := fs.String("psk", "", "'-' reads a base64 pre-shared key from stdin; 'generate' makes one locally")
	first := fs.Bool("first", false, "put the peer at the head of the failover order instead of the tail")
	adopt := fs.Bool("adopt", false, "reuse a peer already in the device even if its stored settings differ")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: exitUsage, err: err}
	}
	if *spec == "" {
		return failf(exitUsage, "--peer is required")
	}
	p, err := parsePeerSpec(*spec)
	if err != nil {
		return failf(exitUsage, "--peer: %w", err)
	}
	pskBytes, err := readPSK(*psk)
	if err != nil {
		return err
	}
	defer zero(pskBytes)

	ctx := context.Background()
	client, auth, tree, err := dev.load(ctx)
	if err != nil {
		return err
	}
	defer auth.Wipe()

	for _, existing := range tree.Peers {
		if string(existing.PubKey[:]) == string(p.PubKey) {
			return failf(exitUsage, "peer %s is already in the configuration as %q",
				base64.StdEncoding.EncodeToString(p.PubKey), existing.Label)
		}
	}
	if len(tree.Peers)+1 > mac.MaxPeers {
		return failf(exitUsage, "the configuration already holds %d peers, the device's message limit allows %d",
			len(tree.Peers), mac.MaxPeers)
	}

	// Check that the interface record can still hold the reference before the
	// key is imported. Finding out afterwards would leave an imported key that
	// no configuration mentions — invisible, and indistinguishable from one an
	// attacker planted.
	probe := tree.Iface
	probe.PeerRefs = append(append([]descr.PeerRef{}, probe.PeerRefs...), descr.MakePeerRef(p.PubKey))
	probe.HasMAC = true
	if _, err := probe.Encode(); err != nil {
		return failf(exitUsage, "adding a peer does not fit: %w", err)
	}

	useTok, err := auth.Token(ctx, "keymgmt:use:"+tree.IfKID)
	if err != nil {
		return err
	}
	wrapped, err := wrapPSK(ctx, client, useTok, tree.IfKID, descr.KID(p.PubKey), pskBytes)
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

	kid, adopted, err := placePeer(ctx, client, auth, p, enc, *adopt)
	if err != nil {
		return err
	}
	if adopted {
		stored, err := readPeerRecord(ctx, client, auth, kid)
		if err != nil {
			return err
		}
		enc = *stored
		if rec, err = descr.DecodePeer(enc[:]); err != nil {
			return failf(exitDevice, "peer record %s: %w", kid, err)
		}
	}

	newPeer := config.Peer{KID: kid, Label: p.Label, Raw: enc, Peer: rec}
	copy(newPeer.PubKey[:], p.PubKey)
	if *first {
		tree.Peers = append([]config.Peer{newPeer}, tree.Peers...)
	} else {
		tree.Peers = append(tree.Peers, newPeer)
	}

	if err := reseal(ctx, client, auth, tree); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Peer %q added (%s), %d peer(s) in the configuration.\n",
		p.Label, p.Endpoint.String(), len(tree.Peers))
	if *psk == "generate" {
		fmt.Printf("psk=%s\n", base64.StdEncoding.EncodeToString(pskBytes))
		fmt.Fprintln(os.Stderr, "The pre-shared key above is shown once — the stored copy is wrapped and cannot be read back.")
	}
	return nil
}

func peerRemove(args []string) error {
	fs := flag.NewFlagSet("peer remove", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dev := addDeviceFlags(fs)
	pubkey := fs.String("pubkey", "", "base64 public key of the peer to drop")
	deleteKey := fs.Bool("delete-key", false, "also delete the imported key from the device")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: exitUsage, err: err}
	}
	want, err := decodePubKey(*pubkey)
	if err != nil {
		return err
	}

	ctx := context.Background()
	client, auth, tree, err := dev.load(ctx)
	if err != nil {
		return err
	}
	defer auth.Wipe()

	idx := -1
	for i, p := range tree.Peers {
		if string(p.PubKey[:]) == string(want) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return failf(exitUsage, "no peer with that public key is in the configuration")
	}
	if len(tree.Peers) == 1 {
		return failf(exitUsage, "%q is the only peer; a configuration with none would have nothing to connect to — use `wg-hem wipe` instead",
			tree.Peers[0].Label)
	}
	gone := tree.Peers[idx]
	tree.Peers = append(tree.Peers[:idx:idx], tree.Peers[idx+1:]...)

	if err := reseal(ctx, client, auth, tree); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Peer %q dropped from the configuration.\n", gone.Label)

	if *deleteKey {
		delTok, err := auth.Token(ctx, "keymgmt:del")
		if err != nil {
			return err
		}
		if err := client.DeleteKey(ctx, delTok, gone.KID); err != nil {
			return classify(err, exitDevice, "deleting key %s", gone.KID)
		}
		fmt.Fprintf(os.Stderr, "Key %s deleted.\n", gone.KID)
	} else {
		// One record exists per public key and several interfaces may reference
		// it, so dropping a reference is not a reason to destroy the key.
		fmt.Fprintf(os.Stderr, "Key %s is left in the device; pass --delete-key to remove it too.\n", gone.KID)
	}
	return nil
}

func peerUpdate(args []string) error {
	fs := flag.NewFlagSet("peer update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dev := addDeviceFlags(fs)
	spec := fs.String("peer", "", "peer spec; its pubkey selects which peer to replace")
	psk := fs.String("psk", "", "'-' reads a key from stdin, 'generate' makes one, 'clear' removes it; omit to keep the current one")
	if err := fs.Parse(args); err != nil {
		return &exitError{code: exitUsage, err: err}
	}
	if *spec == "" {
		return failf(exitUsage, "--peer is required")
	}
	p, err := parsePeerSpec(*spec)
	if err != nil {
		return failf(exitUsage, "--peer: %w", err)
	}

	var pskBytes []byte
	if *psk != "" && *psk != "clear" {
		if pskBytes, err = readPSK(*psk); err != nil {
			return err
		}
		defer zero(pskBytes)
	}

	ctx := context.Background()
	client, auth, tree, err := dev.load(ctx)
	if err != nil {
		return err
	}
	defer auth.Wipe()

	idx := -1
	for i, existing := range tree.Peers {
		if string(existing.PubKey[:]) == string(p.PubKey) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return failf(exitUsage, "no peer with that public key is in the configuration; use `wg-hem peer add`")
	}

	useTok, err := auth.Token(ctx, "keymgmt:use:"+tree.IfKID)
	if err != nil {
		return err
	}
	wrapped := tree.Peers[idx].PSKWrapped // keep what is there unless told otherwise
	switch {
	case *psk == "clear":
		wrapped = nil
	case pskBytes != nil:
		if wrapped, err = wrapPSK(ctx, client, useTok, tree.IfKID, tree.Peers[idx].KID, pskBytes); err != nil {
			return err
		}
	}

	rec, err := p.record(wrapped)
	if err != nil {
		return failf(exitUsage, "peer %s: %w", p.Label, err)
	}
	enc, err := rec.Encode()
	if err != nil {
		return failf(exitUsage, "peer %s: %w", p.Label, err)
	}

	updTok, err := auth.Token(ctx, "keymgmt:upd")
	if err != nil {
		return err
	}
	if err := client.UpdateKey(ctx, updTok, tree.Peers[idx].KID, p.Label, enc[:]); err != nil {
		return classify(err, exitDevice, "updating peer %s", p.Label)
	}
	tree.Peers[idx].Label = p.Label
	tree.Peers[idx].Raw = enc
	tree.Peers[idx].Peer = rec

	if err := reseal(ctx, client, auth, tree); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Peer %q updated (%s).\n", p.Label, p.Endpoint.String())
	if *psk == "generate" {
		fmt.Printf("psk=%s\n", base64.StdEncoding.EncodeToString(pskBytes))
		fmt.Fprintln(os.Stderr, "The pre-shared key above is shown once. The other end must be given the same value.")
	}
	return nil
}

// reseal rewrites the interface record for the tree's current peer list and
// re-authenticates it.
//
// The unchanged fields survive unchanged: because the encoding is distinguished,
// decoding a record and encoding it again reproduces the same bytes, so this
// rewrite touches only what the caller actually changed.
func reseal(ctx context.Context, client *hem.Client, auth *session.Auth, tree *config.Tree) error {
	rec := tree.Iface
	rec.PeerRefs = nil
	var records []mac.PeerRecord
	for _, p := range tree.Peers {
		rec.PeerRefs = append(rec.PeerRefs, descr.MakePeerRef(p.PubKey[:]))
		records = append(records, mac.PeerRecord{PubKey: p.PubKey, Descr: p.Raw})
	}
	rec.HasMAC = true
	rec.MAC = [descr.MACLen]byte{}

	unsigned, err := rec.Encode()
	if err != nil {
		return failf(exitUsage, "interface record: %w", err)
	}
	useTok, err := auth.Token(ctx, "keymgmt:use:"+tree.IfKID)
	if err != nil {
		return err
	}
	sum, err := mac.Sign(ctx, client, useTok, tree.IfKID, tree.IfPubKey, unsigned, records)
	if err != nil {
		return classify(err, exitDevice, "authenticating the configuration")
	}
	rec.MAC = sum
	signed, err := rec.Encode()
	if err != nil {
		return failf(exitUsage, "interface record: %w", err)
	}

	updTok, err := auth.Token(ctx, "keymgmt:upd")
	if err != nil {
		return err
	}
	// The label travels with the description; see UpdateKey in the SDK.
	if err := client.UpdateKey(ctx, updTok, tree.IfKID, tree.IfLabel, signed[:]); err != nil {
		return classify(err, exitDevice, "writing the interface record")
	}
	if err := mac.Verify(ctx, client, useTok, tree.IfKID, tree.IfPubKey, signed, records); err != nil {
		return failf(exitIntegrit, "the configuration just written does not verify: %w", err)
	}
	tree.Iface = rec
	tree.IfRaw = signed
	return nil
}

// wrapPSK wraps a pre-shared key under the interface key's self-ECDH, bound to
// the peer whose record will carry it, or returns nil when there is nothing to
// wrap. Each peer gets its own wrap of the same key: the ciphertexts differ, and
// none of them unwraps anywhere else.
func wrapPSK(ctx context.Context, client *hem.Client, useTok, ifKID, peerKID string, psk []byte) ([]byte, error) {
	if psk == nil {
		return nil, nil
	}
	wrapped, err := client.CipherWrap(ctx, useTok, ifKID, psk, hem.CryptoOpts{
		Alg:    config.WrapAlg,
		ExtKID: ifKID,
		Ctx:    config.PSKContext(peerKID),
	})
	if err != nil {
		return nil, classify(err, exitDevice, "wrapping the pre-shared key")
	}
	if len(wrapped) != descr.PSKWrappedLen {
		return nil, failf(exitDevice, "wrapped PSK is %d bytes, expected %d", len(wrapped), descr.PSKWrappedLen)
	}
	return wrapped, nil
}

func decodePubKey(s string) ([]byte, error) {
	if s == "" {
		return nil, failf(exitUsage, "--pubkey is required")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, failf(exitUsage, "--pubkey is not valid base64: %w", err)
	}
	if len(raw) != pubKeyLen {
		return nil, failf(exitUsage, "--pubkey is %d bytes, a Curve25519 key is %d", len(raw), pubKeyLen)
	}
	return raw, nil
}

// confirm asks for an exact word before something irreversible happens.
func confirm(prompt, want string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.TrimSpace(line) == want
}
