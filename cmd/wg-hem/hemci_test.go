//go:build hemci

// The commands against a real HEM, end to end: provision, verify, peer
// add/update/remove, a tampered record, a pre-shared key unwrapped, wipe.
//
// The unit tests answer the way this code believes the device answers; this
// one asks the device. It exists because the two worst bugs of firmware 1.3
// (hmac/verify answering 200 for a wrong MAC, ctx renamed to hkdf_ctx) passed
// every unit test.
//
// It wipes every WG:* record on the device it is pointed at. Run it only
// against a HEM kept for it:
//
//	WG_HEM_URL=https://wg-tester-ci.playground.ence.do HEM_CI_PASSPHRASE=... \
//	  go test -tags hemci -run TestHEM -v ./cmd/wg-hem
//
// .github/workflows/hem.yml runs it with the passphrase from the hem-ci
// environment.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

// Peer keys made for this test: nothing holds their private halves, and no
// tunnel is brought up here.
const (
	ciPeerA = "i14L0qgxykUZL7GVV2x/hBXwuvbcXbcv+TIEp60Pk0M="
	ciPeerB = "9Sq9OSCbaKMqvV6MDwo1sVoYUqyBRcqCPEHEHZ2Zvhc="
)

func TestHEM(t *testing.T) {
	url, pass := os.Getenv("WG_HEM_URL"), os.Getenv("HEM_CI_PASSPHRASE")
	if url == "" || pass == "" {
		t.Skip("WG_HEM_URL and HEM_CI_PASSPHRASE are not set")
	}
	old := readPassphrase
	readPassphrase = func() ([]byte, error) { return []byte(pass), nil }
	t.Cleanup(func() { readPassphrase = old })

	step := func(name string, fn func([]string) error, args ...string) string {
		t.Helper()
		out, err := capture(fn, args)
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		return out
	}
	expect := func(out string, lines ...string) {
		t.Helper()
		for _, l := range lines {
			if !strings.Contains(out, l+"\n") {
				t.Errorf("verify does not show %q:\n%s", l, out)
			}
		}
	}

	// A previous run that died half way leaves records behind.
	step("wipe before", cmdWipe, "--yes")

	pub := strings.TrimSpace(step("provision", cmdProvision,
		"--address", "192.168.77.2/32",
		"--peer", "pubkey="+ciPeerA+",endpoint=192.0.2.1:51820,allowed-ips=192.168.77.0/24,label=ci-a"))
	if raw, err := base64.StdEncoding.DecodeString(pub); err != nil || len(raw) != 32 {
		t.Fatalf("provision printed %q, not a public key", pub)
	}

	expect(step("verify", cmdVerify),
		"interface.pubkey "+pub,
		"interface.address 192.168.77.2/32",
		"peer.0.label ci-a",
		"peer.0.endpoint 192.0.2.1:51820",
		"peer.0.psk false")

	step("peer add", cmdPeer, "add",
		"--peer", "pubkey="+ciPeerB+",endpoint=198.51.100.7:51820,allowed-ips=192.168.77.0/24,keepalive=25,label=ci-b",
		"--psk", "generate")
	step("peer update", cmdPeer, "update",
		"--peer", "pubkey="+ciPeerA+",endpoint=192.0.2.9:51820,allowed-ips=192.168.77.0/24,label=ci-a")
	expect(step("verify after peer changes", cmdVerify),
		"peer.0.endpoint 192.0.2.9:51820",
		"peer.1.label ci-b",
		"peer.1.keepalive 25",
		"peer.1.psk true")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := hem.NewClient(url, hem.Config{})
	defer c.ClearKeys()
	tok := func(ctx context.Context, scope string) (string, error) {
		return c.AuthPassword(ctx, []byte(pass), scope, 300)
	}

	// The pre-shared key comes back out of the device, under the context that
	// binds it to its peer.
	tree, err := config.Load(ctx, c, tok, nil)
	if err != nil {
		t.Fatalf("loading the tree: %v", err)
	}
	var withPSK *config.Peer
	for i := range tree.Peers {
		if tree.Peers[i].PSKWrapped != nil {
			withPSK = &tree.Peers[i]
		}
	}
	if withPSK == nil {
		t.Fatal("no peer carries a pre-shared key")
	}
	useTok, err := tok(ctx, "keymgmt:use:"+tree.IfKID)
	if err != nil {
		t.Fatal(err)
	}
	if psk, err := tree.UnwrapPSK(ctx, c, useTok, *withPSK); err != nil || len(psk) != config.PSKLen {
		t.Fatalf("unwrapping the pre-shared key: %d bytes, %v", len(psk), err)
	}

	// A record changed behind the MAC's back is refused, and accepted again
	// once it is put back. The change is a well-formed record pointing the
	// peer somewhere else - the attack the MAC exists for - not a flipped bit
	// the decoder would refuse before the MAC is looked at.
	victim := tree.Peers[0]
	moved := victim.Peer
	moved.Endpoint = descr.Endpoint{IP: netip.MustParseAddr("203.0.113.66"), Port: 51820}
	tampered, err := moved.Encode()
	if err != nil {
		t.Fatal(err)
	}
	updTok, err := tok(ctx, "keymgmt:upd")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateKey(ctx, updTok, victim.KID, victim.Label, tampered[:]); err != nil {
		t.Fatalf("tampering with %s: %v", victim.Label, err)
	}
	out, err := capture(cmdVerify, nil)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != exitIntegrit {
		t.Errorf("verify of a tampered tree: %v (want exit %d)\n%s", err, exitIntegrit, out)
	}
	if err := c.UpdateKey(ctx, updTok, victim.KID, victim.Label, victim.Raw[:]); err != nil {
		t.Fatalf("restoring %s: %v", victim.Label, err)
	}
	step("verify after restore", cmdVerify)

	step("peer remove", cmdPeer, "remove", "--pubkey", ciPeerB, "--delete-key")
	out = step("verify after remove", cmdVerify)
	if strings.Contains(out, "peer.1.") {
		t.Errorf("a removed peer is still listed:\n%s", out)
	}

	step("wipe", cmdWipe, "--yes")
	for _, magic := range []string{descr.MagicInterface, descr.MagicPeer} {
		if left, err := c.SearchKeysAll(ctx, "", []byte(magic), hem.SearchOpts{}); err != nil || len(left) != 0 {
			t.Errorf("after wipe: %d %s records left, %v", len(left), magic, err)
		}
	}
}

// capture runs a command with stdout collected; stderr goes to the test log
// as it is.
func capture(fn func([]string) error, args []string) (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	err = fn(args)
	os.Stdout = old
	w.Close()
	out := <-done
	r.Close()
	return string(out), err
}
