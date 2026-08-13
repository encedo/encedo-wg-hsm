package main

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

// treeWith builds an authenticated-looking configuration. Nothing here talks to
// a device: peer selection and the UAPI rendering are decisions made from the
// tree alone, which is what these tests pin down.
func treeWith(t *testing.T, peers ...config.Peer) *config.Tree {
	t.Helper()
	tree := &config.Tree{IfKID: strings.Repeat("a", 32), Peers: peers}
	tree.Iface.Addrs = []netip.Prefix{netip.MustParsePrefix("10.0.0.7/32")}
	return tree
}

func testPeer(label string, keyByte byte, endpoint string, allowed ...string) config.Peer {
	p := config.Peer{Label: label, KID: strings.Repeat(string("0123456789abcdef"[keyByte%16]), 32)}
	for i := range p.PubKey {
		p.PubKey[i] = keyByte
	}
	host, portStr, _ := strings.Cut(endpoint, ":")
	var port uint16
	for _, c := range portStr {
		port = port*10 + uint16(c-'0')
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		p.Endpoint = descr.Endpoint{IP: ip, Port: port}
	} else {
		p.Endpoint = descr.Endpoint{Host: host, Port: port}
	}
	for _, a := range allowed {
		p.AllowedIPs = append(p.AllowedIPs, netip.MustParsePrefix(a))
	}
	return p
}

func withReadLine(t *testing.T, answer string) {
	t.Helper()
	prev := readLine
	t.Cleanup(func() { readLine = prev })
	readLine = func() (string, error) { return answer, nil }
}

func TestASinglePeerIsNotWorthAsking(t *testing.T) {
	withReadLine(t, "this must not be read\n")
	tree := treeWith(t, testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"))

	p, err := selectPeer(tree, 0, "")
	if err != nil {
		t.Fatalf("selectPeer: %v", err)
	}
	if p.Label != "hq" {
		t.Errorf("selected %q, want hq", p.Label)
	}
}

func TestPeerIndexSelects(t *testing.T) {
	tree := treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
	)

	p, err := selectPeer(tree, 2, "")
	if err != nil {
		t.Fatalf("selectPeer: %v", err)
	}
	if p.Label != "backup" {
		t.Errorf("selected %q, want backup", p.Label)
	}
}

func TestPeerIndexOutOfRange(t *testing.T) {
	tree := treeWith(t, testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"))

	_, err := selectPeer(tree, 2, "")
	if err == nil {
		t.Fatal("--peer 2 was accepted against a one-peer configuration")
	}
	assertExit(t, err, exitUsage)
}

func TestPeerPubKeyPrefixSelects(t *testing.T) {
	tree := treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
	)
	want := base64.StdEncoding.EncodeToString(tree.Peers[1].PubKey[:])

	p, err := selectPeer(tree, 0, want[:6])
	if err != nil {
		t.Fatalf("selectPeer: %v", err)
	}
	if p.Label != "backup" {
		t.Errorf("selected %q, want backup", p.Label)
	}
}

// A prefix short enough to match two peers is refused rather than resolved by
// order: the point of naming a key is to be unambiguous about which one.
func TestAnAmbiguousPubKeyPrefixIsRefused(t *testing.T) {
	a := testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0")
	b := testPeer("backup", 1, "198.51.100.1:51820", "0.0.0.0/0")
	b.PubKey[len(b.PubKey)-1] = 0xFF // differs only at the end: a long shared prefix
	tree := treeWith(t, a, b)

	shared := base64.StdEncoding.EncodeToString(a.PubKey[:])[:8]
	_, err := selectPeer(tree, 0, shared)
	if err == nil {
		t.Fatal("a prefix matching two peers was accepted")
	}
	assertExit(t, err, exitUsage)
}

func TestAnUnknownPubKeyPrefixIsRefused(t *testing.T) {
	tree := treeWith(t, testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"))

	if _, err := selectPeer(tree, 0, "ZZZZ"); err == nil {
		t.Fatal("a prefix matching no peer was accepted")
	}
}

func TestTheDefaultAnswerIsTheStoredOrder(t *testing.T) {
	withReadLine(t, "\n")
	tree := treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
	)

	p, err := selectPeer(tree, 0, "")
	if err != nil {
		t.Fatalf("selectPeer: %v", err)
	}
	if p.Label != "hq" {
		t.Errorf("selected %q; an empty answer means the head of the failover order", p.Label)
	}
}

func TestAnAnsweredPromptSelects(t *testing.T) {
	withReadLine(t, "2\n")
	tree := treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
	)

	p, err := selectPeer(tree, 0, "")
	if err != nil {
		t.Fatalf("selectPeer: %v", err)
	}
	if p.Label != "backup" {
		t.Errorf("selected %q, want backup", p.Label)
	}
}

func TestAnAnswerOutsideTheListIsRefused(t *testing.T) {
	withReadLine(t, "7\n")
	tree := treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
	)

	if _, err := selectPeer(tree, 0, ""); err == nil {
		t.Fatal("an answer outside the list was accepted")
	}
}

// A tree with no peers is not a usage problem — it means the configuration in
// the device is not one this client can run, which is an integrity answer.
func TestNoPeersIsAnIntegrityFailure(t *testing.T) {
	if _, err := selectPeer(treeWith(t), 0, ""); err == nil {
		t.Fatal("a configuration with no peers was accepted")
	} else {
		assertExit(t, err, exitIntegrit)
	}
}

func assertExit(t *testing.T, err error, want int) {
	t.Helper()
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("error carries no exit code: %v", err)
	}
	if ee.code != want {
		t.Errorf("exit code %d, want %d (%v)", ee.code, want, err)
	}
}
