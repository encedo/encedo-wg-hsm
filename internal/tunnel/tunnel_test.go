package tunnel

import (
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

// These tests came with the code they cover, from cmd/wg-hem. The helpers below
// are copies of the ones there: the command still needs them for peer selection,
// which stayed behind, and sharing a test helper across a package boundary would
// mean exporting something that exists only for tests.

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

// A range the interface routes and the incoming peer does not claim becomes a
// black hole. section 6.4 keeps the routes on purpose, so the least this can do is say
// which ones are now going nowhere.
func TestWarnsAboutRangesTheNewPeerDoesNotClaim(t *testing.T) {
	from := testPeer("hq", 1, "203.0.113.1:51820", "10.0.0.0/24", "192.168.0.0/16")
	to := testPeer("backup", 2, "198.51.100.1:51820", "10.0.0.0/24")

	out := allowedIPsDiffer(&from, &to)
	if !strings.Contains(out, "192.168.0.0/16") {
		t.Errorf("the orphaned range was not named:\n%s", out)
	}
	if strings.Contains(out, "10.0.0.0/24") {
		t.Errorf("a range the new peer does claim was reported as orphaned:\n%s", out)
	}
}

func TestNoWarningWhenTheNewPeerClaimsEverything(t *testing.T) {
	from := testPeer("hq", 1, "203.0.113.1:51820", "10.0.0.0/24")
	to := testPeer("backup", 2, "198.51.100.1:51820", "10.0.0.0/24", "192.168.0.0/16")

	if out := allowedIPsDiffer(&from, &to); out != "" {
		t.Errorf("warned about nothing:\n%s", out)
	}
}

// A peer whose record has no AllowedIPs at all would silently route nothing;
// the warning is the only thing that would say so.
func TestWarnsWhenTheNewPeerClaimsNothing(t *testing.T) {
	from := testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0")
	to := config.Peer{Label: "empty"}
	to.Endpoint = from.Endpoint
	to.AllowedIPs = nil

	out := allowedIPsDiffer(&from, &to)
	if !strings.Contains(out, "0.0.0.0/0") {
		t.Errorf("an incoming peer claiming nothing went unreported:\n%s", out)
	}
}

// awaitHandshake must not outlive the tunnel: when the interface ends for a
// reason no peer would fix, the wait stops rather than running its timeout out.
func TestAwaitHandshakeStopsWhenTheTunnelEnds(t *testing.T) {
	prev := FailoverTimeout
	FailoverTimeout = 10 * time.Second
	t.Cleanup(func() { FailoverTimeout = prev })

	ending := make(chan struct{})
	close(ending)

	start := time.Now()
	if awaitHandshake("nosuchiface", ending) {
		t.Error("awaitHandshake claimed a handshake on an interface that is not up")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("awaitHandshake waited %s past the end of the tunnel", elapsed)
	}
}

// An interface that never answers is reported as not having handshaken, after
// the timeout and not before.
func TestAwaitHandshakeGivesUpAfterTheTimeout(t *testing.T) {
	prevTimeout, prevPoll := FailoverTimeout, handshakePoll
	FailoverTimeout, handshakePoll = 200*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { FailoverTimeout, handshakePoll = prevTimeout, prevPoll })

	start := time.Now()
	if awaitHandshake("nosuchiface", make(chan struct{})) {
		t.Error("awaitHandshake claimed a handshake on an interface that is not up")
	}
	if elapsed := time.Since(start); elapsed < 150*time.Millisecond {
		t.Errorf("awaitHandshake gave up after %s, before its timeout", elapsed)
	}
}

func TestUAPIReplacePeerDropsThePrevious(t *testing.T) {
	peer := testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0")
	peer.Keepalive = 25

	got := uapiReplacePeer(&peer, nil)
	if !strings.HasPrefix(got, "replace_peers=true\n") {
		t.Errorf("replace_peers is not the first instruction:\n%s", got)
	}
	if strings.Contains(got, "private_key=") {
		t.Errorf("a replacement rewrote the interface's identity:\n%s", got)
	}
	if !strings.Contains(got, "endpoint=198.51.100.1:51820\n") {
		t.Errorf("the new endpoint is missing:\n%s", got)
	}
	if !strings.Contains(got, "persistent_keepalive_interval=25\n") {
		t.Errorf("keepalive is missing:\n%s", got)
	}
}

func TestUAPIReplacePeerCarriesThePSK(t *testing.T) {
	peer := testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0")
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 0x5A
	}

	if got := uapiReplacePeer(&peer, psk); !strings.Contains(got, "preshared_key=") {
		t.Errorf("the incoming peer lost its pre-shared key:\n%s", got)
	}
}

func TestUAPIConfigCarriesTheSelectedPeerOnly(t *testing.T) {
	tree := treeWith(t,
		testPeer("hq", 1, "203.0.113.1:51820", "10.0.0.0/24", "192.168.0.0/16"),
		testPeer("backup", 2, "198.51.100.1:51820", "0.0.0.0/0"),
	)
	tree.Peers[0].Keepalive = 25
	tree.Iface.ListenPort = 51820

	got := uapiConfig(tree, &tree.Peers[0], nil)

	want := []string{
		"private_key=" + strings.Repeat("0", 64),
		"listen_port=51820",
		"public_key=" + hex.EncodeToString(tree.Peers[0].PubKey[:]),
		"endpoint=203.0.113.1:51820",
		"allowed_ip=10.0.0.0/24",
		"allowed_ip=192.168.0.0/16",
		"persistent_keepalive_interval=25",
	}
	for _, line := range want {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
	if strings.Contains(got, hex.EncodeToString(tree.Peers[1].PubKey[:])) {
		t.Error("the unselected peer reached the device; cryptokey routing gives the AllowedIPs to one peer")
	}
	if strings.Contains(got, "preshared_key=") {
		t.Error("a preshared_key line appeared for a peer that has none")
	}
}

// The private key is the whole point: it stays in the device, and the fork takes
// the public key from the injected session instead of deriving it.
func TestUAPIConfigNeverCarriesAPrivateKey(t *testing.T) {
	tree := treeWith(t, testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"))

	got := uapiConfig(tree, &tree.Peers[0], nil)
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "private_key=") && line != "private_key="+strings.Repeat("0", 64) {
			t.Fatalf("private_key is not the sentinel: %q", line)
		}
	}
}

func TestUAPIConfigCarriesThePSK(t *testing.T) {
	tree := treeWith(t, testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"))
	psk := make([]byte, 32)
	for i := range psk {
		psk[i] = 0x5A
	}

	got := uapiConfig(tree, &tree.Peers[0], psk)
	if !strings.Contains(got, "preshared_key="+hex.EncodeToString(psk)+"\n") {
		t.Errorf("the pre-shared key did not reach the device:\n%s", got)
	}
}

func TestUAPIConfigOmitsAnAbsentListenPort(t *testing.T) {
	tree := treeWith(t, testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"))

	if got := uapiConfig(tree, &tree.Peers[0], nil); strings.Contains(got, "listen_port=") {
		t.Errorf("listen_port was set; a client behind NAT wants a random port:\n%s", got)
	}
}

func TestUAPIConfigKeepsAHostEndpointUnresolved(t *testing.T) {
	tree := treeWith(t, testPeer("hq", 1, "vpn.example.com:51820", "0.0.0.0/0"))

	got := uapiConfig(tree, &tree.Peers[0], nil)
	if !strings.Contains(got, "endpoint=vpn.example.com:51820\n") {
		t.Errorf("the endpoint name was not passed through:\n%s", got)
	}
}

func TestDNSServersAreRendered(t *testing.T) {
	tree := treeWith(t, testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"))
	tree.Iface.DNS = []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")}

	got := dnsServers(tree)
	if len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.0.0.2" {
		t.Errorf("dnsServers = %v", got)
	}
}

// A tunnel that cannot see its own interface must not act on what it cannot
// see. Windows is where this happens: upstream's UAPI pipe wants SYSTEM as its
// owner, which an elevated administrator may not assign, so the tunnel comes up
// and nothing can observe it.
//
// Waiting the failover timeout and then declaring the peer dead would be worse
// than not looking at all - it would take a working tunnel down on the strength
// of a question that was never asked.
func TestABlindTunnelDoesNotFailOver(t *testing.T) {
	tree := treeWith(t, testPeer("hq", 1, "203.0.113.1:51820", "0.0.0.0/0"))

	asked := false
	tun := &Tunnel{
		blind: true,
		peer:  &tree.Peers[0],
		opts: Opts{Tree: tree, SelectNext: func(*config.Tree, *config.Peer) (*config.Peer, error) {
			asked = true
			return nil, nil
		}},
	}

	ending := make(chan struct{})
	close(ending)

	done := make(chan error, 1)
	go func() { done <- tun.hold(nil, ending) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("hold returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a blind tunnel waited on a handshake it can never see")
	}
	if asked {
		t.Error("a blind tunnel failed over; it has no evidence the peer is dead")
	}
}
