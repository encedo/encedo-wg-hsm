package mac

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

func pubKey(b byte) [PubKeyLen]byte {
	var k [PubKeyLen]byte
	for i := range k {
		k[i] = b
	}
	return k
}

func peerRecord(t *testing.T, key byte, endpoint string) PeerRecord {
	t.Helper()
	ap, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		t.Fatalf("ParseAddrPort(%q): %v", endpoint, err)
	}
	enc, err := descr.Peer{
		Endpoint:   descr.Endpoint{IP: ap.Addr(), Port: ap.Port()},
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}.Encode()
	if err != nil {
		t.Fatalf("peer Encode: %v", err)
	}
	return PeerRecord{PubKey: pubKey(key), Descr: enc}
}

// tree builds an interface record referencing the given peers, in the given
// reference order.
func tree(t *testing.T, peers []PeerRecord, withMAC bool) [descr.Size]byte {
	t.Helper()
	rec := descr.Interface{
		Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.7/32")},
		MTU:   1380,
	}
	for _, p := range peers {
		rec.PeerRefs = append(rec.PeerRefs, descr.MakePeerRef(p.PubKey[:]))
	}
	if withMAC {
		rec.HasMAC = true
		for i := range rec.MAC {
			rec.MAC[i] = 0xEE
		}
	}
	enc, err := rec.Encode()
	if err != nil {
		t.Fatalf("interface Encode: %v", err)
	}
	return enc
}

func TestCanonicalLayout(t *testing.T) {
	ifPub := pubKey(0x11)
	// 0xF0 sorts after 0x0A, but it is listed first as the preferred peer.
	high := peerRecord(t, 0xF0, "203.0.113.1:51820")
	low := peerRecord(t, 0x0A, "198.51.100.1:51820")
	peers := []PeerRecord{high, low}
	ifDescr := tree(t, peers, true)

	msg, err := Canonical(ifPub, ifDescr, peers)
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if want := fixedLen + 2*perPeer; len(msg) != want {
		t.Fatalf("message is %d bytes, want %d", len(msg), want)
	}

	off := 0
	if got := string(msg[off : off+len(Domain)]); got != Domain {
		t.Errorf("domain = %q, want %q", got, Domain)
	}
	off += len(Domain)
	if !bytes.Equal(msg[off:off+PubKeyLen], ifPub[:]) {
		t.Error("interface public key missing at its offset")
	}
	off += PubKeyLen

	zeroed, _ := descr.ZeroMAC(ifDescr)
	if !bytes.Equal(msg[off:off+descr.Size], zeroed[:]) {
		t.Error("interface record in the message is not the MAC-zeroed form")
	}
	// The stored record still carries its MAC value; only the copy in the
	// message is zeroed, or verification could never reproduce the signature.
	if bytes.Equal(zeroed[:], ifDescr[:]) {
		t.Error("ZeroMAC was a no-op on a record that has a MAC")
	}
	off += descr.Size

	// Peers appear ordered by public key, not in reference order.
	if !bytes.Equal(msg[off:off+PubKeyLen], low.PubKey[:]) {
		t.Errorf("first peer in the message is %x, want the lowest key %x",
			msg[off:off+PubKeyLen], low.PubKey[:PubKeyLen])
	}
	off += PubKeyLen
	if !bytes.Equal(msg[off:off+descr.Size], low.Descr[:]) {
		t.Error("first peer's descr does not follow its public key")
	}
	off += descr.Size
	if !bytes.Equal(msg[off:off+PubKeyLen], high.PubKey[:]) {
		t.Error("second peer is not the higher key")
	}
}

// Reference order is failover priority. It must not change the MAC, or every
// reordering would need a re-signature; it is authenticated anyway, because the
// references live inside the interface record the message includes verbatim.
func TestCanonicalIgnoresReferenceOrder(t *testing.T) {
	ifPub := pubKey(0x11)
	a := peerRecord(t, 0xF0, "203.0.113.1:51820")
	b := peerRecord(t, 0x0A, "198.51.100.1:51820")

	forward := tree(t, []PeerRecord{a, b}, true)
	reversed := tree(t, []PeerRecord{b, a}, true)
	if forward == reversed {
		t.Fatal("the two interface records should differ in their reference order")
	}

	m1, err := Canonical(ifPub, forward, []PeerRecord{a, b})
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	// Same tree, peers supplied in the other order: the peer section must match.
	m2, err := Canonical(ifPub, forward, []PeerRecord{b, a})
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if !bytes.Equal(m1, m2) {
		t.Error("the order peers are passed in must not change the message")
	}

	// A different reference order is a different interface record, so the
	// message does change — the priority is authenticated.
	m3, err := Canonical(ifPub, reversed, []PeerRecord{a, b})
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if bytes.Equal(m1, m3) {
		t.Error("reordering the references must change the authenticated message")
	}
}

func TestCanonicalRequiresExactPeerSet(t *testing.T) {
	ifPub := pubKey(0x11)
	a := peerRecord(t, 0xF0, "203.0.113.1:51820")
	b := peerRecord(t, 0x0A, "198.51.100.1:51820")
	c := peerRecord(t, 0x77, "192.0.2.1:51820")
	ifDescr := tree(t, []PeerRecord{a, b}, true)

	cases := []struct {
		name  string
		peers []PeerRecord
		want  string
	}{
		{"missing peer", []PeerRecord{a}, "references 2 peers, got 1"},
		{"extra peer", []PeerRecord{a, b, c}, "references 2 peers, got 3"},
		{"substituted peer", []PeerRecord{a, c}, "no peer resolves the reference"},
		{"duplicate peer", []PeerRecord{a, a}, "share the reference"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Canonical(ifPub, ifDescr, tc.peers)
			if err == nil {
				t.Fatal("expected rejection: the authenticated set must match the used set")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestMaxPeersMatchesDeviceLimit(t *testing.T) {
	// The limit is the device's 2048-byte message, so it moves with the record
	// size. The spec quotes the figures for 128-byte records.
	if descr.Size == 128 {
		if MaxPeers != 11 {
			t.Errorf("MaxPeers = %d, want 11 (spec §4)", MaxPeers)
		}
		if fixedLen+MaxPeers*perPeer != 1933 {
			t.Errorf("a full tree is %d bytes, spec §4 says 1933", fixedLen+MaxPeers*perPeer)
		}
	}
	if fixedLen+MaxPeers*perPeer > deviceMsgLimit {
		t.Errorf("a full tree of %d peers is %d bytes, over the %d-byte limit",
			MaxPeers, fixedLen+MaxPeers*perPeer, deviceMsgLimit)
	}
	if fixedLen+(MaxPeers+1)*perPeer <= deviceMsgLimit {
		t.Error("one more peer should not fit in the device's message limit")
	}
}

// captured records what the SDK sent to the device.
type captured struct {
	path string
	body map[string]any
}

func mockHEM(t *testing.T, reply string, status int) (*hem.Client, *captured) {
	t.Helper()
	rec := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &rec.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return hem.NewClient(srv.URL, hem.Config{}), rec
}

func TestSignUsesSelfECDH(t *testing.T) {
	want := make([]byte, descr.MACLen)
	for i := range want {
		want[i] = byte(i)
	}
	c, rec := mockHEM(t, `{"mac":"`+base64.StdEncoding.EncodeToString(want)+`"}`, 200)

	ifPub := pubKey(0x11)
	peers := []PeerRecord{peerRecord(t, 0x0A, "198.51.100.1:51820")}
	ifDescr := tree(t, peers, false)

	got, err := Sign(context.Background(), c, "tok", "kid1", ifPub, ifDescr, peers)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !bytes.Equal(got[:], want) {
		t.Errorf("MAC = %x, want %x", got, want)
	}
	if rec.path != "/api/crypto/hmac/hash" {
		t.Errorf("path = %s", rec.path)
	}
	// The MAC key is the interface key against itself. Keying it with a peer's
	// key would let that peer forge a configuration offline.
	if rec.body["kid"] != "kid1" || rec.body["ext_kid"] != "kid1" {
		t.Errorf("kid/ext_kid = %v/%v, want both kid1", rec.body["kid"], rec.body["ext_kid"])
	}
	if rec.body["alg"] != Alg {
		t.Errorf("alg = %v, want %s", rec.body["alg"], Alg)
	}
	if _, ok := rec.body["pubkey"]; ok {
		t.Error("pubkey must not be sent alongside ext_kid")
	}

	sent, err := base64.StdEncoding.DecodeString(rec.body["msg"].(string))
	if err != nil {
		t.Fatalf("decode msg: %v", err)
	}
	expected, _ := Canonical(ifPub, ifDescr, peers)
	if !bytes.Equal(sent, expected) {
		t.Error("the message sent to the device is not the canonical message")
	}
	if len(sent) > deviceMsgLimit {
		t.Errorf("message is %d bytes, over the device limit", len(sent))
	}
}

func TestVerifyRejectsATamperedTree(t *testing.T) {
	c, rec := mockHEM(t, `{}`, 200)
	ifPub := pubKey(0x11)
	peers := []PeerRecord{peerRecord(t, 0x0A, "198.51.100.1:51820")}
	ifDescr := tree(t, peers, true)

	if err := Verify(context.Background(), c, "tok", "kid1", ifPub, ifDescr, peers); err != nil {
		t.Fatalf("Verify against an accepting device: %v", err)
	}
	if rec.path != "/api/crypto/hmac/verify" {
		t.Errorf("path = %s", rec.path)
	}
	if rec.body["mac"] == nil {
		t.Error("the stored MAC must be sent for the device to compare")
	}

	// A record with no MAC at all is not a configuration to fall back on.
	noMAC := tree(t, peers, false)
	if err := Verify(context.Background(), c, "tok", "kid1", ifPub, noMAC, peers); err == nil {
		t.Error("a record without a MAC must not verify")
	}

	// 406 is how the device reports a MAC that does not match.
	reject, _ := mockHEM(t, `{}`, http.StatusNotAcceptable)
	err := Verify(context.Background(), reject, "tok", "kid1", ifPub, ifDescr, peers)
	if err == nil {
		t.Fatal("a rejected MAC must surface as an error, never as a warning")
	}
	if !strings.Contains(err.Error(), "failed authentication") {
		t.Errorf("error should name the failure plainly, got: %v", err)
	}
}

// Changing a peer's AllowedIPs changes what enters the tunnel, so it has to
// change the authenticated message.
func TestPeerRoutingIsAuthenticated(t *testing.T) {
	ifPub := pubKey(0x11)
	p := peerRecord(t, 0x0A, "198.51.100.1:51820")
	ifDescr := tree(t, []PeerRecord{p}, true)

	before, err := Canonical(ifPub, ifDescr, []PeerRecord{p})
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}

	tampered := p
	tampered.Descr, err = descr.Peer{
		Endpoint:   descr.Endpoint{IP: netip.MustParseAddr("198.51.100.1"), Port: 51820},
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, // was 10.0.0.0/24
	}.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	after, err := Canonical(ifPub, ifDescr, []PeerRecord{tampered})
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	if bytes.Equal(before, after) {
		t.Error("widening AllowedIPs to 0.0.0.0/0 must change the authenticated message")
	}
}
