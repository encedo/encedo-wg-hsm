package descr

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

// build assembles a record the way the specification tables read it, so the
// golden vectors below are independent of the encoder they check.
func build(magic string, tlvs ...[]byte) [Size]byte {
	var out [Size]byte
	copy(out[:], magic)
	out[magicLen] = Version
	off := headerLen
	for _, t := range tlvs {
		off += copy(out[off:], t)
	}
	return out
}

func tlv(tag byte, value ...byte) []byte {
	return append([]byte{tag, byte(len(value))}, value...)
}

// requireRoom skips a scenario that the configured record size cannot express.
// The budgets differ enough between 128- and 64-byte firmware that some cases
// only exist on one of them.
func requireRoom(t *testing.T, n int) {
	t.Helper()
	if Size < n {
		t.Skipf("scenario needs %d bytes, records are %d", n, Size)
	}
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func TestInterfaceGoldenVector(t *testing.T) {
	requireRoom(t, 74)
	var macVal [MACLen]byte
	for i := range macVal {
		macVal[i] = byte(i)
	}
	ref1 := PeerRef{0xde, 0xad, 0xbe, 0xef}
	ref2 := PeerRef{0x01, 0x02, 0x03, 0x04}

	in := Interface{
		Addrs:      []netip.Prefix{mustPrefix(t, "10.0.0.7/32")},
		MTU:        1380,
		DNS:        []netip.Addr{netip.MustParseAddr("10.0.0.1")},
		PeerRefs:   []PeerRef{ref1, ref2},
		ListenPort: 51820,
		MAC:        macVal,
		HasMAC:     true,
	}

	want := build(MagicInterface,
		tlv(TagADDR4, 10, 0, 0, 7, 32),
		tlv(TagMTU, 0x05, 0x64), // 1380 big-endian
		tlv(TagDNS4, 10, 0, 0, 1),
		tlv(TagPeerRef, 0xde, 0xad, 0xbe, 0xef),
		tlv(TagPeerRef, 0x01, 0x02, 0x03, 0x04),
		tlv(TagListenPort, 0xca, 0x6c), // 51820 big-endian
		tlv(TagMAC, macVal[:]...),
	)

	got, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got != want {
		t.Fatalf("encoded record differs\n got %s\nwant %s", hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
	}

	back, err := DecodeInterface(got[:])
	if err != nil {
		t.Fatalf("DecodeInterface: %v", err)
	}
	if len(back.Addrs) != 1 || back.Addrs[0] != in.Addrs[0] {
		t.Errorf("Addrs = %v", back.Addrs)
	}
	if back.MTU != 1380 || back.ListenPort != 51820 {
		t.Errorf("MTU = %d, ListenPort = %d", back.MTU, back.ListenPort)
	}
	// Reference order is failover priority - it must survive a round trip.
	if len(back.PeerRefs) != 2 || back.PeerRefs[0] != ref1 || back.PeerRefs[1] != ref2 {
		t.Errorf("PeerRefs = %x", back.PeerRefs)
	}
	if !back.HasMAC || back.MAC != macVal {
		t.Errorf("MAC = %x (has=%v)", back.MAC, back.HasMAC)
	}
}

func TestPeerGoldenVector(t *testing.T) {
	requireRoom(t, 74)
	psk := make([]byte, PSKWrappedLen)
	for i := range psk {
		psk[i] = byte(0xA0 + i%16)
	}

	in := Peer{
		Endpoint:   Endpoint{IP: netip.MustParseAddr("203.0.113.1"), Port: 51820},
		AllowedIPs: []netip.Prefix{mustPrefix(t, "10.0.0.0/24"), mustPrefix(t, "192.168.9.0/24")},
		Keepalive:  25,
		PSKWrapped: psk,
	}

	want := build(MagicPeer,
		tlv(TagEndpoint4, 203, 0, 113, 1, 0xca, 0x6c),
		tlv(TagAIP4, 10, 0, 0, 0, 24),
		tlv(TagAIP4, 192, 168, 9, 0, 24),
		tlv(TagKeepalive, 25),
		tlv(TagPSKWrapped, psk...),
	)

	got, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got != want {
		t.Fatalf("encoded record differs\n got %s\nwant %s", hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
	}

	// The spec's worked example: this record is 74 bytes before padding.
	used := headerLen + 8 + 7 + 7 + 3 + 42
	if used != 74 {
		t.Errorf("budget arithmetic drifted from the spec: %d", used)
	}

	back, err := DecodePeer(got[:])
	if err != nil {
		t.Fatalf("DecodePeer: %v", err)
	}
	if back.Endpoint.String() != "203.0.113.1:51820" {
		t.Errorf("Endpoint = %s", back.Endpoint.String())
	}
	if len(back.AllowedIPs) != 2 || back.AllowedIPs[1].String() != "192.168.9.0/24" {
		t.Errorf("AllowedIPs = %v", back.AllowedIPs)
	}
	if back.Keepalive != 25 || !bytes.Equal(back.PSKWrapped, psk) {
		t.Errorf("Keepalive = %d, PSK = %x", back.Keepalive, back.PSKWrapped)
	}
}

func TestRoundTripIPv6(t *testing.T) {
	in := Interface{
		Addrs:    []netip.Prefix{mustPrefix(t, "fd00::7/128")},
		DNS:      []netip.Addr{netip.MustParseAddr("fd00::1")},
		PeerRefs: []PeerRef{{1, 2, 3, 4}},
	}
	enc, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	back, err := DecodeInterface(enc[:])
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if back.Addrs[0] != in.Addrs[0] || back.DNS[0] != in.DNS[0] {
		t.Errorf("round trip lost data: %+v", back)
	}
	if back.MTU != 0 || back.HasMAC {
		t.Errorf("absent fields should stay absent: MTU=%d hasMAC=%v", back.MTU, back.HasMAC)
	}

	p := Peer{
		Endpoint:   Endpoint{IP: netip.MustParseAddr("2001:db8::1"), Port: 443},
		AllowedIPs: []netip.Prefix{mustPrefix(t, "::/0")},
	}
	pe, err := p.Encode()
	if err != nil {
		t.Fatalf("peer Encode: %v", err)
	}
	pb, err := DecodePeer(pe[:])
	if err != nil {
		t.Fatalf("peer Decode: %v", err)
	}
	if pb.Endpoint.String() != "[2001:db8::1]:443" || pb.AllowedIPs[0].String() != "::/0" {
		t.Errorf("peer round trip: %+v", pb)
	}
}

// The 128-byte ceiling is tight enough that a legal-looking peer overflows it.
// This is the case the spec calls out: a 60-byte hostname fits only while there
// is no wrapped PSK.
func TestHostnamePSKBudget(t *testing.T) {
	requireRoom(t, 128)
	host := strings.Repeat("a", MaxHostname)
	base := Peer{
		Endpoint:   Endpoint{Host: host, Port: 51820},
		AllowedIPs: []netip.Prefix{mustPrefix(t, "10.0.0.0/24"), mustPrefix(t, "192.168.9.0/24")},
		Keepalive:  25,
	}
	if _, err := base.Encode(); err != nil {
		t.Fatalf("a %d-byte hostname without a PSK must fit: %v", MaxHostname, err)
	}

	withPSK := base
	withPSK.PSKWrapped = make([]byte, PSKWrappedLen)
	_, err := withPSK.Encode()
	if err == nil {
		t.Fatal("a 60-byte hostname with a PSK must be rejected, not truncated")
	}
	if !strings.Contains(err.Error(), "over the 128-byte limit") {
		t.Errorf("the error should name the overflow, got: %v", err)
	}

	// Shortening the hostname brings it back under the limit.
	withPSK.Endpoint.Host = strings.Repeat("a", 56)
	if _, err := withPSK.Encode(); err != nil {
		t.Errorf("a 56-byte hostname with a PSK should fit: %v", err)
	}
}

func TestEncodeRejectsOverlongRecords(t *testing.T) {
	var refs []PeerRef
	for i := 0; i < 40; i++ {
		refs = append(refs, PeerRef{byte(i), 0, 0, 0})
	}
	in := Interface{Addrs: []netip.Prefix{mustPrefix(t, "10.0.0.7/32")}, PeerRefs: refs, HasMAC: true}
	if _, err := in.Encode(); err == nil {
		t.Fatal("40 peer references must not fit in 128 bytes")
	}
}

func TestPeerNeedsExactlyOneEndpoint(t *testing.T) {
	if _, err := (Peer{AllowedIPs: []netip.Prefix{mustPrefix(t, "0.0.0.0/0")}}).Encode(); err == nil {
		t.Error("a peer with no endpoint must be rejected at encode time")
	}

	two := build(MagicPeer,
		tlv(TagEndpoint4, 203, 0, 113, 1, 0xca, 0x6c),
		tlv(TagEndpoint4, 198, 51, 100, 1, 0xca, 0x6c),
	)
	if _, err := DecodePeer(two[:]); err == nil {
		t.Error("two endpoints must be rejected at decode time")
	}
}

// A strict parser is the point: everything the format does not define is an
// error, because every byte here is inside the authenticated set.
func TestParserRejectsMalformed(t *testing.T) {
	valid := build(MagicInterface, tlv(TagADDR4, 10, 0, 0, 7, 32))

	cases := []struct {
		name string
		rec  func() [Size]byte
		want string
	}{
		{"wrong magic", func() [Size]byte {
			r := valid
			copy(r[:], "WG:xx:")
			return r
		}, "magic"},
		{"unsupported version", func() [Size]byte {
			r := valid
			r[magicLen] = Version + 1
			return r
		}, "version"},
		{"unknown tag", func() [Size]byte {
			return build(MagicInterface, tlv(0x42, 1, 2, 3))
		}, "unknown tag"},
		{"length runs past the buffer", func() [Size]byte {
			r := build(MagicInterface)
			r[headerLen] = TagADDR4
			r[headerLen+1] = 200
			return r
		}, "claims 200 bytes"},
		{"wrong value length", func() [Size]byte {
			return build(MagicInterface, tlv(TagADDR4, 10, 0, 0, 7))
		}, "expected 5"},
		{"repeated singleton", func() [Size]byte {
			return build(MagicInterface, tlv(TagMTU, 0x05, 0x64), tlv(TagMTU, 0x05, 0x64))
		}, "repeated"},
		{"non-zero padding", func() [Size]byte {
			r := valid
			r[Size-1] = 0xFF
			return r
		}, "non-zero padding"},
		// The MAC has the highest tag, so "MAC last" now falls out of the
		// ordering rule. DecodeInterface keeps an explicit check as well, in
		// case a tag above 0x7F is ever defined.
		{"tag after the MAC", func() [Size]byte {
			return build(MagicInterface,
				tlv(TagMAC, make([]byte, MACLen)...),
				tlv(TagMTU, 0x05, 0x64),
			)
		}, "must ascend"},
		{"tags out of order", func() [Size]byte {
			return build(MagicInterface,
				tlv(TagListenPort, 0xca, 0x6c),
				tlv(TagMTU, 0x05, 0x64),
			)
		}, "must ascend"},
		{"explicit zero MTU", func() [Size]byte {
			return build(MagicInterface, tlv(TagMTU, 0x00, 0x00))
		}, "omit the tag instead"},
		{"invalid prefix length", func() [Size]byte {
			return build(MagicInterface, tlv(TagADDR4, 10, 0, 0, 7, 33))
		}, "invalid prefix length"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.rec()
			_, err := DecodeInterface(r[:])
			if err == nil {
				t.Fatalf("expected rejection")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestZeroMAC(t *testing.T) {
	var macVal [MACLen]byte
	for i := range macVal {
		macVal[i] = 0xEE
	}
	in := Interface{
		Addrs:    []netip.Prefix{mustPrefix(t, "10.0.0.7/32")},
		PeerRefs: []PeerRef{{1, 2, 3, 4}},
		MAC:      macVal,
		HasMAC:   true,
	}
	enc, err := in.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	zeroed, err := ZeroMAC(enc)
	if err != nil {
		t.Fatalf("ZeroMAC: %v", err)
	}
	if zeroed == enc {
		t.Fatal("ZeroMAC changed nothing")
	}
	back, err := DecodeInterface(zeroed[:])
	if err != nil {
		t.Fatalf("decode zeroed: %v", err)
	}
	if !back.HasMAC || back.MAC != ([MACLen]byte{}) {
		t.Errorf("MAC value should be zeros but the tag should remain: %x", back.MAC)
	}
	// Only the MAC value may change; everything else is what gets authenticated.
	if !bytes.Equal(zeroed[:headerLen+7+6], enc[:headerLen+7+6]) {
		t.Error("ZeroMAC touched bytes outside the MAC value")
	}

	// A record without a MAC tag is left alone.
	noMAC := Interface{Addrs: in.Addrs, PeerRefs: in.PeerRefs}
	ne, _ := noMAC.Encode()
	nz, err := ZeroMAC(ne)
	if err != nil || nz != ne {
		t.Errorf("a record with no MAC should pass through unchanged (err=%v)", err)
	}
}

func TestNormalizePadsTrimmedRecords(t *testing.T) {
	in := Interface{Addrs: []netip.Prefix{mustPrefix(t, "10.0.0.7/32")}}
	enc, _ := in.Encode()

	// The device may hand back a descr with the trailing zeros trimmed.
	trimmed := bytes.TrimRight(enc[:], "\x00")
	norm, err := Normalize(trimmed)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if norm != enc {
		t.Error("a trimmed record must normalise back to the padded form the MAC covers")
	}
	if _, err := Normalize(make([]byte, Size+1)); err == nil {
		t.Error("an over-long record must be rejected")
	}
}

// A reference is the start of the KID, and the KID is SHA-1(pubkey)[:16] - the
// derivation the device uses, confirmed against real hardware. Deriving it
// locally is what lets a peer be looked up, or found to be already present,
// before anything is written.
func TestKIDAndPeerRef(t *testing.T) {
	// SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709.
	if got := KID(nil); got != "da39a3ee5e6b4b0d3255bfef95601890" {
		t.Errorf("KID(nil) = %s", got)
	}
	empty := MakePeerRef(nil)
	if got := hex.EncodeToString(empty[:]); got != "da39a3ee" {
		t.Errorf("MakePeerRef(nil) = %s", got)
	}

	// A reference derived from a key and one derived from that key's KID must
	// agree, or a record found by search could not be matched to a reference.
	key := []byte("a 32-byte curve25519 public key!")
	fromKID, err := PeerRefFromKID(KID(key))
	if err != nil {
		t.Fatalf("PeerRefFromKID: %v", err)
	}
	if fromKID != MakePeerRef(key) {
		t.Errorf("PeerRefFromKID(%s) = %x, MakePeerRef = %x", KID(key), fromKID, MakePeerRef(key))
	}

	if _, err := PeerRefFromKID("nothex"); err == nil {
		t.Error("a malformed kid must be rejected")
	}
	if _, err := PeerRefFromKID("abcd"); err == nil {
		t.Error("a short kid must be rejected")
	}
}

func FuzzDecodeInterface(f *testing.F) {
	valid := build(MagicInterface,
		tlv(TagADDR4, 10, 0, 0, 7, 32),
		tlv(TagMTU, 0x05, 0x64),
		tlv(TagPeerRef, 1, 2, 3, 4),
	)
	f.Add(valid[:])
	f.Add([]byte(MagicInterface + "\x01"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := DecodeInterface(data)
		if err != nil {
			return
		}
		// Anything that parses must survive a round trip: the decoder may not
		// accept a record the encoder cannot reproduce, or the bytes under the
		// MAC would differ from the bytes in hand.
		enc, err := rec.Encode()
		if err != nil {
			t.Fatalf("decoded record failed to re-encode: %v (input %x)", err, data)
		}
		norm, err := Normalize(data)
		if err != nil {
			t.Fatalf("accepted a record Normalize rejects: %v (input %x)", err, data)
		}
		if enc != norm {
			t.Fatalf("round trip changed the bytes\n in %x\nout %x", norm, enc)
		}
	})
}

func FuzzDecodePeer(f *testing.F) {
	valid := build(MagicPeer,
		tlv(TagEndpoint4, 203, 0, 113, 1, 0xca, 0x6c),
		tlv(TagAIP4, 10, 0, 0, 0, 24),
	)
	f.Add(valid[:])
	f.Add([]byte(MagicPeer + "\x01"))

	f.Fuzz(func(t *testing.T, data []byte) {
		rec, err := DecodePeer(data)
		if err != nil {
			return
		}
		enc, err := rec.Encode()
		if err != nil {
			t.Fatalf("decoded record failed to re-encode: %v (input %x)", err, data)
		}
		norm, err := Normalize(data)
		if err != nil {
			t.Fatalf("accepted a record Normalize rejects: %v (input %x)", err, data)
		}
		if enc != norm {
			t.Fatalf("round trip changed the bytes\n in %x\nout %x", norm, enc)
		}
	})
}

// TestTightestPeerFits pins the smallest useful peer with a pre-shared key at
// whatever the record size is. On 64-byte firmware it lands on exactly 64: the
// header, an IPv4 endpoint, one allowed-ip range and the wrapped PSK, with no
// room left for keepalive. That is the case worth knowing before provisioning
// against such a device, not after.
func TestTightestPeerFits(t *testing.T) {
	p := Peer{
		Endpoint:   Endpoint{IP: netip.MustParseAddr("203.0.113.1"), Port: 51820},
		AllowedIPs: []netip.Prefix{mustPrefix(t, "0.0.0.0/0")},
		PSKWrapped: make([]byte, PSKWrappedLen),
	}
	if _, err := p.Encode(); err != nil {
		t.Fatalf("a peer with a PSK, an IPv4 endpoint and one route must fit in %d bytes: %v", Size, err)
	}

	used := headerLen + 8 + 7 + 2 + PSKWrappedLen
	withKeepalive := p
	withKeepalive.Keepalive = 25
	_, err := withKeepalive.Encode()
	if used+3 > Size && err == nil {
		t.Errorf("keepalive takes the record to %d bytes, over the %d-byte limit, but it was accepted",
			used+3, Size)
	}
	if used+3 <= Size && err != nil {
		t.Errorf("keepalive fits at %d bytes but was rejected: %v", used+3, err)
	}
}
