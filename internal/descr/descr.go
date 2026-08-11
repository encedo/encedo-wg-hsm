// Package descr encodes and decodes the binary records the config-free client
// stores in a HEM key's descr field. See docs/ENCEDO-WG-CONFIGFREE-SPEC.md §3.
//
// A record is exactly Size bytes: a 6-byte ASCII magic, a version byte, then a
// TLV stream terminated by a 0x00 tag and zero-padded to the end. The ceiling is
// the device's — 128 bytes, or 64 on older firmware, see size_default.go — and
// it is tight enough that a legal-looking set of fields can overflow it, so
// encoding validates the budget rather than truncating and the caller finds out
// at provisioning time instead of at startup on someone else's machine.
//
// Every field here is covered by the interface record's MAC (§4), including the
// zero padding, so the parser is deliberately strict: unknown tags, malformed
// lengths, repeated singletons and non-zero padding are all errors, never
// something to skip past.
package descr

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Magic prefixes. Both are exactly 6 bytes: the shortest prefix the device's
// key search accepts, which is what makes a whole configuration reachable in
// two search calls.
const (
	MagicInterface = "WG:if:"
	MagicPeer      = "WG:pr:"
	magicLen       = 6
)

// Version is the record format version. A format change bumps this and the MAC
// domain string together (§8.6).
const Version = 0x01

// headerLen is the magic plus the version byte.
const headerLen = magicLen + 1

// DefaultMTU applies when an interface record carries no MTU tag. The codec
// never substitutes it: a decoded record reports MTU 0 for "absent", because
// the bytes are what the MAC covers and inventing values here would hide a
// difference between what was signed and what is used.
const DefaultMTU = 1420

// Tags of the interface record (§3.1).
const (
	tagEnd        = 0x00
	TagADDR4      = 0x01
	TagADDR6      = 0x02
	TagMTU        = 0x03
	TagDNS4       = 0x04
	TagDNS6       = 0x05
	TagPeerRef    = 0x06
	TagListenPort = 0x07
	TagMAC        = 0x7F
)

// Tags of the peer record (§3.2).
const (
	TagEndpoint4    = 0x10
	TagEndpoint6    = 0x11
	TagEndpointHost = 0x12
	TagAIP4         = 0x13
	TagAIP6         = 0x14
	TagKeepalive    = 0x15
	TagPSKWrapped   = 0x16
)

// MACLen is the length of the HMAC-SHA2-256 carried in TagMAC.
const MACLen = 32

// PSKWrappedLen is the length of a 32-byte PSK under NIST AES key wrap.
const PSKWrappedLen = 40

// MaxHostname is the longest endpoint hostname the format can carry: the
// format's own cap of 60, or whatever a record has room for once the header and
// the tag's own 4 bytes are spent, whichever is smaller. Fitting is a further
// question — this is the ceiling with nothing else in the record at all. See
// Peer.Encode for the budget that actually applies.
const MaxHostname = min(60, Size-headerLen-4)

// PeerRefLen is the length of a peer reference: the first bytes of the SHA-256
// of the peer's public key.
const PeerRefLen = 4

// PeerRef is a truncated hash of a peer public key, used by an interface record
// to name its peers without spending 32 bytes each.
type PeerRef [PeerRefLen]byte

// MakePeerRef derives the reference for a peer's public key.
func MakePeerRef(pubKey []byte) PeerRef {
	sum := sha256.Sum256(pubKey)
	var ref PeerRef
	copy(ref[:], sum[:PeerRefLen])
	return ref
}

// Interface is the decoded form of a WG:if: record — the identity key's own
// configuration plus the list of peers it may use.
type Interface struct {
	// Addrs are the addresses assigned to the tunnel interface, in the order
	// they were encoded.
	Addrs []netip.Prefix
	// MTU is 0 when the record carries no MTU tag; see DefaultMTU.
	MTU uint16
	// DNS servers, in encoded order.
	DNS []netip.Addr
	// PeerRefs names the usable peers. The order is the failover priority and
	// is itself covered by the MAC, so it must be preserved on re-encode.
	PeerRefs []PeerRef
	// ListenPort is 0 when absent, which is what a client behind NAT wants.
	ListenPort uint16
	// MAC is the HMAC over the whole configuration tree (§4). HasMAC reports
	// whether the record carried one at all.
	MAC    [MACLen]byte
	HasMAC bool
}

// Endpoint is a peer's address: either a literal IP with a port, or a hostname
// to resolve with a port. Exactly one form is set.
type Endpoint struct {
	IP   netip.Addr // invalid when Host is used
	Host string     // empty when IP is used
	Port uint16
}

// IsZero reports whether the endpoint is unset.
func (e Endpoint) IsZero() bool { return !e.IP.IsValid() && e.Host == "" }

// String renders the endpoint in host:port form.
func (e Endpoint) String() string {
	if e.Host != "" {
		return fmt.Sprintf("%s:%d", e.Host, e.Port)
	}
	if !e.IP.IsValid() {
		return ""
	}
	return netip.AddrPortFrom(e.IP, e.Port).String()
}

// Peer is the decoded form of a WG:pr: record. It carries no MAC of its own —
// its integrity comes from the interface record that references it (§4).
type Peer struct {
	Endpoint   Endpoint
	AllowedIPs []netip.Prefix
	Keepalive  uint8  // seconds; 0 = disabled
	PSKWrapped []byte // 40 bytes under AES-KW, or nil
}

var errShort = errors.New("descr: record shorter than its header")

// writer accumulates a record and refuses to exceed the device's capacity.
type writer struct {
	buf []byte
	err error
}

func (w *writer) tlv(tag byte, value []byte) {
	if w.err != nil {
		return
	}
	if len(value) > 255 {
		w.err = fmt.Errorf("descr: tag 0x%02X value is %d bytes, max 255", tag, len(value))
		return
	}
	w.buf = append(w.buf, tag, byte(len(value)))
	w.buf = append(w.buf, value...)
}

// finish pads to Size, or reports by how much the record overflowed. The
// overflow message names the excess because that is the number the operator
// has to act on — one fewer peer, a shorter hostname, an IP instead of a name.
func (w *writer) finish(kind string) ([Size]byte, error) {
	var out [Size]byte
	if w.err != nil {
		return out, w.err
	}
	// The terminator is only needed when there is room left; a record that
	// fills all 128 bytes is terminated by the end of the buffer (§3).
	need := len(w.buf)
	if need > Size {
		return out, fmt.Errorf("descr: %s record needs %d bytes, %d over the %d-byte limit",
			kind, need, need-Size, Size)
	}
	copy(out[:], w.buf)
	return out, nil
}

func appendPrefix4(w *writer, tag byte, p netip.Prefix) {
	a := p.Addr().As4()
	w.tlv(tag, append(a[:], byte(p.Bits())))
}

func appendPrefix6(w *writer, tag byte, p netip.Prefix) {
	a := p.Addr().As16()
	w.tlv(tag, append(a[:], byte(p.Bits())))
}

func be16(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

// encodePrefixes writes every IPv4 prefix under tag4, then every IPv6 prefix
// under tag6, keeping the tag stream ascending.
func encodePrefixes(w *writer, prefixes []netip.Prefix, tag4, tag6 byte, what string) error {
	for _, p := range prefixes {
		if !p.IsValid() {
			return fmt.Errorf("descr: invalid %s %q", what, p)
		}
	}
	for _, p := range prefixes {
		if p.Addr().Is4() {
			appendPrefix4(w, tag4, p)
		}
	}
	for _, p := range prefixes {
		if !p.Addr().Is4() {
			appendPrefix6(w, tag6, p)
		}
	}
	return nil
}

// Encode serialises an interface record. The MAC tag is emitted last, as the
// format requires, and only when HasMAC is set — provisioning encodes once with
// HasMAC false to obtain the bytes to authenticate, then again with the result.
func (i Interface) Encode() ([Size]byte, error) {
	w := &writer{buf: append([]byte(MagicInterface), Version)}

	// Tags are emitted in ascending order, so each family is grouped rather than
	// interleaved in the caller's order. Addresses and DNS servers carry no
	// priority, so grouping loses nothing; peer references do carry priority and
	// share one tag, so their order survives untouched.
	if err := encodePrefixes(w, i.Addrs, TagADDR4, TagADDR6, "interface address"); err != nil {
		return [Size]byte{}, err
	}
	if i.MTU != 0 {
		w.tlv(TagMTU, be16(i.MTU))
	}
	for _, pass := range []bool{true, false} {
		for _, d := range i.DNS {
			if !d.IsValid() {
				return [Size]byte{}, fmt.Errorf("descr: invalid DNS address %q", d)
			}
			if d.Is4() != pass {
				continue
			}
			if pass {
				a := d.As4()
				w.tlv(TagDNS4, a[:])
			} else {
				a := d.As16()
				w.tlv(TagDNS6, a[:])
			}
		}
	}
	for _, ref := range i.PeerRefs {
		r := ref
		w.tlv(TagPeerRef, r[:])
	}
	if i.ListenPort != 0 {
		w.tlv(TagListenPort, be16(i.ListenPort))
	}
	if i.HasMAC {
		m := i.MAC
		w.tlv(TagMAC, m[:])
	}
	return w.finish("interface")
}

// Encode serialises a peer record. Exactly one endpoint form must be set.
//
// The tightest legal case is a hostname endpoint together with a wrapped PSK:
// 7 header + (4 + hostname) endpoint + allowed-IPs + 3 keepalive + 42 PSK. A
// 60-byte hostname fits only while there is no PSK, which is why the budget is
// checked here rather than documented and hoped for.
func (p Peer) Encode() ([Size]byte, error) {
	w := &writer{buf: append([]byte(MagicPeer), Version)}

	switch {
	case p.Endpoint.Host != "":
		if len(p.Endpoint.Host) > MaxHostname {
			return [Size]byte{}, fmt.Errorf("descr: hostname is %d bytes, max %d",
				len(p.Endpoint.Host), MaxHostname)
		}
		w.tlv(TagEndpointHost, append(be16(p.Endpoint.Port), p.Endpoint.Host...))
	case p.Endpoint.IP.Is4():
		a := p.Endpoint.IP.As4()
		w.tlv(TagEndpoint4, append(a[:], be16(p.Endpoint.Port)...))
	case p.Endpoint.IP.IsValid():
		a := p.Endpoint.IP.As16()
		w.tlv(TagEndpoint6, append(a[:], be16(p.Endpoint.Port)...))
	default:
		return [Size]byte{}, errors.New("descr: peer record needs an endpoint")
	}

	if err := encodePrefixes(w, p.AllowedIPs, TagAIP4, TagAIP6, "allowed-ip"); err != nil {
		return [Size]byte{}, err
	}
	if p.Keepalive != 0 {
		w.tlv(TagKeepalive, []byte{p.Keepalive})
	}
	if len(p.PSKWrapped) > 0 {
		if len(p.PSKWrapped) != PSKWrappedLen {
			return [Size]byte{}, fmt.Errorf("descr: wrapped PSK is %d bytes, expected %d",
				len(p.PSKWrapped), PSKWrappedLen)
		}
		w.tlv(TagPSKWrapped, p.PSKWrapped)
	}
	return w.finish("peer")
}

// tlvItem is one parsed tag/value pair.
type tlvItem struct {
	tag   byte
	value []byte
}

// parse splits a record into its header and TLV items, rejecting anything a
// strict reader should not accept: wrong magic or version, a length that runs
// past the buffer, or padding that is not zero. Non-zero padding would be
// covered by the MAC anyway, but failing here says what is wrong instead of
// leaving an operator with an unexplained integrity error.
func parse(b []byte, magic string) ([]tlvItem, error) {
	if len(b) < headerLen {
		return nil, errShort
	}
	if len(b) > Size {
		return nil, fmt.Errorf("descr: record is %d bytes, max %d", len(b), Size)
	}
	if string(b[:magicLen]) != magic {
		return nil, fmt.Errorf("descr: expected magic %q, got %q", magic, b[:magicLen])
	}
	if b[magicLen] != Version {
		return nil, fmt.Errorf("descr: unsupported record version 0x%02X", b[magicLen])
	}

	var items []tlvItem
	lastTag := byte(0)
	i := headerLen
	for i < len(b) {
		tag := b[i]
		if tag == tagEnd {
			for j := i; j < len(b); j++ {
				if b[j] != 0 {
					return nil, fmt.Errorf("descr: non-zero padding at offset %d", j)
				}
			}
			return items, nil
		}
		// Tags ascend, repeats allowed. Without this a record could be reordered
		// into a second encoding of the same configuration; one configuration
		// has to mean one byte sequence in a format that is authenticated, and
		// compared, byte for byte.
		if tag < lastTag {
			return nil, fmt.Errorf("descr: tag 0x%02X follows 0x%02X; tags must ascend", tag, lastTag)
		}
		lastTag = tag
		if i+1 >= len(b) {
			return nil, fmt.Errorf("descr: tag 0x%02X at offset %d has no length byte", tag, i)
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			return nil, fmt.Errorf("descr: tag 0x%02X at offset %d claims %d bytes, %d remain",
				tag, i, n, len(b)-i-2)
		}
		items = append(items, tlvItem{tag: tag, value: b[i+2 : i+2+n]})
		i += 2 + n
	}
	return items, nil
}

// expect checks a TLV's length before its value is read.
func expect(tag byte, value []byte, n int) error {
	if len(value) != n {
		return fmt.Errorf("descr: tag 0x%02X is %d bytes, expected %d", tag, len(value), n)
	}
	return nil
}

// once guards tags that may appear at most one time.
func once(seen map[byte]bool, tag byte) error {
	if seen[tag] {
		return fmt.Errorf("descr: tag 0x%02X repeated", tag)
	}
	seen[tag] = true
	return nil
}

// nonZero rejects an optional numeric tag carrying zero.
//
// Zero is how these fields say "absent" — MTU 0 is not a usable MTU, listen
// port 0 already means "let the kernel choose", keepalive 0 means disabled — so
// an explicit zero tag and a missing tag describe the same configuration.
//
// Rejecting the longer form is not what stops forgery; the MAC is over the
// bytes, so a rewritten record simply fails to verify. It is what keeps one
// configuration to one encoding, the same property DER exists to give ASN.1.
// That buys two concrete things: encode(decode(x)) == x becomes an invariant a
// fuzzer can hold the codec to, and two records can be compared as bytes rather
// than by decoding both and comparing meanings.
func nonZero(tag byte, v uint64, name string) error {
	if v == 0 {
		return fmt.Errorf("descr: tag 0x%02X carries %s 0; omit the tag instead", tag, name)
	}
	return nil
}

func prefixFrom(value []byte, addrLen int) (netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(value[:addrLen])
	if !ok {
		return netip.Prefix{}, errors.New("descr: malformed address")
	}
	bits := int(value[addrLen])
	p := netip.PrefixFrom(addr, bits)
	if !p.IsValid() {
		return netip.Prefix{}, fmt.Errorf("descr: invalid prefix length %d for %s", bits, addr)
	}
	return p, nil
}

// DecodeInterface parses a WG:if: record. A record shorter than Size is
// accepted — the device may return a trimmed descr — but a MAC computed over it
// must use the zero-padded 128-byte form; see Normalize.
func DecodeInterface(b []byte) (Interface, error) {
	items, err := parse(b, MagicInterface)
	if err != nil {
		return Interface{}, err
	}

	var out Interface
	seen := map[byte]bool{}
	for n, it := range items {
		if seen[TagMAC] {
			return Interface{}, fmt.Errorf("descr: tag 0x%02X follows the MAC, which must be last", it.tag)
		}
		switch it.tag {
		case TagADDR4:
			if err := expect(it.tag, it.value, 5); err != nil {
				return Interface{}, err
			}
			p, err := prefixFrom(it.value, 4)
			if err != nil {
				return Interface{}, err
			}
			out.Addrs = append(out.Addrs, p)
		case TagADDR6:
			if err := expect(it.tag, it.value, 17); err != nil {
				return Interface{}, err
			}
			p, err := prefixFrom(it.value, 16)
			if err != nil {
				return Interface{}, err
			}
			out.Addrs = append(out.Addrs, p)
		case TagMTU:
			if err := once(seen, it.tag); err != nil {
				return Interface{}, err
			}
			if err := expect(it.tag, it.value, 2); err != nil {
				return Interface{}, err
			}
			out.MTU = binary.BigEndian.Uint16(it.value)
			if err := nonZero(it.tag, uint64(out.MTU), "MTU"); err != nil {
				return Interface{}, err
			}
		case TagDNS4:
			if err := expect(it.tag, it.value, 4); err != nil {
				return Interface{}, err
			}
			a, _ := netip.AddrFromSlice(it.value)
			out.DNS = append(out.DNS, a)
		case TagDNS6:
			if err := expect(it.tag, it.value, 16); err != nil {
				return Interface{}, err
			}
			a, _ := netip.AddrFromSlice(it.value)
			out.DNS = append(out.DNS, a)
		case TagPeerRef:
			if err := expect(it.tag, it.value, PeerRefLen); err != nil {
				return Interface{}, err
			}
			var ref PeerRef
			copy(ref[:], it.value)
			out.PeerRefs = append(out.PeerRefs, ref)
		case TagListenPort:
			if err := once(seen, it.tag); err != nil {
				return Interface{}, err
			}
			if err := expect(it.tag, it.value, 2); err != nil {
				return Interface{}, err
			}
			out.ListenPort = binary.BigEndian.Uint16(it.value)
			if err := nonZero(it.tag, uint64(out.ListenPort), "listen port"); err != nil {
				return Interface{}, err
			}
		case TagMAC:
			if err := once(seen, it.tag); err != nil {
				return Interface{}, err
			}
			if err := expect(it.tag, it.value, MACLen); err != nil {
				return Interface{}, err
			}
			if n != len(items)-1 {
				return Interface{}, errors.New("descr: MAC must be the last tag")
			}
			copy(out.MAC[:], it.value)
			out.HasMAC = true
		default:
			return Interface{}, fmt.Errorf("descr: unknown tag 0x%02X in an interface record", it.tag)
		}
	}
	return out, nil
}

// DecodePeer parses a WG:pr: record.
func DecodePeer(b []byte) (Peer, error) {
	items, err := parse(b, MagicPeer)
	if err != nil {
		return Peer{}, err
	}

	var out Peer
	seen := map[byte]bool{}
	endpoints := 0
	for _, it := range items {
		switch it.tag {
		case TagEndpoint4:
			endpoints++
			if err := expect(it.tag, it.value, 6); err != nil {
				return Peer{}, err
			}
			a, _ := netip.AddrFromSlice(it.value[:4])
			out.Endpoint = Endpoint{IP: a, Port: binary.BigEndian.Uint16(it.value[4:])}
		case TagEndpoint6:
			endpoints++
			if err := expect(it.tag, it.value, 18); err != nil {
				return Peer{}, err
			}
			a, _ := netip.AddrFromSlice(it.value[:16])
			out.Endpoint = Endpoint{IP: a, Port: binary.BigEndian.Uint16(it.value[16:])}
		case TagEndpointHost:
			endpoints++
			if len(it.value) < 3 || len(it.value) > 2+MaxHostname {
				return Peer{}, fmt.Errorf("descr: hostname endpoint is %d bytes, expected 3..%d",
					len(it.value), 2+MaxHostname)
			}
			out.Endpoint = Endpoint{
				Host: string(it.value[2:]),
				Port: binary.BigEndian.Uint16(it.value[:2]),
			}
		case TagAIP4:
			if err := expect(it.tag, it.value, 5); err != nil {
				return Peer{}, err
			}
			p, err := prefixFrom(it.value, 4)
			if err != nil {
				return Peer{}, err
			}
			out.AllowedIPs = append(out.AllowedIPs, p)
		case TagAIP6:
			if err := expect(it.tag, it.value, 17); err != nil {
				return Peer{}, err
			}
			p, err := prefixFrom(it.value, 16)
			if err != nil {
				return Peer{}, err
			}
			out.AllowedIPs = append(out.AllowedIPs, p)
		case TagKeepalive:
			if err := once(seen, it.tag); err != nil {
				return Peer{}, err
			}
			if err := expect(it.tag, it.value, 1); err != nil {
				return Peer{}, err
			}
			out.Keepalive = it.value[0]
			if err := nonZero(it.tag, uint64(out.Keepalive), "keepalive"); err != nil {
				return Peer{}, err
			}
		case TagPSKWrapped:
			if err := once(seen, it.tag); err != nil {
				return Peer{}, err
			}
			if err := expect(it.tag, it.value, PSKWrappedLen); err != nil {
				return Peer{}, err
			}
			out.PSKWrapped = append([]byte(nil), it.value...)
		default:
			return Peer{}, fmt.Errorf("descr: unknown tag 0x%02X in a peer record", it.tag)
		}
	}
	if endpoints != 1 {
		return Peer{}, fmt.Errorf("descr: peer record has %d endpoints, expected exactly 1", endpoints)
	}
	return out, nil
}

// Normalize widens a stored descr to the fixed 128-byte form the MAC is
// computed over. The device may hand back fewer bytes than were written; the
// canonical message is defined over the padded record, so the two must be
// reconciled before hashing rather than after a failed verification.
func Normalize(b []byte) ([Size]byte, error) {
	var out [Size]byte
	if len(b) > Size {
		return out, fmt.Errorf("descr: record is %d bytes, max %d", len(b), Size)
	}
	if len(b) < headerLen {
		return out, errShort
	}
	copy(out[:], b)
	return out, nil
}

// ZeroMAC returns the record with the MAC tag's value replaced by zeros, which
// is the form the canonical message uses (§4). A record without a MAC tag is
// returned unchanged.
func ZeroMAC(rec [Size]byte) ([Size]byte, error) {
	items, err := parse(rec[:], MagicInterface)
	if err != nil {
		return rec, err
	}
	out := rec
	// The parsed values alias rec, so an offset is recovered by walking again.
	off := headerLen
	for _, it := range items {
		if it.tag == TagMAC {
			for j := off + 2; j < off+2+len(it.value); j++ {
				out[j] = 0
			}
			return out, nil
		}
		off += 2 + len(it.value)
	}
	return out, nil
}
