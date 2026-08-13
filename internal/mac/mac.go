// Package mac builds and checks the single MAC that authenticates a whole
// config-free WireGuard configuration. See docs/ENCEDO-WG-CONFIGFREE-SPEC.md §4.
//
// The MAC key is the interface key's self-ECDH, computed inside the HEM and
// never present outside it. Keying it with ECDH(interface, peer) would be a
// mistake worth naming: whoever holds the peer's private key — or imports a
// public key of their own choosing — could derive the same secret offline and
// forge a configuration. Self-ECDH has no such holder.
//
// One MAC covers the interface record and every peer record it references, so
// changing a peer's AllowedIPs or endpoint invalidates it. Those two fields
// decide what enters the tunnel and where it goes, which is why they are inside
// the authenticated set rather than trusted from the device's key repository.
package mac

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

// Domain separates this MAC from any other use of the same key. A change to the
// record format bumps this string and the record version together (§8.6); v2
// accompanies the PEER_REF change from a public-key digest to a KID prefix.
const Domain = "ENC-WG-MAC-v2"

// Alg is the HMAC hash the device is asked for.
const Alg = "SHA2-256"

// PubKeyLen is the length of a Curve25519 public key.
const PubKeyLen = 32

// deviceMsgLimit is the largest msg the HEM accepts on /api/crypto/*.
const deviceMsgLimit = 2048

// perPeer is the contribution of one peer to the canonical message.
const perPeer = PubKeyLen + descr.Size

// fixedLen is the part of the message that does not depend on the peer count.
const fixedLen = len(Domain) + PubKeyLen + descr.Size

// MaxPeers is how many peers fit in one authenticated tree, set by the device's
// message limit rather than by anything in WireGuard. Typical deployments use
// two or three.
const MaxPeers = (deviceMsgLimit - fixedLen) / perPeer

// ErrNotAuthentic reports that the stored configuration is not the one that was
// provisioned. Callers match on it rather than on a message because it is the
// one failure that must stop a startup outright, and it has to be told apart
// from an unreachable device or an expired token.
var ErrNotAuthentic = errors.New("configuration failed authentication")

// PeerRecord pairs a peer's public key with its stored descr, both exactly as
// they live in the HEM.
type PeerRecord struct {
	PubKey [PubKeyLen]byte
	Descr  [descr.Size]byte
}

// Canonical builds the message the MAC is computed over.
//
// Peers are ordered by public key, not by the reference order in the interface
// record. The reference order carries failover priority and must stay free to
// change meaning without changing the sort, yet it is still authenticated,
// because the references themselves sit inside the interface record that the
// message includes verbatim.
//
// The peers passed in must correspond exactly to the record's references: every
// reference resolved, nothing extra. A peer the client would use but did not
// authenticate is precisely the gap this MAC exists to close.
func Canonical(ifPubKey [PubKeyLen]byte, ifDescr [descr.Size]byte, peers []PeerRecord) ([]byte, error) {
	rec, err := descr.DecodeInterface(ifDescr[:])
	if err != nil {
		return nil, fmt.Errorf("mac: interface record: %w", err)
	}
	if err := matchRefs(rec.PeerRefs, peers); err != nil {
		return nil, err
	}
	if len(peers) > MaxPeers {
		return nil, fmt.Errorf("mac: %d peers exceeds the %d that fit in the device's %d-byte message",
			len(peers), MaxPeers, deviceMsgLimit)
	}

	zeroed, err := descr.ZeroMAC(ifDescr)
	if err != nil {
		return nil, fmt.Errorf("mac: interface record: %w", err)
	}

	sorted := append([]PeerRecord(nil), peers...)
	sort.Slice(sorted, func(a, b int) bool {
		return bytes.Compare(sorted[a].PubKey[:], sorted[b].PubKey[:]) < 0
	})

	msg := make([]byte, 0, fixedLen+len(sorted)*perPeer)
	msg = append(msg, Domain...)
	msg = append(msg, ifPubKey[:]...)
	msg = append(msg, zeroed[:]...)
	for _, p := range sorted {
		msg = append(msg, p.PubKey[:]...)
		msg = append(msg, p.Descr[:]...)
	}
	return msg, nil
}

// matchRefs checks that the supplied peers are exactly the ones the interface
// record names — a bijection, so neither a missing peer nor an unreferenced
// extra can slip into the authenticated set.
func matchRefs(refs []descr.PeerRef, peers []PeerRecord) error {
	if len(refs) != len(peers) {
		return fmt.Errorf("mac: interface record references %d peers, got %d", len(refs), len(peers))
	}
	byRef := make(map[descr.PeerRef]int, len(peers))
	for i, p := range peers {
		ref := descr.MakePeerRef(p.PubKey[:])
		if _, dup := byRef[ref]; dup {
			return fmt.Errorf("mac: two peers share the reference %x", ref)
		}
		byRef[ref] = i
	}
	for _, ref := range refs {
		if _, ok := byRef[ref]; !ok {
			return fmt.Errorf("mac: no peer resolves the reference %x", ref)
		}
		delete(byRef, ref)
	}
	if len(byRef) != 0 {
		return fmt.Errorf("mac: %d peers are not referenced by the interface record", len(byRef))
	}
	return nil
}

// Sign computes the MAC over the configuration tree. ifDescr is the record as
// it will be stored, with the MAC tag present and zeroed or absent entirely;
// the returned value is what goes into that tag.
//
// Scope: keymgmt:use:<kid> — the same scope the handshake already needs, so
// authenticating a configuration grants no new authority, and every attempt
// lands in the device's audit log.
func Sign(ctx context.Context, c *hem.Client, token, kid string,
	ifPubKey [PubKeyLen]byte, ifDescr [descr.Size]byte, peers []PeerRecord) ([descr.MACLen]byte, error) {

	var out [descr.MACLen]byte
	msg, err := Canonical(ifPubKey, ifDescr, peers)
	if err != nil {
		return out, err
	}
	sum, err := c.HmacHash(ctx, token, kid, msg, hem.CryptoOpts{Alg: Alg, ExtKID: kid})
	if err != nil {
		return out, fmt.Errorf("mac: hmac/hash: %w", err)
	}
	if len(sum) != descr.MACLen {
		return out, fmt.Errorf("mac: device returned a %d-byte MAC, expected %d", len(sum), descr.MACLen)
	}
	copy(out[:], sum)
	return out, nil
}

// Verify checks the MAC carried in the interface record. The comparison happens
// inside the device, so nothing here has to be constant-time.
//
// A failure means the stored configuration is not the one that was provisioned.
// There is no degraded mode to fall back to: the caller must refuse to start
// (§8.3).
func Verify(ctx context.Context, c *hem.Client, token, kid string,
	ifPubKey [PubKeyLen]byte, ifDescr [descr.Size]byte, peers []PeerRecord) error {

	rec, err := descr.DecodeInterface(ifDescr[:])
	if err != nil {
		return fmt.Errorf("mac: interface record: %w", err)
	}
	if !rec.HasMAC {
		return fmt.Errorf("mac: %w: the interface record carries no MAC", ErrNotAuthentic)
	}
	msg, err := Canonical(ifPubKey, ifDescr, peers)
	if err != nil {
		return err
	}
	if err := c.HmacVerify(ctx, token, kid, msg, rec.MAC[:], hem.CryptoOpts{Alg: Alg, ExtKID: kid}); err != nil {
		// The record length is inside the canonical message (§3), so a build that
		// reads the wrong size computes a different message over the same bytes
		// and the device refuses it — which is indistinguishable, from here, from
		// somebody having edited the configuration.
		//
		// It is worth naming because the two call for opposite reactions: one is
		// an attack and the other is a build flag. This build says which size it
		// reads, so whoever sees it can check that first.
		return fmt.Errorf("mac: %w: %w\n"+
			"This build reads %d-byte records. If the appliance stores the other size, "+
			"that alone produces this — rebuild with the matching descr size before "+
			"treating it as tampering.", ErrNotAuthentic, err, descr.Size)
	}
	return nil
}
