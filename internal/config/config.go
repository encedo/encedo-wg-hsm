// Package config loads a config-free client's whole configuration out of a HEM
// and authenticates it. See docs/ENCEDO-WG-CONFIGFREE-SPEC.md section 6.2.
//
// Nothing here trusts the device's key repository on its own. The repository
// says which records exist; the MAC says which ones were provisioned together.
// Those are different claims, and only the second one is worth acting on: an
// attacker who can import a key can add a plausible peer record, but cannot
// make the interface record's MAC cover it.
package config

import (
	"context"
	"fmt"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/mac"
)

// PSKContextPrefix domain-separates the key that wraps a pre-shared key from any
// other wrap use of the same interface key (section 5).
const PSKContextPrefix = "ENC-WG-PSK-v2|"

// PSKContext returns the HKDF context for one peer's wrapped pre-shared key.
//
// Binding it to the peer's identifier makes the wrap positional. AES key wrap
// authenticates what it holds, but not where it sits: with one context per
// identity, a ciphertext lifted from one peer's record unwraps perfectly well in
// another's, and only the configuration MAC would notice. With the peer in the
// context the two derive different keys, so a moved wrap simply fails.
//
// Wrap and unwrap must agree on this byte for byte, or the derived key differs.
func PSKContext(peerKID string) []byte {
	return []byte(PSKContextPrefix + peerKID)
}

// WrapAlg selects the size of the derived key-encryption key.
const WrapAlg = "AES256"

// PSKLen is the length of a WireGuard pre-shared key.
const PSKLen = 32

// searchPage is how many entries to ask for per search call. The device
// defaults to 15; asking for more keeps a large repository to fewer round trips.
const searchPage = 50

// TokenFunc returns a token for a scope. The SDK caches tokens per scope, so
// asking twice for the same scope costs nothing.
type TokenFunc func(ctx context.Context, scope string) (string, error)

// Peer is one authenticated peer: its key material, its stored record, and the
// decoded form of that record.
type Peer struct {
	KID    string
	Label  string
	PubKey [mac.PubKeyLen]byte
	Raw    [descr.Size]byte
	descr.Peer
}

// Tree is a complete, authenticated configuration.
type Tree struct {
	IfKID    string
	IfLabel  string
	IfPubKey [mac.PubKeyLen]byte
	IfRaw    [descr.Size]byte
	Iface    descr.Interface

	// Peers are in PEER_REF order, which is the failover priority.
	Peers []Peer
}

// Load finds the configuration in the device, resolves it, and verifies its MAC.
// It returns an error rather than a partial result if anything does not add up:
// there is no degraded mode to fall back to (section 8.3).
//
// choose is consulted only when the device holds more than one identity, and may
// be nil where there is nobody to ask - see ChooseFunc.
func Load(ctx context.Context, c *hem.Client, tok TokenFunc, choose ChooseFunc) (*Tree, error) {
	ifEntries, err := search(ctx, c, tok, descr.MagicInterface)
	if err != nil {
		return nil, err
	}
	entry, err := pick(ifEntries, choose)
	if err != nil {
		return nil, err
	}
	return loadFrom(ctx, c, tok, entry, fromDevice(c, tok))
}

// loadFrom resolves and authenticates one interface record, whichever way it was
// arrived at. Everything from here on knows exactly which identity it is working
// on, which is why the choosing lives entirely above it.
func loadFrom(ctx context.Context, c *hem.Client, tok TokenFunc, entry hem.KeyEntry, ring keyring) (*Tree, error) {
	t := &Tree{IfKID: entry.KID, IfLabel: entry.Label}
	var err error
	t.IfRaw, err = descr.Normalize(entry.Descr)
	if err != nil {
		return nil, fmt.Errorf("interface record: %w", err)
	}
	t.Iface, err = descr.DecodeInterface(t.IfRaw[:])
	if err != nil {
		return nil, fmt.Errorf("interface record: %w", err)
	}
	if len(t.Iface.PeerRefs) == 0 {
		return nil, fmt.Errorf("the interface record names no peers")
	}

	// Search returns identifiers and records, never key material, so the public
	// keys come from somewhere else - see keys.go for the two somewheres and why
	// one of them costs nothing.
	if t.IfPubKey, err = resolve(ctx, ring, t.IfKID); err != nil {
		return nil, fmt.Errorf("the interface public key: %w", err)
	}

	peerEntries, err := search(ctx, c, tok, descr.MagicPeer)
	if err != nil {
		return nil, err
	}

	// A reference is the start of the peer's KID, and search returns the KID of
	// every record, so the candidates are matched without reading a single key.
	// Only the peers this interface actually references are then read - a
	// repository holding records for several identities costs nothing here.
	byRef := make(map[descr.PeerRef]hem.KeyEntry, len(peerEntries))
	for _, e := range peerEntries {
		ref, err := descr.PeerRefFromKID(e.KID)
		if err != nil {
			continue // not a KID this client can make sense of
		}
		if prev, dup := byRef[ref]; dup {
			return nil, fmt.Errorf("peer records %s and %s share the reference %x; the interface record cannot say which it means",
				prev.KID, e.KID, ref)
		}
		byRef[ref] = e
	}

	var records []mac.PeerRecord
	for _, ref := range t.Iface.PeerRefs {
		e, ok := byRef[ref]
		if !ok {
			return nil, fmt.Errorf("the interface record references peer %x, which is not in the device", ref)
		}
		pub, err := resolve(ctx, ring, e.KID)
		if err != nil {
			return nil, fmt.Errorf("peer %s: %w", e.KID, err)
		}

		p := Peer{KID: e.KID, Label: e.Label, PubKey: pub}
		if p.Raw, err = descr.Normalize(e.Descr); err != nil {
			return nil, fmt.Errorf("peer record %s: %w", e.KID, err)
		}
		if p.Peer, err = descr.DecodePeer(p.Raw[:]); err != nil {
			return nil, fmt.Errorf("peer record %s: %w", e.KID, err)
		}
		t.Peers = append(t.Peers, p)
		records = append(records, mac.PeerRecord{PubKey: p.PubKey, Descr: p.Raw})
	}

	useTok, err := tok(ctx, "keymgmt:use:"+t.IfKID)
	if err != nil {
		return nil, err
	}
	if err := mac.Verify(ctx, c, useTok, t.IfKID, t.IfPubKey, t.IfRaw, records); err != nil {
		return nil, err
	}
	return t, nil
}

// search pages through the device's key repository for one record type. It
// tries without a token first: a device configured with allow_keysearch answers
// an anonymous prefix search, which is what lets startup need no credentials
// until there is something to authenticate.
func search(ctx context.Context, c *hem.Client, tok TokenFunc, magic string) ([]hem.KeyEntry, error) {
	pattern := []byte(magic)

	token := ""
	var all []hem.KeyEntry
	for offset := 0; ; {
		total, page, err := c.SearchKeys(ctx, token, pattern, offset, searchPage)
		if err != nil {
			if token == "" && isAuthError(err) {
				// The device wants a token for searching; ask once and restart.
				token, err = tok(ctx, "keymgmt:search")
				if err != nil {
					return nil, err
				}
				continue
			}
			return nil, fmt.Errorf("searching for %s records: %w", magic, err)
		}
		all = append(all, page...)
		offset += len(page)
		if len(page) == 0 || offset >= total {
			return all, nil
		}
	}
}

func isAuthError(err error) bool {
	he, ok := err.(*hem.HemError)
	return ok && (he.Status == 401 || he.Status == 403)
}

// UnwrapPSK recovers a peer's pre-shared key. The wrapping key is the interface
// key's self-ECDH, so the plaintext exists only in this process, only from here
// until the interface is configured.
func (t *Tree) UnwrapPSK(ctx context.Context, c *hem.Client, useTok string, p Peer) ([]byte, error) {
	if len(p.PSKWrapped) == 0 {
		return nil, nil
	}
	psk, err := c.CipherUnwrap(ctx, useTok, t.IfKID, p.PSKWrapped, hem.CryptoOpts{
		Alg:    WrapAlg,
		ExtKID: t.IfKID,
		Ctx:    PSKContext(p.KID),
	})
	if err != nil {
		return nil, fmt.Errorf("unwrapping the pre-shared key of %s: %w", p.Label, err)
	}
	if len(psk) != PSKLen {
		return nil, fmt.Errorf("unwrapped pre-shared key is %d bytes, expected %d", len(psk), PSKLen)
	}
	return psk, nil
}

// MTU reports the configured MTU, or the default when the record omits it.
func (t *Tree) MTU() uint16 {
	if t.Iface.MTU == 0 {
		return descr.DefaultMTU
	}
	return t.Iface.MTU
}
