// Package config loads a config-free client's whole configuration out of a HEM
// and authenticates it. See docs/ENCEDO-WG-CONFIGFREE-SPEC.md §6.2.
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
	"strings"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/mac"
)

// PSKContext domain-separates the key that wraps a pre-shared key from any
// other wrap use of the same interface key (§5). Wrap and unwrap must agree on
// it exactly or the derived key differs.
const PSKContext = "ENC-WG-PSK-v1"

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
// there is no degraded mode to fall back to (§8.3).
func Load(ctx context.Context, c *hem.Client, tok TokenFunc) (*Tree, error) {
	ifEntries, err := search(ctx, c, tok, descr.MagicInterface)
	if err != nil {
		return nil, err
	}
	switch len(ifEntries) {
	case 0:
		return nil, fmt.Errorf("no %s record in the device — run `wg-hem provision` first", descr.MagicInterface)
	case 1:
	default:
		kids := make([]string, 0, len(ifEntries))
		for _, e := range ifEntries {
			kids = append(kids, e.KID)
		}
		return nil, fmt.Errorf("the device holds %d interface records (%s); this client configures one",
			len(ifEntries), strings.Join(kids, ", "))
	}

	t := &Tree{IfKID: ifEntries[0].KID, IfLabel: ifEntries[0].Label}
	t.IfRaw, err = descr.Normalize(ifEntries[0].Descr)
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

	// One keymgmt:get token reads every public key: the interface's own and each
	// candidate peer's. Search returns descr but not key material, so the peer
	// references cannot be resolved without this.
	getTok, err := tok(ctx, "keymgmt:get")
	if err != nil {
		return nil, err
	}
	ifKey, err := c.GetPubKey(ctx, getTok, t.IfKID)
	if err != nil {
		return nil, fmt.Errorf("reading the interface public key: %w", err)
	}
	if len(ifKey.PubKey) != mac.PubKeyLen {
		return nil, fmt.Errorf("interface public key is %d bytes, expected %d",
			len(ifKey.PubKey), mac.PubKeyLen)
	}
	copy(t.IfPubKey[:], ifKey.PubKey)

	peerEntries, err := search(ctx, c, tok, descr.MagicPeer)
	if err != nil {
		return nil, err
	}

	// A reference is the start of the peer's KID, and search returns the KID of
	// every record, so the candidates are matched without reading a single key.
	// Only the peers this interface actually references are then read — a
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
		key, err := c.GetPubKey(ctx, getTok, e.KID)
		if err != nil {
			return nil, fmt.Errorf("reading public key of peer %s: %w", e.KID, err)
		}
		if len(key.PubKey) != mac.PubKeyLen {
			return nil, fmt.Errorf("peer %s has a %d-byte public key, expected %d",
				e.KID, len(key.PubKey), mac.PubKeyLen)
		}
		// The device's identifier must be the one this client derives, or every
		// reference it resolves is guesswork. Checking here turns a wrong
		// assumption about the device into a clear error rather than a MAC
		// failure with no explanation.
		if got := descr.KID(key.PubKey); got != e.KID {
			return nil, fmt.Errorf("peer %s reports a public key whose KID is %s; this client derives identifiers as SHA-1(pubkey)[:16] and the device evidently does not",
				e.KID, got)
		}

		p := Peer{KID: e.KID, Label: e.Label}
		copy(p.PubKey[:], key.PubKey)
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
		Ctx:    []byte(PSKContext),
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
