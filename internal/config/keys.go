package config

import (
	"context"
	"fmt"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/mac"
)

// A key identifier is a hash of the key it names - `KID = SHA-1(pubkey)[0:16]`,
// section 3 - and that one fact decides where public keys may come from.
//
// The device can be asked, which costs a `keymgmt:get` token and one call per
// key. Or somebody who already asked can pass them along, which costs nothing
// and is safe for a reason that has nothing to do with trusting them: a supplied
// key is checked against the identifier it claims, and producing a different key
// with the same identifier is a second-preimage attack on SHA-1.
//
// So the privileged component reads the *identifiers* itself - freshly, because
// the MAC authenticates a tree without saying which version of it is current,
// and an old tree replayed would verify perfectly well - and takes the keys from
// whoever already has them.

// keyring resolves a key identifier to the public key it names.
type keyring func(ctx context.Context, kid string) ([]byte, error)

// fromDevice reads public keys one call at a time, under a `keymgmt:get` token.
// It is what a client with nobody to ask uses, and what the command line has
// always done.
func fromDevice(c *hem.Client, tok TokenFunc) keyring {
	var getTok string
	return func(ctx context.Context, kid string) ([]byte, error) {
		if getTok == "" {
			var err error
			if getTok, err = tok(ctx, "keymgmt:get"); err != nil {
				return nil, err
			}
		}
		key, err := c.GetPubKey(ctx, getTok, kid)
		if err != nil {
			return nil, err
		}
		return key.PubKey, nil
	}
}

// fromSupplied answers out of what it was handed, and refuses anything it was
// not.
func fromSupplied(keys map[string][]byte) keyring {
	return func(_ context.Context, kid string) ([]byte, error) {
		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("no public key was supplied for %s", kid)
		}
		return key, nil
	}
}

// resolve gets a key and checks that it is the key that identifier names.
//
// The check runs on both paths, not only the supplied one. On the device path it
// catches an appliance that derives identifiers differently from this client -
// which would otherwise surface as a MAC failure with no explanation - and on
// the supplied path it is what makes supplying them safe at all.
func resolve(ctx context.Context, ring keyring, kid string) ([mac.PubKeyLen]byte, error) {
	var out [mac.PubKeyLen]byte

	raw, err := ring(ctx, kid)
	if err != nil {
		return out, err
	}
	if len(raw) != mac.PubKeyLen {
		return out, fmt.Errorf("the public key of %s is %d bytes, expected %d", kid, len(raw), mac.PubKeyLen)
	}
	if got := descr.KID(raw); got != kid {
		return out, fmt.Errorf("the public key offered for %s has identifier %s; identifiers are SHA-1(pubkey)[:16] and this one is not that key",
			kid, got)
	}
	copy(out[:], raw)
	return out, nil
}
