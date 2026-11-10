// Package policy holds what the client knows about the device policy that
// firmware 1.3 sets at initialisation. It depends on the SDK alone, so the
// window can import it without pulling in the tunnel.
package policy

import (
	"context"
	"errors"
	"fmt"

	hem "github.com/encedo/hem-sdk-go"
)

// ErrRawECDHRefused is what a HEM without the raw_ecdh_enabled policy answers
// to every handshake.
//
// WireGuard cannot do without the raw shared secret: Noise feeds it into its
// own HKDF over BLAKE2s, so none of the hashed or HKDF variants the device
// offers in its place produce a usable value. Firmware 1.3 returns the raw
// X25519 secret only when the policy was set at personalisation, and the policy
// can not be changed afterwards - a module upgraded from older firmware has it
// off, and only a re-initialisation turns it on.
var ErrRawECDHRefused = errors.New("the HEM refuses raw ECDH: its policy does not include raw_ecdh_enabled.\n" +
	"WireGuard needs the raw X25519 shared secret, and the device hands it out only when\n" +
	"raw ECDH was enabled at initialisation. The policy can not be changed later:\n" +
	"re-initialise the module in Encedo Manager with raw ECDH enabled (this erases its keys),\n" +
	"then provision again")

// RawECDHRefused reports whether err is the device's 403 on a raw ECDH.
//
// A 403 there has one other cause, a token whose scope is not
// keymgmt:use:<kid> for this key. Every caller here asks for exactly that scope
// for exactly that key, so what is left is the policy.
func RawECDHRefused(err error) bool {
	var he *hem.HemError
	return errors.As(err, &he) && he.Status == 403
}

// CheckRawECDH asks the device for one raw ECDH with the key against its own
// public key and reports whether the policy allows it. Costs no approval
// beyond the keymgmt:use token the caller already holds.
func CheckRawECDH(ctx context.Context, c *hem.Client, token, kid string, pub []byte) error {
	_, err := c.ECDH(ctx, token, kid, hem.CryptoOpts{PubKey: pub})
	if err == nil {
		return nil
	}
	if RawECDHRefused(err) {
		return ErrRawECDHRefused
	}
	return fmt.Errorf("trying an ECDH with the identity key: %w", err)
}
