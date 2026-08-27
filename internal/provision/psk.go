package provision

import (
	"context"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// WrapPSK wraps a pre-shared key under the interface key's self-ECDH, bound to
// the peer whose record will carry it, or returns nil when there is nothing to
// wrap. Each peer gets its own wrap of the same key: the ciphertexts differ, and
// none of them unwraps anywhere else.
func WrapPSK(ctx context.Context, client *hem.Client, useTok, ifKID, peerKID string, psk []byte) ([]byte, error) {
	if psk == nil {
		return nil, nil
	}
	wrapped, err := client.CipherWrap(ctx, useTok, ifKID, psk, hem.CryptoOpts{
		Alg:    config.WrapAlg,
		ExtKID: ifKID,
		Ctx:    config.PSKContext(peerKID),
	})
	if err != nil {
		return nil, session.Classify(err, session.KindDevice, "wrapping the pre-shared key")
	}
	if len(wrapped) != descr.PSKWrappedLen {
		return nil, session.Fail(session.KindDevice, "wrapped PSK is %d bytes, expected %d", len(wrapped), descr.PSKWrappedLen)
	}
	return wrapped, nil
}
