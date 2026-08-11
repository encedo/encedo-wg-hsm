package runtime

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/device"

	hem "github.com/encedo/hem-sdk-go"
)

// ecdhTimeout bounds a single HEM call on the handshake path. WireGuard
// retransmits its first message after 5 s, so an ECDH that has not answered well
// before then is better retried than waited on.
const ecdhTimeout = 3 * time.Second

const (
	ecdhRetries    = 3
	ecdhRetryDelay = 2 * time.Second
)

// HSM binds a wireguard-go device to an interface key that never leaves the
// Encedo device. Noise_IKpsk2 needs the private key in three places and only one
// of them can be precomputed, so the tunnel makes a live call at every handshake
// — roughly every three minutes, twice.
//
// Both clients share this because the retry policy is part of the tunnel's
// failure behaviour, not a detail of either one: it decides how long a tunnel
// survives a HEM that has gone quiet, and how quickly it gives up rather than
// sitting on a handshake WireGuard has already retransmitted.
type HSM struct {
	client *hem.Client
	token  string
	kid    string
	pubKey device.NoisePublicKey

	// extKIDs lets a peer whose public key is already imported into the device
	// have its static-static DH done with both operands inside it: neither key
	// value passes through this process.
	extKIDs map[device.NoisePublicKey]string

	dead chan struct{}
}

func NewHSM(client *hem.Client, token, kid string, pubKey device.NoisePublicKey) *HSM {
	return &HSM{
		client:  client,
		token:   token,
		kid:     kid,
		pubKey:  pubKey,
		extKIDs: make(map[device.NoisePublicKey]string),
		dead:    make(chan struct{}, 1),
	}
}

// AddPeerKID records that a peer's public key is in the device under kid, which
// turns its static-static DH into an operation with no key material on either
// side of the wire.
func (h *HSM) AddPeerKID(pubKey device.NoisePublicKey, kid string) {
	h.extKIDs[pubKey] = kid
}

// Dead fires when a handshake ECDH has failed past its retries. The tunnel
// cannot rekey after that, so the caller's part is to bring the interface down
// rather than leave it up and silent.
func (h *HSM) Dead() <-chan struct{} { return h.dead }

// Inject installs the session into wireguard-go. It is process-wide: the fork
// keeps one session, which is all either client needs.
func (h *HSM) Inject() {
	device.InjectHSMSession(&device.HSMSession{
		PublicKey: h.pubKey,
		ECDH: func(pub device.NoisePublicKey) ([device.NoisePublicKeySize]byte, error) {
			if extKID, ok := h.extKIDs[pub]; ok {
				return h.ecdh(hem.CryptoOpts{ExtKID: extKID})
			}
			// An ephemeral, read off the wire: it exists nowhere but this
			// handshake, so it goes to the device as a value.
			result, err := h.ecdh(hem.CryptoOpts{PubKey: pub[:]})
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: HEM unreachable — shutting down interface: %v\n", err)
				select {
				case h.dead <- struct{}{}:
				default:
				}
			}
			return result, err
		},
	})
}

func (h *HSM) ecdh(opts hem.CryptoOpts) ([32]byte, error) {
	what := "ECDH"
	if opts.ExtKID != "" {
		what = "ECDH (internal)"
	}
	var lastErr error
	for i := 0; i < ecdhRetries; i++ {
		if i > 0 {
			fmt.Fprintf(os.Stderr, "HEM %s error: %v — retrying (%d/%d)...\n", what, lastErr, i, ecdhRetries-1)
			time.Sleep(ecdhRetryDelay)
		}
		ctx, cancel := context.WithTimeout(context.Background(), ecdhTimeout)
		result, err := h.client.ECDH(ctx, h.token, h.kid, opts)
		cancel()
		if err == nil {
			var out [32]byte
			copy(out[:], result)
			return out, nil
		}
		lastErr = err
	}
	return [32]byte{}, fmt.Errorf("HEM %s unreachable after %d attempts: %w", what, ecdhRetries, lastErr)
}
