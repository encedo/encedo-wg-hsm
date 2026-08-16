package runtime

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"

	hem "github.com/encedo/hem-sdk-go"
)

// debug turns on the handshake trace: one line per ECDH, which is the only way
// to watch the tunnel rekey from outside the device. Off unless WG_HEM_DEBUG is
// set in the environment or a command calls SetDebug.
var debug = os.Getenv("WG_HEM_DEBUG") != ""

// SetDebug turns the handshake trace on from a command's flags.
func SetDebug(on bool) { debug = on }

// ecdhSeq numbers the calls so a reader can count them against handshakes: a
// completed handshake costs two, and a number that stops climbing is a tunnel
// that has stopped rekeying.
var ecdhSeq atomic.Uint64

// headTail renders a value as its first and last four bytes. For a 32-byte
// shared secret that shows 8 of them - enough to see the value change from one
// handshake to the next, and 192 bits short of being of use to anyone who reads
// the log. Peer ephemerals are rendered the same way for symmetry; those are
// public regardless, since they cross the wire in cleartext.
func headTail(b []byte) string {
	if len(b) <= 8 {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:4]) + "..." + hex.EncodeToString(b[len(b)-4:])
}

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
// - roughly every three minutes, twice.
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
	//
	// Guarded: failover adds to it from the foreground while the device's own
	// goroutines may be reading it for a handshake already in flight. The token
	// is under the same lock, for the same reason - a session that is renewed
	// mid-flight is written from whoever is holding the conversation with the
	// person, while a handshake in progress is reading it.
	mu      sync.RWMutex
	extKIDs map[device.NoisePublicKey]string

	dead chan struct{}
}

// SetToken replaces the credential every subsequent handshake acts with.
//
// Renewal is a human act - the token expires and only somebody at a window or a
// terminal can prove who they are again - so it arrives from outside, while
// handshakes are in flight. A rekey that has already begun keeps the token it
// started with, which is right: it is either still valid, in which case nothing
// is wrong, or it has expired, in which case the retry after it picks up the
// new one.
func (h *HSM) SetToken(token string) {
	h.mu.Lock()
	h.token = token
	h.mu.Unlock()
}

func (h *HSM) currentToken() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.token
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
	h.mu.Lock()
	defer h.mu.Unlock()
	h.extKIDs[pubKey] = kid
}

func (h *HSM) peerKID(pubKey device.NoisePublicKey) (string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	kid, ok := h.extKIDs[pubKey]
	return kid, ok
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
			if extKID, ok := h.peerKID(pub); ok {
				return h.ecdh(hem.CryptoOpts{ExtKID: extKID})
			}
			// An ephemeral, read off the wire: it exists nowhere but this
			// handshake, so it goes to the device as a value.
			result, err := h.ecdh(hem.CryptoOpts{PubKey: pub[:]})
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: HEM unreachable - shutting down interface: %v\n", err)
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
	seq := ecdhSeq.Add(1)
	var lastErr error
	for i := 0; i < ecdhRetries; i++ {
		if i > 0 {
			fmt.Fprintf(os.Stderr, "HEM %s error: %v - retrying (%d/%d)...\n", what, lastErr, i, ecdhRetries-1)
			time.Sleep(ecdhRetryDelay)
		}
		ctx, cancel := context.WithTimeout(context.Background(), ecdhTimeout)
		started := time.Now()
		result, err := h.client.ECDH(ctx, h.currentToken(), h.kid, opts)
		took := time.Since(started)
		cancel()
		if err == nil {
			var out [32]byte
			copy(out[:], result)
			if debug {
				trace(seq, opts, out[:], took, i+1)
			}
			return out, nil
		}
		if debug {
			fmt.Fprintf(os.Stderr, "[hsm] %s ecdh#%-4d %-9s FAILED after %s (try %d/%d): %v\n",
				time.Now().Format("15:04:05.000"), seq, operandKind(opts), took.Round(time.Millisecond),
				i+1, ecdhRetries, err)
		}
		lastErr = err
	}
	return [32]byte{}, fmt.Errorf("HEM %s unreachable after %d attempts: %w", what, ecdhRetries, lastErr)
}

// operandKind names which of the two DHs this is. "static" is the peer's own
// key, already inside the device, so only its identifier travels; "ephemeral"
// is the key read off the wire for this one handshake.
func operandKind(opts hem.CryptoOpts) string {
	if opts.ExtKID != "" {
		return "static"
	}
	return "ephemeral"
}

// trace prints one line per successful ECDH. Two lines with the same second and
// different operands are one handshake; the gap between such pairs is the rekey
// interval, and the ss column changing across them is the tunnel actually
// rotating rather than reusing a session.
func trace(seq uint64, opts hem.CryptoOpts, ss []byte, took time.Duration, try int) {
	operand := "-"
	if opts.ExtKID != "" {
		operand = opts.ExtKID
		if len(operand) > 16 {
			operand = operand[:8] + "..." + operand[len(operand)-8:]
		}
	} else if len(opts.PubKey) > 0 {
		operand = headTail(opts.PubKey)
	}
	fmt.Fprintf(os.Stderr, "[hsm] %s ecdh#%-4d %-9s peer=%-19s ss=%-19s %7s try=%d\n",
		time.Now().Format("15:04:05.000"), seq, operandKind(opts), operand,
		headTail(ss), took.Round(time.Millisecond), try)
}
