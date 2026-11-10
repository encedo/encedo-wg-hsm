package runtime

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/policy"
)

// A device without raw_ecdh_enabled answers every handshake with 403, and the
// policy does not change between attempts. The tunnel has to say so at once,
// in words that name the policy, rather than spend three retries and then
// report the HEM as gone.
func TestHandshakeECDHStopsOnThePolicy(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	h := NewHSM(hem.NewClient(srv.URL, hem.Config{}), "tok", "00112233445566778899aabbccddeeff", device.NoisePublicKey{})
	start := time.Now()
	_, err := h.ecdh(hem.CryptoOpts{PubKey: make([]byte, 32)})
	if !errors.Is(err, policy.ErrRawECDHRefused) {
		t.Fatalf("err = %v, want ErrRawECDHRefused", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("%d calls, want 1: a policy refusal is not worth retrying", n)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("took %s, the retry delay was paid", took)
	}
}
