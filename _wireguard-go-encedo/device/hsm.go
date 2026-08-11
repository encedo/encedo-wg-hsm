/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2026 Krzysztof Rutecki
 *
 * New file, not derived from wireguard-go: the seam through which the device
 * package reaches an Encedo HEM.
 */

package device

import "fmt"

// HSMSession holds the active Encedo HSM connection for live ECDH operations.
// Inject via InjectHSMSession before configuring the WireGuard device.
// If nil, all code paths fall through to standard wireguard-go behaviour.
type HSMSession struct {
	PublicKey NoisePublicKey // our public key (from HSM GetPubKey)
	ECDH      func(pub NoisePublicKey) ([NoisePublicKeySize]byte, error)
}

var hsmSession *HSMSession

// InjectHSMSession sets the HSM session to be used by this device package.
// Call before device.NewDevice / device.SetPrivateKey.
func InjectHSMSession(s *HSMSession) {
	hsmSession = s
}

// hsmDH performs a Curve25519 DH via the HSM for the given public key.
// Used for both precomputedStaticStatic and per-handshake ephemeral DH.
func hsmDH(pub NoisePublicKey) ([NoisePublicKeySize]byte, error) {
	if hsmSession == nil || hsmSession.ECDH == nil {
		return [NoisePublicKeySize]byte{}, fmt.Errorf("no HSM session")
	}
	return hsmSession.ECDH(pub)
}
