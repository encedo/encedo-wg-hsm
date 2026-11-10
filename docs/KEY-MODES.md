# Key modes: WireGuard on a HEM without device-wide raw ECDH

Status: design, 2026-11-10. Firmware references are to the HEM REST API 1.3.x
reference.

Decision (2026-11-10): **R ships now**, on firmware 1.3.x. **N1 is the next
iteration**, with firmware 1.4.x. K, W and N2 stay on the table and are not
scheduled.

## The problem

WireGuard's Noise handshake needs the raw X25519 shared secret: it feeds it into
its own HKDF over HMAC-BLAKE2s, so none of the hashed or HKDF variants the HEM
offers can stand in for it. Firmware 1.3 returns the raw secret from
`POST /api/crypto/ecdh` only when the device was initialised with the
`raw_ecdh_enabled` policy, and that policy is device-wide and fixed at
`auth/init`.

Turning it on is not free for everything else on the module. Several HEM
operations derive their keys from an ECDH secret inside the device -
`hmac/hash` with a peer, `cipher/wrap` and `cipher/unwrap` in modes 1/2 (KEK =
HKDF(ECDH, `encedo-wrap:v1:` ‖ ctx)), `keymgmt/derive` from an ECDH key. With
raw ECDH available, anyone who once holds a `keymgmt:use:<kid>` token for such a
key can take the secret out and compute every key derived from it offline, for
good, long after the token has expired. Leaving the policy off is right for a
module shared with other applications, and today that makes the module unusable
for WireGuard.

This document lays out the options, including the one we have now, so that more
than one can be offered.

## What the HEM contributes

The owner's framing, and the yardstick for every option below. A WireGuard
private key in process memory is already protected by the operating system;
what the HEM adds is:

1. **Zero files on disk.** No `PrivateKey` in a `.conf`, nothing to back up,
   nothing to leak with a laptop image.
2. **Portability.** A new computer, the module and the passphrase: the VPN works
   at once, because the whole configuration lives in the module.
3. **Physical possession and MFA.** Nothing starts without the module in the
   port and the passphrase or a phone approval.

Two further properties hold only while the private key never leaves the module:

4. **Kill switch.** Pulling the module ends the tunnel at the next rekey
   (measured 2026-11-10: the first rekey after removal failed three ECDH
   attempts and the interface came down cleanly).
5. **Token theft is bounded.** A stolen session token lets an attacker run
   handshakes as this client while the token is valid (8 h by default), and no
   longer. Where the key itself can be read out, one valid token is a permanent
   compromise until the key is rotated and every server is told.

Every option keeps 1-3. They differ on 4 and 5, and on what they cost in
firmware.

## The options

### R - raw ECDH, device policy (today)

The identity key is a `CURVE25519` key generated in the HEM. Every handshake
calls `crypto/ecdh` without `alg`: one call per peer for the static-static
secret, one per handshake for the ephemeral one. Measured on firmware 1.3:
72-133 ms per call.

- Needs `raw_ecdh_enabled` on the device. `provision` checks it with one trial
  ECDH before writing anything; the tunnel names the policy on a 403 instead of
  retrying (`internal/policy`).
- Keeps 1-5.
- Cost: the device-wide exposure described above. Right for a module dedicated
  to WireGuard; wrong for a shared one.

### N1 - raw ECDH per key (firmware: a key mode)

The same handshake as R, but raw ECDH is allowed for one key rather than for
the device. Modelled on DEV-503's `HPKE` mode, which already scopes a key pair
to one use:

- `POST /api/keymgmt/create` with `type: CURVE25519`, `mode: "NOISE"` creates a
  key with a new flag, `NOISE` (name open). Set only at creation, never by
  `keymgmt/update`, so a token with `keymgmt:upd` cannot turn an existing key
  into one that yields raw secrets.
- `crypto/ecdh` without `alg` is allowed for a `NOISE` key regardless of the
  device policy.
- Every other path may stay open for that key: whatever `hmac/hash` or
  `cipher/wrap` derive from it with `ext_kid = kid` is computable from the raw
  secret anyway, so allowing them adds no exposure, and it lets the
  configuration MAC and the PSK wrap work exactly as now.
- The attestation `key.modes` reports `NOISE`, so a verifier can see that this
  key, and only this key, yields raw secrets.

Client changes: create the identity key with `mode: "NOISE"`; the 403 check stays
for devices whose firmware predates the mode. Handshake path and record format
unchanged. Keys created without the mode cannot gain it: modules provisioned
under R move to N1 by provisioning a new identity key, which changes the public
key every server holds.

- Keeps 1-5. The exposure is confined to a key that exists only for WireGuard.
- Cost: a small firmware change (a flag, one condition in the ECDH handler, the
  mode in `create` and in the attestation).

### N2 - Noise mixing inside the HEM (firmware: a new operation)

The raw secret never leaves the device, not even for a `NOISE` key. The HEM does
the DH and the WireGuard KDF step in one operation and returns only its output.

WireGuard uses the secret in exactly two ways (wireguard-go
`device/noise-protocol.go`):

- `KDF2(ck, DH)` -> (ck', k): static-static in `CreateMessageInitiation` and
  `ConsumeMessageInitiation`, ephemeral-static in `ConsumeMessageInitiation`;
- `KDF1(ck, DH)` -> ck': static-ephemeral in `ConsumeMessageResponse`;

where `KDFn` is HKDF with HMAC-BLAKE2s, the WireGuard construction.

Proposed endpoint, `POST /api/crypto/noise/mix`:

| Field | Type | Rules |
|---|---|---|
| `kid` | string | 32 hex, a `CURVE25519` key with the `NOISE` flag |
| `pubkey` / `ext_kid` | string | the peer key, as in `crypto/ecdh` |
| `ck` | string | base64, 32 B, the current chaining key |
| `n` | number | 1 or 2: how many outputs |

Reply: `{"ck": "<32 B>", "k": "<32 B, only for n = 2>"}`. A zero DH result (low
order point) answers 400, as `crypto/ecdh` does since DEV-501.

Client changes: the overlay patch moves from "ask the HEM for DH" to "ask the
HEM for the KDF step" at those three sites. The static-static secret can no
longer be precomputed, because `ck` differs per handshake: two HEM calls per
handshake on either side instead of one plus a cached one. The patch touches
more of upstream, which `UPSTREAM.md` has to account for on every rebase.

- Keeps 1-5, and in addition a token holder gets only the KDF output of the
  handshakes it runs: the module is not a DH oracle even for its own key.
- Cost: BLAKE2s and HMAC-BLAKE2s in firmware, a new endpoint, a deeper client
  patch, one more HEM call per handshake. The gain over N1 is real but small,
  because a `NOISE` key exists for nothing but WireGuard.

### K - derived software key (no firmware change)

The private key is derived by the HEM and handed to an unmodified wireguard-go,
which holds it in memory for the life of the tunnel.

- The anchor is an HMAC key, `SHA2-256`, created in the HEM at provisioning. The
  interface record moves to its `descr`.
- At `up`: `POST /api/crypto/kdf` with `kid` = anchor, `alg: HKDF`, `len: 32`,
  `info = "ENC-WG-KEY-v1|" ‖ epoch (uint32 BE)`. The output, clamped, is the
  X25519 private key; the public key is computed on the host.
- **Nothing peer-specific goes into the derivation, and no ECDH with the peer's
  key.** A WireGuard interface has one static key for all its peers, so a
  per-peer key is impossible anyway; and a key derived from ECDH(HEM key, peer
  public key) could be recomputed by the server from its own private key and
  the HEM public key.
- The epoch is a rotation counter in the interface record, not a clock.
  WireGuard identifies a client by its static public key, so every new epoch
  means a new `[Peer]` block on every server. It is raised by hand, or after a
  suspected compromise.
- MAC: `hmac/hash` with the anchor over the canonical message, under a new
  domain (`ENC-WG-MAC-v3`). It is computed inside the device as now.
- PSK: AES-KW under a KEK from `crypto/kdf` with
  `info = "ENC-WG-PSKKEK-v1|" ‖ peer KID`, unwrapped on the host. The wrapped
  form stays 40 B in TLV 0x16; only the KEK's origin changes.
- Needs no device policy and no firmware change.
- Keeps 1-3. Loses 4: the tunnel outlives the module. A periodic presence check
  can take it down, but that is courtesy, not security - the key is already in
  memory. Loses 5: one `crypto/kdf` call with a valid token yields the key for
  as long as the epoch stands.

### W - wrapped software key (no firmware change)

The private key is generated on the host, or taken from an imported `.conf`,
and stored wrapped in the module.

- Two keys in the HEM: `AES256` (the KEK, `cipher/wrap` mode 0) and `SHA2-256`
  (the MAC anchor, as in K).
- The wrapped key is 40 B in a new interface-record TLV; `up` unwraps it.
- PSK: `cipher/wrap` mode 0 with the same AES key, 40 B in TLV 0x16 as now.
- What only W can do: **keep an existing key**. Importing a `.conf` today
  discards its `PrivateKey` and makes a new key in the module, so the server has
  to be told. Under W the import wraps the key from the file: an existing
  WireGuard user moves into the HEM without anyone touching the server.
- Same security as K, and weaker at birth: the key existed on the host before
  the module ever saw it. Keeps 1-3, loses 4 and 5.

## Side by side

| | R | N1 | N2 | K | W |
|---|---|---|---|---|---|
| Firmware change | - | key mode | key mode + endpoint | - | - |
| Device policy needed | `raw_ecdh_enabled` | - | - | - | - |
| Exposure for other HEM uses | device-wide | none | none | none | none |
| Private key ever outside the HEM | no | no | no | yes, in RAM | yes, in RAM and at birth |
| HEM calls per handshake | 1 (+1 per peer) | 1 (+1 per peer) | 2 | 0 | 0 |
| Kill switch on removal (4) | yes | yes | yes | no | no |
| Token theft bounded to its validity (5) | yes | yes | yes | no | no |
| Keeps an imported key | no | no | no | no | yes |
| Rotation | new key | new key | new key | epoch +1 | new key |
| Server update on rotation | yes | yes | yes | yes | yes |
| Client handshake patch | as now | as now | deeper | none | none |
| Record format | v2 | v2 | v2 | v3 (anchor, epoch) | v3 (wrapped key) |

## Record format

R, N1 and N2 keep the v2 records of `ENCEDO-WG-CONFIGFREE-SPEC.md`. K and W need
a v3 interface record, distinguishable on read:

- version byte `0x03`;
- `0x08` KEYMODE, 1 B: `0x01` K, `0x02` W;
- `0x09` EPOCH, 4 B (K);
- `0x0A` KEYWRAPPED, 40 B (W).

KEYMODE goes under the MAC like everything else in the record. Otherwise
whoever can write a `descr` could downgrade a configuration from one mode to
another.

## Recommendation

1. **N1 as the primary mode**, to be asked of the firmware now. It is the
   smallest change that removes the conflict: other users of the module keep
   their protection, WireGuard keeps all five properties, and the client
   changes by one field at key creation.
2. **R stays** for modules already initialised with the policy, which includes
   every module provisioned today.
3. **K as the no-firmware fallback**, offered explicitly and named as a
   different, weaker mode - "software key" against "hardware key" in the CLI,
   in the window and on the website - never chosen silently. It is the right
   answer for a module whose owner will not change its policy and cannot wait
   for N1.
4. **W only if migration without a server change is something we want to
   sell.** The capability is real, but it starts from a key that has already
   lived on a disk.
5. **N2 later, if a customer asks for "no DH oracle at all".** It is the
   strongest option and the most expensive one.

## Open questions

- Firmware: the name of the flag, and whether `NOISE` keys may keep the
  `ext_kid = kid` paths (MAC, PSK wrap). This design assumes yes; without them
  N1 needs the v3 MAC anchor from K as well.
- Can the mode be chosen per module automatically - N1 when the firmware has it,
  R when the policy is on, K only on request - or should it always be an
  explicit choice at `provision`?
- K: is a presence check (end the tunnel when the module goes away) worth
  having as a setting, given that it changes nothing about the key's exposure?
- W: should an imported key be marked as such in the record, so that `verify`
  and the window can say "this key was not made in the module"?
