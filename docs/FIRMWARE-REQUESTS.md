# Requests to the firmware and Authenticator teams

From the Encedo WG client, 2026-11-14. Firmware source read at `d8ae20c4`
(`Firmware/src`), the Authenticator at `f2e77e5`. Three items, most useful
first. None of them blocks a release: each says what the client does today
without it.

## 1. Let a client propose how long a phone-approved session lasts

**What happens today.** Whoever approves on the phone picks the period, on the
request screen under "For how long": 15 min, 1 h, 8 h or 24 h, with 1 h
selected (`src/screens/Request.svelte`, `let period = $state(3600)`;
`event::PERIODS` in `src-tauri/crates/protocol/src/event.rs`). The app puts
`exp = now + period` in its authreply, and `api_post_auth_ext_token` copies that
`exp` into the token it issues (`api_auth.c`, around line 2433).

The client has no say. `api_post_auth_ext_request` reads `epk`, `ctx`, `note`
and `scope` and nothing else; the `exp` it writes into the request
(`alter_requested_scope`, around line 1733: 60 min, or 15 min when the first
scope is a `keymgmt:use:` key the device knows) is how long the request stays
valid, not how long the session will last. The Authenticator's own
`docs/PROTOCOL.md` documents `POST /api/auth/ext/request {epk, scope, exp}`,
but the firmware does not read an `exp` there.

**Why it matters for WireGuard.** A tunnel is a working day, not a sign-in.
With the default of 1 h the client has to ask the phone again every hour; it
does so five minutes before the end since 2026-11-14, so the tunnel survives,
but somebody is interrupted seven times a day unless they remember to tap
"8 h" on the first request.

**The request.**
- Firmware: accept an optional requested lifetime in `ext/request` (a field
  such as `ttl`, seconds) and carry it, under the request's MAC, to the app.
  A device policy may cap it.
- Authenticator: preselect the period closest to the requested one, still
  letting the person change it. The person keeps the decision; the client only
  stops having to hope the right button is pressed.

Client side, nothing more than sending the field: `--session 8` already exists
and today applies to the passphrase only.

## 2. Raw ECDH for one key, not for the device (mode N1, for 1.4.x)

**What happens today.** WireGuard needs the raw X25519 result: Noise runs its
own HKDF over BLAKE2s, so the device's hashed and HKDF variants are no use.
Firmware 1.3 returns the raw value only on a device initialised with the
`raw_ecdh_enabled` policy, which is set once and covers every key on the
device. Encedo WG works only on such a device and says so (HTTP 403 is named,
not retried).

**The request.** A key mode, set only at creation, that allows `crypto/ecdh`
without `alg` for that one key whatever the device policy:

- `POST /api/keymgmt/create` with `type: CURVE25519` and a new mode, `NOISE`
  (name open). Never settable by `keymgmt/update`, so `keymgmt:upd` cannot turn
  an existing key into one that yields raw secrets.
- The `ext_kid = kid` paths (`hmac/hash`, `cipher/wrap`) stay open for that
  key: whatever they derive is computable from the raw secret anyway, and the
  client's configuration MAC and pre-shared-key wrap use them.
- Attestation `key.modes` reports `NOISE`, so a verifier sees that this key,
  and only this key, yields raw secrets.

The whole design and the alternatives weighed against it are in
`docs/KEY-MODES.md`, mode N1. The client change is one field at key creation;
records and the handshake path stay as they are.

## 3. `return_pubkey` without a token: answer 401 instead of dropping it

**What happens today.** `POST /api/keymgmt/search` without a token, on a device
with `allow_keysearch`, ignores `return_pubkey` and answers 200 without public
keys (`api_keymgmt.c`, around line 509: `get_pubkey = false; // Note: without
JWT token this feature is disabled always`). The comment on the access check a
few lines above says the opposite rule: allow without a token "ONLY if no
pubkey is requested to be returned, otherwise check scope&token" - which reads
as 401 for a tokenless request that asks for keys.

**Why it matters.** A client cannot tell "this device's `pubkey_in_search`
policy is off" from "you sent no token". Both come back as a 200 with no keys.

**The request.** Either answer 401 when `return_pubkey` is set and there is no
token, as the comment describes, or keep the behaviour and fix the comment and
the API reference so the silent drop is the documented rule. Encedo WG copes
with both: it searches without a token first for the key identifiers, and asks
for public keys only with a token.
