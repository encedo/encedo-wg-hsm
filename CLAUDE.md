# wg-hsm — Claude Code Session Handoff

## Project goal

Fork of wireguard-go integrating Encedo HEM (EPA/PPA) as the cryptographic backend.
The WireGuard private key **never leaves the HEM**.
HEM performs ECDH on demand at every WireGuard handshake (~every 3 minutes).

---

## Architecture — what we're doing

### Problem with standard WireGuard
- `wg0.conf` contains `PrivateKey` in plaintext
- Linux kernel module does not allow any interception
- Solution: wireguard-go (userspace) + live HEM ECDH

### Our approach
```
wg-quick-encedo up wg1
  → Parse config (HEM_URL, HEM_KID, peers)
  → Checkin HEM (sync RTC)
  → Auth with password or mobile → JWT token (configurable duration, default 8h)
  → GetPubKey(myKID) → pub_i
  → Inject HSMSession{pub_i, ECDH func} into wireguard-go device
  → Start wireguard-go (TUN + UAPI)
  → HEM MUST stay online — every handshake (~3min) = 2x ECDH call

runtime:
  → handshake initiation: hsmDH(peerStaticPub) → precomputedStaticStatic
  → handshake response:   hsmDH(peerEphemeralPub) → ConsumeMessageResponse DH
  → ECDH error: 3 retries with 2s delay → graceful interface shutdown
```

### Why HEM must stay online at all times
WireGuard Noise_IKpsk2 requires the private key in THREE places:
1. `precomputedStaticStatic = DH(myPriv, peerStaticPub)` — when adding a peer
2. `DH(myPriv, peerEphemeralPub)` — in `ConsumeMessageResponse`, when WE initiated
3. `DH(myPriv, peerEphemeralPub)` — in `ConsumeMessageInitiation`, when the PEER initiated

Points 2 and 3 cannot be precomputed — the peer's ephemeral key is generated fresh
for every handshake and arrives in the packet. Either side of a WireGuard tunnel may
initiate, so both paths are live; patching only point 2 leaves peer-initiated
handshakes failing silently (the AEAD open fails and the packet is dropped as
unauthentic, with no log).

---

## Config format: wg1.conf

Minimal, extended with two fields in `[Interface]`.
`[Peer]` section — **unchanged**, `PublicKey` remains.

```ini
[Interface]
Address = 10.1.1.5/24
HEM_URL = https://my.ence.do      # EPA or PPA — identical API
HEM_KID = <32-char-hex-key-id>            # 32-char hex

[Peer]
PublicKey = i14L0qgxykUZL7GVV2x/hBXwuvbcXbcv+TIEp60Pk0M=
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.1.1.0/24
PersistentKeepalive = 25
```

Rules:
- `PrivateKey` → **never** in config
- `ListenPort` → do not set if client is behind NAT (uses a random port)
- `HEM_URL` → one per file
- `HEM_KID` → 32-character hex string

---

## Encedo HEM API — full specification

### Base URL
```
https://<HEM_URL>     # e.g. https://my.ence.do (PPA) or https://epa.company.com (EPA)
```
TLS 1.3 required. HTTP 418 = no TLS.
EPA and PPA have **identical APIs**.

### 1. Checkin
```
GET  /api/system/checkin → {"check": "JWT_challenge"}
POST /api/system/checkin {"checked": "..."} → {"status": "OK"}
```
Wide open — no Authorization. Requires Encedo backend to compute `checked`.

### 2. Password auth
```
GET  /api/auth/token → {"exp":..., "spk":"base64", "jti":"base64", "lbl":"...", "eid":"base64"}
POST /api/auth/token {"auth": "..."} → {"token": "eyJ..."}
```

### 3. Get Public Key
```
GET /api/keymgmt/get/:kid
Authorization: Bearer TOKEN
→ {"pubkey": "base64", "type": "CURVE25519", "updated": timestamp}
```

### 4. ECDH — the key operation
```
POST /api/crypto/ecdh
Authorization: Bearer TOKEN
{"kid": "32hex", "pubkey": "base64", "alg": ""}
→ {"ecdh": "base64_32bytes"}
```
`alg: ""` = raw Curve25519, no hash — identical result to WireGuard DH.

---

## wireguard-go patch — what we changed

### New file: `device/hsm.go`
```go
type HSMSession struct {
    PublicKey NoisePublicKey
    ECDH      func(pub NoisePublicKey) ([NoisePublicKeySize]byte, error)
}

var hsmSession *HSMSession

func InjectHSMSession(s *HSMSession) { hsmSession = s }

func hsmDH(pub NoisePublicKey) ([NoisePublicKeySize]byte, error) {
    if hsmSession == nil || hsmSession.ECDH == nil {
        return [NoisePublicKeySize]byte{}, fmt.Errorf("no HSM session")
    }
    return hsmSession.ECDH(pub)
}
```

### Patch: `device/peer.go` — `precomputeSharedSecret`
```go
if ek2, err := hsmDH(pk); err == nil {
    handshake.precomputedStaticStatic = ek2
} else {
    handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
}
```

### Patch: `device/noise-protocol.go` — `ConsumeMessageResponse` (we initiated)
```go
// instead of: ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
if hsmSession != nil {
    ss, err = hsmDH(msg.Ephemeral)
    if err != nil { return false }
} else {
    ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
    if err != nil { return false }
}
```

### Patch: `device/noise-protocol.go` — `ConsumeMessageInitiation` (peer initiated)
Same DH, other side. `ss` must be declared up front because upstream uses `:=`.
```go
var ss [NoisePublicKeySize]byte
var err error
if hsmSession != nil {
    ss, err = hsmDH(msg.Ephemeral)
} else {
    ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
}
if err != nil { return nil }
```
The result decrypts `msg.Static`; with the zeroed private key the AEAD open fails
and the peer's initiation is dropped without a log line.

### Patch: `device/device.go` — `SetPrivateKey`
```go
if hsmSession != nil {
    device.staticIdentity.publicKey = hsmSession.PublicKey
    device.cookieChecker.Init(hsmSession.PublicKey)
    return nil
}
```

---

## Project structure

```
wg-hsm/
  build.sh                        <- checkout wireguard-go + overlay patches + build dist/
  go.mod                          <- module github.com/encedo/encedo-wg-hsm
  README.md                       <- technical documentation
  PRODUCT.md                      <- marketing summary
  CLAUDE.md                       <- this file

  hem-sdk-go/                     <- git submodule: github.com/encedo/hem-sdk-go
                                     package hem. Never edit here — change it in
                                     the SDK repo, commit, push, then bump the
                                     submodule pointer. go.mod resolves it via
                                     `replace => ./hem-sdk-go`, so the build uses
                                     the checked-out commit.

  _wireguard-go-encedo/           <- ONLY our files (4 files) — overlay on upstream.
                                     The leading underscore is load-bearing: the go
                                     tool skips such directories, and these files
                                     reference upstream symbols that are absent
                                     here, so `go test ./...` would fail on them.
    device/
      hsm.go                      <- NEW: HSMSession + hsmDH
      device.go                   <- PATCH: SetPrivateKey
      peer.go                     <- PATCH: precomputedStaticStatic
      noise-protocol.go           <- PATCH: ConsumeMessageResponse + ConsumeMessageInitiation

  wireguard-go/                   <- gitignored, generated by build.sh
                                     commit: f333402 (v0.0.20250522)

  docs/
    ENCEDO-WG-CONFIGFREE-SPEC.md  <- spec for the config-free client (wg-hem)

  internal/                       <- shared by both CLIs
    descr/                        <- TLV codec for the descr records (spec §3)
                                     size_default.go / size_descr64.go pick 128 or
                                     64 B. Build -tags descr64 for old firmware;
                                     the record length is inside the MAC, so the
                                     two builds cannot read each other's trees.
    mac/                          <- canonical message + Sign/Verify (spec §4)
    config/                       <- load + authenticate the whole tree (spec §6.2)
    runtime/                      <- the OS half of bringing an interface up (spec §9):
                                     hsm.go holds the handshake ECDH path shared by both
                                     clients -- the retry policy is the tunnel's failure
                                     behaviour, not either client's detail.
                                     uapi.go dials a running interface and parses its
                                     get-operation: the only source that knows whether a
                                     handshake has actually happened.
                                     addresses, routes, MTU, DNS, UAPI socket, and the
                                     endpoint pinning of routing.go. Imported as `rt` to
                                     stay visibly apart from the standard library's
                                     runtime. Its Peer type carries only Endpoint and
                                     AllowedIPs, so neither client's notion of a peer
                                     leaks into it: wg-quick-encedo fills it from
                                     wg1.conf, wg-hem from the descr records.
                                     platform_{linux,darwin,windows}.go hold everything
                                     that differs per OS.

  cmd/
    wg-hem/                       <- config-free client: provision | verify
      main.go                     <- dispatch + exit codes (0/1/2/3/4/5)
      up.go                       <- bring the tunnel up from the stored config (§6.2).
                                     cmdUp decides (which peer), the tunnel type executes.
                                     usePeer is the only peer-dependent step, which is what
                                     lets failover swap one without disturbing the rest.
      failover.go                 <- §6.4 v1: 15 s without a handshake -> re-prompt, marking
                                     the peer that failed. Only the FIRST handshake after a
                                     peer is configured is watched; a peer that answers and
                                     later stops is v2 (health check + hysteresis).
      state.go                    <- /var/run/wireguard/<if>.wg-hem.json: pid, interface,
                                     if/peer KID, endpoint, HEM URL. No secrets. It is how
                                     down and status find the process that owns the routes.
      down.go                     <- SIGTERM to that process so it undoes its own pins and
                                     DNS; removes the interface itself only when the owner
                                     is gone or will not go, and says so.
      status.go                   <- state + UAPI (handshake, transfer) + hmac/verify
      provision.go                <- write a configuration into the HEM (spec §6.1)
      verify.go                   <- read it back, check the MAC, dump it (spec §10.3)
      peer.go                     <- peer add|remove|update, re-MACs the tree
      wipe.go                     <- delete the WG:* records (typed confirmation)
      peerspec.go                 <- --peer flag parsing
      session.go                  <- shared device flags, connect + load
      auth.go                     <- one passphrase, several scoped tokens
    wg-quick-encedo/
      main.go                     <- up / down / pubkey, interactive auth, ECDH retry;
                                     the OS work goes through internal/runtime
      config.go                   <- wg1.conf parser + HEM_URL/HEM_KID. Addresses and
                                     AllowedIPs are netip.Prefix, parsed here: a typo
                                     would otherwise surface with the interface half up
```

---

## Implementation status

Release 0.9.1. Both clients build for six platforms in two record sizes; CI
covers both on every push and publishes nothing (releases are signed by hand).

**Tested end to end on 2026-08-11, Linux arm64 client to a stock server.** The
far end is `blbx.pl`, ordinary Ubuntu `wireguard-tools` on the kernel module,
which knows nothing about any of this: an unmodified `[Peer]` entry with a
`PublicKey`. What was exercised, against a real HEM with 64-byte descr records
and no PSK, split tunnel:

- `provision` — identity key, peer import, MAC over the tree, read-back verify
- `verify` — the MAC checks and the stored records decode to what went in
- `up` — handshake completed, so a private key that exists only inside the
  device satisfied the reference implementation's Noise handshake
- failover — a peer that did not answer within 15 s was reported and re-offered,
  and choosing it again swapped it back in without disturbing the interface
- rekey — handshakes renewed at the expected interval, each costing two HEM calls
- `status` — state file, live counters and a fresh MAC check agreed

Round-trip time through the tunnel matched the raw RTT to the endpoint within
about a millisecond: the HEM is on the handshake path, not the data path.

**Soaked on 2026-08-11**, 7.5 hours on one tunnel: 225 ECDH calls with no gap in
the sequence, 224 ephemeral shared secrets and 224 distinct values, rekeys at
120-123 s against a 180 s limit, and device latency flat from first hour to last
(238 ms median, 237 ms in the second half). Not one call needed a retry. It ended
on token expiry — three attempts, then a clean shutdown — which is the documented
behaviour and the second thing that run confirmed.

**Losing the device mid-tunnel was tested on 2026-08-12** and behaved as
documented: the PPA was unplugged from a live tunnel, the next rekey found it
gone, three ECDH attempts five seconds apart (a 3 s timeout plus the 2 s delay),
then `The HEM is gone or the token has expired` and a clean teardown. `down` was
exercised the same evening — it stops an `up` running in another terminal — and
so was running without root, on `cap_net_admin` alone, on both arm64 and amd64.

**Windows works end to end, 2026-08-15.** An unprivileged window, a service
running as LocalSystem, a named pipe between them, and a tunnel whose key never
leaves the module — `ping` through it answered in about 50 ms. Peer `blbx`,
address 10.99.0.7/32, on Windows amd64 against the same stock server the Linux
client uses.

The route there is worth keeping, because the wall was real. On 2026-08-13 an
elevated administrator got as far as creating the adapter and answering the
first ECDH in 232 ms, then `ipc.UAPIListen` failed with "this security ID may
not be assigned as the owner of this object": upstream creates that pipe with
`O:SY`, and assigning SYSTEM as an owner is not something an administrator may
do. The account it was written for is LocalSystem, which is what the official
client's per-tunnel services use — so the component became a service, and
everything answered from that pipe came back with it. `docs/WINDOWS.md` has the
phases and what each test settled.

Two things found on the way that cost an evening each and are written up where
they happened. Upstream's fork of the namedpipe library hardcodes
`SECURITY_ANONYMOUS`, so anything dialling our control pipe through it is
identified as ANONYMOUS LOGON — the window and the probe ask for
`SECURITY_IDENTIFICATION` explicitly, and the component refuses S-1-5-7. And the
window runs a scripted stand-in unless given `-live`, which looked exactly like a
working tunnel: it now says "(stand-in)" beside the state.

**Still not tested:** full-tunnel routing, failover across more than one
candidate (there is one peer in the repository), macOS, Windows on ARM, and
packaging for Windows — there is no installer, so the service is registered with
`wg-hem service install` by hand. See `TODO.md` and `docs/WINDOWS.md`.

## Implemented

- Routes (AllowedIPs -> netlink/route/netsh per platform)
- Full-tunnel routing (`internal/runtime`): endpoints that AllowedIPs would capture are
  pinned to the pre-tunnel default gateway before the tunnel's own routes go in,
  and unpinned on teardown. The HEM is tested the same way but not pinned -- it
  works from inside the tunnel (rekey overlap), so the client reports it and
  continues, and refuses only if the HEM stops answering once the routes are up.
- MTU (netlink/ifconfig/netsh)
- DNS (resolvectl on Linux, no-op on macOS with warning, netsh on Windows)
- HEM_BROKER_URL in [Interface] (fallback to `https://api.encedo.com`)
- `pubkey <ifname>` -- reads public key from `/var/run/wireguard/<ifname>.pub`
- Auth defaults: Enter = 8h + password
- Zeroing of sensitive data (passBytes, seed, sharedSecret)

## TODO

In `TODO.md`, with the reasoning that makes each item resumable. Two entries
there are decisions rather than omissions and are worth knowing before proposing
either as an oversight: token refresh (expiry ends the tunnel; refreshing would
need the passphrase to outlive the auth step) and daemonising (`up` holds the
foreground because a daemon that restarts cannot re-authenticate).

---

## Important technical facts

- **An unknown key id comes back as HTTP 406, not 404.** `GET /api/keymgmt/get/<kid>`
  answers "not acceptable" for an identifier the device cannot resolve, which reads like
  a permission problem and is not one. Measured: the same key with the same scope gives
  200 while it is in the repository and 406 once deleted, and the scope is irrelevant to
  which of the two comes back. Treating only 404 as absence is what broke provisioning in
  `195f5d2`; `adopt.go` now accepts both. Anything that asks the device whether a key
  exists has to know this.
- Scopes are not interchangeable and each names what it permits: `keymgmt:get` reads a
  public key, `keymgmt:use:<KID>` grants use of that one key, `keymgmt:upd` changes a
  descr, `keymgmt:del` removes a key. Provisioning holds the first three and asks for the
  fourth only to remove an identity key its own run created and could not finish.
- `hsmSession == nil` -> original wireguard-go behaviour unchanged (wg0 works normally)
- `wg show` does not show public key -- because private key = 0, `wg` cannot derive it. Expected.
- `ListenPort` in client config behind NAT = problem (server tries to reach a fixed port). Do not set.
- DisableKeepAlives=true in HTTP client (HEM embedded closes connections)
- private_key in UAPI = 64x"0" (intercepted by SetPrivateKey patch)
- Logger: LogLevelError (not Verbose)
- ECDH retry: 3 attempts, 2s delay, then graceful shutdown. Each attempt is
  bounded by a 3s context -- WireGuard retransmits msg1 after 5s, so a call that
  has not answered by then is worth retrying rather than waiting on.
- Token expiry: asked at startup, default 8h, maximum depends on HEM

## Memory management -- sensitive data

Zeroing, in the order it happens:
1. `sharedSecret []byte` (X25519) -- zeroed in `buildEjwt` via `defer` after the HMAC
2. `seed []byte` (PBKDF2) -- each `AuthPassword` call works on its own copy and
   zeroes it via `defer`. A copy, not the cached slice, so `ClearKeys` is safe to
   call while a request is in flight.
3. the SDK's cached seed -- wiped by `client.ClearKeys()`, deferred in
   `authInteractive` so it does not outlive the auth step. Both tokens are held
   as JWT strings for the life of the process; the key that minted them is not.
4. `passBytes` in `main.go` -- zeroed via `defer` after `authInteractive` returns

`AuthPassword` takes `[]byte` (not `string`) -- no copy to an immutable string.
It does NOT zero `password` internally: the caller may pass the same slice twice.
The second scope is requested with `password=nil`, which reuses the cached key
instead of running a second 600k-round PBKDF2 over the same passphrase.
From the moment tokens are returned, only JWT strings live in memory.
