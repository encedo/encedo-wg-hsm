# Encedo HEM × WireGuard — Config-Free Client (Implementation Specification)

Version: 2.1 (2026-08-11) · Status: ready for implementation
Base: fork `github.com/encedo/encedo-wg-hsm` (wireguard-go with the private key held in HEM)
HEM FW: v1.7b (current API, **zero firmware changes required**)
SDK: `github.com/encedo/hem-sdk-go` — every call in §7 is implemented

Changes in 1.4: self-ECDH addressed by `ext_kid` rather than `pubkey` (§4, §5);
§7 endpoint paths corrected to `/api/keymgmt/*`.

Changes in 1.5: §3 states the encoding rules that make the format distinguished
(ascending tags, no zero-valued optional tags). These constrain what a *writer*
may emit and what a *reader* must reject; no field, tag or offset changed, and
no record valid under 1.4's tables becomes invalid unless it was already relying
on two encodings of one configuration. `ENC-WG-MAC-v1` stands.

Changes in 1.6: §5 states where a PSK comes from (infra via stdin, or generated
locally) — the device has no randomness endpoint, so the previous "from the HEM
RNG" was not implementable. §6.2 corrects the call count at startup: search does
not return public keys, so each candidate peer needs a pubkey read, all covered
by one `keymgmt:get` token.

Changes in 1.7: §3 records that the 64 B `descr` of older firmware is a
supported build target, and what stops fitting at that size.

Changes in 1.8: §6.2 step 8 adds the HEM reachability check. The endpoint
exception was already there; the HEM's own address needs the same treatment,
because a handshake cannot complete without it.

Changes in 2.1: the PSK wrap context becomes per-peer (`ENC-WG-PSK-v2|<peer KID>`),
so a wrapped key is bound to the record it sits in and not merely to the identity.
§4 records why each peer's public key is in the canonical message, since that is
the part most likely to look redundant to a future reader. No record layout
changed; previously wrapped keys will not unwrap, which at this stage costs a
re-provision.

Changes in 2.0 (**format change**): PEER_REF is the first 4 B of the peer's KID
instead of a SHA-256 digest of its public key, since `KID = SHA-1(pubkey)[0:16]`
is derivable locally and is what key search returns. Record version 0x01→0x02 and
the MAC domain v1→v2 accordingly (§8.6). §2 states what sharing a peer record does
and does not allow.

Changes in 1.9: corrects that check. A HEM inside the tunnel is informational,
not a warning to confirm — rekeying overlaps a live session by 60 s, so it uses
the tunnel it is renewing. Only a session that has lapsed entirely cannot
rebuild itself, and a restart clears that.

## 1. Goal

A WireGuard client that requires **no configuration file and no key material** on the machine.
All state lives inside the Encedo HEM (PPA/EPA):

- identity key (Curve25519 private) — HEM object, non-exportable,
- peer (server) public keys — imported into HEM,
- network configuration — binary-encoded (TLV) in the `descr` fields (128 B per key),
- configuration integrity — HMAC computed and verified **inside HEM** (self-ECDH),
- optional PSK — random 32 B, stored as an AES-KW wrap in the peer's `descr`.

On the host: a single `wg-hem` binary (wrapper + forked wireguard-go) + the physical HEM. Nothing else.

That holds for the command-line client and is a rule rather than a description — it does not change. The graphical client adds a window and a privileged component beside it, both of which are the same binary or ship with it; what runs privileged, and what crosses between them, is `docs/ARCHITECTURE-GUI.md` (2026-08-13), which is the newer document wherever the two touch.

## 2. Architecture

```
┌─────────────┐   REST/TLS    ┌──────────────────────────────┐
│  Encedo HEM │◄─────────────►│  wg-hem (Go, single binary)  │
│  PPA / EPA  │               │  ├─ hemclient (API client)   │
│             │               │  ├─ descr codec (TLV)        │
│ keys+descr  │               │  ├─ provisioner              │
│ ECDH/HMAC/  │               │  ├─ runtime (netlink, DNS,   │
│ wrap inside │               │  │   routes, failover)       │
└─────────────┘               │  └─ wireguard-go fork (device│
                              │      → HEM ECDH per handshake)│
                              └──────────────────────────────┘
```

Object mapping: **1 interface (if) key → N peers** (list of references in the if key's `descr`).

A device may hold **several such identities**, each with its own peers: N private keys, N configurations, one repository. They do not interact — one MAC closes over one identity and the peers it names — so the only thing multiplicity changes is that something has to choose. The rule is the one §6.2 step 5 already applies to peers: a single record is used without asking, several are offered. `keymgmt:use:<if_kid>` names one key, so that choice necessarily precedes the token.
The binding is one-directional: the identity record enumerates its peers, and a peer
record points at nothing. That is what lets one MAC close over the whole set, and what
makes a peer record shareable.

Public keys in HEM are unique — a peer record exists exactly once, and the device
refuses a second import of a key it already holds. So several identity keys may
reference the same peer, but they all authenticate **the same bytes**: sharing works
only where they agree on the peer's endpoint, routes and keepalive. A client adopts an
existing record rather than rewriting it, since rewriting would invalidate the MAC of
every other identity referencing it.

**A shared peer cannot carry a PSK.** TLV 0x16 is wrapped under the *identity* key's
self-ECDH (§5), so a second identity cannot unwrap it, and one record holds one wrap.
Peers used by more than one identity are therefore PSK-less; a PSK peer belongs to a
single identity.

## 3. Data format — DESCR (128 B, binary)

Common header:

| offset | size | content |
|---|---|---|
| 0 | 6 B | ASCII magic: `WG:if:` or `WG:pr:` (exactly 6 chars — the HEM prefix-search minimum) |
| 6 | 1 B | version = `0x02` |
| 7 | … | TLV stream: `tag(1B) len(1B) value(len B)`; terminated by tag `0x00` or end of buffer; zero-padded |

**Record length.** 128 B, the capacity of the `descr` field. Firmware predating
that capacity offers 64 B; build with `-tags descr64` (or `WG_HEM_DESCR=64 bash
build.sh`) to target it. The length is not a private matter of the encoder — the
canonical message of §4 includes each record at its full padded length, so a
tree written against one length cannot be verified against the other. At 64 B a
peer with a wrapped PSK fits only with a literal IPv4 endpoint, exactly one
AllowedIPs range and no keepalive (7+8+7+42 = 64 exactly); a hostname endpoint
and a PSK cannot coexist; and an interface record has room for one address, one
option and two peer references beside its MAC.

**Encoding rules (normative).** One configuration has exactly one encoding — the
property DER gives ASN.1, and for the same reason: the record is authenticated,
compared and stored as bytes.

- Tags MUST appear in **ascending order**. A repeatable tag may of course repeat.
- An optional numeric tag (`0x03` MTU, `0x07` LISTEN_PORT, `0x15` KEEPALIVE) MUST NOT
  carry the value `0`. Zero is how each of those fields says "absent", so an explicit
  zero and a missing tag would describe the same configuration — omit the tag.
- Padding after the terminator MUST be zero.

A decoder rejects anything else rather than normalising it. This is not what
prevents forgery — the MAC over the bytes already does that — but it makes
`encode(decode(x)) == x` an invariant the codec can be fuzzed against, and it
lets two records be compared without decoding both.

**Key identifiers.** `KID = SHA-1(pubkey)[0:16]`, lowercase hex — confirmed against
a device for Curve25519 keys. Two consequences the design leans on:

- A peer's identifier is knowable before any call, so a client can tell whether a
  key is already in the repository, and read its record, before attempting an
  import that the device would refuse anyway (one public key, one record).
- `PEER_REF` is the start of that identifier rather than a separate digest, so key
  search — which returns a KID with every record — resolves references directly.
  Public keys are then read only for the peers actually referenced.

A reference is an index, not a credential: four bytes collide, and someone able to
import keys could grind a collision. The result is an ambiguous or unresolvable
reference, never a substituted peer, because the canonical message of §4 carries
each peer's full public key and record.

### 3.1 `WG:if:` record (identity key)

| tag | name | len | value | notes |
|---|---|---|---|---|
| 0x01 | ADDR4 | 5 | addr(4) + prefixlen(1) | repeatable |
| 0x02 | ADDR6 | 17 | addr(16) + prefixlen(1) | repeatable |
| 0x03 | MTU | 2 | uint16 BE | optional (default 1420) |
| 0x04 | DNS4 | 4 | addr(4) | repeatable, optional |
| 0x05 | DNS6 | 16 | addr(16) | repeatable, optional |
| 0x06 | PEER_REF | 4 | first 4 B of the peer's KID | repeatable; **order = failover priority** |
| 0x07 | LISTEN_PORT | 2 | uint16 BE | optional |
| 0x7F | MAC | 32 | HMAC-SHA2-256 | **always the last TLV**; see §4 |

Example budget: 7 (hdr) + 5 (addr) + 2+2 (mtu) + 4+2 (dns) + 3×(4+2) (refs) + 32+2 (mac) = **74 B** ✓

### 3.2 `WG:pr:` record (peer / server)

| tag | name | len | value | notes |
|---|---|---|---|---|
| 0x10 | ENDPOINT4 | 6 | addr(4) + port(2 BE) | exactly one of 0x10/0x11/0x12 |
| 0x11 | ENDPOINT6 | 18 | addr(16) + port(2 BE) | |
| 0x12 | ENDPOINT_HOST | 3–62 | port(2 BE) + hostname UTF-8 | hostname max 60 B |
| 0x13 | AIP4 | 5 | addr(4) + prefixlen(1) | AllowedIPs, repeatable |
| 0x14 | AIP6 | 17 | addr(16) + prefixlen(1) | repeatable |
| 0x15 | KEEPALIVE | 1 | seconds (uint8) | optional |
| 0x16 | PSK_WRAPPED | 40 | AES-KW ciphertext (NIST KW, 32 B PSK → 40 B) | optional; see §5 |

**The peer record carries NO MAC** — integrity is provided by the if key's MAC (§4).
Budget: 7 + 8 (ep4) + 2×7 (2×aip4) + 3 (ka) + 42 (psk) = **74 B**; with a 60 B hostname instead of ep4: **130 B > 128 — therefore: the 60 B hostname limit applies ONLY without PSK; with PSK, hostname max ~56 B or use an IP endpoint**. The codec MUST validate this at encode time.

## 4. Integrity — a single MAC over the whole tree

**MAC key = self-ECDH of the if key, computed inside HEM.** It never exists outside the device.

⚠️ **Never key the MAC with ECDH(if, peer)** — the holder of the peer's private key (or an attacker importing their own pubkey) can compute the shared secret offline and forge the MAC. Self-ECDH (the key against itself) is resistant (CDH equivalence). Confirmed: HEM performs self-ECDH without issues.

Address the second operand with **`ext_kid` = `<if_kid>`**, not with `pubkey`. Both are accepted — self-ECDH works anywhere ECDH does — but `ext_kid` names the key the device already holds, whereas `pubkey` would force the client to read its own public key back out of the HEM first only to hand it straight back. It is also the form the certification suite exercises (`hem-api-tester/test_11.php`, subtest 5).

Canonical message:

```
msg = "ENC-WG-MAC-v2"                      # 13 B ASCII, domain separation
    || if_pubkey (32 B)
    || if_descr[0..127] with the TLV 0x7F value zeroed (32 × 0x00 in place of the MAC)
    || for each peer on the PEER_REF list, sorted ascending by full pubkey (bytes):
         peer_pubkey (32 B) || peer_descr (128 B)
```

- Sort by **pubkey**, not by PEER_REF order (the refs order carries failover priority and is itself covered by the MAC via if_descr).
- **Each peer's full public key is in the message, not just its record.** This is not
  redundancy with PEER_REF and must not be optimised away. A reference is 4 bytes, so an
  attacker able to import keys can grind one whose KID collides — 2³² is minutes of CPU —
  and give it a record byte-identical to the legitimate peer's. If the message covered only
  the records, that forgery would verify. The endpoint in the record still names the real
  server, but with a hostname endpoint and a position in DNS or on the path, the client
  would then complete a handshake against the attacker's static key, which the attacker
  holds. Including the public key reduces this to an unresolvable reference: a failure,
  not an impersonation.
- HEM `msg` limit = 2048 B → max **11 peers** per if (13+32+128+11×160 = 1933 B). Enormous headroom (typically 2–3).

Calls (FW v1.7b, scope `keymgmt:use:<if_kid>` — the same scope already required for handshake ECDH):

```
POST /api/crypto/hmac/hash     {alg:"SHA2-256", kid:<if_kid>, ext_kid:<if_kid>, msg:b64(canonical)} → {mac}
POST /api/crypto/hmac/verify   {alg:"SHA2-256", kid:<if_kid>, ext_kid:<if_kid>, msg:b64(canonical), mac:…} → 200/406
```

Consequences:
- any change to any peer ⇒ re-MAC the if record (1 call, done by the provisioner),
- forgery requires the `use` scope on the if key ⇒ every attempt lands in the HEM audit log,
- startup verification = **one** `hmac/verify` call.

## 5. PSK (optional)

- API confirmed (FW v1.7b): `POST /api/crypto/cipher/wrap` / `/api/crypto/cipher/unwrap`, `alg:"AES256"`, indirect ECDH via `kid` + `ext_kid` as in §4, scope `keymgmt:use:<if_kid>`. Do not pass `iv` (deterministic NIST KW, default IV).
- **`ctx = "ENC-WG-PSK-v2|" + <peer KID hex>`** (14 + 32 = 46 B, inside the endpoint's 64 B
  limit). The prefix domain-separates this KEK from other wrap uses of the same key; the
  peer's identifier makes the wrap **positional**. NIST key wrap authenticates the key it
  carries but says nothing about where that ciphertext sits, so with one context per
  identity a wrap lifted from one peer's record unwraps perfectly well in another's, and
  only the configuration MAC would notice. With the peer in the context the two derive
  different KEKs and a moved wrap simply fails. One PSK shared by several peers is
  therefore wrapped once per peer: same plaintext, different ciphertext in each record.
- The MAC still has to cover TLV 0x16. Key wrap protects the ciphertext's **integrity**,
  not its **presence**: deleting the tag outright would silently drop the tunnel from
  PSK-protected to unprotected, which is exactly the guarantee the PSK exists to provide.
- Source of the PSK: either supplied by the infrastructure (`--psk -`, read from stdin — never from argv) or generated by the client (`--psk generate`, local CSPRNG). The device exposes no randomness endpoint, so there is no third option; the infrastructure-supplied path is the normal one, since the server side needs the same value anyway.
- Provisioning: `cipher/wrap` with kid=if, ext_kid=if (**self-ECDH** — same principle as §4; ECDH(if,peer) would expose the KEK to the server side / to a key importer), ctx as above. The 40 B raw result → TLV 0x16 in the peer's descr. The same PSK value is provisioned on the server side.
- Startup: `cipher/unwrap` (kid=if, ext_kid=if, ctx for that peer as above) → PSK into memory → UAPI → **zeroize** buffers once the device is configured. Every argument must match the wrap call — a differing `ctx` derives a different KEK.
- Fallback (when the infrastructure mandates a passphrase): `PSK = Argon2id(passphrase, salt=server_pubkey)` — no TLV 0x16, the user types it at startup. Deliberately reduces the PQ hedge to the passphrase's entropy.

## 6. Flows

### 6.1 Provisioning (`wg-hem provision`)

1. Authenticate to HEM (User session; PIN/touch/ExtAuth).
2. Create (or select) an if key of type curve25519 in HEM.
3. Import the server pubkey(s) → `POST /api/keymgmt/import`, `descr` = encoded `WG:pr:` record.
4. (opt.) PSK: generate, wrap, append TLV 0x16, update the peer's descr (`update a key`).
5. Build the `WG:if:` record (addr/mtu/dns/refs, MAC=zeros), compute the MAC (`hmac/hash`), write the descr.
6. Print the server-side provisioning data: if_pubkey, (opt.) PSK — one-shot, to stdout, never to a file.

### 6.2 Client startup (`wg-hem up`)

1. Authenticate to HEM. For PPA the address is known (`https://my.ence.do`, a name because the connection is TLS) — startup with literally no arguments; for EPA: URL from argument/env (still not a file) or discovery.
2. `key/search` prefix `WG:if:` → if key(s) + descr (search returns descr in results — confirmed in docs) → parse. **One record is used without asking; several are offered as a choice** (§2), and the choice comes before the `use` token that names it.
3. `key/search` prefix `WG:pr:` → all peer records with descr (paginated; the device returns 15 per page by default). Search does not return public keys, so each candidate needs `/api/keymgmt/get/<kid>` before its PEER_REF can be computed — one `keymgmt:get` token covers all of them, and the same token reads the interface public key. **2 search calls plus one pubkey read per candidate peer.**
4. Assemble the canonical message → `hmac/verify`. **Failure = hard stop, no fallback.**
5. **Peer selection: interactive.** The client asks the user which peer to connect to (list from descr: label/endpoint, PEER_REF order as the suggestion). With a single peer — no prompt.
6. (opt.) unwrap the PSK.
7. Resolve the endpoint (DNS before the tunnel; ENDPOINT_HOST requires a working resolver). Create the interface (wireguard-go in-process), configure via UAPI in memory: privkey = sentinel (HEM), the selected peer, AllowedIPs, keepalive, PSK.
8. Netlink: addr, mtu, routes from AllowedIPs, DNS (systemd-resolved via D-Bus / resolvconf).
   With AllowedIPs 0.0.0.0/0: **routing exception for the endpoint IP** via the default gw.
   **HEM reachability.** Every handshake is a live HEM call, so the HEM's own address
   deserves the same attention as the endpoint's. Resolve the host from the HEM URL and
   test it against the selected peer's AllowedIPs; after the interface is up, confirm with
   an unauthenticated `GET /api/system/version`.
   - HEM outside the tunnel (PPA on its USB link, or an EPA the AllowedIPs do not cover):
     nothing to do.
   - HEM inside the tunnel but still answering: **inform and continue.** Steady-state
     rekeying is unaffected: it starts at REKEY_AFTER_TIME (~120 s) while the previous
     session is still valid to REJECT_AFTER_TIME (180 s), so the HEM call travels over the
     live session — the 60 s overlap of §6.3. Nor does sending msg1 need the HEM at all;
     `precomputedStaticStatic` was computed when the peer was configured. Only consuming
     msg2 does.
     The narrow case worth mentioning: if a session lapses completely, because the peer was
     unreachable past that overlap, the client cannot finish a handshake — msg2 needs the
     HEM and the HEM is behind the dead tunnel. It is not a lock-out; restarting `wg-hem up`
     removes the routes, the HEM is reachable again, and the tunnel rebuilds.
   - HEM unreachable once the routes are in place: **refuse**, restore the previous routing
     and report. The first rekey would take the interface down anyway.
9. Runtime: handshake monitoring + connection-error handling (§6.4).

**With the graphical client the same nine steps are split across two processes.** Steps 1–5 — reaching the device, authenticating, listing identities and peers, and both choices — belong to the window, which ends by holding a `keymgmt:use:<if_kid>` token and nothing privileged. Steps 2–4 are then performed *again* by the privileged component, deliberately: it reads and verifies the tree it was named rather than trusting one it was handed, which is what lets it be a monitor rather than an executor. Steps 6–9 are the component's alone. See `docs/ARCHITECTURE-GUI.md`.

### 6.3 Handshake (wireguard-go fork)

- `ss` (static-static): precompute once per peer at configuration time — `POST /api/crypto/ecdh` (kid=if, pubkey=peer_pub).
- `se`/`es` (static × remote ephemeral): **live HEM call during the handshake** — initiator in ConsumeMessageResponse, responder in ConsumeMessageInitiation. `e_peer` is only known from the received packet — zero lead time, precompute impossible.
- Timing budget: REKEY_TIMEOUT = 5 s (msg1 retransmit), old session keys valid until REJECT_AFTER_TIME = 180 s with rekey every ~120 s ⇒ 60 s of overlap. PPA over USB/REST = tens of ms ⇒ ~100× margin. HTTP timeout to HEM: 3 s, 1 retry.
- The if private key is **never** in process memory.

### 6.4 Failover

WG has no native failover (cryptokey routing: active peers cannot share AllowedIPs). Active = 1 peer at a time.

**v1 (implement now): interactive.** No successful handshake > 15 s after initiation ⇒ report "peer X (endpoint) is not responding" and re-prompt for peer selection (marking which one failed). Action on selection: UAPI replace peer (pubkey+endpoint+PSK, same AllowedIPs), new `ss` precompute.

**v2 (later, behind `--auto-failover`): automatic.** PEER_REF order = priority, auto-switch to the next peer, optional return to #1 after a health check with hysteresis.

Note: concurrent peers with disjoint AllowedIPs (split routing) are legal and supported — the conflict applies only to identical ranges.

## 7. HEM endpoints used (v1.7b)

| Operation | Endpoint | When |
|---|---|---|
| Auth | `/api/auth/*` (User / ExtAuth) | startup, provisioning |
| Search | `/api/keymgmt/search` (prefix ≥ 6 B — `WG:if:`/`WG:pr:` = exactly 6; the `^` anchor goes on the base64, and `descr` may be sent with no token when the device is configured with `allow_keysearch`) | startup |
| Get pubkey / list | `/api/keymgmt/get/<kid>` (scope `keymgmt:get` covers every key — one token for all peers), `/api/keymgmt/list/<offset>/<limit>` | startup, provisioning |
| Import pubkey | `/api/keymgmt/import` (descr = TLV record) | provisioning |
| Update descr | `/api/keymgmt/update` | provisioning, rotations |
| Delete | `/api/keymgmt/delete/<kid>` | `wipe` |
| ECDH | `/api/crypto/ecdh` | ss precompute + se/es per handshake |
| HMAC | `/api/crypto/hmac/hash` + `/verify` (self-ECDH: kid + ext_kid, both `<if_kid>`) | provisioning / startup |
| Wrap/Unwrap | `/api/crypto/cipher/wrap` + `/unwrap` (AES256 NIST KW, self-ECDH, `ctx="ENC-WG-PSK-v2\|"`+peer KID) | PSK |

## 8. Security invariants

1. The private key never leaves HEM; the MAC key and the KEK (self-ECDH) never exist outside HEM.
2. Treat DESCR as public — the only secret in a descr is the **wrapped** PSK.
3. `hmac/verify` failure ⇒ refuse to start; no "degraded" mode.
4. AllowedIPs and the endpoint are security-critical (routing) — hence covered by the MAC; defensive TLV parser (length bounds, tag-duplication rules, unknown tag ⇒ hard error for `ver=0x01`).
5. Zeroization: PSK, ECDH shared secrets, UAPI buffers.
6. Versioning: `version` in the header + `ENC-WG-MAC-v1` in domain separation — a format change ⇒ bump both.
7. The format becomes part of a certified product (CC) — treat this spec as a controlled document.

## 9. Repo layout / tasks for Claude Code

```
encedo-wg-hsm/
├── cmd/wg-hem/            # CLI: provision | up | down | status | rotate-psk
├── internal/hem/          # HEM REST client (auth, keys, ecdh, hmac, wrap)
├── internal/descr/        # TLV codec + 128 B budget validation + round-trip tests
├── internal/mac/          # canonical message + hash/verify (sort by pubkey!)
├── internal/runtime/      # netlink, DNS, route exception, failover state machine
├── wireguard-go/          # fork: device → HEM ECDH (ss precompute, se/es live)
└── docs/                  # this spec
```

Implementation order:
1. `internal/descr` — codec + tests (golden vectors, parser fuzzing).
2. `internal/hem` — auth + ecdh + hmac + search (mock HEM for tests).
3. `internal/mac` — canonicalization + vector tests (incl. peer ordering, MAC zeroing).
4. `cmd provision` end-to-end against a real PPA.
5. Device fork (ss/se) — based on the existing encedo-wg-hsm.
6. `cmd up` + runtime + failover.
7. Integration tests: 1 if / 3 peers, kill the active endpoint, measure failover time.

## 10. CLI surface

Single binary, three modes. Provisioning flags map 1:1 to the admin data set (§6.1 inputs).

### 10.1 Provisioning

```
wg-hem provision \
  --address 10.0.0.7/32 \
  --peer pubkey=BASE64,endpoint=vpn.acme.com:51820,allowed-ips=0.0.0.0/0[,keepalive=25] \
  [--peer …]                        # repeatable; order = PEER_REF priority
  [--psk -]                         # infra-supplied PSK via stdin (NEVER via argv — visible in ps/history)
  [--dns 10.0.0.1] [--mtu 1380] \
  [--hem https://my.ence.do]        # default PPA; EPA via flag or env WG_HEM_URL
```

- No flags → interactive wizard (prompts follow the admin data table).
- Output: the client public key, base64, **clean on stdout** (pipeable to clipboard/Ansible); everything else on stderr.
- Data returned to infra: **public key only** (PSK is generated by infra and passed in; the client only wraps it — §5).

### 10.2 Runtime

```
wg-hem up [--identity KID|PREFIX]             # no flag: interactive prompt when the device holds >1 identity (§2)
          [--peer N | --peer-pubkey PREFIX]   # no flag: interactive peer prompt when >1 peer (§6.2 step 5)
wg-hem down
wg-hem status                                  # active peer, last handshake, transfer, hmac/verify result
```

### 10.3 Maintenance

```
wg-hem peer add|remove|update …    # same flags as --peer; every change triggers a tree re-MAC (automatic)
                                   # `peer update --psk -|generate|clear` is the PSK rotation: it rewraps
                                   # under the peer's own context (§5) and re-MACs, so no separate verb
wg-hem verify                      # standalone hmac/verify + parsed-config dump; the "has anyone touched the config" diagnostic
wg-hem wipe                        # remove all WG:* records from HEM (with confirmation)
```

### 10.4 Conventions

1. Secrets only via stdin (`-`), never argv or env.
2. stdout = machine-readable payload only; human output = stderr.
3. Distinct exit codes: auth failure / MAC verify failure / network failure / usage error.
4. v2: `wg-hem provision --web` — the same provisioner logic behind an embedded (go:embed) localhost form; the browser is UI only, all HEM calls go through the same Go code path. No standalone SPA talking to the HEM REST API directly (logic duplication in a CC-bound format, CORS/TLS against the device, secrets in browser context).
