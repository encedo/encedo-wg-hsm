# How it works

Where the key stays, what is patched to keep it there, and what the two clients
are made of. The graphical client and the privileged component behind it are a
separate document: [ARCHITECTURE-GUI.md](ARCHITECTURE-GUI.md).

## The problem

Standard WireGuard stores the private key in plaintext in
`/etc/wireguard/wg0.conf`. Anyone with root access — or read access to the config
file — can extract the private key, impersonate the device, and decrypt
previously captured traffic.

This is acceptable for many use cases, but not for:
- Servers handling sensitive workloads
- Devices deployed in physically insecure locations
- Environments with strict key custody requirements (compliance, military,
  critical infrastructure)

## The path a tunnel takes

```
┌─────────────────────────────────────────────────┐
│  wg-quick-encedo up wg1 /etc/wireguard/wg1.conf  │
└────────────────────────┬────────────────────────┘
                         │
           ┌─────────────▼─────────────┐
           │  1. Parse wg1.conf        │
           │     HEM_URL, HEM_KID,     │
           │     peer KIDs             │
           └─────────────┬─────────────┘
                         │
           ┌─────────────▼─────────────┐
           │  2. Encedo HEM            │
           │     Checkin (sync RTC)    │
           │     Auth (password/mobile)│
           │     GetPubKey(KID)        │
           └─────────────┬─────────────┘
                         │
           ┌─────────────▼─────────────┐
           │  3. Inject HSMSession     │
           │     into wireguard-go     │
           │     device package        │
           └─────────────┬─────────────┘
                         │
           ┌─────────────▼─────────────┐
           │  4. Start WireGuard       │
           │     TUN interface up      │
           │     UAPI listener active  │
           └─────────────┬─────────────┘
                         │
           ┌─────────────▼─────────────┐
           │  5. Runtime (every ~3min) │
           │     Handshake → HEM ECDH  │
           │     live, on demand       │
           └───────────────────────────┘
```

## WireGuard Noise protocol — the patched operations

WireGuard uses the Noise_IKpsk2 protocol. The static private key is required in
three places:

**1. `precomputedStaticStatic` (peer creation)**
```
standard: DH(myPrivateKey, peerStaticPublicKey)
patched:  HEM.ECDH(KID, peerStaticPublicKey)  ← same result, key stays in HEM
```

**2. `ConsumeMessageResponse` — we initiated, the peer answered (~3 min)**
```
standard: DH(myPrivateKey, peerEphemeralPublicKey)
patched:  HEM.ECDH(KID, peerEphemeralPublicKey)  ← live call, key stays in HEM
```

**3. `ConsumeMessageInitiation` — the peer initiated**
```
standard: DH(myPrivateKey, peerEphemeralPublicKey)
patched:  HEM.ECDH(KID, peerEphemeralPublicKey)  ← live call, key stays in HEM
```

Cases 2 and 3 are the same DH on opposite sides of the handshake, and neither can
be precomputed: the peer's ephemeral key is fresh in every handshake and arrives
in the packet itself. **The HEM must be reachable at all times.**

## Patched files in wireguard-go

| File | Change |
|------|--------|
| `device/hsm.go` | New — `HSMSession` struct, `hsmDH()` dispatcher |
| `device/peer.go` | `precomputedStaticStatic` via `hsmDH()` |
| `device/noise-protocol.go` | `ConsumeMessageResponse` + `ConsumeMessageInitiation` static DH via `hsmDH()` |
| `device/device.go` | `SetPrivateKey` — injects HEM public key, skips private key |

When `hsmSession == nil`, all patches fall through to standard wireguard-go
behaviour. Existing WireGuard interfaces are unaffected.

The three upstream files are changed by a patch applied at build time, not by
keeping edited copies of them in this repository — 49 added lines against a
pinned commit, so raising that pin stops the build if upstream has touched the
same code. [UPSTREAM.md](../UPSTREAM.md) explains the pin and how to move it.

## Lifecycle and failure handling

```
startup:    checkin → auth → get public key → resolve peer keys → plan routing
            → inject session → up → pin endpoints → routes → DNS → HEM probe
runtime:    every ~3 min: handshake → 2× HEM ECDH calls
on error:   ECDH retried 3× with 2s delay
on failure: interface brought down gracefully, pinned routes removed
on expiry:  token expires → interface shuts down cleanly
on Ctrl+C:  clean shutdown, interface removed
```

## Project structure

```
encedo-wg-hsm/
  build.sh                        # clone upstream, apply the patch, build every binary
  UPSTREAM.md                     # the wireguard-go relationship, and how to raise the pin
  TODO.md                         # what is left, and why each item is where it is
  hem-sdk-go/                     # git submodule -> github.com/encedo/hem-sdk-go
  _wireguard-go-encedo/           # our changes to wireguard-go, and nothing of theirs
                                  # leading _ keeps the go tool out: hsm.go references
                                  # upstream symbols absent from this directory
    device/hsm.go                 # new file — HSMSession + hsmDH dispatcher
    patches/
      0001-delegate-...patch      # the four call sites, as a diff against the pin
  docs/
    INSTALL.md                    # getting a binary onto a machine
    USAGE.md                      # both clients, command by command
    ARCHITECTURE.md               # this file
    ARCHITECTURE-GUI.md           # the window and the privileged component
    WINDOWS.md                    # the service, the pipe, and what each test settled
    ENCEDO-WG-CONFIGFREE-SPEC.md  # specification for the config-free client
    RELEASING.md                  # build, sign, package, in that order
  internal/
    descr/                        # TLV codec; size_default.go / size_descr64.go pick 128 or 64 B
    mac/                          # configuration MAC (self-ECDH, computed inside the HEM)
    config/                       # load and authenticate the whole stored tree
    session/                      # auth, scoped tokens, and the state file
    tunnel/                       # the tunnel itself: handshake wait, failover walk, UAPI
    runtime/                      # the OS half, shared by both clients:
                                  #   hsm.go       handshake ECDH, retry policy, --debug trace
                                  #   routing.go   endpoint pinning for full-tunnel
                                  #   uapi.go      talks to a running interface
                                  #   platform_{linux,darwin,windows}.go
    version/                      # the release number both commands report
  cmd/
    wg-quick-encedo/              # config-file client: up / down / pubkey
    wg-hem/                       # config-free client: provision, import, up, down, status,
                                  # verify, peer, wipe — plus failover and state file
  gui/                            # the window; a separate Go module, because it needs cgo
  packaging/                      # .deb, MSI, the service and the polkit rule
  .github/workflows/              # ci.yml both record sizes; gui.yml the window and packages
```
