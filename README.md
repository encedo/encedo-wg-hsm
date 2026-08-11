# wg-hsm

[![CI](https://github.com/encedo/encedo-wg-hsm/actions/workflows/ci.yml/badge.svg)](https://github.com/encedo/encedo-wg-hsm/actions/workflows/ci.yml)

**Version 0.9.1**

WireGuard userspace implementation with hardware-backed private key protection via **Encedo HEM** — Hardware Encryption Module (EPA/PPA).

The WireGuard private key **never leaves the HEM**. All Curve25519 operations requiring the static private key are delegated to the Encedo HEM at runtime.

The configuration file contains **zero cryptographic material** — only opaque HEM key identifiers. It is safe to store in git, CMDB, or any backup system.

## Two clients

They differ in where the configuration lives, not in how the key is protected.

| | `wg-quick-encedo` | `wg-hem` |
|---|---|---|
| Configuration | `wg1.conf`, keys replaced by HEM key ids | in the HEM, under a MAC computed inside the device |
| On disk | one file | nothing |
| Peer selection | the config file | interactive failover across stored peers |
| Tampering with routes | possible, undetected | detectable — the MAC covers addresses, routes and DNS |

`wg-quick-encedo` is the smaller step from a standard WireGuard deployment: the
file you already have, with `PrivateKey` gone. `wg-hem` removes the file. Both
share the same handshake path and the same failure behaviour.

Both have been tested against a stock kernel WireGuard server — the far end runs
unmodified `wireguard-tools` from the distribution and needs to know nothing
about any of this.

---

## The Problem

Standard WireGuard stores the private key in plaintext in `/etc/wireguard/wg0.conf`. Anyone with root access — or read access to the config file — can extract the private key, impersonate the device, and decrypt previously captured traffic.

This is acceptable for many use cases, but not for:
- Servers handling sensitive workloads
- Devices deployed in physically insecure locations
- Environments with strict key custody requirements (compliance, military, critical infrastructure)

---

## Installation

### Option A — Download a pre-built binary

From the [releases page](https://github.com/encedo/encedo-wg-hsm/releases). Each
release carries both clients for six platforms:

| Suffix | Platform |
|---|---|
| `-linux-amd64` | Linux x86\_64 |
| `-linux-arm64` | Linux ARM64 (Raspberry Pi, Graviton) |
| `-darwin-amd64` | macOS Intel |
| `-darwin-arm64` | macOS Apple Silicon |
| `-windows-amd64.exe` | Windows x86\_64 |
| `-windows-arm64.exe` | Windows ARM64 |

**Pick the right record size.** Binaries with a `-descr64` suffix target firmware
whose `descr` field is 64 bytes rather than 128. The length is part of what the
configuration MAC covers, so a tree written by one build cannot be verified by
the other — this is not a compatibility shim but two incompatible dialects. If
unsure, run `wg-hem version`, which reports both the release and the size it was
built for.

All binaries are statically linked and depend on no system libraries.

**Windows comes as a bundle.** `encedo-wg-windows-<arch>.zip` holds both clients,
the `wintun.dll` they need, and the licences of both — unpack it and everything
is in one directory, which is where the DLL has to be. Wintun is redistributed
unmodified and with its licence, as clause 3(d) of that licence provides for
software using only its documented API.

### Option B — Build from source

**Requirements:** Go 1.26+, git

```bash
git clone --recurse-submodules https://github.com/encedo/encedo-wg-hsm
cd encedo-wg-hsm
bash build.sh                       # 128-byte records
WG_HEM_DESCR=64 bash build.sh       # 64-byte records, suffixed -descr64
```

The HEM SDK lives in its own repository and is wired in as the `hem-sdk-go`
submodule — `--recurse-submodules` is required, or `git submodule update --init`
in an existing clone. The build resolves the module from the checked-out
submodule, not from the module proxy.

`build.sh` clones the upstream wireguard-go at the pinned commit, overlays the
Encedo patches, and builds every binary into `dist/`, stamping the release number
and the commit it came from.

---

## Setup

### Linux

**1. Place the binary**

```bash
sudo cp wg-quick-encedo-linux-amd64 /usr/local/bin/wg-quick-encedo
sudo chmod +x /usr/local/bin/wg-quick-encedo
```

**2. Grant network capabilities** (allows running without sudo)

```bash
sudo setcap cap_net_admin=eip /usr/local/bin/wg-quick-encedo
```

**3. Create UAPI socket directory**

```bash
sudo mkdir -p /var/run/wireguard
sudo chmod 777 /var/run/wireguard
```

To persist across reboots, create `/etc/tmpfiles.d/wireguard.conf`:

```
d /var/run/wireguard 0777 root root -
```

**4. Create config file**

```bash
sudo mkdir -p /etc/wireguard
sudo nano /etc/wireguard/wg1.conf
```

```ini
[Interface]
Address = 10.1.1.5/24
HEM_URL = https://my.ence.do
HEM_KID = <your-private-key-kid>

[Peer]
HEM_KID = <peer-public-key-kid>
Endpoint = <server-ip>:51820
AllowedIPs = 10.1.1.0/24
PersistentKeepalive = 25
```

**5. Start the interface**

```bash
wg-quick-encedo up wg1 /etc/wireguard/wg1.conf
```

---

### macOS

**1. Place the binary**

```bash
sudo cp wg-quick-encedo-darwin-arm64 /usr/local/bin/wg-quick-encedo
sudo chmod +x /usr/local/bin/wg-quick-encedo
```

**2. Create config** — same format as Linux, save to `/etc/wireguard/wg1.conf`

**3. Start** (requires sudo on macOS — no setcap equivalent)

```bash
sudo wg-quick-encedo up wg1 /etc/wireguard/wg1.conf
```

> The interface will be named `utun5` (or similar) — macOS assigns utun names automatically.

---

### Windows

**1. Unpack the bundle**

`encedo-wg-windows-amd64.zip` from the releases page already contains both
clients and `wintun.dll`. Extract it to `C:\WireGuard` and skip to step 3 —
nothing else is needed.

The tunnel device is created through `wintun.dll`, which is loaded by name at
runtime and found beside the executable, so the three files have to stay
together. If you would rather supply it yourself, take it from
[wintun.net](https://www.wintun.net/) with the architecture matching the
executable, or run the WireGuard installer from
[wireguard.com](https://www.wireguard.com/install/), which registers it
system-wide; the GUI application itself is not needed.

**2. Place the binary** (only if you did not use the bundle)

Copy `wg-quick-encedo-windows-amd64.exe` to `C:\WireGuard\wg-quick-encedo.exe` (or any location in PATH).

**3. Create config** — same format as Linux, save to `C:\WireGuard\wg1.conf`

**4. Start** (run PowerShell as Administrator)

```powershell
C:\WireGuard\wg-quick-encedo.exe up wg1 C:\WireGuard\wg1.conf
```

Administrator is required, not merely convenient: creating the adapter and
opening the UAPI pipe under `\\.\pipe\ProtectedPrefix\Administrators\WireGuard\`
both need it. Runtime files — the interface public key, and `wg-hem`'s state
file — go to `%ProgramData%\WireGuard`, which is where `/var/run/wireguard`
means on this platform.

> **Only Linux has been tested end to end.** The macOS and Windows binaries are
> built and cross-checked on every push, and the platform code is there, but
> neither has been run against a real tunnel. Treat them as untested.

---

## Config format

All cryptographic keys are replaced with opaque HEM key identifiers (`HEM_KID`). The config file contains no key material.

> A second client, `wg-hem`, removes the file entirely: the addresses, peers, routes and DNS
> live in the HEM alongside the keys, under a MAC computed inside the device, so tampering with
> the routing is detectable rather than merely unprofitable. `wg-hem provision` writes a
> configuration, `wg-hem up` runs from it with interactive failover, and `down` and
> `status` manage it. See
> [docs/ENCEDO-WG-CONFIGFREE-SPEC.md](docs/ENCEDO-WG-CONFIGFREE-SPEC.md).

```ini
[Interface]
Address = 10.1.1.5/24
HEM_URL = https://my.ence.do                 # Encedo EPA or PPA endpoint
HEM_KID = <my-private-key-id>              # my private key ID in HEM

[Peer]
HEM_KID = <peer-public-key-id>             # peer's public key ID in HEM
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.1.1.0/24
PersistentKeepalive = 25
```

- `PrivateKey` — **never present**
- `[Interface] HEM_KID` — identifies my private key in HEM
- `[Peer] HEM_KID` — identifies the peer's imported public key in HEM; ECDH is performed fully internally, neither key value passes through software
- `[Peer] PublicKey` — supported for standard WireGuard peers without HEM keys

> **Note:** Do not set `ListenPort` if the client is behind NAT — WireGuard will use a random port automatically. A fixed port requires inbound UDP to be reachable from the internet.

### Full tunnel — `AllowedIPs = 0.0.0.0/0`

A tunnel carries its own transport, so a default route on the interface would
route the UDP to `Endpoint` into the tunnel that UDP is supposed to carry. Before
installing the tunnel's routes, `wg-quick-encedo` resolves every endpoint and
pins the addresses that `AllowedIPs` would capture to the gateway that was
default beforehand — a `/32` beats a `/0`, so the endpoint keeps its physical
path. The pins are removed when the interface goes down.

`HEM_URL` gets the same test but not the same treatment. Routing HEM traffic
through the tunnel can be deliberate, and it works: rekeying begins around 120 s
while the previous session is valid to 180 s, so the ECDH call travels over the
live session. When the HEM falls inside `AllowedIPs`, the client says so and
continues; if the HEM stops answering once the routes are in, the interface is
refused and the routing table put back, because the first rekey would take it
down anyway. Names are resolved before the interface exists — afterwards the
resolver may be behind the tunnel that the answer is needed to build.

---

## Usage

```bash
# Start interface
wg-quick-encedo up wg1 /etc/wireguard/wg1.conf

# Stop interface
wg-quick-encedo down wg1

# Show interface public key (while interface is running)
wg-quick-encedo pubkey wg1

# Monitor traffic and handshakes (standard WireGuard tools work unchanged)
wg show wg1
```

On startup you will be prompted for:
- Session duration in hours — press Enter for default **8h**
- Auth method — press Enter for default **password** (`p`), or type `m` for mobile push

Just pressing Enter twice starts a standard 8h password session.

> **Note:** `wg show` does not display the interface public key — WireGuard derives it from the private key, which is intentionally zero in this setup. Use `wg-quick-encedo pubkey wg1` instead.

When peers use `HEM_KID`, two auth prompts appear with a single password entry:
1. `keymgmt:get` token — resolves peer public keys at startup (120s fixed)
2. `keymgmt:use:<KID>` token — used for all ECDH operations at runtime

---

## `wg-hem` — no config file at all

The addresses, peers, routes, DNS and MTU live in the HEM beside the keys, under
a single MAC computed inside the device. Nothing is written to disk, and altering
the stored routing is detectable rather than merely unprofitable. Full
specification: [docs/ENCEDO-WG-CONFIGFREE-SPEC.md](docs/ENCEDO-WG-CONFIGFREE-SPEC.md).

**Write a configuration into the device.** No file is produced; the client public
key goes to stdout, everything else to stderr, so it pipes.

```bash
wg-hem provision \
  --address 10.99.0.7/32 \
  --peer 'pubkey=<SERVER_PUBKEY>,endpoint=vpn.example.com:51820,allowed-ips=10.99.0.0/24,keepalive=25,label=hq' \
  --mtu 1420
```

Repeat `--peer` for failover candidates; the order is the priority. A pre-shared
key comes from the infrastructure over stdin (`--psk -`) or is generated locally
(`--psk generate`), never from the command line, where it would sit in the
process list. Hand the printed public key to whoever runs the other end — the far
side sees an ordinary WireGuard peer.

If provisioning cannot finish, it removes the identity key it created rather than
leaving a key no record names and `wipe` cannot find.

**Bring the tunnel up.** With several peers and no selection flag, it asks; a peer
that does not answer within 15 seconds is reported and another offered.

```bash
sudo wg-hem up                    # add --debug to trace every handshake ECDH
sudo wg-hem status                # state, live counters, and a fresh MAC check
sudo wg-hem down
```

**Inspect and maintain.**

```bash
wg-hem verify                     # re-check the MAC and print the configuration
wg-hem peer add|remove|update     # re-authenticates the whole tree
wg-hem wipe                       # remove the WG:* records (typed confirmation)
wg-hem version                    # release, and the record size it was built for
```

`--debug` prints one line per ECDH: which of the two Diffie-Hellmans it is, how
long the device took, and the shared secret as its first and last four bytes.
That is enough to watch the tunnel rekey — roughly every two minutes, two calls
each — without putting key material in a log destined for a bug report.

The device is reached at `https://192.168.7.1` unless `--hem` or `$WG_HEM_URL`
says otherwise, so a PPA on its USB link needs no arguments at all.

### Worked example, per platform

The same tunnel on each. `provision` runs once and needs no privileges — it
touches neither interfaces nor disk; everything after it does.

**Linux**

```bash
sudo install -m755 wg-hem-linux-amd64 /usr/local/bin/wg-hem

wg-hem provision \
  --address 10.99.0.7/32 \
  --peer 'pubkey=<SERVER_PUBKEY>,endpoint=vpn.example.com:51820,allowed-ips=10.99.0.0/24,keepalive=25,label=hq' \
  --mtu 1420
# stdout: the client public key — hand it to whoever runs the server

sudo wg-hem up                    # holds the terminal; --debug traces each ECDH
sudo wg-hem status                # from a second terminal
sudo wg-hem down
```

**macOS**

```bash
sudo install -m755 wg-hem-darwin-arm64 /usr/local/bin/wg-hem

wg-hem provision --address 10.99.0.7/32 --peer 'pubkey=…,endpoint=…,allowed-ips=…'

sudo wg-hem up
#   Interface utun5 is up.        <- macOS names it, not you
sudo wg-hem status               # finds utun5 on its own
sudo wg-hem down
```

Two differences worth knowing before the first run. `--interface wg0` is a
request macOS does not grant: the kernel assigns `utunN`, and the state file is
written under that name. `down` and `status` therefore look for the interface
that is actually running when the name was left at its default, so the commands
above need no `--interface`. Pass one and it is used exactly as given; with
several tunnels up and no name, they refuse and list what is running rather than
guess. And setting DNS is a no-op here with a warning — the tunnel carries
traffic, but `--dns` from the stored configuration is not applied.

**Windows** — PowerShell as Administrator, `wintun.dll` beside the executable:

```powershell
cd C:\WireGuard

.\wg-hem.exe provision `
  --address 10.99.0.7/32 `
  --peer 'pubkey=<SERVER_PUBKEY>,endpoint=vpn.example.com:51820,allowed-ips=10.99.0.0/24,keepalive=25,label=hq'

.\wg-hem.exe up
.\wg-hem.exe status
.\wg-hem.exe down
```

The interface keeps the name it is given, so no `--interface` juggling. Runtime
files land in `%ProgramData%\WireGuard`.

For `wg-quick-encedo` the per-platform differences are the same ones, and its
setup is covered under [Setup](#setup) above.

---

## Architecture

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

---

## How It Works

### WireGuard Noise Protocol — patched operations

WireGuard uses the Noise_IKpsk2 protocol. The static private key is required in three places:

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
in the packet itself. The HEM must be reachable at all times.

### Patched files in wireguard-go

| File | Change |
|------|--------|
| `device/hsm.go` | New — `HSMSession` struct, `hsmDH()` dispatcher |
| `device/peer.go` | `precomputedStaticStatic` via `hsmDH()` |
| `device/noise-protocol.go` | `ConsumeMessageResponse` + `ConsumeMessageInitiation` static DH via `hsmDH()` |
| `device/device.go` | `SetPrivateKey` — injects HEM public key, skips private key |

When `hsmSession == nil`, all patches fall through to standard wireguard-go behaviour. Existing WireGuard interfaces are unaffected.

The three upstream files are changed by a patch applied at build time, not by
keeping edited copies of them in this repository — 49 added lines against a
pinned commit, so raising that pin stops the build if upstream has touched the
same code. [UPSTREAM.md](UPSTREAM.md) explains the pin and how to move it.

---

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

---

## HEM requirements

- Encedo EPA or PPA reachable over TLS 1.3
- Key of type `CURVE25519` with scope `keymgmt:use:<KID>` for the private key
- Optionally: peer public keys imported into HEM, scope `keymgmt:get` for lookup token

`wg-hem` additionally uses `keymgmt:gen` and `keymgmt:imp` to write a
configuration, `keymgmt:upd` to store the records, `keymgmt:search` to find them
again, and `keymgmt:del` only to take back an identity key whose provisioning it
could not finish.

> One behaviour worth knowing before reading any error: a key id the device
> cannot resolve comes back as **HTTP 406**, not 404. The status describes
> existence, not permission, however much it reads like the latter.

---

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
    ENCEDO-WG-CONFIGFREE-SPEC.md  # specification for the config-free client
  internal/
    descr/                        # TLV codec; size_default.go / size_descr64.go pick 128 or 64 B
    mac/                          # configuration MAC (self-ECDH, computed inside the HEM)
    config/                       # load and authenticate the whole stored tree
    runtime/                      # the OS half, shared by both clients:
                                  #   hsm.go       handshake ECDH, retry policy, --debug trace
                                  #   routing.go   endpoint pinning for full-tunnel
                                  #   uapi.go      talks to a running interface
                                  #   platform_{linux,darwin,windows}.go
    version/                      # the release number both commands report
  cmd/
    wg-quick-encedo/              # config-file client: up / down / pubkey
    wg-hem/                       # config-free client: provision, up, down, status,
                                  # verify, peer, wipe — plus failover and state file
  .github/workflows/ci.yml        # both record sizes, on every push
```

---

## Releasing

CI builds and verifies every push, and publishes nothing. The Windows binaries
are signed on a hardware token, which cannot be given to a runner, so releases
are assembled by hand and the tag goes on after the signing rather than before.

The order matters more than it looks:

```bash
./build.sh                      # 1. both variants
WG_HEM_DESCR=64 ./build.sh

#  2. sign dist/wg-hem-windows-*.exe and dist/wg-quick-encedo-windows-*.exe
#     Do NOT sign wintun.dll — see package-windows.sh for why.

./package-windows.sh            # 3. bundle, AFTER signing
WG_HEM_DESCR=64 ./package-windows.sh

sha256sum dist/*.zip dist/wg-* > dist/SHA256SUMS

git tag -a v0.9.1 -m "0.9.1"    # 4. tag the commit that was built
git push origin v0.9.1
#  5. create the release and upload dist/ by hand
```

Packaging before signing is the mistake worth guarding against: it succeeds, and
produces archives whose executables are unsigned, which nothing downstream will
notice until a user meets SmartScreen. A `.zip` carries no signature of its own,
so the checksums are what covers the archive.

---

> `wireguard-go/` and `dist/` are not stored in the repository. `build.sh` produces
> both: it clones upstream at the pinned commit and applies the patch, rather than
> keeping copies of upstream's files. See [UPSTREAM.md](UPSTREAM.md) — that choice
> is what makes a version bump fail loudly instead of silently discarding upstream
> changes to the handshake.
