# wg-hsm

WireGuard userspace implementation with hardware-backed private key protection via **Encedo HEM** — Hardware Encryption Module (EPA/PPA).

The WireGuard private key **never leaves the HEM**. All Curve25519 operations requiring the static private key are delegated to the Encedo HEM at runtime.

The configuration file contains **zero cryptographic material** — only opaque HEM key identifiers. It is safe to store in git, CMDB, or any backup system.

---

## The Problem

Standard WireGuard stores the private key in plaintext in `/etc/wireguard/wg0.conf`. Anyone with root access — or read access to the config file — can extract the private key, impersonate the device, and decrypt previously captured traffic.

This is acceptable for many use cases, but not for:
- Servers handling sensitive workloads
- Devices deployed in physically insecure locations
- Environments with strict key custody requirements (compliance, military, critical infrastructure)

---

## Installation

### Option A — Download pre-built binary

Download the binary for your platform from the `dist/` directory:

| File | Platform |
|---|---|
| `wg-quick-encedo-linux-amd64` | Linux x86\_64 |
| `wg-quick-encedo-linux-arm64` | Linux ARM64 (Raspberry Pi, Graviton) |
| `wg-quick-encedo-darwin-amd64` | macOS Intel |
| `wg-quick-encedo-darwin-arm64` | macOS Apple Silicon (M1/M2/M3) |
| `wg-quick-encedo-windows-amd64.exe` | Windows x86\_64 |
| `wg-quick-encedo-windows-arm64.exe` | Windows ARM64 |

### Option B — Build from source

**Requirements:** Go 1.26+, git

```bash
git clone --recurse-submodules https://github.com/encedo/encedo-wg-hsm
cd wg-hsm
bash build.sh
```

The HEM SDK lives in its own repository and is wired in as the `hem-sdk-go`
submodule — `--recurse-submodules` is required, or `git submodule update --init`
in an existing clone. The build resolves the module from the checked-out
submodule, not from the module proxy.

`build.sh` clones the upstream wireguard-go at the pinned commit, overlays the Encedo patches, and builds all 6 binaries into `dist/`.

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

**1. Install Wintun driver**

Download and run the WireGuard installer from [wireguard.com](https://www.wireguard.com/install/) — this installs the Wintun driver. The WireGuard GUI app itself is not needed.

**2. Place the binary**

Copy `wg-quick-encedo-windows-amd64.exe` to `C:\WireGuard\wg-quick-encedo.exe` (or any location in PATH).

**3. Create config** — same format as Linux, save to `C:\WireGuard\wg1.conf`

**4. Start** (run PowerShell as Administrator)

```powershell
C:\WireGuard\wg-quick-encedo.exe up wg1 C:\WireGuard\wg1.conf
```

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

---

## Project structure

```
wg-hsm/
  build.sh                        # clone wireguard-go + overlay patches + build all binaries
  go.mod
  dist/                           # pre-built binaries
  hem-sdk-go/                     # git submodule -> github.com/encedo/hem-sdk-go
  _wireguard-go-encedo/           # ONLY our changes to wireguard-go (4 files)
                                  # leading _ keeps the go tool out: these files
                                  # only compile once overlaid on upstream
    device/
      hsm.go                      # new — HSMSession + hsmDH
      device.go                   # patched — SetPrivateKey injects HEM public key
      peer.go                     # patched — precomputedStaticStatic via hsmDH
      noise-protocol.go           # patched — ConsumeMessageResponse via hsmDH
  docs/
    ENCEDO-WG-CONFIGFREE-SPEC.md  # spec for the config-free client (wg-hem)
  internal/
    descr/                        # TLV codec for the 128 B descr records
    mac/                          # configuration MAC (self-ECDH, computed in HEM)
  cmd/
    wg-quick-encedo/
      main.go                     # CLI: up / down / pubkey
      config.go                   # config parser
      platform_linux.go           # Linux: netlink, resolvectl, UAPI socket
      platform_darwin.go          # macOS: ifconfig, route, utun
      platform_windows.go         # Windows: netsh, Wintun named pipe
```

> `wireguard-go/` is not stored in the repository — `build.sh` clones it at build time.
