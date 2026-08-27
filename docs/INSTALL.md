# Installing and setting up

Both clients are single static binaries and depend on no system libraries. This
page covers getting one onto a machine and configuring `wg-quick-encedo`, the
client that keeps a file. For `wg-hem`, which keeps no file at all, see
[USAGE.md](USAGE.md).

## Option A — download a pre-built binary

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

**Windows comes as a bundle.** `encedo-wg-windows-<arch>.zip` holds both clients,
the `wintun.dll` they need, and the licences of both — unpack it and everything
is in one directory, which is where the DLL has to be. Wintun is redistributed
unmodified and with its licence, as clause 3(d) of that licence provides for
software using only its documented API.

## Option B — build from source

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

## Setup — Linux

**1. Place the binary**

```bash
sudo cp wg-quick-encedo-linux-amd64 /usr/local/bin/wg-quick-encedo
sudo chmod +x /usr/local/bin/wg-quick-encedo
```

**2. Grant network capabilities** (allows running without sudo)

```bash
sudo setcap cap_net_admin=eip /usr/local/bin/wg-quick-encedo
```

This is granted per binary and is lost on every rebuild or reinstall — a client
that suddenly wants root again has usually just been replaced by a fresh copy.

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

## Setup — macOS

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

> The interface will be named `utun5` (or similar) — macOS assigns utun names
> automatically.

> **macOS has not been run against real hardware.** The platform code is there
> and is built and cross-checked on every push, but no tunnel on this platform
> has ever met a HEM. Treat it as untested.

---

## Setup — Windows

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

Copy `wg-quick-encedo-windows-amd64.exe` to `C:\WireGuard\wg-quick-encedo.exe`
(or any location in PATH).

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

For the graphical client and the privileged service behind it, which is how
Windows is meant to be used, see [WINDOWS.md](WINDOWS.md).

---

## HEM requirements

- Encedo EPA or PPA reachable over TLS 1.3
- Key of type `CURVE25519` with scope `keymgmt:use:<KID>` for the private key
- Optionally: peer public keys imported into HEM, scope `keymgmt:get` for the
  lookup token

`wg-hem` additionally uses `keymgmt:gen` and `keymgmt:imp` to write a
configuration, `keymgmt:upd` to store the records, `keymgmt:search` to find them
again, and `keymgmt:del` only to take back an identity key whose provisioning it
could not finish.

> One behaviour worth knowing before reading any error: a key id the device
> cannot resolve comes back as **HTTP 406**, not 404. The status describes
> existence, not permission, however much it reads like the latter.
