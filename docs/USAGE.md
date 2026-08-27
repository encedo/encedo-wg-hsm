# Using the two clients

They differ in where the configuration lives, not in how the key is protected.
Installation is in [INSTALL.md](INSTALL.md).

## `wg-quick-encedo` — the file, without the key

All cryptographic keys are replaced with opaque HEM key identifiers (`HEM_KID`).
The config file contains no key material, which is what makes it safe to store in
git, a CMDB, or any backup system.

```ini
[Interface]
Address = 10.1.1.5/24
HEM_URL = https://my.ence.do                 # the Encedo HEM
HEM_KID = <my-private-key-id>              # my private key ID in HEM

[Peer]
HEM_KID = <peer-public-key-id>             # peer's public key ID in HEM
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.1.1.0/24
PersistentKeepalive = 25
```

- `PrivateKey` — **never present**
- `[Interface] HEM_KID` — identifies my private key in HEM
- `[Peer] HEM_KID` — identifies the peer's imported public key in HEM; ECDH is
  performed fully internally, neither key value passes through software
- `[Peer] PublicKey` — supported for standard WireGuard peers without HEM keys

> **Note:** Do not set `ListenPort` if the client is behind NAT — WireGuard will
> use a random port automatically. A fixed port requires inbound UDP to be
> reachable from the internet.

### Commands

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
- Auth method — press Enter for default **password** (`p`), or type `m` for
  mobile push

Just pressing Enter twice starts a standard 8h password session.

> **Note:** `wg show` does not display the interface public key — WireGuard
> derives it from the private key, which is intentionally zero in this setup. Use
> `wg-quick-encedo pubkey wg1` instead.

When peers use `HEM_KID`, two auth prompts appear with a single password entry:
1. `keymgmt:get` token — resolves peer public keys at startup (120s fixed)
2. `keymgmt:use:<KID>` token — used for all ECDH operations at runtime

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

> **Not yet exercised against real hardware.** Full-tunnel routing is the one
> path in `internal/runtime` that has never carried a live tunnel. Until it has,
> treat this section as designed rather than proven.

---

## `wg-hem` — no config file at all

The addresses, peers, routes, DNS and MTU live in the HEM beside the keys, under
a single MAC computed inside the device. Nothing is written to disk, and altering
the stored routing is detectable rather than merely unprofitable. Full
specification: [ENCEDO-WG-CONFIGFREE-SPEC.md](ENCEDO-WG-CONFIGFREE-SPEC.md).

### Start from a file you already have

If there is an ordinary WireGuard client configuration on the machine, `import`
is the shortest path in:

```bash
wg-hem import ~/Downloads/wg0.conf
```

It reads the addresses, DNS, MTU and peer, **discards the `PrivateKey`** — the
identity is generated inside the module instead — and prints the new public key
beside the address. Two consequences to be clear about with whoever runs the
server:

- **The tunnel will not come up until the server is told the new public key.**
  That is the one line that changes on the far side; the client's address does
  not, so `AllowedIPs` there stays as it is.
- **A `PresharedKey` in the file is refused, not carried.** One that has sat in a
  file is already out; provision with `-psk generate` and give the server the new
  one.

`wg-quick`'s own directives — `PostUp`, `PreUp`, `PostDown`, `PreDown`, `Table`,
`SaveConfig`, `FwMark` — are refused rather than ignored. This client runs no
scripts and does not drive `wg-quick`'s routing table handling, so a file that
relies on them does not mean the same thing here, and importing it quietly would
produce a tunnel that looks healthy with its `iptables` rule simply gone.

`-dry-run` prints the equivalent `provision` command and stops, so what an import
does is exactly what somebody could have typed.

### Or write a configuration directly

No file is produced; the client public key goes to stdout, everything else to
stderr, so it pipes.

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

### Bring the tunnel up

With several peers and no selection flag, it asks; a peer that does not answer
within 15 seconds is reported and another offered.

```bash
sudo wg-hem up                    # add --debug to trace every handshake ECDH
sudo wg-hem status                # state, live counters, and a fresh MAC check
sudo wg-hem down
```

### Inspect and maintain

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

The device is reached at `https://my.ence.do` unless `--hem` or `$WG_HEM_URL`
says otherwise, so a module at its default address needs no arguments at all.
That default is a name and not the address behind it: the connection is TLS, and
a certificate is issued for a name.

---

## Worked example, per platform

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

`install` replaces the binary, and with it the `cap_net_admin` capability granted
to the old copy — re-run `setcap` after every install, or the next `up` will ask
for root and look like a regression.

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
setup is covered in [INSTALL.md](INSTALL.md).
