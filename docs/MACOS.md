# macOS: the plan, and the one decision it turns on

Written 2026-09-18, after Windows shipped and before any macOS work. Nothing
here has been run on a Mac against hardware. It is written now because the
expensive parts are decisions and waiting, not typing, and both can start before
anyone opens Xcode.

## What already exists, measured rather than assumed

The command-line client builds for `darwin/amd64` and `darwin/arm64` in
`build.sh`, and `internal/runtime/platform_darwin.go` implements the OS half:
`Up`, `Down`, `AddRoutes`, `SetMTU`, the default-gateway lookup and the host
routes that pin an endpoint outside the tunnel, plus `UAPIListen` and
`UAPIDial`. The window builds on macOS in CI today and is uploaded as
`encedo-wg-gui-macOS-ARM64`.

Two holes in that, and only two:

- **DNS is a stub.** `SetDNS` prints a warning and returns; `RevertDNS` does
  nothing. The comment says why: macOS wants a *network service* name and the
  client has a `utun` interface name, and mapping one to the other is not
  obvious.
- **There is no privileged component.** `cmd/wg-hem/service_other.go` is a
  deliberate no-op, because on Linux the packaging registers the service. There
  is no `packaging/macos`, no launchd job, no `.pkg`.

So the window has nothing to talk to, and runs its scripted stand-in. Nobody
should read a macOS window drawing "Connected" as a tunnel — the code says so in
`gui/main.go` for exactly this reason.

## The decision this all turns on

Two designs are written down in this repository and they are not the same.
`ARCHITECTURE-GUI.md` says the privileged component on macOS is a **system
extension** — `NEPacketTunnelProvider` in Swift with the Go core linked as a
`c-archive`. `MVP.md`, outside the repository, says a **launchd daemon** with a
socket that verifies its caller, the direct counterpart of the Windows service
and the Linux systemd unit. Whoever starts M5 has to pick one first, because
almost everything else follows from it.

### What a launchd daemon costs and buys

It reuses what is already built and tested twice. `internal/ipc` is transport
agnostic on purpose — "the same framing runs over a unix socket on Linux and a
named pipe on Windows without knowing which it is under" — so macOS is a third
transport of a shape that already exists. `platform_darwin.go` stays as the OS
half. The window needs nothing new.

It also removes two problems that `ARCHITECTURE-GUI.md` takes on knowingly, and
this is the part worth reading twice:

- **The heartbeat disappears.** That document's liveness rule is "no window, no
  tunnel", and it notes that on Linux and Windows the open channel *is* the
  signal while macOS is the exception needing a heartbeat — because an
  application sends a message to an extension and gets a reply rather than
  holding a connection. Over a unix socket it holds a connection, so macOS stops
  being the exception, and the App Nap problem that comes with the heartbeat
  stops existing.
- **The dead toggle disappears.** A system extension registers a VPN
  configuration, the system draws a switch for it, and switching it on starts an
  extension with no token; the document accepts a visibly broken control as UX
  debt. A daemon registers no configuration and the switch is never drawn.

What it costs: **the daemon runs as root.** Linux avoided root with
`AmbientCapabilities=CAP_NET_ADMIN` and macOS has no equivalent — creating a
`utun` and installing routes is root's work. That is a real reduction in
posture against the Linux service, and it should be stated in the documentation
rather than discovered. It also means no System Settings integration, no
on-demand VPN and no per-app routing, none of which this product offers today on
any platform.

### What a system extension costs and buys

It is what Apple's own tools are shaped around, it needs no root daemon, and it
leaves room for on-demand and per-app routing later. `ARCHITECTURE-GUI.md` is
right that the entitlement is self-serve rather than a gate.

It is also, in that document's own words, "a port, not a repackage": the system
hands the extension a `packetFlow` instead of a file descriptor, routes and DNS
are *declared* in `NEPacketTunnelNetworkSettings` rather than installed with
commands, and endpoint pinning becomes `excludedRoutes`. So
`platform_darwin.go` does not cross, the heartbeat has to be built, App Nap has
to be handled, and the work is Xcode, Swift, two entitlement sets, an app bundle
and an external build target for the Go archive.

### The recommendation

**Start with the launchd daemon.** It is the smaller piece of work by a wide
margin, it ships, and everything it produces — the `.pkg`, the signing, the
notarisation, the DNS work, the first run against real hardware — is needed by
the other design too and is not thrown away if the extension is built later.
The extension is then a replacement of the privileged half behind an unchanged
channel, which is the seam this architecture already has.

Reasons to overturn this: wanting the VPN to appear in System Settings, wanting
on-demand, or a refusal to ship a root daemon. All three are product decisions
rather than engineering ones, which is why this document recommends rather than
decides. Whichever is chosen, `ARCHITECTURE-GUI.md` needs amending so that the
repository stops holding two answers.

## Phases, in the order that de-risks the most per day

**Phase 0 — enrolment, today, in parallel with everything.** The Apple Developer
Program costs 99 USD a year, needs a D-U-N-S number for the company and takes
days to weeks. It blocks signing, notarisation and therefore any distribution,
and it is pure waiting. `MVP.md` has said to start it since 2026-08-26.

**Phase 1 — the CLI against real hardware, and it needs no Apple account.**
`platform_darwin.go` has never seen a HEM. Run `wg-hem provision`, `import`,
`up`, a ping through the tunnel, `status`, `down`, under `sudo`, from the
artifact CI already builds. Expect surprises in `utun` naming, in the route
table and in MTU: those three are where a platform half usually differs, and
finding them here costs an afternoon rather than a release.

**Phase 2 — DNS, which is the one genuinely unsolved piece of the OS half.**
Two candidates, and the choice should be made with a test rather than from
documentation: `networksetup -setdnsservers` against the active network
services, which is what `wg-quick` does on macOS and which touches settings the
user can see, or `scutil` writing a `State:/Network/Service/<id>/DNS` key, which
is what the official client does and which is invisible in the UI and
disappears when the daemon does. Split DNS has to be tested either way, and
teardown has to be tested by killing the daemon rather than by asking it to
stop.

**Phase 3 — the daemon.** A launchd job with a unix socket, the caller verified
the way Linux verifies it — `internal/ipc` already says identity arrives "in
whatever terms the platform gave — a uid on Linux, a SID on Windows", so macOS
needs its term and its check. `service_other.go` grows a darwin sibling, or the
packaging does the registering as it does on Linux. The window then gets its
`-live` path on macOS for the first time.

**Phase 4 — the `.pkg`.** The daemon, both binaries, the launchd plist and a
scripted uninstall, since a `.pkg` has no uninstaller of its own and this is the
platform where that is most often forgotten. The Windows lesson applies:
uninstalling is tested on the same day as installing, on a machine that has
never had it.

**Phase 5 — signing, hardened runtime, notarisation and stapling.** Developer ID
Application for the binaries, Developer ID Installer for the `.pkg`, hardened
runtime on both. Then `notarytool` uploads it to Apple, waits for a scan, and
`stapler` attaches the ticket. **Notarisation is not signing**: without the
ticket Gatekeeper says the developer cannot be verified, and it is the only step
in the whole pipeline that cannot be done offline.

## The signing decision, which is not the same as the Windows one

Windows signing was easy to accept because there is no key: Azure Artifact
Signing holds it, GitHub authenticates by OIDC and CI never sees anything worth
stealing. Developer ID is the opposite. The certificate has to be exported as a
`.p12` and put in a secret, so **a real private key lands in GitHub**.

In a product whose entire thesis is that a key never leaves a hardware module,
that deserves a deliberate decision rather than a default. The options, in
increasing order of comfort and effort: accept it with a scoped secret and
rotation; sign and notarise on a developer's machine and let CI produce only the
unsigned `.pkg`; or keep the certificate in a hardware token and drive
`notarytool` from a machine that holds it. Nothing decides this but the owner.

## What is still open

- Whether the `-systemextension` entitlement carries deployment restrictions
  (TN3134). Only matters if the extension design wins.
- Which architecture the test Mac is, since it decides whether the `.pkg` ships
  a universal binary or one per architecture.
- Whether the daemon's socket lives beside the Linux one in spirit — its own
  directory, owner-only — and what group, if any, macOS uses in place of the
  `wireguard` group the `.deb` creates.
- The trademark answer, which was asked for on 2026-09-17 and applies to an
  installer on any platform.
