# Windows: what is left, in the order it has to happen

Linux was accepted as the reference implementation on 2026-08-14. This is the
plan for bringing Windows to the same place, written against what that reference
proves rather than against what Windows might need.

The short version: the architecture ports unchanged, four things are Unix-shaped,
and one of the four blocks the other three.

## What is already true

Measured rather than assumed, on 2026-08-13 and 2026-08-14.

The command-line client **runs a tunnel on Windows today**, elevated. The adapter
is created, the first ECDH answers in 232 ms, traffic moves. So the device path,
the configuration path and the Noise handshake all work there; nothing in the
cryptography or the protocol is waiting on this document.

It runs **blind**. `ipc.UAPIListen` fails with *"this security ID may not be
assigned as the owner of this object"*, because upstream creates that pipe with
`O:SY` and assigning SYSTEM as an owner is not something an administrator may do.
The account it was written for is LocalSystem. Everything answered from that pipe
is therefore off: `wg show`, `wg-hem status` and failover.

Both Windows architectures **cross-build clean** from the Linux tree —
`GOOS=windows GOARCH=amd64` and `GOARCH=arm64`, whole module, no errors — and
`build.sh` already lists both in `PLATFORMS`. `golang.org/x/sys` is already a
dependency, so `windows/svc` costs no new module.

`internal/paths/paths_windows.go` already settles where things live:
`%ProgramData%\WireGuard`, with a note that the UAPI is a pipe and does not live
there. `internal/daemon/peercred_other.go` already states what this document
plans, and refuses rather than guessing until it exists.

## The four Unix-shaped things

1. **Privilege.** `CAP_NET_ADMIN`, `setcap` and a `wireguard` group. Windows has
   no equivalent and does not need one: it is LocalSystem, which upstream's
   `O:SY` already forces.
2. **The channel.** `net.Listen("unix")` in `cmd/wg-hem/daemon.go`,
   `net.Dial("unix")` in `gui/live.go`, and a `defaultSocket()` returning a Unix
   path.
3. **Who may drive it.** `peerUID` via `SO_PEERCRED`.
4. **Lifecycle and packaging.** A systemd unit and a `.deb`.

## Phase 0 — re-establish the ground before building on it

Cheap, and first, because four reports in one afternoon on 2026-08-12 were all
stale binaries. On each of the three machines: record the architecture, build
both halves from one clean tree with the `scripts/version.sh` stamp, and confirm
the failure is still the one described above — adapter yes, ECDH yes, UAPIListen
refused with the security-ID message. A different message is a different problem
and this plan does not cover it.

The three machines and what each is for:

| Machine | Role |
|---|---|
| Windows on ARM, on this host | The fast loop. Same box as the development tree, so a build can be tested in seconds — and it can run the whole thing, since Wintun ships an ARM64 build (see phase 5). |
| Windows 10, second machine | The oldest API surface. Anything that compiles but needs a version newer than this one fails here and only here. |
| Windows 11, third machine | The target most users are on. |

## Phase 1 — the service, which unblocks everything else

A `wg-hem service` verb running under the Service Control Manager as
LocalSystem, mirroring what `encedo-wg.service` does on Linux.

`golang.org/x/sys/windows/svc` is the whole of the mechanism and is already
available. The verbs follow the Linux package's postinst rather than inventing a
vocabulary: install, uninstall, and the run mode SCM itself invokes.

**Done when** the service starts, `UAPIListen` returns a listener instead of the
security-ID error, and `wg show` — run elevated — reports the interface the
service created. That single test settles `wg-hem status` and failover with it,
since all three read the same pipe.

Nothing else in this plan can be tested before this works, which is why it is
first even though the channel is the more interesting problem.

## Phase 2 — the channel

A named pipe in place of the Unix socket, behind a seam so that neither
`daemon.go` nor `live.go` names a transport.

**Not AF_UNIX, though it would work.** Go builds Unix-socket support for Windows
— `net/unixsock_posix.go` carries `//go:build unix || js || wasip1 || windows` —
and Windows 10 has had `AF_UNIX` since 1803, so the existing code would compile
and run there with no change at all. It is refused anyway, for the reason phase 3
exists: `AF_UNIX` on Windows has no `SO_PEERCRED`, so the socket could say who
may connect and never who did. A pipe answers both. Taking the easy port here
would mean discovering in phase 3 that the channel has to be rewritten.

The pipe's DACL is set at creation, which is the counterpart of the Linux
socket's `0660` and group — and better in one respect: it is not a file on disk
that something else can chmod between creation and first use.

## Phase 3 — who may drive it

`peerUID` returns a `uint32` today because a Unix uid is one. A Windows principal
is a SID, so the interface changes to something opaque that both platforms can
answer, and the daemon compares principals rather than numbers.

The mechanism is `ImpersonateNamedPipeClient`, then the thread token, then the
token's user SID. **Not `GetNamedPipeClientProcessId`**: Project Zero published a
technique for spoofing the client PID of a named pipe, so a PID read off the pipe
is not an identity. It is also not in `x/sys/windows` yet (golang/go#70086),
which would have meant a direct kernel32 call for an answer that should not be
trusted anyway.

## Phase 4 — the window

Fyne needs cgo, so the window is built on each target rather than cross-compiled;
`windows/arm64` with cgo is the one build in this plan whose toolchain has not
been proven and should be tried early rather than assumed.

Three things the Linux window learned that have Windows counterparts, none of
them ported for free:

- The icon and the taskbar. On Linux this was `StartupWMClass` in a desktop
  entry; on Windows it is the icon embedded in the executable and an
  AppUserModelID for grouping.
- The tray. `trayAvailable()` asks a D-Bus question that has no meaning here.
  Windows always has a notification area, so the answer is a constant — but the
  code should say that rather than fall through a Linux-shaped check.
- Close, minimise and the session. "The GUI is the session" holds; what a window
  manager does with the close button does not change across platforms, but the
  minimise asymmetry recorded in `TODO.md` is a Fyne limit and will be present
  here too.

## Phase 5 — packaging

An installer that places both binaries, registers and starts the service, and
ships Wintun.

**Wintun covers every architecture here**, which was the one thing that could
have reduced the ARM machine to running only the window. Checked by PE machine
type rather than by the directory a file sits in, from Wintun 0.14.1 — the last
release, October 2021, signed by WireGuard LLC:

| | Machine type | SHA-256 |
|---|---|---|
| `amd64/wintun.dll` | PE32+ x86-64, min OS 6.00 | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| `arm64/wintun.dll` | PE32+ ARM64, min OS 6.02 | `f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80` |

`arm` (ARMv7) and `x86` are in the same distribution and are not targets here.
The copy this work is using is at
`/mnt/hgfs/Nextcloud/develop/tmp/wintun-0.14.1/` on the development host. It is
deliberately not committed: it is a signed third-party binary, and an installer
that fetches and verifies it is honest in a way a copy in a Git tree is not. The
hashes above are what the installer should check against.

## What this plan does not do

It does not touch the protocol, the record format, or anything the device sees. A
Windows client and a Linux client talk to the same appliance and read the same
configuration tree, and nothing here changes that. If something in these phases
seems to require a protocol change, that is a sign the phase has been
misunderstood.

It also does not revisit macOS, which is a different shape again — the tunnel
belongs in a system extension and the channel to it is authenticated by code
signature, so phases 2 and 3 do not transfer.
