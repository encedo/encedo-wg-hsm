# Windows: done, and how it got there

**It works, 2026-08-15.** An unprivileged window, a service as LocalSystem, a
named pipe between them, a tunnel whose key never leaves the module, and `ping
10.99.0.1` answering in about 50 ms through it. Peer `blbx`, address
10.99.0.7/32, Windows amd64, against the same stock server the Linux client
talks to. Phases 1 through 4 of what follows are all closed; phase 5, packaging,
is not started.

The rest of this document is the plan as it was written on 2026-08-14, with each
phase marked as it was settled. It is kept in that shape deliberately: two of
the phases were harder than the plan said and one was easier, and the record of
which is more useful than a tidy summary would be.

Two findings on the way are worth carrying to any other platform. Upstream's
fork of the namedpipe library hardcodes `SECURITY_ANONYMOUS`, so anything
dialling a control pipe through it is identified as ANONYMOUS LOGON — found by
reading the library, not by running it, and it would have made every caller the
same principal. And the window runs a scripted stand-in unless given `-live`,
which drew "Connected", an address, a byte counter and a desktop notification
with nothing behind them; it now says "(stand-in)" beside the state, because
somebody reading that screen has no VPN and thinks they do.

## The plan, as written on 2026-08-14

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

## Phase 1 — done, and the hypothesis held

**Confirmed on hardware, 2026-08-15**, on the amd64 machine. `wg-hem up` run as
LocalSystem through `psexec -s -i` brings a tunnel up: the security-ID refusal is
gone, so `ipc.UAPIListen` succeeds for that account and the reading of the
failure on 2026-08-13 was right. The service installs, registers and runs.

What that settles and what it does not. It settles the premise the whole plan
rests on — that LocalSystem is both necessary and sufficient for the UAPI pipe —
and with it phases 2 and 3, which were only worth writing if this were true.
## Phases 2 and 3 — done, confirmed the same day

`wg-hem probe` against the installed service, 2026-08-15:

	socket \\.\pipe\encedo-wg
	component 0.9.1+506003a (descr 64 B)
	this 0.9.1+506003a (descr 64 B)
	identified-as sid:S-1-5-21-…-1002

Four things at once, none of which had been run before. The service created the
pipe with the descriptor written here, a client reached it, the protocol made a
round trip over it, and the component identified the caller as a real account
rather than as S-1-5-7. That last one is the whole of the authorisation on this
channel and the part that was written blind: impersonation with the OS thread
locked, and a client asking for SECURITY_IDENTIFICATION because go-winio and
upstream's namedpipe both default to anonymous.

**One thing it did not settle.** The probe ran from the same elevated prompt
that installed the service, so the caller matched the descriptor's
Administrators ACE. Whether an ordinary user can connect — the Authenticated
Users ACE, which is the one that matters, since the window is not elevated — is
still unproven. It is one run of `wg-hem probe` from a normal prompt.

The refusal path is likewise unexercised: nothing has yet connected anonymously,
so the S-1-5-7 check has never fired. That is a guard rather than a feature, and
it fires only when something is wrong.

One thing the test found on the way. `wg-hem status` from an ordinary elevated
prompt answers "Odmowa dostępu" — access denied — and that is expected in
substance: the state file belongs to whoever ran the tunnel, which here is
LocalSystem, for the same reason the tunnel works. The message was wrong though,
and wrong in a way that only shows up on this platform: the remedy offered was
`sudo adduser "$USER" wireguard`, which is Linux's answer, and there is no sudo,
no adduser and no such group here. The advice is now written per platform.

## Phase 1 as it was planned — the service, which unblocks everything else

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

## Phase 4 — done, and it ran first time

The window built on windows-latest in CI, which was the first time
`gui/control_windows.go` had been compiled by anything — Fyne needs cgo and the
development machine has no mingw, so the pipe dial and the impersonation level
were written blind. It then ran, connected and carried traffic without a code
change.

What it cost instead was two false starts that had nothing to do with the window
itself. Half the artifacts came from one build and half from another, because
the two halves were produced by two workflows and their stamps have to agree —
fixed by building both in one job. And the first thing anybody sees on
double-clicking is the stand-in, which is indistinguishable from a working
tunnel unless you know the debug buttons only exist in front of a fake.

The three counterparts this phase expected are settled: the taskbar icon and
grouping came for free from the embedded icon, the tray answered `true` without
the D-Bus question Linux needs, and close-to-tray behaves as it does elsewhere.

## Phase 4 as it was planned — the window

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

A PowerShell pair, `packaging/windows/install.ps1` and `uninstall.ps1`, does this
today: both binaries and the driver into Program Files, the service registered
and started, one Start menu entry, and a refusal if the two halves carry
different stamps. It is the shape of the `.deb` and it is enough to test with.

**It is an interim, and an EXE or MSI is what this ends with.** Decided on
2026-08-15; not started. What that step is really about is not the file format —
a script already places files correctly — but the three things a script cannot
be:

- *Signed.* An installer somebody downloads and runs elevated should carry a
  certificate, and a `.ps1` cannot. Note the one thing that must stay unsigned:
  `wintun.dll` arrives signed by WireGuard LLC with Microsoft's attestation for
  the driver inside it, and re-signing would both modify the Software, which its
  licence clause 3(a) forbids, and displace the chain Windows trusts.
- *Listed.* Add or remove programs, an upgrade path that replaces rather than
  installs beside, and a rollback when a step fails partway.
- *Ordinary.* Somebody who has not been told to bypass an execution policy can
  double-click it.

Between the two formats: MSI through WiX gives the upgrade table and the
rollback and can be built on the runner with a dotnet tool; an EXE through Inno
Setup or NSIS is quicker to write and gives neither. The upgrade table is the
part worth having, because two builds installed beside each other is the failure
this project keeps meeting in other forms.

### Where the driver comes from, signed or not

It is already answered and does not change. `wintun.dll` is not in this
repository and will not be in the installer's sources either: the Bundle step in
`gui.yml` reads the version and the SHA-256 out of `package-windows.sh`,
downloads the archive from wintun.net, verifies it before opening it, and copies
the DLL for the architecture being built. A driver is the last thing to take on
faith from a URL, and a hash in a script is a claim somebody can check; a binary
committed two years ago is not.

For a signed installer the same verified file goes in unchanged, and it is the
one thing in the payload that must **not** be signed by us — see the note above,
and `package-windows.sh`, which says it at greater length.

### Defender calls the component a trojan, and signing is the answer

On 2026-08-16, immediately after a successful install, Windows Defender
quarantined `C:\Program Files\Encedo WG\wg-hem.exe` as
`Trojan:Win32/Bearfoos.A!ml`.

The suffix is the whole diagnosis. `!ml` means a machine-learning model decided
this, not a signature: Defender is saying the file is statistically unusual, not
that it recognises it. Bearfoos is the generic name Microsoft gives such
findings, and it lands on new Go and Rust binaries often enough that several
well-known projects carry an issue about this exact string.

Why this one in particular, and it is worth being honest about: an unsigned
executable, newly built, with no prevalence anywhere, that registers a service
running as LocalSystem, creates a virtual network adapter and opens a named
pipe. Read without provenance, that is a fair description of malware. Note that
it flagged the component and not the window - the component is the half that
does all of it.

What is not a contributing cause here, and is the usual one elsewhere: the
binary is not compressed. build.sh does not pack, so there is no UPX layer for a
model to react to.

**The fix is the signature**, which moves the signing work from something to do
eventually to something that blocks distribution. An Authenticode signature, and
Trusted Signing's reputation with Microsoft in particular, is the documented
remedy rather than a hopeful one. Until then, a false positive can be submitted
at `https://www.microsoft.com/en-us/wdsi/filesubmission`, which clears it from
the cloud model but only for the exact file submitted - so every new build earns
the alert again. That is not a workflow, which is the point.

Worth doing anyway before believing any of the above: put the file through
VirusTotal. A handful of engines out of seventy is what a false positive looks
like; a broad consensus would mean something else entirely and this document
would be wrong.

### ARM64, from 2026-09-17: a native component and an emulated window

The ARM line is supported, and an arm64 installation is a **native component
with an emulated x64 window**. That is not the design anyone set out to build;
it is what the platform allows, measured on the day.

**What was tried.** A `windows-11-arm` job builds both halves natively. The
runner cannot do it unaided and still cannot: its image provisions i686 and
x86_64 mingw and nothing else, so `gcc` there is an x86-64 compiler under
emulation and cgo handing it the arm64 assembly in `runtime/cgo` answers
`no such instruction: stp x29,x30`. The job therefore installs llvm-mingw
itself - one pinned archive, checksum verified - and points `CC` and `CXX` at
its `aarch64-w64-mingw32` drivers. That part works: the window and the
component both compile, and an arm64 installer was produced and installed.

**What stopped it.** The installed arm64 window puts its icon in the tray and
never opens. Run as a console build, it says:

    Fyne error: window creation error
      Cause: APIUnavailable: WGL: The driver does not appear to support OpenGL
      At: fyne.io/fyne/v2@v2.8.0/internal/driver/glfw/driver.go:180

Read that error carefully, because the obvious diagnosis is the wrong one. This
is not `fyne-io/fyne#6483`, where an arm64 build asks for OpenGL ES through WGL
and is refused - that failure names GLES and this one does not reach the
question. GLFW fails while initialising WGL at all: a native arm64 process on
this machine is offered no OpenGL of any kind. Microsoft's OpenCL and OpenGL
Compatibility Pack, installed from the Store, changed nothing - it maps desktop
OpenGL onto Direct3D, and the failure is earlier than the flavour.

**What was measured, in the order it was measured**, on a Windows 11 ARM guest
on a macOS host:

| | Result |
|---|---|
| arm64 installer | installs |
| arm64 window, native | tray icon, no window, the error above |
| tray menu "Show" | nothing |
| x64 window, emulated, same machine | opens and runs |
| Compatibility Pack, then arm64 again | unchanged |

The fourth row is what settles it. The machine can present an OpenGL context;
it will not present one to a native arm64 process. A virtual machine is the
likeliest place to meet a thin graphics stack, so this is not proof about
Snapdragon hardware - but Windows on ARM ships no desktop OpenGL driver of its
own, which is why the Compatibility Pack exists at all, and a toolkit that
needs WGL is betting on the machine having one.

**So the bundle is split by what each half needs.** The component is on the
handshake path, does the ECDH for every rekey and creates the adapter: it is
native arm64, and `wintun.dll` follows it. The window sits in a tray doing
nothing until somebody clicks it: it is the x64 build, emulated, which the same
machine runs without complaint. Both are built by the x64 job, because the
component is `CGO_ENABLED=0` and cross-builds - so one job still holds both
halves of every bundle, one checkout, one stamp, which is the rule the rest of
the pipeline is built around.

**The native window is still built** by the `windows-11-arm` job and uploaded
under a name the signing job does not match. It ships nowhere: a signed copy of
a window that cannot open is a file somebody would download, run and watch do
nothing. It is kept because the toolchain it proves is real, and because it is
what gets re-tested when something changes - a Fyne release that falls back to
EGL and ANGLE, a driver, or real hardware. The console copy beside it is the
one to run, since the shipped linkage has no console and prints nowhere.

### Signing: what exists, as of 2026-09-16

**Proven end to end on 2026-09-16**, run 35105123345 of the GUI workflow: the
build, the reviewer gate, OIDC login, nine signatures (four loose executables,
their four copies in the staged bundles, and the rebuilt MSI), and `signtool
verify /pa /v` on every one of them — chain to *Microsoft Identity Verification
Root Certificate Authority 2020*, subject *RKV spolka z ograniczona
odpowiedzialnoscia*, each timestamped. The first attempt failed at login, and
the cause is recorded below because the portal invites it.

The Azure side is complete and was verified in the portal. Microsoft has since
renamed the service from Trusted Signing to Artifact Signing; the variable names
below predate that and were kept. Nothing here is a secret — an application id
and a tenant id identify, they do not authorise — which is why the repository
holds them as *variables*.

**In Azure**, under the RKV sp. z o.o. subscription:

1. **Identity validation** as an Organization, completed, valid until
   2028-12-04. The certificate's subject is the company, which is what a person
   sees in the publisher line. Renewal is a button that appears near expiry.
2. **An Artifact Signing account**, `win11`, in North Europe. Not West Europe:
   that region refuses new tenants (`RequestDisallowedByRegionAccessPolicy`),
   and since the endpoint the workflow calls is the region's, a mismatch there
   fails at signing time with something that reads like a permissions problem.
3. **A certificate profile**, `SigningCode`, Public Trust. The three-day expiry
   the portal shows is the current certificate's; it rotates by itself.
4. **An app registration**, `gh-actions-wg-hem-signing`, with a **federated
   credential** for GitHub Actions scoped to this repository and the environment
   `release`, and no client secret. The OIDC subject Azure accepts is therefore
   `repo:encedo/encedo-wg-hsm:environment:release`, exactly that.
5. **The role assignment** *Artifact Signing Certificate Profile Signer* for that
   application, on the account — the role that permits requesting a certificate
   from the profile. An earlier version of this note listed *Identity Verifier*
   as well; it was not assigned, and the first signed run showed it is not
   needed for signing.

**In the repository**, as variables:

    AZURE_CLIENT_ID            the app registration
    AZURE_TENANT_ID
    AZURE_SUBSCRIPTION_ID
    TRUSTED_SIGNING_ENDPOINT   https://neu.codesigning.azure.net/
    TRUSTED_SIGNING_ACCOUNT    win11
    TRUSTED_SIGNING_PROFILE    SigningCode

and an environment `release` with a required reviewer and deployment rules that
list the `v*` tags. The sign job in `gui.yml` runs in that environment: a job
that is not in it cannot sign, and a job that is waits for the reviewer. How
the job is triggered and what it does is in [RELEASING.md](RELEASING.md).

When a first attempt fails: `AADSTS700213` is the subject not matching — the
job is outside the environment, or the environment or repository is named
differently, **or the portal generated the subject**. The Entra portal's
"GitHub Actions" credential form now demands numeric organisation and
repository ids and builds the subject from them, as
`repo:encedo@7176084/encedo-wg-hsm@1188321703:environment:release`, which is
not what GitHub sends; that is exactly how the first run here failed. The
fix is *Edit (optional)* under the subject field, or the *Other issuer*
scenario, and the literal `repo:encedo/encedo-wg-hsm:environment:release`. The
run log prints the subject GitHub presented, so the two can be compared
character for character. A login that succeeds followed by a 403 at signing is the role not
yet propagated (minutes) or a wrong endpoint, account or profile value; a run
that fails before its first step is the ref missing from the environment's
deployment rules. A SmartScreen warning on a correctly signed download is not a
configuration error — reputation accrues to a new publisher over time, and
nothing in the workflow changes that.

### Signing, assumed to be Azure Trusted Signing

Decided in principle on 2026-08-15: both halves and the installer signed with
Trusted Signing, since renamed Artifact Signing. Written on 2026-09-16 as a
`sign` job in `gui.yml`; the first end-to-end run is what remains. Three things
about it shape the pipeline rather than being details of it.

*Order.* Sign `wg-hem.exe` and `encedo-wg-gui.exe` **before** the installer is
built, then sign the installer. An installer embeds or compresses its payload,
so signing it does not reach inside; signing the binaries afterwards would mean
shipping unsigned copies of them.

*Timestamping is not optional.* A Trusted Signing certificate is valid for about
three days and is renewed daily. Without an RFC 3161 timestamp
(`http://timestamp.acs.microsoft.com`, SHA-256) every signature is dead within
the week — the timestamp is what makes it outlive the certificate that made it.

*It runs on Windows only.* `azure/trusted-signing-action` needs a Windows
runner, which the pipeline already converges on: the Windows job in `gui.yml` is
where both halves exist with one stamp and where the bundle is assembled. The
signing belongs in that job and nowhere else, and it needs an Azure identity —
OIDC federated credentials and `id-token: write` — rather than a secret holding
a key.

One divergence to settle when this is done: `ci.yml` also produces Windows
binaries, cross-built on Linux, and those cannot be signed there. Either they
stop being published or they are signed in a Windows job of their own. Two
downloads of the same program, one signed and one not, is worse than either.

Also: any checksum published for these artifacts has to be taken after signing,
because signing changes the file.

**One thing gates it rather than following it.** `TODO.md` says to ask about the
names before the first signed release — `wg-quick-encedo` reads as a variant of
upstream's `wg-quick`, the policy has an address for exactly that question, and
such requests "will be trivially approved without debate". Signing a distribution
with a company certificate is that moment. Renaming afterwards costs
incomparably more than one email now.

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
