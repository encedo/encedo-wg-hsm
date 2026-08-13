# The graphical client — architecture

Status: settled on 2026-08-13, nothing built. Supersedes the split assumed by
`internal/helper`; see *What this replaces*.

This describes where the tunnel runs, what crosses the boundary between an
unprivileged window and a privileged component, and what each of the three
platforms makes of that. It does not describe the interface itself, which is in
`TODO.md` under *A graphical client*.

## The rule that comes first

**The command-line client does not change.** `wg-hem up` stays what it is: a
foreground process, a capability and a writable directory, no service, no socket,
nobody's daemon. Everything below is an *addition* — the same binary with a second
entry point — and an administrator who wants none of it should never meet it.

That is why the privileged component is `wg-hem` itself rather than a new
program. A second implementation of the tunnel would be a second thing to test
against real hardware, and the first one has taken a week.

## The shape

```
   window (the user's session)              component (privileged)
   ───────────────────────────              ──────────────────────
   find the appliance                   ┌── read the identity it was named
   authenticate — passphrase or extAuth │   verify its MAC
   list identities, offer the choice    │   create the interface, addresses,
   list its peers, offer that choice    │   routes, MTU, DNS
   obtain keymgmt:use:<if_kid> ─────────┘   run wireguard-go
        │                                   ECDH at every handshake
        │  URL + token + identity + peer ─► unwrap the pre-shared key
        │                                   rekey; on a dead peer, walk the
        │  ◄─────────────── events          stored order itself (§6.4 v2)
        │                                        │
        └──────── connection open ───────────────┘
                  closes → tear down
```

## Which identity, and why the order is forced

A device may hold several `WG:if:` records — N private keys, each with its own
peers and its own configuration. The rule is the one §6.2 already applies to
peers: **one is used without asking, several are offered as a choice.** Symmetry
with a behaviour people already have is worth more here than any argument for a
different treatment.

Today `internal/config.Load` refuses outright when it finds more than one, which
is honest for a client that configures one interface and is not what a window
wants. It splits: enumerate, then load the one that was named.

The order that follows is not a preference. `keymgmt:use:<if_kid>` **names one
key**, so the token cannot be minted before the choice is made — enumeration
happens first and needs only search (which a device with `allow_keysearch` answers
without a token at all) or a read scope. The consequence for the everyday path is
one more approval than the scope table in `TODO.md` counts, on any device holding
more than one identity, and that is a firmware question rather than something this
design can arrange away.

## What crosses, and what does not

**A scoped token, and nothing else.** Not the passphrase, not key material, not
the configuration.

Authentication is a challenge and a response: the passphrase derives the answer,
and the answer buys a JWT. The tunnel needs only the JWT. So the window does the
whole authentication and hands over the result — which means `extAuth` and a
passphrase become indistinguishable at the boundary, and the privileged side
never grows a second code path for them.

What a stolen token buys, stated plainly, because this is the number that matters
once a credential lives in a privileged process:

- **It cannot decrypt recorded traffic.** Noise mixes `DH(e_i, s_r)` and
  `DH(e_r, e_i)`; both need an ephemeral private key that no longer exists. An
  oracle for the static key does not replace them, so forward secrecy holds.
- **It can impersonate the identity in new handshakes**, and unwrap pre-shared
  keys, for as long as it is valid — the same scope covers the self-ECDH.
- **Its reach is the appliance's reach.** Against a personal appliance on a USB
  link the token is useless anywhere but that machine, and an attacker already
  there has won. Against an enterprise appliance it is useful from anywhere that
  can see the appliance. Those are two different risk assessments for one design
  and should be documented as two.

Which is why **revocation belongs in the first version**, not later: revoked when
the tunnel stops, the token's effective life is the session rather than its
expiry, and the argument above stops depending on how long an expiry happens to
be. This is a **firmware question before it is an SDK one**: the SDK has no such
call, and neither does the endpoint table (§7) — there may be nothing to wrap. It
is on the firmware list in `TODO.md` and unresolved. The tension to hold in view
until it is: the interface wants eight-hour sessions so the tunnel stops dying
mid-afternoon, and expiry is currently the *only* bound on a stolen token — those
two pull in opposite directions, and no wording here resolves them. If revocation
does not come, the fallback is short use-tokens re-minted by the window, which
costs keeping the passphrase-derived material in the window's memory for the
session — a trade this project once rejected for convenience and would then be
buying for containment.

**How many tokens** is settled by a firmware change already asked for: search
that returns public keys (`TODO.md`, the firmware list) lets the component read
the whole tree without `keymgmt:get`, collapsing the handover to exactly one
credential — `keymgmt:use:<if_kid>`. Until that ships, the handover is that token
plus a small read bundle (search, get), and the analysis above must be read as
covering the bundle: the read scopes reveal nothing the design does not already
treat as public (§8 — descr and public keys), so the impersonation analysis is
unchanged, but stating "one token" before the firmware ships would be false.

**TLS is verified, always.** There is no `--insecure` in this design and there
must not be: a request that tells a root process to skip certificate
verification is a different thing from a flag a person types about their own
session. Both appliance kinds carry real certificates.

## Who may talk to it

This is where the security went once the boundary moved, and it is authorisation
rather than encryption.

Every platform hands over the peer's identity, authenticated by the kernel, for
free: `SO_PEERCRED` on Linux, the client token's SID on Windows, a code-signature
check on macOS — which is stronger than the other two, since it says *this signed
application* rather than *this user*.

A key pair over the channel was considered and rejected. The window's private key
would live in a file the user can read, so the boundary it buys is "the same
user" — precisely what the operating system gives without an enrolment ceremony, a
key store, or a revocation story we do not have. Encryption would answer a
question nobody asked: a local socket is mediated by the kernel and has no
eavesdropper. Reconsider only for a channel the system cannot vouch for.

Two rules follow:

- **The privileged side does not trust the configuration it is handed** — it is
  not handed one. It reads and authenticates the tree itself, which is what makes
  it a monitor rather than something pretending to be one.
- **It never becomes an ECDH oracle.** It holds a token; if any operation
  performed a device call on request, whoever reached the channel would obtain
  exactly what the token was meant to withhold.

## The channel

Four verbs and a stream — written down because "three verbs" was the first
draft's undercount, and a protocol that gets discovered during implementation is
how the previous one died.

- **start** — the URL, the token, the identity and the peer the person chose, and
  what the window is (see *One version*). The component answers with its own, or
  refuses. Both identities are named because the token is scoped to the first and
  means nothing without it.
- **stop.**
- **refresh** — a fresh token, mid-session. Renewal is a human act and the human
  is at the window: the interface promises one-click renewal, and without this
  verb expiry simply ends the tunnel.
- **events** — a stream, not a poll: state, the peer in use, counters, expiry,
  and the notices a terminal used to print. The window draws what it is told;
  the component is the source of truth.

**Failover crosses the boundary as news, not as a question.** §6.4 v1 made it a
dialogue because a terminal had a human in front of it; that was the PoC showing
through, not a requirement. The component has nobody to ask and does not need
anybody: the stored order *is* the priority (§3.1, PEER_REF), so it walks it and
reports what it did — which is §6.4 v2, promoted from "later" to what this
architecture requires. Manual choice survives in the advanced mode as
stop-and-start-with-this-peer, never as a mid-session prompt.

## One version

The window and the component are separate artifacts — one needs cgo and a build
per platform, the other stays static — but they are **one repository and one
release**: both carry the commit they were built from, `start` exchanges it, and
the component refuses a window it does not match rather than guessing what an
older one meant. `status` reports both, so a human can see the skew a refusal is
about.

**The record dialect travels with the version**, for the same reason and with a
sharper edge. A 128-byte window against a 64-byte component does not fail to
start — it fails at MAC verification, which is the signature of a configuration
somebody has tampered with. That is the worst available error message for a
mismatch of build flags, so the two exchange `descr.Size` at `start` and refuse
each other by name.

Saying the product ships 128 only would be true and useless: the firmware in
front of the people building this is 64, `WG_HEM_DESCR=64` is how everything gets
built today, and a rule that holds only after a firmware update is not a rule
that protects the next fortnight. Both artifacts are built for both dialects and
the pairing is checked at run time, until the day the 64-byte build is deleted.

## Liveness: no window, no tunnel

The window is still the session. The component could now run without one — it does
its own device calls — so this is enforced rather than inherent, and has to be
written as a rule.

On Linux and Windows the open channel *is* the signal: the socket or pipe closing
is observable, and teardown follows. macOS is the exception and needs a
heartbeat, because an application sends to an extension and receives a reply
rather than holding a connection.

## Linux

A systemd service, **not as root**: a system user with
`AmbientCapabilities=CAP_NET_ADMIN`. The measurement that shaped the CLI shapes
this too — everything privileged here wants one capability, and root is merely
the coarse way to get it.

This settles the one thing a capability could not cover. `resolvectl` is a
privileged interface of its own, and a process holding `CAP_NET_ADMIN` and
nothing else is one polkit asks a human about — an authentication dialogue in the
middle of bringing a tunnel up. A polkit rule naming the service's user answers
it, which is the first of the three options `TODO.md` recorded, chosen by the
architecture rather than on its own merits.

IPC is a unix socket in the service's **own runtime directory**
(`RuntimeDirectory=`, so `/run/encedo-wg`), with the socket's mode and
`SO_PEERCRED` doing the access control — and the service's state lives there
too. It does not touch `/var/run/wireguard`: that directory is the CLI's, owned
however the README's instructions left it, and two entry points writing one
root-owned directory under different owners is a fight the rule at the top of
this document exists to prevent. The one open detail: whether the UAPI socket
also moves (invisible to `wg(8)`) or stays in the shared directory for tooling's
sake — to be decided when the unit is written, not discovered. The package
carries the unit, the tmpfiles rule, the polkit rule and the desktop entry.

`setcap` on a thirty-megabyte cgo binary disappears with it: the window becomes an
ordinary user program.

The cost, stated honestly: Linux gains a service it did not technically need. It
buys one architecture instead of two, and DNS without a dialogue box.

## Windows

`wg-hem` registered as a service, LocalSystem — needed for Wintun, for routes and
for `netsh`. Not a second implementation; a second way to start the first.

IPC is a named pipe with a security descriptor, and the caller's identity comes
from its token. Who is allowed is a product decision still open: the official
WireGuard client restricts control to Administrators and, optionally, Network
Configuration Operators; "any interactive user, tunnel bound to their session" is
also defensible.

**The adapter is created by the service and its handle goes nowhere**, which
removes the most expensive part of the previous plan: no `DuplicateHandle`, no
Windows equivalent of descriptor passing to invent. No driver ships either —
Wintun is signed by WireGuard LLC — so nothing here needs attestation signing.

Development and testing need no certificate. Windows does not require services to
be signed, unlike drivers; signing is for distribution, where it buys SmartScreen
reputation rather than function.

Fewest unknowns of the three.

## macOS

The privileged component is not ours: it is a **system extension**.
`NEPacketTunnelProvider` in Swift with the Go core linked as a `c-archive`, which
is how the official client is built — its "Go backend version" string is
wireguard-go reporting from inside a Swift application. Developer ID, notarised,
distributed outside the App Store; the sandbox and review of the store are the
wrong shape for a product built around a hardware module.

The entitlement is **self-serve**, not a gate: Apple's developer support states
there is no approval process for a packet tunnel provider, and it has been a
checkbox since November 2016. Only Hotspot Helper and the app push provider
remain managed. What does apply is TN3120 — a packet tunnel provider is for VPN
and nothing else, which describes this exactly. The `-systemextension` variant
specifically is worth confirming against TN3134 before relying on it.

Three differences to hold on to:

- **The token travels as a provider message, never in the provider
  configuration.** That configuration is stored by the system, and credentials do
  not go in it.
- **Liveness needs a heartbeat**, as above — and the first thing that will break
  the heartbeat is **App Nap**. A windowless application waiting in the tray is
  exactly what macOS suspends, and a suspended window misses beats for a tunnel
  that is fine — the same availability bug that disqualified putting the window
  on the handshake path, reintroduced through the liveness mechanism. Declaring
  the activity (`NSProcessInfo`'s `beginActivity`) and a timeout generous enough
  to survive a missed beat are part of the design, not tuning left for later.
- **The toggle in System Settings will be pulled, and it must fail loudly.** The
  system shows every VPN configuration with a switch, and switching it starts the
  extension — which has no token, because the token only comes from the
  application. Failing is correct; failing *silently* would read as a broken
  product, so the extension cancels with a displayable error naming the
  application to open. A dead switch on the user's screen is a UX debt this
  architecture takes on knowingly.

**This is a port, not a repackage.** The DH-delegation patch and the descr and
MAC code cross intact — they are the point of the whole design — but the OS half
of `internal/runtime` does not cross at all: the system hands the extension a
`packetFlow` instead of a file descriptor, routes and DNS are *declared* in
`NEPacketTunnelNetworkSettings` rather than installed with commands, and the
endpoint pinning of `routing.go` becomes `excludedRoutes`. The work is Xcode,
Swift, two entitlement sets, an app bundle and an external build target for the
Go archive — a change of tools *and* of code, and the platform half was always
going to be rewritten.

## What this replaces

`internal/helper` was written for the other split — an unprivileged brain and
privileged hands. Its nine operations (`create-tun`, `up`, `add-routes`,
`set-mtu`, `set-dns`, `pin`, `unpin`, …) are the vocabulary of a component that
is told what to do step by step. **It was deleted on 2026-08-13**, when
`internal/ipc` replaced it.

Here the component decides for itself, and the channel carries the four verbs
and the event stream of *The channel*. What survived is `Validate()` on the
privileged side and the rule about what may cross, restated precisely as *no key
material and no long-lived credential; a scoped token with an expiry is what
crosses* — with a second test alongside it asserting that no field can ever ask a
privileged process to skip certificate verification.

What did not survive is the operation list and `SendFD`/`RecvFD`. No descriptor
leaves the process that creates it any more, and that turned out to be worth more
than the deleted code cost: descriptor passing is a unix socket's trick with no
Windows counterpart, and without it the framing is plain `io.Reader` and
`io.Writer` — the same code over a unix socket and a named pipe, neither knowing
which it is under.

## Still open

- Token revocation — a firmware question, not an SDK one (§7 has no such
  endpoint), and until it exists expiry is the only bound on a stolen token,
  which the eight-hour session the interface wants stretches to eight hours.
- Who may drive the Windows service.
- Whether the `-systemextension` entitlement carries deployment restrictions
  (TN3134).
- Where the Linux service's UAPI socket lands: its own directory (invisible to
  `wg(8)`) or the shared one (shared ownership again).
- The WireGuard trademark, before the name reaches an installer or a
  certificate rather than after.
