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
   find the appliance                   ┌── read the configuration
   authenticate — passphrase or extAuth │   verify its MAC
   read the tree, offer a choice        │   create the interface, addresses,
   obtain keymgmt:use:<KID>  ───────────┘   routes, MTU, DNS
        │                                   run wireguard-go
        │  URL + token ───────────────────► ECDH at every handshake
        │                                   unwrap the pre-shared key
        │  ◄─────────────── status          rekey
        │                                        │
        └──────── connection open ───────────────┘
                  closes → tear down
```

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
be. The SDK has no such call today — checkin, passphrase and extAuth, nothing
else — so this is an addition there before it is one here.

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

IPC is a unix socket under `/run`, with the socket's mode and `SO_PEERCRED` doing
the access control. The package carries the unit, the tmpfiles rule, the polkit
rule and the desktop entry.

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
- **Liveness needs a heartbeat**, as above. This is the only place the "no
  window, no tunnel" rule costs a mechanism of its own.
- **The extension cannot start a tunnel without a token, and the token only
  comes from the application.** Somebody enabling the VPN from System Settings
  gets nothing, without a defence being written for it.

The work stops being Go and starts being Xcode: two entitlement sets, an app
bundle, a Swift shell, an external build target for the Go archive. That is a
change of tools, not of estimate.

## What this replaces

`internal/helper` was written for the other split — an unprivileged brain and
privileged hands. Its nine operations (`create-tun`, `up`, `add-routes`,
`set-mtu`, `set-dns`, `pin`, `unpin`, …) are the vocabulary of a component that
is told what to do step by step.

Here the component decides for itself, and the channel carries three verbs: start
with this token, stop, report. What survives is `Validate()` on the privileged
side and the rule that a request carries no secrets — enforced by a test, and
worth restating precisely as *no key material and no long-lived credential; a
scoped token with an expiry is what crosses*. What does not survive is the
operation list and `SendFD`/`RecvFD`, since no descriptor leaves the process that
creates it any more.

## Still open

- Token revocation — absent from the SDK, and it is what makes the token's
  lifetime a secondary question rather than the primary one.
- Who may drive the Windows service.
- Whether the `-systemextension` entitlement carries deployment restrictions
  (TN3134).
- The WireGuard trademark, before the name reaches an installer or a
  certificate rather than after.
