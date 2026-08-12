# TODO

What is left, and why each item is where it is. Items carry enough context to be
picked up cold; the specification sections they refer to are in
`docs/ENCEDO-WG-CONFIGFREE-SPEC.md`.

Status as of 0.9.1: `provision`, `verify`, `up`, `down`, `status`, `peer` and
`wipe` all work against real hardware, tested Linux-to-Linux against a stock
kernel WireGuard server. A 7.5-hour soak on 2026-08-11 held 224 rekeys with no
repeated secret, no retry and no drift in device latency, and ended on token
expiry exactly as designed.

---

## Not yet written

**Interactive `provision` wizard (§10.1).** The specification promises "no flags
→ interactive wizard (prompts follow the admin data table)". Everything else in
§10.1 is implemented. This is the last piece of that section.

**Failover v2 — health check with hysteresis (§6.4).** Today only the *first*
handshake after a peer is configured is watched: `failover.go` gives a peer 15
seconds, and a peer that answers and later goes quiet is never noticed. v2 needs
a periodic liveness check against the UAPI handshake timestamp, with enough
hysteresis that a single missed rekey does not flap a working tunnel.

**Integration test for failover (§9.7).** One interface, three peers, kill the
active endpoint, measure the switch. Today's testing used a single peer, so
failover was only exercised on the path where there is nowhere to switch *to*
— the selection logic across several candidates is untested.

**Ask about the names before the first signed release.** "WireGuard" and its logo
are registered trademarks of Jason A. Donenfeld. The policy forbids using the
marks in a product name, and marks "so similar … that may confuse or mislead
people"; it says nothing either way about the abbreviation `wg`. Nothing here
contains "WireGuard", but `wg-quick-encedo` reads as a variant of upstream's
`wg-quick`, which is the case the second clause is about. The policy gives an
address for exactly this — wireguard-trademark-usage@zx2c4.com — and says such
requests "will be trivially approved without debate". One email turns an
unanswered question into written permission, and it is worth having before a
company signs a distribution with its own certificate: renaming afterwards costs
incomparably more than asking now.

## v2.1 — proposed: the version somebody's assistant can run

Neither of these is started. Both assume `wg-hem` as it stands and add nothing to
the protocol; they are about who can operate it.

**A graphical client.** Simple by default, with an advanced mode, on the
assumption that 99.9% of use is: open it, connect, close it. One decision comes
before any of the interface work and is expensive to reverse.

*The GUI is the session.* Closing the window ends the tunnel. `up` already holds
the foreground, needs privilege, and holds a token that cannot be renewed without
a human — so a process surviving the window would be the daemon this project
deliberately does not build, holding a credential nobody is watching. Minimising
to a tray icon keeps the session; closing ends it, and the first close should say
so — though not every desktop has a tray, which is taken up under *toolkit*
below. Privileged work (TUN, routes, DNS) belongs in a helper that knows nothing
about keys; the session and the token stay in the GUI.

*Module presence is the primary state, not a connect button.* Plugged in, ready,
connected. This is the one VPN client whose identity is an object the user can
hold, and that is easier to teach than any profile dialog. Prompt on insertion;
do not connect on insertion, because a tunnel that raises itself without intent is
a bad tunnel.

*Three things will bite.* Token expiry, which today defaults to an hour and simply
ends the tunnel mid-afternoon — show the remaining time permanently, warn before
it, offer one-click renewal, and default to eight hours rather than one. Module
removal, which does not end the tunnel until the next rekey up to two minutes
later, long enough for the user to believe all is well — react on removal, not on
failure. And failover, which prompts in a terminal today; a GUI should try the
next peer and say what it did, keeping manual choice for the advanced mode.

*Advanced mode* is a toggle in the same window, not a second application: peer
selection, the `--debug` ECDH trace, the decoded configuration from `verify` with
its MAC check, HEM URL, last handshake. `status` already returns all of it.
Provisioning stays out — the person running the tunnel is not the person who
provisions it.

*The constraint that decides more than the toolkit does: cgo.* Every usable Go GUI
library needs `CGO_ENABLED=1`, and that costs both of the properties `build.sh`
was deliberately given. Cross-compilation ends — six targets from one machine
becomes one build per operating system, so CI grows `macos-latest` and
`windows-latest` runners beside the `ubuntu-latest` it has now. Static linking
ends with it, and the glibc problem that made every binary static comes back
wearing GUI libraries. **So the GUI is a separate artifact**, built per platform,
sharing `internal/` with the CLI. `wg-hem` itself stays as it is: static,
cross-compiled, portable. Letting a toolkit drag cgo into the command-line client
would trade the thing that works everywhere for the thing that needs a window.

*Linux does not need the helper, and measuring that changed the estimate.* Every
privileged thing this client does on Linux — creating the interface, its
addresses, its routes, its MTU — wants one capability, `cap_net_admin`, and not
root. `/dev/net/tun` is world-writable already. What is left is `/var/run/wireguard`,
which is root-owned, and a tmpfiles rule settles that. So on Linux the answer is
`setcap` plus a directory, which the README has documented for the config-file
client since before any of this: no helper process, no elevation, nothing new to
write.

`Preflight` in `internal/runtime` now reports both conditions before the
passphrase is asked for, with the command to fix each. That matters more than it
sounds: the failure it replaces is netlink returning "operation not permitted"
from three layers down, after authentication, at which point the obvious move is
sudo — which works, and teaches that this client needs root, which it does not.

macOS and Windows are where the helper is actually required, because neither has
an equivalent of `setcap`: there is no way to grant one binary one permission.
That is two platforms rather than three, and the second of them is the one whose
demo assumption is already in doubt.

*Toolkit.* The choice looks like it is settled by §10.4.4 and it is not. That
section objects to *logic* duplication — reimplementing the TLV codec and the MAC
canonicalisation in JavaScript, in a format bound for certification. A native UI
calling Go functions directly duplicates nothing, and satisfies the intent more
completely than a webview does, because there is no JavaScript at all.

That leaves a plain trade. A webview wrapper (Wails) reuses the embedded HTML and
looks like the browser it is, at the cost of a webview runtime on every platform —
WebView2 on Windows, which would be the *second* runtime dependency there after
`wintun.dll`, and WebKitGTK on Linux. A self-rendering toolkit (Fyne) needs
nothing installed and produces one file, at the cost of not looking native
anywhere.

**Recommendation: a self-rendering toolkit for the user-facing application, and
the embedded HTML form for administrator provisioning.** This interface is three
states, a button, a countdown and an advanced panel; the richness a webview buys
is wasted on it, and the runtime dependency is not. These are two presentations
for two audiences and two shapes of task, both calling one Go core — not two
implementations of anything.

*Where it lives: a nested module, not a second repository.* Measured rather than
assumed. Go's `internal/` rule works on the import path prefix, so a module named
`github.com/encedo/encedo-wg-gui` cannot see `internal/config`, `internal/runtime`,
`internal/descr` or `internal/mac` — the compiler refuses outright. Making a
separate repository work would mean promoting the TLV codec, the MAC
canonicalisation and the runtime to public API, with the compatibility obligation
that follows, for a format §8.7 says is headed for certification as a controlled
document. That is the wrong direction, and it arrives with the submodule friction
this project already knows.

A directory with its own `go.mod` has neither problem, and it is not the same as a
plain subdirectory:

```
encedo-wg-hsm/
├── go.mod          module github.com/encedo/encedo-wg-hsm
├── cmd/            CLI: static, cross-compiled, unchanged
├── internal/       shared core
└── gui/
    └── go.mod      module github.com/encedo/encedo-wg-hsm/gui
                    replace github.com/encedo/encedo-wg-hsm => ../
```

The prefix matches, so `internal/` is importable; the nested module is invisible to
`go list ./...` at the root, so cgo never reaches a build of the CLI. One
repository, one tag, changes to the core and the interface land together and
cannot drift. A plain subdirectory inside the *same* module would do the opposite
— `go build ./...` would drag cgo and the GUI libraries into every build of the
command-line client, which is the outcome the previous paragraph exists to avoid.
The committed `replace` means CI needs no `go.work` and no extra setup; the only
cost is that `go install …/gui@latest` will not work for an outsider, which does
not matter for something distributed as signed binaries.

*The tray is not uniform, and it carries a design decision.* Windows has a
notification area and macOS a menu bar, both idiomatic. Stock GNOME has neither:
tray icons were removed and return only through an AppIndicator extension. That is
easy to miss from a developer machine that happens to have it enabled. Since
minimising to the tray is what distinguishes "keep the session" from "end it", a
Linux desktop without a tray leaves the user no way to express the first. Detect
the absence and stop offering minimise-to-tray as window behaviour rather than
promising something the desktop will not deliver.

*Signing and packaging.* CI still builds and does not publish; that does not
change. A third artifact joins the two CLI binaries on the signing token, in the
same order as before — sign, then package, never the reverse. If a webview
wrapper is chosen after all, its Windows bootstrapper needs the same redistribution
check that `wintun.dll` was given.

*Approvals are the currency, and the count is a firmware question.* ExtAuth is
available, so the connect flow can be a phone approval instead of a typed
passphrase — which is the better experience by a wide margin, and the reason the
number below matters more than it looks. Tokens cache by scope, so asking for the
same scope repeatedly is free; **each distinct scope is one notification**. That
makes the two authentication methods behave in opposite directions: a passphrase
buys every scope with one prompt, because the SDK caches the derived key, while
ExtAuth charges per scope.

Today `up` needs two (`keymgmt:get`, `keymgmt:use:<ifKID>`) and `provision` five.
The coming firmware changes both halves of that. Multi-scope tokens bundle what a
command needs, and a search that returns public keys as well as identifiers
removes `keymgmt:get` from the client altogether: `config.Load` stops reading the
interface key and each peer key one call at a time, and the existence probe in
`adopt.go` goes with it, since `readPeerRecord` already answers that question
through search. **Deleting that scope is a real cleanup to schedule**, and it
retires the endpoint whose 406 for an unknown key cost an afternoon to diagnose.

What is left is small enough to state in full:

| command | token(s) | approvals |
|---|---|---|
| `up`, `status`, `verify` | `use:<ifKID>` | 1 |
| `provision --kid` | `use:<kid>` `imp` `upd` `search` `del` | 1 |
| `provision`, new identity | `gen` `imp` `upd` `search` `del`, then `use:<KID>` | 2 |
| `peer add/update` | `use:<kid>` `upd` | 1 |
| `wipe` | `del` | 1 |

So the largest bundle is **five**, and the everyday path is a single approval.
`keymgmt:del` stays in the provisioning bundle although only a failed run uses it:
a token taken once at the start cannot go back for more at the moment something
has already gone wrong.

*The binding constraint is ordering, not count.* `keymgmt:use:<KID>` names a key,
and there are two places where the key is not yet known when the token would be
requested. Provisioning a new identity learns the KID from `CreateKey`, so it
needs two rounds however many scopes a token carries — a key that does not exist
cannot be named, and no firmware change will alter that. `up`, `status` and
`verify` learn it from the search for the `WG:if:` record, so their single
approval holds only while anonymous search is permitted; without it the search
takes a token of its own and the everyday path costs two again.

*Three things worth saying to whoever specifies the firmware.* A use-scope that is
not bound to one KID — a list, or a wildcard — would make `up` a single approval
in every case rather than only when anonymous search is on; provisioning a new key
stays at two regardless, because a key that does not exist cannot be named.
Whatever replaces `keymgmt:get` must keep reading every peer in one grant, as
search-returning-public-keys does: per-key use-scopes would grow the bundle with
the number of peers, and a token whose size depends on how many peers a
configuration has is a token that eventually will not fit. And `allow_keysearch`
now carries user-visible weight rather than mere convenience — while it is on, the
everyday path is one tap; with it off, two.

*What it costs, roughly.* The interface is the cheap part and reads as the whole
job, which is how this kind of work gets underestimated. Three states, a button, a
countdown and a panel is about a week. What dominates is everything around it.

| | estimate |
|---|---|
| A drivable session API extracted from `cmdUp` | 3–5 d |
| The interface itself | 5–8 d |
| Privileged helper — macOS and Windows only, see below | **8–16 d** |
| Module presence (poll the device; hotplug APIs are not worth it) | 1–2 d |
| Tray, including desktops that have none | 3–5 d |
| Packaging, signing, notarisation, CI | 5–10 d |
| Testing on three platforms against real hardware | 5–10 d |

Call it 32–60 developer-days, so two to three months for one person working on it
properly. The privileged helper is both the largest number and the least certain:
three platforms, three mechanisms, and each with its own installation and
permission story.

Staged, it looks better than the total suggests. Assume elevated privileges and
the twenty-day line disappears, which is what makes a demonstration cheap relative
to the whole. Getting one platform to production quality after that is another
three or four weeks; the third platform is mostly packaging rather than code.

*A demonstration, running elevated.* One fact decides the shape of it: **the
session lives in `package main`.** `tunnel`, `authenticator` and the whole tunnel
lifecycle are in `cmd/wg-hem`, while `internal/` holds only the pieces — config,
descr, mac, runtime. A separate `gui/` module has nothing to import today. So
there are two routes and they differ by a factor of two.

*Drive the existing binary* — 3–5 days. The interface starts `wg-hem up` as a
child process, reads its stderr for the states it already announces, and
disconnects with SIGTERM. Nothing in the core changes. One obstacle is not
obvious: `readPassphrase` calls `term.ReadPassword` on stdin, which requires a
terminal and fails on a pipe, so this route needs either a pty or a relaxation of
that read. The relaxation is an hour's work and a security-relevant decision —
acceptable in a throwaway, deliberate in anything else. The code is discarded
afterwards, but the question gets answered in full.

*Do it in process* — 7–10 days, of which 2–3 are moving the session
orchestration out of `package main` into `internal/`, with authentication
injected rather than held in a package-level variable. **That part is not
discarded**: it is the same seam the *extract the provisioner core* entry below
already calls for, and the first slice of the real thing.

Prefer the second unless the demonstration is needed this week, because the
throwaway route costs nearly as much once the pty work is counted. Either way this
is the right thing to build first: it answers the only question the design is
genuinely unsure about — whether *the window is the session* is intelligible to
somebody who was not part of deciding it. Everything else in the table above is
work whose answers are already known. If that model turns out to be wrong, every
other estimate here is void anyway.

*One purchase this depends on.* The code-signing certificate being bought signs
Windows. macOS needs an Apple Developer ID and notarisation through Apple, which
is a separate certificate, a separate subscription and a first-time process worth
budgeting days for on its own. Worth knowing while the Windows one is still being
chosen.

**A migration tool.** Read an existing `wg0.conf`, carry over everything that can
be carried, and return the new public key; the administrator changes one line on
the server and the migration is done. The shape is right and the one-line claim
holds: the client's address does not change, so `AllowedIPs` on the server stays,
and the pre-shared key can be carried too (`provision --psk -` wraps it), so
`PresharedKey` stays as well. Only `PublicKey` changes.

*What cannot be carried is the part that matters.* `PrivateKey` is left behind by
design — that is the entire point, and the new identity is generated inside the
module. But `PostUp`, `PreUp`, `PostDown`, `PreDown`, `Table` and `FwMark` have no
TLV representation and never will: the record format has seven tags and none of
them is a script. A configuration with an `iptables` rule in `PostUp` will come up
after migration looking healthy while the rule is simply gone. **These must be
listed and acknowledged, not dropped quietly** — a silent behaviour change found a
week later costs more trust than a refusal on the day.

*Give it a diff, not a wizard.* Original file on one side, what will be stored on
the other, and beneath them the list of what could not be carried and why. A black
box invites suspicion at exactly the moment a migration tool needs to be believed;
`verify` can then show what actually landed in the module for comparison.

*Cutover is reversible until the swap.* The old file and old key keep working
until the administrator changes the line, so provisioning early and switching
later is safe. Zero-downtime needs the new identity to take a different address
and a second `[Peer]` alongside the old one — the same `AllowedIPs` on two peers
of one interface makes the routing ambiguous.

## Parked: provisioning for an administrator

Deliberately set aside, not forgotten. The thread: a service provider wants to
deploy keys for many users, and today `provision` serves one person at a
terminal. Nothing here is started.

**Extract the tunnel from the CLI shell.** Started, and the groundwork is done.
The tunnel no longer reads a terminal to choose a peer after a failover, no
longer writes to stderr, and no longer speaks in exit codes: all three are
injected or named in `internal/session`, which is also where the state file now
lives. What is left is the move itself — `tunnel`, `awaitHandshake` and the UAPI
builders out of `cmd/wg-hem` — and it is mechanical, because the couplings that
would have made it a redesign are gone. This is what the graphical client needs
before it can drop its fake.

**Extract the provisioner core from the CLI shell.** `cmdProvision` interleaves
flag parsing, validation and device work in one function and returns its result
through `fmt.Println`, so nothing but `os.Args` can drive it. Splitting it into
`Params → Run(...) (Result, error)` with the CLI as a thin adapter is a
precondition for everything below and for the wizard above. The cost is
`provision_test.go`, which drives `cmdProvision(args)` and would follow the seam.

**Server-side output.** `provision` prints the client public key; assembling the
matching server peer entry — `PublicKey`, `AllowedIPs`, `PresharedKey` — is left
to a human, and it is the only step in the whole flow where a typo goes
undetected. All three values are known to the process at the moment it prints.
Open question, unanswered: `[Peer]` block, JSON, `wg set` command, or several.

**Invite / enrolment channel.** How an administrator gets provisioning parameters
to a user and the public key back. Sketch: parameters in a URL fragment (never
sent to the server), encrypted under a PIN passed out of band because the
fragment carries the PSK. §10.4.4 already settles where the UI runs — an
embedded localhost form, browser as UI only, all HEM calls through the same Go
code path — and explicitly rejects a standalone SPA. Note that the transport
objection in §10.4.4 is now stale: current firmware has a valid certificate and
full CORS, so a hosted page reaching the device is possible. The remaining
objection is not: the passphrase would be typed into a page served from the
administrator's origin, re-trusted on every load.

## Blocked on firmware

Deferred until the new firmware is available; the client side is ready.

- HEM lost mid-tunnel: three retries, then a clean interface shutdown rather than
  a tunnel that stays up and silent. Token expiry exercises the same shutdown by
  a different route and has now been seen; losing the device itself has not.
- Full-tunnel variant (`allowed-ips=0.0.0.0/0`). The only untested path in
  `internal/runtime`: endpoints the tunnel would swallow are pinned to the
  pre-tunnel gateway, and the HEM is probed but deliberately not pinned.

**Multi-scope tokens.** The coming firmware issues one JWT covering several
scopes, which changes how many approvals a command costs rather than what it can
do. The analysis — the six-scope maximum, why ordering binds harder than count,
and what a use-scope not tied to a single KID would buy — sits with the GUI entry
above, because that is where the number is felt.

**Remove the 64-byte record variant once the target firmware ships.** It is a
temporary accommodation for current hardware, not a product characteristic, and
it should not outlive the firmware that needs it. It reaches further than it
looks: `descr64` and the `-descr64` suffix in `build.sh`, the two-way matrix in
the CI workflow, `size_descr64.go`, the record size reported by `wg-hem version`,
and the passages in `README.md`, `CLAUDE.md` and `UPSTREAM.md` that explain why a
tree written by one build cannot be read by the other. Removing half of that
leaves a build flag that no longer does anything and documentation describing a
choice nobody has. The customer-facing page already says nothing about record
sizes, deliberately — until this is done, the repository and that page disagree.

## Outside the code

**The landing page.** A single page aimed at a technically literate buyer, built
from `PRODUCT.md`, `README.md` and the specification, and resolving the one thing
none of them said on its own: there are **two** guarantees here, not one, and they
fail separately. The key cannot be taken — that is the claim `PRODUCT.md` already
made. The routing cannot be altered unnoticed — that is v2 only, and it is the
reason v2 exists. A file with no key in it is still a file somebody can edit, and
changing one `AllowedIPs` entry sends traffic elsewhere with the key perfectly
safe. That argument is the spine of the page and appears nowhere else.

It presents the line as v0 (standard WireGuard) → v1 (`wg-quick-encedo`) → v2
(`wg-hem`), drawn as three states of the same configuration file, and gives the
strongest commercial point its own full-width band: any standard-conforming
implementation is a valid other end, so there is no migration, no coordination
window, and no provider to leave. It also states what the design costs and what
has not been tested, on the grounds that a page listing only advantages reads as a
brochure to the audience it is written for.

Deliberately absent: any call to action with contact details, since none were
available to invent; and any mention of record sizes, per the entry above. Named
VPN brands are avoided too — categories and implementations make the same point
without implying a relationship with anyone. The trademark notice in the footer
follows the same reasoning as the entry in *Not yet written*.

Source: `docs/landing-page.html`, self-contained — one file, no external
requests, and it renders in both light and dark.

## Deliberate non-goals

Recorded so they are not re-proposed as oversights.

- **Token refresh.** Expiry ends the tunnel; the user restarts it. Refreshing
  would need the passphrase to outlive the auth step.
- **Daemonising.** `up` holds the foreground. A daemon that restarts cannot
  re-authenticate without a human.
