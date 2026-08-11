# TODO

What is left, and why each item is where it is. Items carry enough context to be
picked up cold; the specification sections they refer to are in
`docs/ENCEDO-WG-CONFIGFREE-SPEC.md`.

Status as of 0.9.0: `provision`, `verify`, `up`, `down`, `status`, `peer` and
`wipe` all work against real hardware, tested Linux-to-Linux against a stock
kernel WireGuard server.

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

**`down` and `status` should find the interface macOS actually created.** `up`
asks for `wg0`, the kernel hands back `utunN`, and the state file is written
under the name that came back. `down` and `status` default to `wg0` and look for
a file that is not there, so on macOS both need `--interface utun5` — a name the
user has to read out of the `up` output first. When the named state file is
absent and `RunDir` holds exactly one, using it would be right far more often
than failing is. Ambiguity is the only case worth refusing.

**Integration test for failover (§9.7).** One interface, three peers, kill the
active endpoint, measure the switch. Today's testing used a single peer, so
failover was only exercised on the path where there is nowhere to switch *to*
— the selection logic across several candidates is untested.

## Parked: provisioning for an administrator

Deliberately set aside, not forgotten. The thread: a service provider wants to
deploy keys for many users, and today `provision` serves one person at a
terminal. Nothing here is started.

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

- Long rekey soak. Each handshake costs two HEM round trips and WireGuard rekeys
  roughly every two minutes, so hours of running is the only way to see whether
  the ECDH path is stable. Watch that the handshake age never approaches
  `REJECT_AFTER_TIME` (180 s). `wg-hem up --debug` traces every ECDH for this.
- HEM lost mid-tunnel: three retries, then a clean interface shutdown rather than
  a tunnel that stays up and silent.
- Token expiry, which is the same shutdown by a different route and needs to be
  told apart from the above.
- Full-tunnel variant (`allowed-ips=0.0.0.0/0`). The only untested path in
  `internal/runtime`: endpoints the tunnel would swallow are pinned to the
  pre-tunnel gateway, and the HEM is probed but deliberately not pinned.

## Deliberate non-goals

Recorded so they are not re-proposed as oversights.

- **Token refresh.** Expiry ends the tunnel; the user restarts it. Refreshing
  would need the passphrase to outlive the auth step.
- **Daemonising.** `up` holds the foreground. A daemon that restarts cannot
  re-authenticate without a human.
