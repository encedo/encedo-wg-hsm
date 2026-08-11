# Relationship to wireguard-go

This project is **not** a GitHub fork of wireguard-go. It is a small patch
against a pinned upstream release, applied at build time.

```
upstream   https://git.zx2c4.com/wireguard-go
pinned at  f333402bd9cbe0f3eeb02507bd14e23d7d639280   (0.0.20250522, 2025-05-22)
declared   WG_COMMIT in build.sh
```

`build.sh` clones upstream at that commit, copies in one new file, and applies
one patch. The result lands in `wireguard-go/`, which is generated and not
stored in this repository.

```
_wireguard-go-encedo/
  device/hsm.go                              new file, ours, copied in
  patches/
    0001-delegate-static-key-dh-to-the-hem.patch   49 added / 8 removed lines
```

## Why a patch and not a copy of the files

This repository used to hold complete copies of the three upstream files it
changes — 1550 lines of upstream code carrying 38 lines of our own — and
`build.sh` copied them over the checkout. That works only while the pin never
moves. Raising `WG_COMMIT` would have silently reverted every upstream change to
`device.go`, `peer.go` and `noise-protocol.go`, with no conflict and a green
build, and those are the files the Noise handshake lives in. A security fix
upstream would have disappeared without a word.

A patch fails instead. That failure is the review a version bump deserves.

## What the patch changes

WireGuard's Noise_IKpsk2 needs the static private key in three places. Here it
does not exist, so each call site asks the HEM instead.

| File | Function | Change |
|---|---|---|
| `device/device.go` | `SetPrivateKey` | takes the public key from the injected session rather than deriving it |
| `device/peer.go` | `NewPeer` | `precomputedStaticStatic` comes from the HEM |
| `device/noise-protocol.go` | `ConsumeMessageInitiation` | live DH against the peer's ephemeral, in the HEM |
| `device/noise-protocol.go` | `ConsumeMessageResponse` | the same DH, other side of the handshake |

`device/hsm.go` is new and derived from nothing: it holds `HSMSession` and the
`hsmDH` dispatcher the four call sites reach through. With no session injected,
every one of them falls through to unmodified upstream behaviour.

## Raising the pin

1. Change `WG_COMMIT` in `build.sh`.
2. Run `./build.sh`. If the patch still applies, read what upstream changed
   anyway — the patch applying is not evidence that the surrounding logic still
   means what it did.
3. If it does not apply, the build stops and prints how to regenerate it. Resolve
   by hand:

   ```bash
   cd wireguard-go
   git checkout --force <new-commit> && git clean -qfd
   git apply --3way ../_wireguard-go-encedo/patches/0001-*.patch
   # resolve conflicts, then:
   git diff -- device/ > ../_wireguard-go-encedo/patches/0001-delegate-static-key-dh-to-the-hem.patch
   ```

4. Re-run the tests for **both** record sizes, and re-run a real tunnel against a
   stock kernel WireGuard server. The unit tests do not exercise the handshake.

Do not force a patch through. Every hunk sits on a Diffie-Hellman the whole
design depends on.

## Reading upstream history

The generated checkout is a full clone, so upstream's history is there:

```bash
git -C wireguard-go log --oneline f333402..origin/master -- device/
```

That command is the one worth running before a bump: it lists exactly what
happened to the package this patch lands in.

## Licensing

wireguard-go is MIT, Copyright (C) 2017-2025 WireGuard LLC. The patch reproduces
that notice in each file it touches and records what was changed there, so a
reader who recognises the file learns at the top that its handshake no longer
does what upstream's does. `LICENSE` states the same relationship for the project
as a whole.
