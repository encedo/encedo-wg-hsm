# Releasing

CI builds and verifies every push and publishes nothing. `ci.yml` covers both
command-line clients in both record sizes; `gui.yml` builds the window on three
runners, signs the Windows binaries, and produces the `.deb`, the bundle and the
MSI.

## The order, which matters more than it looks

```
binaries  →  signature  →  package  →  signature of the package
```

Signing an installer wrapped around unsigned binaries is worse than not signing
it at all: Defender looks at what is inside. `gui.yml` therefore signs the loose
executables *before* the bundle copies them, so every copy of every binary is
signed rather than only the ones inside an archive.

Two rules that follow from the certificate rather than from taste:

- **Every signature carries a timestamp.** A Trusted Signing certificate lives
  about three days and is renewed daily. Without a timestamp the signature stops
  verifying within a week of being made.
- **`SHA256SUMS` is computed after signing**, because signing changes the file. A
  `.zip` carries no signature of its own, so the checksums are what covers the
  archive.

One version stamp covers both halves — the window and the privileged component
refuse to work together when their stamps disagree, which is deliberate and is
how a half-upgraded machine announces itself rather than misbehaving quietly.

## Signing on Windows

Signing runs in Actions through **Azure Trusted Signing**, authenticated by OIDC:
there is no key to store, so nothing sensitive lives in the repository. It is
switched on by six repository *variables* and no secrets at all —
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
`TRUSTED_SIGNING_ENDPOINT`, `TRUSTED_SIGNING_ACCOUNT`, `TRUSTED_SIGNING_PROFILE`.
Every signing step is conditioned on the first of them, so a repository without
them builds exactly as it does today rather than failing at a step nobody can
satisfy.

What has to exist in Azure before those mean anything is in
[WINDOWS.md](WINDOWS.md) under *Signing*. The long pole is identity validation —
Microsoft checking that the organisation is who it says it is — and no workflow
can hurry it.

> **Known gaps, both open.** The **MSI is not signed**: the signing step sits
> before the bundle, and the installer is built afterwards with no signing step
> of its own, so the file a person double-clicks first is from an unknown
> publisher. And signing is not yet **gated to tags** — it should run only on a
> tag, in a protected environment, and never on a pull request from a fork.
> Until both are done, releasing is not finished. See `TODO.md`.

## Building by hand

```bash
./build.sh                      # 128-byte records
WG_HEM_DESCR=64 ./build.sh      # 64-byte records, suffixed -descr64

./package-windows.sh            # bundle — AFTER signing, never before
WG_HEM_DESCR=64 ./package-windows.sh

sha256sum dist/*.zip dist/wg-* > dist/SHA256SUMS

git tag -a v0.9.1 -m "0.9.1"    # tag the commit that was built
git push origin v0.9.1
```

Do **not** sign `wintun.dll` — `package-windows.sh` explains why. It is
redistributed unmodified, with its own licence, exactly as clause 3(d) of that
licence provides for.

The submodule goes first: `hem-sdk-go` must be pushed before this repository, or
every workflow dies in checkout on a commit the runner cannot fetch.
