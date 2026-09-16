# Releasing

CI builds and verifies every push and publishes nothing. `ci.yml` covers both
command-line clients in both record sizes; `gui.yml` builds the window on three
runners and produces the `.deb`, the bundle and the MSI. On a `v*` tag, or on
request, a second job in `gui.yml` signs the Windows output — see below.

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

Signing runs in Actions through **Azure Artifact Signing** — the service
Microsoft launched as Trusted Signing and renamed in 2026 — authenticated by
OIDC: there is no key to store, so nothing sensitive lives in the repository.
Six repository *variables* and no secrets say which account to use —
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
`TRUSTED_SIGNING_ENDPOINT`, `TRUSTED_SIGNING_ACCOUNT`, `TRUSTED_SIGNING_PROFILE`
— and what stands behind them in Azure is in [WINDOWS.md](WINDOWS.md) under
*Signing*.

It works: first proven on 2026-09-16, and `docs/WINDOWS.md` has the run and
the one trap in the Azure portal that cost the first attempt.

It does not run on every push. The `sign` job in `gui.yml` runs after the build,
only on a `v*` tag or a manual run with *sign* ticked, and only inside the
`release` environment, which waits for a reviewer. Three things follow:

- **The environment name is part of the credential.** Azure accepts the OIDC
  token only when its subject is `repo:encedo/encedo-wg-hsm:environment:release`.
  A job outside that environment, or an environment under another name, fails at
  login with `AADSTS700213`.
- **The environment decides which refs may sign.** Its deployment rules list the
  `v*` tags; a manual run from a branch not on the list fails before its first
  step. Add the branch for a test, remove it afterwards.
- **A pull request never signs.** The job's condition names the two events that
  may reach it, and `pull_request` is not one of them.

What the job does, in the order above: signs every executable the build
uploaded, the copies inside the staged bundles included; rebuilds the MSI from
the signed stage with `packaging/windows/build-msi.sh`, the same script the
build used; signs the MSI; verifies every signature with `signtool verify /pa /v`
and refuses one without a timestamp; writes `SHA256SUMS`; and uploads
`encedo-wg-windows-signed-X64`. The run log carries the signtool output, which
makes it the record of what was signed and by whom.

> **Still open.** `ci.yml` also runs on `v*` tags and publishes Windows bundles
> cross-built on Linux, which cannot be signed there — so a tag yields a signed
> set from `gui.yml` and an unsigned set from `ci.yml`, two downloads of one
> program. Either the latter stop being published or they are built and signed
> on Windows; until one of those is done, releasing is not finished. The build
> job's own unsigned Windows upload is the same shape of thing, on a smaller
> scale — it is what the sign job consumes, and it should not be what anyone
> is handed. `install.ps1` and `uninstall.ps1` are not signed either; the MSI is
> the installer, and signing the scripts is a follow-up if they stay in the
> bundle.

## Building by hand

```bash
./build.sh                      # 128-byte records
WG_HEM_DESCR=64 ./build.sh      # 64-byte records, suffixed -descr64

./package-windows.sh            # bundle — AFTER signing, never before
WG_HEM_DESCR=64 ./package-windows.sh

sha256sum dist/*.zip dist/wg-* > dist/SHA256SUMS

git tag -a v0.9.1 -m "0.9.1"    # tag the commit that was built
git push origin v0.9.1          # starts the signed build; it then waits for a reviewer
```

Do **not** sign `wintun.dll` — `package-windows.sh` explains why. It is
redistributed unmodified, with its own licence, exactly as clause 3(d) of that
licence provides for.

The submodule goes first: `hem-sdk-go` must be pushed before this repository, or
every workflow dies in checkout on a commit the runner cannot fetch.
