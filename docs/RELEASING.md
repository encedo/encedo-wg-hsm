# Releasing

Three workflows, in the shape encedo-chat uses:

- **`ci.yml`** runs on every push to `main` and `gui` and on pull requests. It
  tests both command-line clients in both record sizes and compiles the window
  and the component on every platform through `build.yml`. It packages nothing
  and uploads nothing, and it deletes artifacts older than a week.
- **`build.yml`** is not run on its own. It is the matrix both other workflows
  call: five runners, the window and the component, and - when `release.yml`
  asks - the `.deb`, the Windows bundles and the MSIs.
- **`release.yml`** runs on a `v*` tag, or by hand. It creates a draft GitHub
  Release, builds everything, signs Windows behind a reviewer, and attaches
  the release's files to the draft. Publishing the draft is done by hand.

Only 128-byte builds are attached. The `descr64` builds are made and signed in
the same run and stay in its artifacts, for the team: none may go out, not even
as a pre-release, so that no customer ever migrates when the firmware drops it
(MVP.md, 3.3). The attach step removes anything named `descr64` and then refuses
to continue if one is left.

What the draft gets: the `.deb` for amd64 and arm64, `encedo-wg-amd64.msi` and
`encedo-wg-arm64.msi` (signed), the macOS window for both architectures, the
command-line clients for Linux and macOS, and `SHA256SUMS` over all of it. No
loose Windows executables: the only Windows files in a release are the signed
installers.

## The order, which matters more than it looks

```
binaries  →  signature  →  package  →  signature of the package
```

Signing an installer wrapped around unsigned binaries is worse than not signing
it at all: Defender looks at what is inside. `release.yml` therefore signs the loose
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

It does not run on every push. The `sign` job in `release.yml` runs after the build,
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
`encedo-wg-windows-signed`. The run log carries the signtool output, which
makes it the record of what was signed and by whom.

Both architectures go through it, and both are assembled by the x64 job: the
component cross-builds, so that job holds both of them and the only window that
works, an arm64 installation being a native component with an emulated x64
window. `docs/WINDOWS.md` has the measurement behind that. Signing is one job on
an x64 runner, because a signature is over a file's bytes and does not care what
machine type its header declares. The one thing that job cannot do is run an
arm64 executable, which is why `build-msi.sh` checks the stamp against the
binary only where the two architectures match, and against the `VERSION` the
build recorded everywhere else.

The `windows-11-arm` job uploads a native arm64 window under a name the signing
job does not match. It ships nowhere, for the reason in `WINDOWS.md`, and is
there to be re-tested.

> **Settled 2026-09-28.** A tag used to yield a signed Windows set from the old
> `gui.yml` and an unsigned one from `ci.yml`, two downloads of one program.
> `ci.yml` no longer runs on tags and uploads nothing, and the draft release
> carries only the signed MSIs. `install.ps1` and `uninstall.ps1` inside the
> bundles are still unsigned; the MSI is the installer, and signing the scripts
> is a follow-up if they stay in the bundle.

## Building by hand

```bash
./build.sh                      # 128-byte records
WG_HEM_DESCR=64 ./build.sh      # 64-byte records, suffixed -descr64

./package-windows.sh            # bundle — AFTER signing, never before
WG_HEM_DESCR=64 ./package-windows.sh

sha256sum dist/*.zip dist/wg-* > dist/SHA256SUMS

git tag -a v0.9.2 -m "0.9.2"    # tag the commit that was built
git push origin v0.9.2          # starts the signed build; it then waits for a reviewer
```

Do **not** sign `wintun.dll` — `package-windows.sh` explains why. It is
redistributed unmodified, with its own licence, exactly as clause 3(d) of that
licence provides for.

The submodule goes first: `hem-sdk-go` must be pushed before this repository, or
every workflow dies in checkout on a commit the runner cannot fetch.
