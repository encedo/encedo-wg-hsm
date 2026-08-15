#!/usr/bin/env bash
set -euo pipefail

WG_REPO="https://git.zx2c4.com/wireguard-go"
WG_COMMIT="f333402"
WG_DIR="wireguard-go"
PATCH_DIR="_wireguard-go-encedo"

PATCH_ABS="$(cd "$(dirname "$0")" && pwd)/${PATCH_DIR}"

echo "==> Checking out wireguard-go @ ${WG_COMMIT}..."
if [ -d "${WG_DIR}/.git" ]; then
    echo "    already cloned, fetching..."
    git -C "${WG_DIR}" fetch --quiet
else
    rm -rf "${WG_DIR}"
    git clone --quiet "${WG_REPO}" "${WG_DIR}"
fi
# --force and clean, not a plain checkout: the previous build left this tree
# patched, and a patch is not idempotent the way the old file copy was. The
# checkout has to put upstream back exactly before anything is applied again.
git -C "${WG_DIR}" checkout --quiet --force "${WG_COMMIT}"
git -C "${WG_DIR}" clean -qfd

echo "==> Applying the Encedo changes..."
# hsm.go is ours outright, so it is copied in. The other three files are
# upstream's and are changed by patch rather than replaced. That distinction is
# the point: a whole-file copy would silently discard whatever upstream had done
# to those files since WG_COMMIT, and they are the files the handshake lives in.
# A patch that no longer applies stops the build, which is the review that a
# version bump deserves.
cp "${PATCH_ABS}/device/hsm.go" "${WG_DIR}/device/hsm.go"
for patch in "${PATCH_ABS}"/patches/*.patch; do
    name="$(basename "${patch}")"
    if git -C "${WG_DIR}" apply --whitespace=nowarn "${patch}"; then
        echo "    applied ${name}"
    else
        cat >&2 <<MSG

${name} does not apply to wireguard-go ${WG_COMMIT}.

Upstream has changed the lines this project depends on. Do not force it: the
patch touches the static-key Diffie-Hellman in the Noise handshake, and the
whole design rests on those call sites. Read what upstream changed, decide
whether the delegation still belongs where it was, and regenerate:

    cd ${WG_DIR}
    git checkout --force ${WG_COMMIT} && git clean -qfd
    git apply --3way ${patch}      # resolve the conflicts by hand
    git diff -- device/ > ${patch}

See UPSTREAM.md.
MSG
        exit 1
    fi
done

# WG_PREPARE_ONLY stops here, with the patched upstream tree in place and
# nothing built. It exists for the Windows job in .github/workflows/gui.yml,
# which needs that tree in order to build the component beside the window — the
# component imports wireguard-go, and go.mod resolves it to this directory — but
# does not want the other eleven binaries this script would go on to produce.
if [ -n "${WG_PREPARE_ONLY:-}" ]; then
    echo "==> Prepared; stopping before the build as asked."
    exit 0
fi

echo "==> Building..."

# Emptied first, every time. This directory used to accumulate, and what
# accumulated was two series differing by one suffix in the filename: a
# descr64 build beside a default one, three days apart, both plausible. Picking
# the wrong one does not fail — the record length is inside the configuration
# MAC, so it reads as a corrupt tree rather than as a mismatched binary, which is
# an hour spent looking at the wrong thing.
#
# The cost is that building both record sizes now means keeping the first
# elsewhere, which is the right way round: two variants side by side is a
# deliberate act and should look like one, rather than being what happens when
# nobody cleans up. packaging/linux/reinstall.sh clears old packages for the same
# reason, and that was written after a glob matched two of them and installed the
# older.
rm -rf dist
mkdir -p dist

# wg-quick-encedo: the config-file client (v1).
# wg-hem:          the config-free client, everything in the HEM (docs/).
# WG_HEM_DESCR=64 builds against firmware whose descr field is 64 bytes rather
# than 128. The record length is part of what the configuration MAC covers, so
# such a binary and a default one cannot read each other's trees; the suffix
# keeps the two apart in dist/.
TAGS=""
SUFFIX=""
if [ "${WG_HEM_DESCR:-128}" = "64" ]; then
    TAGS="descr64"
    SUFFIX="-descr64"
    echo "    descr field: 64 bytes (legacy firmware)"
fi

# The release number lives in internal/version; a checkout stamps the commit
# onto it, so a binary from a working tree says which one it came from and a
# tagged build says only the release.
VERSION="$(sh scripts/version.sh)"
echo "    version: ${VERSION}"

PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
for cmd in wg-quick-encedo wg-hem; do
    for platform in ${PLATFORMS}; do
        os="${platform%/*}"
        arch="${platform#*/}"
        out="dist/${cmd}-${os}-${arch}${SUFFIX}"
        [ "${os}" = "windows" ] && out="${out}.exe"
        # CGO_ENABLED=0 for every target, not just the cross ones: a native build
        # would otherwise link against the builder's glibc and refuse to start on
        # an older distribution, while the cross builds are static already. Same
        # switch everywhere means the artefacts are alike.
        CGO_ENABLED=0 GOOS="${os}" GOARCH="${arch}" go build \
            ${TAGS:+-tags "${TAGS}"} \
            -ldflags "-X github.com/encedo/encedo-wg-hsm/internal/version.Version=${VERSION}" \
            -o "${out}" "./cmd/${cmd}/"
    done
done

echo "==> Done."
ls -lh dist/
