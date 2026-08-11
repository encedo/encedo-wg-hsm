#!/usr/bin/env bash
set -euo pipefail

WG_REPO="https://git.zx2c4.com/wireguard-go"
WG_COMMIT="f333402"
WG_DIR="wireguard-go"
PATCH_DIR="_wireguard-go-encedo"

echo "==> Checking out wireguard-go @ ${WG_COMMIT}..."
if [ -d "${WG_DIR}/.git" ]; then
    echo "    already cloned, pulling..."
    git -C "${WG_DIR}" fetch --quiet
else
    rm -rf "${WG_DIR}"
    git clone --quiet "${WG_REPO}" "${WG_DIR}"
fi
git -C "${WG_DIR}" checkout --quiet "${WG_COMMIT}"

echo "==> Overlaying Encedo patches..."
cp -r "${PATCH_DIR}/." "${WG_DIR}/"

echo "==> Building..."
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
VERSION="$(sed -n 's/^var Version = "\(.*\)"$/\1/p' internal/version/version.go)"
if git rev-parse --git-dir >/dev/null 2>&1; then
    desc="$(git describe --always --dirty 2>/dev/null || true)"
    [ -n "${desc}" ] && VERSION="${VERSION}+${desc}"
fi
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
