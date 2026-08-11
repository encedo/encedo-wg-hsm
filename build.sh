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
PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
for cmd in wg-quick-encedo wg-hem; do
    for platform in ${PLATFORMS}; do
        os="${platform%/*}"
        arch="${platform#*/}"
        out="dist/${cmd}-${os}-${arch}"
        [ "${os}" = "windows" ] && out="${out}.exe"
        GOOS="${os}" GOARCH="${arch}" go build -o "${out}" "./cmd/${cmd}/"
    done
done

echo "==> Done."
ls -lh dist/
