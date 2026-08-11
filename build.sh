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

GOOS=linux   GOARCH=amd64 go build -o dist/wg-quick-encedo-linux-amd64        ./cmd/wg-quick-encedo/
GOOS=linux   GOARCH=arm64 go build -o dist/wg-quick-encedo-linux-arm64         ./cmd/wg-quick-encedo/
GOOS=darwin  GOARCH=amd64 go build -o dist/wg-quick-encedo-darwin-amd64        ./cmd/wg-quick-encedo/
GOOS=darwin  GOARCH=arm64 go build -o dist/wg-quick-encedo-darwin-arm64        ./cmd/wg-quick-encedo/
GOOS=windows GOARCH=amd64 go build -o dist/wg-quick-encedo-windows-amd64.exe   ./cmd/wg-quick-encedo/
GOOS=windows GOARCH=arm64 go build -o dist/wg-quick-encedo-windows-arm64.exe   ./cmd/wg-quick-encedo/

echo "==> Done."
ls -lh dist/
