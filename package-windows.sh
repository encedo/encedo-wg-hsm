#!/usr/bin/env bash
#
# Builds the Windows bundles: the two clients, the Wintun driver DLL they need,
# and the licences of both. Without wintun.dll beside the executable a Windows
# user gets a failure at the moment the tunnel is created, which is late and
# unhelpful, so it ships in the same archive.
#
# Redistributing wintun.dll is permitted by its own licence — clause 3(d)
# excepts "the Software … distributed alongside other software that uses the
# Software only via the Permitted API", which is what wireguard-go does through
# wintun.h. The conditions that come with it are honoured here: the DLL is
# copied byte for byte and never modified, and its licence travels with it.
#
# DO NOT SIGN wintun.dll. It arrives signed by WireGuard LLC through DigiCert,
# carrying Microsoft's attestation for the driver inside it, and that is the
# signature Windows trusts. Authenticode is written into the PE file, so signing
# it again would both modify the Software — which clause 3(a) forbids, and which
# is the same clause the permission above depends on — and displace a chain we
# cannot reissue. Sign wg-hem.exe and wg-quick-encedo.exe; leave the driver
# exactly as it came.
#
# Run after build.sh, and with the same WG_HEM_DESCR, so the binaries and the
# archive names agree.
set -euo pipefail

WINTUN_VERSION="0.14.1"
WINTUN_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
WINTUN_URL="https://www.wintun.net/builds/wintun-${WINTUN_VERSION}.zip"

cd "$(dirname "$0")"

SUFFIX=""
if [ "${WG_HEM_DESCR:-128}" = "64" ]; then
    SUFFIX="-descr64"
fi

if [ ! -f "dist/wg-hem-windows-amd64${SUFFIX}.exe" ]; then
    echo "dist/wg-hem-windows-amd64${SUFFIX}.exe is missing — run build.sh first" >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

echo "==> Fetching Wintun ${WINTUN_VERSION}..."
curl -sSLf -o "${work}/wintun.zip" "${WINTUN_URL}"

# Verified rather than trusted: this archive is redistributed to users, and a
# driver DLL is not the place to find out that a download was tampered with.
# The hash is the one published beside the download.
echo "${WINTUN_SHA256}  ${work}/wintun.zip" | sha256sum -c - >/dev/null
echo "    checksum verified"

unzip -q "${work}/wintun.zip" -d "${work}/wintun"

for arch in amd64 arm64; do
    name="encedo-wg-windows-${arch}${SUFFIX}"
    stage="${work}/${name}"
    mkdir -p "${stage}"

    # Plain names inside the archive: the platform and record size are already
    # in the name of the archive, and repeating them in every path makes the
    # commands in the README longer than they need to be.
    cp "dist/wg-hem-windows-${arch}${SUFFIX}.exe"          "${stage}/wg-hem.exe"
    cp "dist/wg-quick-encedo-windows-${arch}${SUFFIX}.exe" "${stage}/wg-quick-encedo.exe"
    cp "${work}/wintun/wintun/bin/${arch}/wintun.dll"      "${stage}/wintun.dll"
    cp LICENSE                                             "${stage}/LICENSE.txt"
    cp "${work}/wintun/wintun/LICENSE.txt"                 "${stage}/WINTUN-LICENSE.txt"

    descr_note="128 bytes"
    [ -n "${SUFFIX}" ] && descr_note="64 bytes (legacy firmware)"

    cat > "${stage}/README.txt" <<EOF
encedo-wg for Windows (${arch}), descr records: ${descr_note}

  wg-hem.exe           no configuration file; everything lives in the HEM
  wg-quick-encedo.exe  reads wg1.conf, with the private key replaced by a key id
  wintun.dll           the tunnel driver, ${WINTUN_VERSION}, from wintun.net

Keep all three in the same directory. wintun.dll is loaded by name at run time
and is found beside the executable; moving the .exe on its own will break it.

Run from an elevated PowerShell. Administrator is required rather than merely
convenient: creating the adapter and opening the management pipe both need it.

  .\\wg-hem.exe provision --address 10.99.0.7/32 --peer 'pubkey=...,endpoint=...,allowed-ips=...'
  .\\wg-hem.exe up
  .\\wg-hem.exe status
  .\\wg-hem.exe down

Runtime files — the interface public key and wg-hem's state file — are written
to %ProgramData%\\WireGuard.

Only Linux has been tested end to end. These binaries are built and checked on
every push, but no tunnel has been run on Windows.

LICENSE.txt          this project, MIT
WINTUN-LICENSE.txt   wintun.dll, WireGuard LLC — redistributed unmodified under
                     clause 3(d) of that licence
EOF

    (cd "${work}" && zip -qr "${name}.zip" "${name}")
    mv "${work}/${name}.zip" "dist/${name}.zip"
    echo "    dist/${name}.zip"
done

echo "==> Done."
