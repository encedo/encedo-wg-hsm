#!/bin/sh
# Rebuilds both halves from this working tree, packages them and installs the
# result. One command, because doing it by hand has gone wrong in four different
# ways in one afternoon: a stale client, a stale window, a glob that matched two
# packages and installed the older, and a capability dropped by the rebuild.
#
#	WG_HEM_DESCR=64 sh packaging/linux/reinstall.sh
#
# The record dialect follows build.sh's convention, so this and the client are
# never asked the same question twice. Everything else — the capability, the
# group, enabling the service — is the package's job and not repeated here.
set -eu

cd "$(dirname "$0")/../.."

ARCH="$(dpkg --print-architecture)"
VARIANT=""
[ "${WG_HEM_DESCR:-}" = "64" ] && VARIANT="-descr64"

if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
	# Not a refusal: an uncommitted tree stamps both halves "-dirty", which is
	# consistent and installable. It is worth saying, because that stamp will not
	# match anything built from a commit.
	echo "note: the tree has uncommitted changes; both halves will be stamped -dirty" >&2
fi

echo "==> Building the command-line client"
WG_HEM_DESCR="${WG_HEM_DESCR:-}" bash build.sh >/dev/null

echo "==> Building the window"
STAMP="-X github.com/encedo/encedo-wg-hsm/internal/version.Version=$(sh scripts/version.sh)"
TAGS=""
[ -n "$VARIANT" ] && TAGS="-tags descr64"
mkdir -p dist-gui
( cd gui && CGO_ENABLED=1 go build $TAGS -ldflags "$STAMP" \
	-o "../dist-gui/encedo-wg-gui-linux-${ARCH}${VARIANT}" . )

echo "==> Packaging"
DEB="$(sh packaging/linux/build-deb.sh "$ARCH" "$VARIANT")"

echo "==> Installing $(basename "$DEB")"
sudo dpkg -i "$DEB"
