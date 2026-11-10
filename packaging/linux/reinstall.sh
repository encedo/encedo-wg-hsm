#!/bin/sh
# Rebuilds both halves from this working tree, packages them and installs the
# result. One command, because doing it by hand has gone wrong in four different
# ways in one afternoon: a stale client, a stale window, a glob that matched two
# packages and installed the older, and a capability dropped by the rebuild.
#
#	sh packaging/linux/reinstall.sh
#
# Everything else - the capability, the group, enabling the service - is the
# package's job and not repeated here.
set -eu

cd "$(dirname "$0")/../.."

ARCH="$(dpkg --print-architecture)"

if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
	# Not a refusal: an uncommitted tree stamps both halves "-dirty", which is
	# consistent and installable. It is worth saying, because that stamp will not
	# match anything built from a commit.
	echo "note: the tree has uncommitted changes; both halves will be stamped -dirty" >&2
fi

echo "==> Building the command-line client"
bash build.sh >/dev/null

echo "==> Building the window"
STAMP="-X github.com/encedo/encedo-wg-hsm/internal/version.Version=$(sh scripts/version.sh)"
mkdir -p dist-gui
( cd gui && CGO_ENABLED=1 go build -ldflags "$STAMP" \
	-o "../dist-gui/encedo-wg-gui-linux-${ARCH}" . )

echo "==> Packaging"
DEB="$(sh packaging/linux/build-deb.sh "$ARCH")"

echo "==> Installing $(basename "$DEB")"
sudo dpkg -i "$DEB"
