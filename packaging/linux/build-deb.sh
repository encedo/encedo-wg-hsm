#!/bin/sh
# Builds a .deb holding both halves of the graphical client and the three files
# that let them run without anybody being an administrator.
#
# Run from the repository root, after build.sh has produced dist/ and the window
# has been built into dist-gui/. Both are needed and neither is built here: the
# command-line client is cross-compiled from one machine, the window needs cgo
# and a build per platform, and pretending otherwise is how a package ends up
# with two halves from different commits.
#
#	WG_HEM_DESCR=64 bash build.sh
#	(cd gui && go build -tags descr64 -ldflags "-X …version.Version=$(sh scripts/version.sh)" -o ../dist-gui/encedo-wg-gui-linux-arm64-descr64 .)
#	sh packaging/linux/build-deb.sh arm64 -descr64
set -eu

ARCH="${1:-amd64}"
VARIANT="${2:-}"   # "" or -descr64

ROOT="$(pwd)"
VERSION="$(sh scripts/version.sh)"
# Debian will not take a + or a dirty marker in a version the way git prints it.
DEBVER="$(printf '%s' "$VERSION" | tr '+' '~')"

CLI="dist/wg-hem-linux-${ARCH}${VARIANT}"
GUI="dist-gui/encedo-wg-gui-linux-${ARCH}${VARIANT}"
for f in "$CLI" "$GUI"; do
	[ -f "$ROOT/$f" ] || { echo "missing $f — see the comment at the top" >&2; exit 1; }
done

# The two halves refuse to drive each other unless their stamps match, so a
# package containing a mismatched pair is a package that cannot work. Better to
# find that here than after somebody installs it — and both halves are checked,
# because a stale window is exactly the mismatch this is guarding against.
stale() {
	cat >&2 <<MSG
$1 was built at $2, and this tree is $VERSION.

Packaging them together would produce a window and a component that refuse to
drive each other. Rebuild both from here:

  WG_HEM_DESCR=64 bash build.sh
  STAMP="-X github.com/encedo/encedo-wg-hsm/internal/version.Version=\$(sh scripts/version.sh)"
  (cd gui && go build -tags descr64 -ldflags "\$STAMP" -o ../$GUI .)
MSG
	exit 1
}

cli_build="$("$ROOT/$CLI" version)"
case "$cli_build" in
	*"$VERSION"*) ;;
	*) stale "$CLI" "$cli_build" ;;
esac

gui_build="$("$ROOT/$GUI" -version | tail -1)"
case "$gui_build" in
	*"$VERSION"*) ;;
	*) stale "$GUI" "$gui_build" ;;
esac

PKG="$(mktemp -d)"
trap 'rm -rf "$PKG"' EXIT

install -Dm755 "$ROOT/$CLI" "$PKG/usr/bin/wg-hem"
install -Dm755 "$ROOT/$GUI" "$PKG/usr/bin/encedo-wg-gui"

install -Dm644 "$ROOT/packaging/linux/encedo-wg.service"        "$PKG/lib/systemd/system/encedo-wg.service"
install -Dm644 "$ROOT/packaging/linux/wireguard.conf"           "$PKG/usr/lib/tmpfiles.d/wireguard.conf"
install -Dm644 "$ROOT/packaging/linux/50-encedo-wg-resolve.rules" "$PKG/usr/share/polkit-1/rules.d/50-encedo-wg-resolve.rules"

install -Dm644 "$ROOT/gui/icon.svg" "$PKG/usr/share/icons/hicolor/scalable/apps/encedo-wg.svg"

# The installed entry points at the installed binary and at the service's socket,
# so opening it from the applications list does the whole thing.
mkdir -p "$PKG/usr/share/applications"
sed 's|^Exec=.*|Exec=/usr/bin/encedo-wg-gui -live /run/encedo-wg/wg-hem.sock|' \
	"$ROOT/gui/packaging/encedo-wg.desktop" > "$PKG/usr/share/applications/encedo-wg.desktop"
chmod 644 "$PKG/usr/share/applications/encedo-wg.desktop"

mkdir -p "$PKG/DEBIAN"
cat > "$PKG/DEBIAN/control" <<EOF
Package: encedo-wg
Version: ${DEBVER}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Krzysztof Rutecki <krzysztof@encedo.com>
Depends: libgl1, libx11-6, libcap2-bin, adduser
Recommends: wireguard-tools
Description: WireGuard client whose private key never leaves an Encedo module
 The key is generated inside the hardware module and stays there; every
 handshake asks the device to do the Diffie-Hellman. Nothing cryptographic is
 written to disk, and there is no configuration file.
 .
 Installs the command-line client, a window, and a service that lets the window
 run tunnels without anybody being an administrator.
EOF

cat > "$PKG/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

# The service runs as its own user, holding one capability and no more.
if ! getent passwd encedo-wg >/dev/null; then
	adduser --system --group --no-create-home --home /nonexistent \
		--gecos "Encedo WireGuard service" encedo-wg
fi

# /var/run/wireguard is shared with the command-line client and with wg(8), by
# group. The service joins it; a person who wants to run `wg-hem up` themselves
# adds their own account.
if ! getent group wireguard >/dev/null; then
	addgroup --system wireguard
fi
adduser encedo-wg wireguard >/dev/null 2>&1 || true

systemd-tmpfiles --create /usr/lib/tmpfiles.d/wireguard.conf >/dev/null 2>&1 || true

# The capability the command-line client needs, granted here because dpkg does
# not carry file capabilities through an upgrade and a person should not have to
# know that. It lives in the file's extended attributes, so every install drops
# it and every install has to put it back.
#
# The service does not depend on this — it has the capability from its unit —
# but a file carrying any capability clears the ambient set on exec, so this
# grant is what the service ends up using too. One source rather than two that
# could disagree.
setcap cap_net_admin=eip /usr/bin/wg-hem 2>/dev/null || true

# Whoever installed this is who will use it. Being in the group is what lets the
# window reach the service and lets `wg-hem status` read the run directory, and
# it is the one thing a package cannot finish: group membership is fixed when a
# session begins, so it takes a log out or a reboot.
target_user="${SUDO_USER:-}"
if [ -z "$target_user" ] && [ -n "${PKEXEC_UID:-}" ]; then
	target_user="$(getent passwd "$PKEXEC_UID" | cut -d: -f1)"
fi
if [ -n "$target_user" ] && [ "$target_user" != root ]; then
	adduser "$target_user" wireguard >/dev/null 2>&1 || true
fi

# Not enabled at boot. The service exists so that opening the window does not
# require being an administrator, not so that a tunnel exists without anybody
# opening anything — and a socket-activated service would still be the right
# shape later.
systemctl daemon-reload >/dev/null 2>&1 || true

systemctl enable encedo-wg >/dev/null 2>&1 || true
systemctl restart encedo-wg >/dev/null 2>&1 || true

cat <<MSG

encedo-wg is installed and the service is running.

  capability   granted on /usr/bin/wg-hem
  group        ${target_user:-nobody} added to "wireguard"
  service      enabled and started

Group membership is fixed when a session begins, so log out and back in — or
reboot — before opening the window. Until then it cannot reach the service, and
says so as a permission error rather than as anything about groups.

MSG
EOF
chmod 755 "$PKG/DEBIAN/postinst"

cat > "$PKG/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ]; then
	systemctl stop encedo-wg >/dev/null 2>&1 || true
	systemctl disable encedo-wg >/dev/null 2>&1 || true
fi
EOF
chmod 755 "$PKG/DEBIAN/prerm"

mkdir -p "$ROOT/dist-deb"

# Older packages for the same architecture and dialect go, because they are this
# script's own output and leaving them is a trap: `dpkg -i dist-deb/*.deb` then
# matches several, unpacks all of them and configures whichever it reaches last,
# which is not the one that was just built. Seen doing exactly that.
rm -f "$ROOT/dist-deb"/encedo-wg_*_"${ARCH}${VARIANT}".deb

OUT="$ROOT/dist-deb/encedo-wg_${DEBVER}_${ARCH}${VARIANT}.deb"
dpkg-deb --build --root-owner-group "$PKG" "$OUT" >/dev/null
echo "$OUT"
