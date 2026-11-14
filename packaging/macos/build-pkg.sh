#!/bin/bash
# Builds the macOS installer: the window as "Encedo WG.app", both command-line
# clients, the launchd job that runs the privileged component, and the script
# that takes it all away again.
#
#   packaging/macos/build-pkg.sh <arm64|amd64>
#
# Run on macOS from the repository root, after the cell has built
#   dist/wg-hem-darwin-<arch>, dist/wg-quick-encedo-darwin-<arch>,
#   dist-gui/encedo-wg-gui-darwin-<arch> and dist-gui/VERSION.
# Writes dist-pkg/wg-hem-gui-darwin-<arch>.pkg. Unsigned: signing and
# notarisation wait for the Apple Developer account (docs/MACOS.md, phase 5),
# so an installer from here opens past a Gatekeeper warning and is for testing.
set -euo pipefail

arch="${1:?usage: $0 <arm64|amd64>}"
here="packaging/macos"
cli="dist/wg-hem-darwin-$arch"
quick="dist/wg-quick-encedo-darwin-$arch"
gui="dist-gui/encedo-wg-gui-darwin-$arch"
for f in "$cli" "$quick" "$gui" dist-gui/VERSION; do
	[ -f "$f" ] || { echo "missing $f - build the cell first" >&2; exit 1; }
done

stamp="$(cat dist-gui/VERSION)"
# CFBundleShortVersionString wants numbers; the stamp goes in CFBundleVersion.
release="${stamp%%[+-]*}"

# The two halves refuse each other unless their stamps match; checked here, on
# the machine that can run both, rather than after somebody installs them.
# Only the native architecture can be run, as with the MSI.
if [ "$arch" = "$(uname -m | sed 's/x86_64/amd64/')" ]; then
	said="$("$cli" version)"
	[ "$said" = "wg-hem $stamp" ] || { echo "stamp mismatch: $said, want $stamp" >&2; exit 1; }
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/root"

app="$root/Applications/Encedo WG.app/Contents"
mkdir -p "$app/MacOS" "$app/Resources"
install -m 755 "$gui" "$app/MacOS/encedo-wg-gui"
sed -e "s/@RELEASE@/$release/" -e "s/@STAMP@/$stamp/" "$here/Info.plist.in" > "$app/Info.plist"
plutil -lint "$app/Info.plist" >/dev/null

# The icon, from the one PNG the repository keeps, at the sizes an iconset has.
iconset="$work/icon.iconset"
mkdir -p "$iconset"
for s in 16 32 128 256 512; do
	sips -z $s $s gui/packaging/icon-1024.png --out "$iconset/icon_${s}x${s}.png" >/dev/null
	d=$((s * 2))
	sips -z $d $d gui/packaging/icon-1024.png --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Resources/icon.icns"

# Seal the bundle with an ad-hoc signature until there is a Developer ID. The Go
# linker signs the executable alone, so the bundle had no identity tying the
# Info.plist to it, and macOS listed the app under Local Network with the switch
# on while still refusing its connections ("no route to the address"). Launched
# from Terminal it worked, on Terminal's permission. Re-signing the installed
# bundle this way fixed it on the first Mac, 2026-11-14.
codesign --force --sign - "$app/.."
codesign --verify --strict "$app/.."

mkdir -p "$root/usr/local/bin" "$root/Library/LaunchDaemons"
install -m 755 "$cli"   "$root/usr/local/bin/wg-hem"
install -m 755 "$quick" "$root/usr/local/bin/wg-quick-encedo"
install -m 755 "$here/encedo-wg-uninstall" "$root/usr/local/bin/encedo-wg-uninstall"
install -m 644 "$here/com.encedo.wg.plist" "$root/Library/LaunchDaemons/com.encedo.wg.plist"
plutil -lint "$root/Library/LaunchDaemons/com.encedo.wg.plist" >/dev/null

# Without this, Installer may put the app wherever it finds an older copy
# with the same bundle id instead of /Applications.
comp="$work/component.plist"
pkgbuild --analyze --root "$root" "$comp" >/dev/null
plutil -replace BundleIsRelocatable -bool NO "$comp"

mkdir -p dist-pkg
out="dist-pkg/wg-hem-gui-darwin-$arch.pkg"
pkgbuild --root "$root" --component-plist "$comp" \
	--scripts "$here/scripts" \
	--identifier com.encedo.wg --version "$release" \
	--install-location / "$out"
pkgutil --payload-files "$out" | sed 's/^/  /'
ls -l "$out"
