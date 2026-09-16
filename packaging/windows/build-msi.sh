#!/usr/bin/env bash
# Builds the Windows installer from a staged bundle: one file to download and
# double-click.
#
#     packaging/windows/build-msi.sh <amd64|arm64> <build-number>
#
# Run from the repository root, after the Bundle step has laid down
# dist-gui/encedo-wg-windows-<arch>-descr64/. Writes dist-gui/encedo-wg-<arch>.msi.
#
# A script rather than a workflow step because two jobs in gui.yml build the
# installer and must not drift: the build job, from binaries fresh off the
# compiler, and the sign job, again, from the same stage once the binaries in it
# carry a signature. An installer embeds its payload, so signing it does not
# reach inside - the MSI has to be rebuilt after the executables are signed and
# then signed itself. Two copies of this logic would be two things to forget.
#
# Only the descr64 dialect gets an installer. The two record sizes cannot read
# each other's configuration, so a machine wants exactly one of them, and two
# installers sharing an UpgradeCode would silently replace each other while two
# with different ones would fight over the same directory. Today's firmware is
# 64-byte; when that stops being true this grows a second product rather than a
# second file.
#
# WiX needs Windows: it is .NET and starts on Linux, but the bind phase - where
# the MSI database is written - wants msi.dll. The authoring is checked on Linux
# up to that point, which catches everything except one bogus complaint about
# Directory/@Name.
set -euo pipefail

usage="usage: $0 <amd64|arm64> <build-number>"
goarch="${1:?$usage}"
build="${2:?$usage}"
case "$goarch" in
	amd64) wixarch=x64   ;;
	arm64) wixarch=arm64 ;;
	*) echo "unknown architecture $goarch" >&2; exit 1 ;;
esac

stage="dist-gui/encedo-wg-windows-$goarch-descr64"
[ -f "$stage/wg-hem.exe" ] || {
	echo "no bundle at $stage - the Bundle step comes first" >&2; exit 1; }

VERSION="$(sh scripts/version.sh)"

# The stamp goes into the installer twice - ARPCOMMENTS, and a registry value
# the two halves can be checked against - so it has to be the stamp the
# binaries carry, not merely the one this checkout computes. The two agree by
# construction when the installer is built beside the compiler; when it is
# rebuilt in another job from downloaded binaries they agree only if that job
# checked out the same commit in the same state, and this is where that is
# checked rather than assumed. The component says its own stamp; the window
# cannot be asked, but it was built from the same VERSION in the same step.
said="$("$stage/wg-hem.exe" version)"
[ "$said" = "wg-hem $VERSION (descr 64 B)" ] || {
	echo "stamp mismatch: this checkout says '$VERSION', the component says '$said'" >&2
	exit 1; }

# MSI versions are numeric and only the first three fields decide an upgrade,
# so the release goes in those and the build number in the fourth. Without the
# build number every build of a release would look like the same version and an
# upgrade would decline to replace it.
release="${VERSION%%+*}"
msiversion="$release.$build"

export PATH="$PATH:$HOME/.dotnet/tools"
command -v wix >/dev/null 2>&1 || dotnet tool install --global wix --version 5.0.2 >/dev/null

wix build -arch "$wixarch" \
	-d Version="$msiversion" \
	-d Stamp="$VERSION (descr 64 B)" \
	-d Payload="$(cd "$stage" && pwd)" \
	packaging/windows/encedo-wg.wxs \
	-o "dist-gui/encedo-wg-$goarch.msi"

ls -l "dist-gui/encedo-wg-$goarch.msi"
