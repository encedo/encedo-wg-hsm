#!/bin/sh
# Installs the window as an application the desktop knows about, rather than as
# a binary somebody runs from a terminal.
#
# It is a real gap and not a nicety: an executable with no desktop entry has no
# icon in the dash, no name but its filename, and no way to be launched except by
# path. The tray icon looked right the whole time, which made it look like
# something half-finished rather than something never installed.
#
# Everything goes under ~/.local by default, so no privileges are needed. Set
# PREFIX=/usr/local and run it with sudo to install for everybody.
set -eu

BIN=${1:-}
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
	echo "usage: $0 <path-to-encedo-wg-gui>" >&2
	exit 2
fi

PREFIX=${PREFIX:-$HOME/.local}
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -Dm755 "$BIN" "$PREFIX/bin/encedo-wg-gui"
install -Dm644 "$here/../icon.svg" "$PREFIX/share/icons/hicolor/scalable/apps/encedo-wg.svg"

# The entry names the binary by its full path. ~/.local/bin is on PATH for most
# desktops and on some it is not, and an entry that only works on the first kind
# is the sort of thing nobody can reproduce.
install -d "$PREFIX/share/applications"
sed "s|^Exec=.*|Exec=$PREFIX/bin/encedo-wg-gui|" \
	"$here/encedo-wg.desktop" > "$PREFIX/share/applications/encedo-wg.desktop"
chmod 644 "$PREFIX/share/applications/encedo-wg.desktop"

# Both caches are advisory - the desktop rebuilds them itself eventually, and
# neither exists on every system - so a failure here is not a failed install.
update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
gtk-update-icon-cache -f -t "$PREFIX/share/icons/hicolor" 2>/dev/null || true

echo "Installed to $PREFIX. It should appear in the applications list as encedo-wg."
echo "If the icon is still a placeholder, log out and back in - the dash caches by WM_CLASS."
