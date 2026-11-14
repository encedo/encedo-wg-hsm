#!/bin/sh
# Prints the version both artifacts stamp themselves with.
#
# It exists as its own file because two builds need the same answer and they are
# not the same build: the command-line client is cross-compiled from one machine
# by build.sh, the window needs cgo and is built per platform in CI. When the two
# disagree they refuse to drive each other - deliberately, since a mismatched
# pair fails later and worse - so "the same answer" has to mean one definition
# rather than two that were equal when they were written.
#
# Run from the repository root.
set -eu

VERSION="$(sed -n 's/^var Version = "\(.*\)"$/\1/p' internal/version/version.go)"
if git rev-parse --git-dir >/dev/null 2>&1; then
	desc="$(git describe --always --dirty 2>/dev/null || true)"
	case "${desc}" in
		# On this release's own tag, or past it: the tag already says the
		# version, so it is the version - 0.9.3-rc3, 0.9.3-rc3-2-gabc1234 -
		# rather than 0.9.3+v0.9.3-rc3, which repeated it.
		"v${VERSION}" | "v${VERSION}"-*) VERSION="${desc#v}" ;;
		"") ;;
		*) VERSION="${VERSION}+${desc}" ;;
	esac
fi
printf '%s\n' "${VERSION}"
