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
	[ -n "${desc}" ] && VERSION="${VERSION}+${desc}"
fi
printf '%s\n' "${VERSION}"
