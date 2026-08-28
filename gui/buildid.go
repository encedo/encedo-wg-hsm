package main

import (
	"fmt"
	"strings"
)

// buildID is the build on screen in the shortest form that still names it:
// `v0.9.1 (f18ed43)`.
//
// The version alone does not identify a build. Several carry one version, and
// the first question a bug report has to answer is which code produced the
// behaviour - which is why this is beside the Advanced toggle rather than
// inside the panel it opens. The panel keeps the long form, the one the
// component compared against and the one somebody reads out after a refusal;
// this is the one that is simply there.
//
// It is the same line, in the same shape, that onchato.com/chat puts in its
// login card and at the foot of its settings. Two products of one house
// answering "which build is this?" two different ways is a difference nobody
// benefits from.
//
// The dirty marker is a trailing `+` rather than the `-dirty` git describe
// writes: a build from uncommitted work is not the commit it names, and one
// character says so in a row that already has a checkbox in it.
func buildID(release string) string {
	// Empty is not a build with no name, it is a build the stamp never reached
	// - and the component refuses it by protocol ("start needs to say which
	// build is asking"). Saying so here is how somebody learns that before the
	// refusal rather than from it.
	if release == "" {
		return "unstamped build"
	}
	version, commit, ok := strings.Cut(release, "+")
	if !ok || commit == "" {
		// A build stamped with a bare version - `go run .` without ldflags. No
		// hash to name, and empty parentheses read as one that failed to load.
		return "v" + version
	}
	dirty := ""
	if trimmed, cut := strings.CutSuffix(commit, "-dirty"); cut {
		commit, dirty = trimmed, "+"
	}
	return fmt.Sprintf("v%s (%s%s)", version, commit, dirty)
}
