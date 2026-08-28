package main

import (
	"testing"

	"fyne.io/fyne/v2/test"
)

// The shapes version.sh can produce, and what each has to read as. It is a
// table rather than three assertions because the interesting cases are the ones
// that are not the everyday one: a tree nobody committed, and a build the stamp
// never reached.
func TestBuildIDNamesTheCommit(t *testing.T) {
	cases := []struct {
		name    string
		release string
		want    string
	}{
		{"a build from a commit", "0.9.1+f18ed43", "v0.9.1 (f18ed43)"},
		{"built from uncommitted work", "0.9.1+f18ed43-dirty", "v0.9.1 (f18ed43+)"},
		{"a repository with tags", "0.9.1+v0.9.1-12-gf18ed43", "v0.9.1 (v0.9.1-12-gf18ed43)"},
		{"no git, so no commit to name", "0.9.1", "v0.9.1"},
		{"the stamp never ran", "", "unstamped build"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildID(tc.release); got != tc.want {
				t.Errorf("buildID(%q) = %q, want %q", tc.release, got, tc.want)
			}
		})
	}
}

// The build shares a row with the Advanced toggle, and the window is a fixed
// width. A row that needs more than it has does not complain: the border layout
// gives the toggle its minimum and draws the build over the top of it.
//
// Measured against the longest thing that row can hold - a describe that names
// a tag, a distance and a dirty tree, which is what a build from somebody's
// working copy between releases looks like.
func TestTheBuildRowFits(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()

	u := &ui{app: a, sess: newFakeSession()}
	defer u.sess.Close()
	u.win = test.NewWindow(nil)
	defer u.win.Close()
	u.build()

	u.buildText.SetText(buildID("0.9.1+v0.9.1-12-gf18ed43-dirty"))
	u.render(Event{State: Ready})

	if need := u.win.Content().MinSize().Width; need > windowWidth {
		t.Errorf("the footer needs %.1f of width and the window is %d - the build will be drawn over the toggle",
			need, windowWidth)
	}
}
