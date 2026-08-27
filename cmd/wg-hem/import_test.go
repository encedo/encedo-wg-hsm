package main

import (
	"strings"
	"testing"
)

// TestImportTakesTheFileInEitherPosition. Go's flag package stops at the first
// argument that is not a flag, so a file written before the flags left them
// unparsed - and the command then asked for a name it had already been given.
func TestImportTakesTheFileInEitherPosition(t *testing.T) {
	cases := [][]string{
		{"client.conf", "-name", "x", "-dry-run"},
		{"-name", "x", "client.conf", "-dry-run"},
		{"-dry-run", "client.conf", "-name", "x"},
		{"-name=x", "client.conf"},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			ours, _ := splitAtDoubleDash(args)
			path, rest := takeFirstBareArg(ours)
			if path != "client.conf" {
				t.Fatalf("found the file as %q", path)
			}
			for _, r := range rest {
				if r == "client.conf" {
					t.Fatal("the file was left in the flags as well")
				}
			}
		})
	}
}

func TestImportPassesTheRestToProvision(t *testing.T) {
	ours, theirs := splitAtDoubleDash(
		[]string{"client.conf", "-name", "x", "--", "-session", "8", "-label", "laptop"})
	if got := strings.Join(theirs, " "); got != "-session 8 -label laptop" {
		t.Errorf("passthrough = %q", got)
	}
	if path, _ := takeFirstBareArg(ours); path != "client.conf" {
		t.Errorf("file = %q", path)
	}
}
