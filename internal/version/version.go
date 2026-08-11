// Package version carries the release number both commands report.
//
// It is a var rather than a const so a build can stamp the commit it came from:
//
//	go build -ldflags "-X github.com/encedo/encedo-wg-hsm/internal/version.Version=0.9.1-g1a2b3c4"
//
// build.sh does exactly that when the working tree is a git checkout. A plain
// `go build` reports the number below, which is the released one.
package version

// Version is the release number. Semantic: the record format and the MAC
// domain-separation string are what a bump has to consider, since a tree
// written by one build is only readable by another that agrees on both.
var Version = "0.9.1"
