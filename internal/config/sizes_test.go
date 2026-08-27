package config

import (
	"strings"
	"testing"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

func otherSize() int {
	if descr.Size == 64 {
		return 128
	}
	return 64
}

// The firmware-day case: every record the device returns is the other length.
// That is one dialect meeting another, and it is the whole reason this exists -
// the failure it causes is reported as "failed authentication", which reads as
// tampering to anyone who has not been told otherwise.
func TestSizesExplainsAConsistentDifference(t *testing.T) {
	s := newSizes(otherSize())
	s.add(otherSize())
	s.add(otherSize())

	got := s.explain()
	if got == "" {
		t.Fatal("a device speaking the other size explains nothing")
	}
	if !strings.Contains(got, "not tampering") {
		t.Errorf("the explanation does not correct the obvious reading:\n%s", got)
	}
}

// A build that matches must stay silent, or every unrelated failure grows a
// paragraph about record sizes and people learn to skip it.
func TestSizesIsSilentWhenTheyMatch(t *testing.T) {
	s := newSizes(descr.Size)
	s.add(descr.Size)
	if got := s.explain(); got != "" {
		t.Errorf("explained a device that agrees:\n%s", got)
	}
}

// Records of assorted lengths mean something other than a dialect mismatch,
// and this has no business guessing what. Saying nothing is the honest answer.
func TestSizesIsSilentWhenTheLengthsDisagree(t *testing.T) {
	s := newSizes(otherSize())
	s.add(descr.Size)
	if got := s.explain(); got != "" {
		t.Errorf("explained a mixture it cannot account for:\n%s", got)
	}
}
