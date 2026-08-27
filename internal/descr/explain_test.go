package descr

import (
	"strings"
	"testing"
)

// The day the firmware changes record size, every client in the field reports
// "failed authentication" until it is replaced. Without this sentence beside
// it, that message says somebody has edited the configuration - which is the
// opposite of what happened and calls for the opposite reaction.
func TestExplainSizeNamesBothLengths(t *testing.T) {
	other := 64
	if Size == 64 {
		other = 128
	}
	got := ExplainSize(other)
	if got == "" {
		t.Fatal("a record of the other size explains nothing")
	}
	for _, want := range []string{"not tampering", "wg-hem version"} {
		if !strings.Contains(got, want) {
			t.Errorf("the sentence does not contain %q:\n%s", want, got)
		}
	}
}

// Silence when there is nothing to say. A build that matches the device must
// not have a paragraph about record sizes appended to every unrelated failure.
func TestExplainSizeIsSilentWhenTheSizesMatch(t *testing.T) {
	if got := ExplainSize(Size); got != "" {
		t.Errorf("explained a match:\n%s", got)
	}
	if got := ExplainSize(0); got != "" {
		t.Errorf("explained an absent record:\n%s", got)
	}
}
