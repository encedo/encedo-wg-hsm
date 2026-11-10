package descr

import (
	"strings"
	"testing"
)

// A tree written before firmware 1.3 fails verification as "failed
// authentication". Without this sentence beside it, that message says somebody
// has edited the configuration - which is the opposite of what happened and
// calls for the opposite reaction.
func TestExplainSizeNamesBothLengths(t *testing.T) {
	got := ExplainSize(64)
	if got == "" {
		t.Fatal("a record of the other size explains nothing")
	}
	for _, want := range []string{"not tampering", "wg-hem wipe"} {
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
