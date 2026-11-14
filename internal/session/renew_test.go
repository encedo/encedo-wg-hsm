package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRenewLead(t *testing.T) {
	for _, c := range []struct{ life, want time.Duration }{
		{time.Hour, 5 * time.Minute},
		{8 * time.Hour, 5 * time.Minute},
		{15 * time.Minute, 5 * time.Minute},
		{9 * time.Minute, 3 * time.Minute},
	} {
		if got := renewLead(c.life); got != c.want {
			t.Errorf("renewLead(%s) = %s, want %s", c.life, got, c.want)
		}
	}
}

// A session about to end is renewed by asking again, and the tunnel is handed
// the new token; the next renewal is then scheduled from the new expiry.
func TestRenewalHandsTheTunnelANewToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	first := fakeJWT(t, []string{"keymgmt:use:k"}, time.Now().Add(1500*time.Millisecond))
	second := fakeJWT(t, []string{"keymgmt:use:k"}, time.Now().Add(time.Hour))

	var mu sync.Mutex
	var applied []string
	var said []string
	done := make(chan struct{})
	r := Renewal{
		Ask: func(context.Context) (string, error) { return second, nil },
		Apply: func(tok string) error {
			mu.Lock()
			defer mu.Unlock()
			applied = append(applied, tok)
			close(done)
			return nil
		},
		Say: func(s string) { mu.Lock(); said = append(said, s); mu.Unlock() },
	}
	go r.Run(ctx, first)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no renewal before the session ended")
	}
	cancel()
	mu.Lock()
	defer mu.Unlock()
	if len(applied) != 1 || applied[0] != second {
		t.Fatalf("applied %d tokens, want the new one once", len(applied))
	}
	if !strings.Contains(strings.Join(said, "\n"), "Session renewed") {
		t.Errorf("said %q, want a line saying the session was renewed", said)
	}
}

// A renewal that fails with too little time left for another attempt says when
// the tunnel ends and stops asking.
func TestRenewalThatFailsLateGivesUp(t *testing.T) {
	tok := fakeJWT(t, []string{"keymgmt:use:k"}, time.Now().Add(1500*time.Millisecond))
	asked := 0
	var said []string
	r := Renewal{
		Ask:   func(context.Context) (string, error) { asked++; return "", errors.New("declined on the phone") },
		Apply: func(string) error { t.Fatal("applied a token that was never issued"); return nil },
		Say:   func(s string) { said = append(said, s) },
	}
	finished := make(chan struct{})
	go func() { r.Run(context.Background(), tok); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("still renewing after the session ended")
	}
	if asked != 1 {
		t.Errorf("asked %d times, want 1", asked)
	}
	last := said[len(said)-1]
	if !strings.Contains(last, "declined on the phone") || !strings.Contains(last, "The tunnel ends at") {
		t.Errorf("last line %q, want the reason and when the tunnel ends", last)
	}
}

// A token whose new expiry is already as good as gone is not a renewal: a
// clock far ahead of the device's makes every token look like this.
func TestRenewalRefusesATokenAboutToEnd(t *testing.T) {
	tok := fakeJWT(t, []string{"keymgmt:use:k"}, time.Now().Add(1500*time.Millisecond))
	stale := fakeJWT(t, []string{"keymgmt:use:k"}, time.Now().Add(10*time.Second))
	var said []string
	r := Renewal{
		Ask:   func(context.Context) (string, error) { return stale, nil },
		Apply: func(string) error { t.Fatal("applied a token about to end"); return nil },
		Say:   func(s string) { said = append(said, s) },
	}
	r.Run(context.Background(), tok)
	if !strings.Contains(strings.Join(said, "\n"), "check this computer's clock") {
		t.Errorf("said %q, want the clock named", said)
	}
}
