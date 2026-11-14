package session

import (
	"context"
	"fmt"
	"time"

	hem "github.com/encedo/hem-sdk-go"
)

// Renewal keeps a tunnel's session going by asking the person again shortly
// before it ends: a new request to the phone, or the passphrase typed again.
//
// This is not the token refresh CLAUDE.md records as a decision not to make.
// That one would have kept the passphrase, or the key derived from it, alive
// for the length of the tunnel so that something could re-authorise on its
// own. Here nothing is kept: every renewal is a person answering, and a
// session nobody renews still ends when the device said it would. The window
// has done the same since its Renew button; this is the terminal's version.
//
// It matters most for the phone. The session lasts the period picked on the
// phone's request screen, an hour unless somebody taps another (see CLAUDE.md,
// "A phone-approved session"), and without this a tunnel started with --mobile
// ended then, however long it had been asked to run.
type Renewal struct {
	// Ask gets a new token from the person, the same way the first was got.
	Ask func(ctx context.Context) (string, error)

	// Apply hands the new token to the tunnel.
	Apply func(token string) error

	// Say tells whoever is watching. Required.
	Say func(string)

	// Before, when set, is said once as a renewal starts, before Ask. A
	// terminal uses it to explain the passphrase prompt that follows.
	Before string
}

// retryEvery is how long a failed renewal waits before asking again, and
// lastAsk how close to the end a new request is still worth starting: a phone
// request can take a minute to answer.
const (
	retryEvery = time.Minute
	lastAsk    = 30 * time.Second
)

// renewLead is how long before the end a session is renewed: five minutes, or
// a third of a shorter one, so a 15-minute token is not renewed the moment it
// is issued.
func renewLead(lifetime time.Duration) time.Duration {
	const lead = 5 * time.Minute
	if lifetime >= 3*lead {
		return lead
	}
	return lifetime / 3
}

// Run renews the session that token opened, again and again, until ctx ends
// or a renewal does not happen in time. It returns only then, so a caller runs
// it in its own goroutine and cancels ctx when the tunnel is down.
func (r Renewal) Run(ctx context.Context, token string) {
	for {
		exp := hem.TokenExpiry(token)
		if exp.IsZero() {
			return // nothing to schedule against; the device ends it
		}
		at := exp.Add(-renewLead(time.Until(exp)))
		if !sleepUntil(ctx, at) {
			return
		}

		next, ok := r.once(ctx, exp)
		if !ok {
			return
		}
		token = next
	}
}

// once is one renewal: ask, and on failure ask again every minute while there
// is still time for an answer.
func (r Renewal) once(ctx context.Context, exp time.Time) (string, bool) {
	end := exp.Local().Format("15:04:05")
	r.Say(fmt.Sprintf("The session ends at %s - renewing it.", end))
	for {
		if r.Before != "" {
			r.Say(r.Before)
		}
		tok, err := r.Ask(ctx)
		if ctx.Err() != nil {
			return "", false
		}
		if err == nil {
			if exp := hem.TokenExpiry(tok); !exp.IsZero() && time.Until(exp) < lastAsk {
				err = fmt.Errorf("the new session ends at %s, which is no renewal - check this computer's clock",
					exp.Local().Format("15:04:05"))
			}
		}
		if err == nil {
			err = r.Apply(tok)
		}
		if err == nil {
			r.Say(fmt.Sprintf("Session renewed - the tunnel now runs until %s.",
				hem.TokenExpiry(tok).Local().Format("15:04:05")))
			return tok, true
		}

		retry := time.Now().Add(retryEvery)
		if time.Until(exp)-retryEvery < lastAsk {
			r.Say(fmt.Sprintf("Renewing failed: %v. The tunnel ends at %s.", err, end))
			return "", false
		}
		r.Say(fmt.Sprintf("Renewing failed: %v. Asking again at %s; the tunnel ends at %s.",
			err, retry.Local().Format("15:04:05"), end))
		if !sleepUntil(ctx, retry) {
			return "", false
		}
	}
}

// sleepUntil waits for t, or for ctx; it says which by returning false when
// ctx ended first.
func sleepUntil(ctx context.Context, t time.Time) bool {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
