package session

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
)

// Device is how a session reaches a HEM: where it is, how to prove who is
// asking, and who to ask when proving needs a person.
//
// It exists because reaching the device is the half of a session that a window
// keeps. The privileged component authenticates nothing - it is handed a token -
// so everything here belongs to whoever faces the human, and the two things that
// used to make it terminal-only are now supplied rather than assumed.
type Device struct {
	URL     string
	Broker  string
	Mobile  bool
	ExpSecs int

	// Insecure keeps TLS and drops only the check on the certificate: expired,
	// self-signed, or issued for another name are all then accepted. The
	// connection is still encrypted; what is given up is knowing who is at the
	// other end of it.
	//
	// Not for ordinary use. A provisioned device presents a certificate that
	// verifies normally, so needing this means either a device whose
	// certificate has not been installed yet or a stand-in for one. It stays on
	// the command line and is deliberately absent from the protocol the
	// privileged component speaks - see internal/ipc.
	Insecure bool

	// Passphrase is asked for the secret, at most once per session: the SDK
	// caches the key derived from it, so later scopes cost a round trip and not
	// another prompt.
	//
	// Supplied rather than read, because the thing doing the reading is a
	// terminal in one client and a password field in another. Unused when
	// Mobile is set.
	Passphrase func() ([]byte, error)

	// Notify carries what is happening while somebody waits - reaching the
	// device, and each prod at a phone that has not answered yet. A terminal
	// prints it, a window puts it in a status line, and a daemon logs it.
	Notify func(string)

	// Expect names the scopes the command is going to need besides the one it
	// asks for first. Firmware 1.3 issues one token for up to eight scopes
	// (DEV-436), so the first request carries them all: one passphrase and,
	// with Mobile, one approval on the phone instead of one per scope. Later
	// requests for any of them are answered from the SDK's cache.
	//
	// A scope that depends on a key the command has not found yet - the
	// identity's keymgmt:use:<kid> on most paths - cannot be listed here; the
	// configuration loader asks for it first instead, so it opens the request.
	Expect []string
}

// Auth hands out scoped tokens, asking for the passphrase once.
//
// Provisioning needs five different scopes. Since firmware 1.3 one token can
// hold up to eight, so the first request carries every scope the command said
// it would need (Device.Expect) and the SDK's cache answers the rest. The SDK
// also caches the key derived from the passphrase, so only the first call pays
// for the passphrase and for PBKDF2. Wipe releases that cached key, which is
// why provisioning defers it.
type Auth struct {
	client  *hem.Client
	dev     Device
	asked   bool
	expSecs int
	pending []string // Device.Expect, until the first request has carried it
}

// remotePoll is how long a mobile authorisation is waited on, and how often the
// device is asked whether it has happened yet.
const (
	remotePoll    = 2 * time.Second
	remoteTimeout = 60 * time.Second
)

// Connect performs the checkin every session begins with and returns a client
// alongside an authenticator that will ask for the passphrase at most once.
func (d Device) Connect(ctx context.Context) (*hem.Client, *Auth, error) {
	client := hem.NewClient(d.URL, hem.Config{Broker: d.Broker, InsecureSkipVerify: d.Insecure})

	d.say("Connecting to " + d.URL + "...")
	if err := client.Checkin(ctx); err != nil {
		return nil, nil, Classify(err, KindNetwork, "checkin")
	}
	if d.Mobile {
		var err error
		if d, err = d.settleMobile(probePaired(ctx, client)); err != nil {
			return nil, nil, err
		}
	}
	return client, &Auth{client: client, dev: d, expSecs: d.ExpSecs,
		pending: append([]string(nil), d.Expect...)}, nil
}

// pairing is what the device says about a paired Authenticator app.
type pairing int

const (
	pairingUnknown pairing = iota // the device would not say
	pairingNone
	pairingFound
)

// pairedMagic opens the descr of the key the Authenticator app leaves on the
// device when it is paired. Asking for it is how encedo-oidc decides whether to
// offer the phone, and it is the device's own answer: the broker's "paired" was
// seen saying yes for a device with no app on it.
const pairedMagic = "EXTAID"

// ErrNoPhone is a request for the phone on a device no Authenticator app is
// paired with. Named so that a window can say it in its own words: it is an
// authentication failure, but not a refused passphrase.
var ErrNoPhone = errors.New("no Authenticator app is paired with this HEM")

// PhonePaired says whether the device has an Authenticator app paired with it,
// for a window deciding whether to offer the phone at all. Only a yes is a yes:
// a device that would not say is treated as one without.
func PhonePaired(ctx context.Context, c *hem.Client) bool {
	return probePaired(ctx, c) == pairingFound
}

// probePaired searches for that key without a token. A device that does not
// allow an anonymous search answers 401, and then nothing is known.
func probePaired(ctx context.Context, c *hem.Client) pairing {
	page, err := c.SearchKeys(ctx, "", []byte(pairedMagic), hem.SearchOpts{Match: hem.MatchPrefix, Limit: 1})
	switch {
	case err != nil:
		return pairingUnknown
	case len(page.Keys) > 0:
		return pairingFound
	default:
		return pairingNone
	}
}

// settleMobile decides what a request for the phone becomes once the device
// has been asked. With no app paired, a push would be sent to nobody and the
// broker would answer a bare 404 after the user had already been told to look
// at their phone; so the passphrase is asked for instead, or, with no way to
// ask it, the error says what is missing. Unknown leaves the phone in place.
func (d Device) settleMobile(p pairing) (Device, error) {
	if p != pairingNone {
		return d, nil
	}
	if d.Passphrase == nil {
		return d, &Error{Kind: KindAuth, Err: fmt.Errorf("%w - pair one, or use the passphrase", ErrNoPhone)}
	}
	d.say("No Authenticator app is paired with this HEM - using the passphrase instead.")
	d.Mobile = false
	return d, nil
}

// Load connects and returns the authenticated configuration. Every command that
// changes a configuration goes through here first: re-signing a tree that does
// not currently verify would launder someone else's edit into an authentic one.
//
// choose settles which identity, and is consulted only when the device holds
// more than one - see config.ChooseFunc.
func (d Device) Load(ctx context.Context, choose config.ChooseFunc) (*hem.Client, *Auth, *config.Tree, error) {
	client, auth, err := d.Connect(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	tree, err := config.Load(ctx, client, auth.Token, choose)
	if err != nil {
		auth.Wipe()
		return nil, nil, nil, err
	}
	return client, auth, tree, nil
}

func (d Device) say(msg string) {
	if d.Notify != nil {
		d.Notify(msg)
	}
}

// Token returns a token for one scope, asking whoever is watching to prove who
// they are the first time it is needed.
//
// The first request also carries Device.Expect, so it may come back holding
// more than scope; whatever the phone did not approve is asked for again, on
// its own, when it is actually needed.
func (a *Auth) Token(ctx context.Context, scope string) (string, error) {
	scopes := a.bundle(scope)
	what := strings.Join(scopes, ", ")

	if a.dev.Mobile {
		a.dev.say("Approve on your phone: " + what)
		// The time left, on every poll: a window shows it where it shows
		// progress, so a person can see how long the request will still wait
		// rather than finding out when it stops.
		start := time.Now()
		opts := hem.RemoteOpts{
			PollInterval: remotePoll,
			PollTimeout:  remoteTimeout,
			OnPending: func() {
				left := (remoteTimeout - time.Since(start) + time.Second/2) / time.Second
				if left < 0 {
					left = 0
				}
				a.dev.say(fmt.Sprintf("Waiting for the phone - %d s left", left))
			},
		}
		var tok string
		var err error
		if len(scopes) == 1 {
			tok, err = a.client.AuthRemote(ctx, scope, opts)
		} else {
			tok, err = a.client.AuthRemoteScopes(ctx, scopes, opts)
		}
		if err != nil {
			return "", Classify(err, KindAuth, "authorizing %s", what)
		}
		a.sayExpiry(tok)
		return a.check(tok, scope)
	}

	var pass []byte
	if !a.asked {
		if a.dev.Passphrase == nil {
			return "", Fail(KindAuth, "no way to ask for the passphrase")
		}
		p, err := a.dev.Passphrase()
		if err != nil {
			return "", Fail(KindAuth, "reading passphrase: %v", err)
		}
		defer zero(p)
		pass = p
		a.asked = true
	}

	// A nil passphrase on later calls reuses the key derived for the first one.
	var tok string
	var err error
	if len(scopes) == 1 {
		tok, err = a.client.AuthPassword(ctx, pass, scope, a.expSecs)
	} else {
		tok, err = a.client.AuthPasswordScopes(ctx, pass, scopes, a.expSecs)
	}
	if err != nil {
		return "", Classify(err, KindAuth, "authorizing %s", what)
	}
	return a.check(tok, scope)
}

// sayExpiry says how long the phone approved the session for. The phone sets
// that, not this client, and the SDK reuses a token only while this computer's
// clock says it is still valid - so a clock running ahead shows up as the phone
// being asked again for scopes it has just approved. Said every time, because
// it is also when a tunnel started on this approval will end.
func (a *Auth) sayExpiry(tok string) {
	exp := hem.TokenExpiry(tok)
	if exp.IsZero() {
		return
	}
	left := time.Until(exp).Round(time.Second)
	msg := fmt.Sprintf("Approved until %s (%s from now by this computer's clock).",
		exp.Local().Format("15:04:05"), left)
	if left < 30*time.Second {
		msg += " That is too soon to use - check this computer's clock."
	}
	a.dev.say(msg)
}

// bundle is what to ask for: scope, then on the first request everything the
// command said it would need. A keymgmt:use: value goes first, because the
// device attaches that key's label to the first one and the phone shows it.
func (a *Auth) bundle(scope string) []string {
	out := []string{scope}
	for _, s := range a.pending {
		if len(out) == hem.MaxScopes {
			break
		}
		dup := false
		for _, o := range out {
			dup = dup || o == s
		}
		if !dup {
			out = append(out, s)
		}
	}
	a.pending = nil
	sort.SliceStable(out, func(i, j int) bool {
		return strings.HasPrefix(out[i], "keymgmt:use:") && !strings.HasPrefix(out[j], "keymgmt:use:")
	})
	return out
}

// check refuses a token that does not hold the scope it was asked for, which
// happens when the phone approved only part of a request. The device would
// answer the call with a 403 that names nothing; this names the scope.
func (a *Auth) check(tok, scope string) (string, error) {
	held := hem.TokenScopes(tok)
	if held == nil {
		return tok, nil // unreadable: let the device decide
	}
	for _, h := range held {
		if h == scope {
			return tok, nil
		}
	}
	return "", Fail(KindAuth, "the approval did not include %s", scope)
}

// Wipe drops the derived key. A session is short-lived next to a tunnel, but it
// holds the key only for as long as it is still asking for tokens.
func (a *Auth) Wipe() {
	if a != nil && a.client != nil {
		a.client.ClearKeys()
	}
}

// Zero clears a buffer that held something worth clearing.
//
// Exported because the same obligation runs through every layer that touches a
// pre-shared key or a passphrase, and CLAUDE.md documents the order they are
// cleared in. One definition means one thing to audit.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func zero(b []byte) { Zero(b) }
