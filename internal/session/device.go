package session

import (
	"context"
	"time"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
)

// Device is how a session reaches a HEM: where it is, how to prove who is
// asking, and who to ask when proving needs a person.
//
// It exists because reaching the device is the half of a session that a window
// keeps. The privileged component authenticates nothing — it is handed a token —
// so everything here belongs to whoever faces the human, and the two things that
// used to make it terminal-only are now supplied rather than assumed.
type Device struct {
	URL     string
	Broker  string
	Mobile  bool
	ExpSecs int

	// Insecure skips TLS verification, and stays because the command-line
	// client has always had it: a person typing a flag about their own session
	// is entitled to. It must never become something a request can ask for —
	// see docs/ARCHITECTURE-GUI.md — because a message telling a privileged
	// process to stop checking certificates is not the same act at all.
	Insecure bool

	// Passphrase is asked for the secret, at most once per session: the SDK
	// caches the key derived from it, so later scopes cost a round trip and not
	// another prompt.
	//
	// Supplied rather than read, because the thing doing the reading is a
	// terminal in one client and a password field in another. Unused when
	// Mobile is set.
	Passphrase func() ([]byte, error)

	// Notify carries what is happening while somebody waits — reaching the
	// device, and each prod at a phone that has not answered yet. A terminal
	// prints it, a window puts it in a status line, and a daemon logs it.
	Notify func(string)
}

// Auth hands out scoped tokens, asking for the passphrase once.
//
// Provisioning needs four different scopes and the device issues one token per
// scope. The SDK caches the key derived from the passphrase, so only the first
// call pays for the passphrase and for PBKDF2; the rest are a single round trip
// each. Wipe releases that cached key, which is why provisioning defers it.
type Auth struct {
	client  *hem.Client
	dev     Device
	asked   bool
	expSecs int
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
	return client, &Auth{client: client, dev: d, expSecs: d.ExpSecs}, nil
}

// Load connects and returns the authenticated configuration. Every command that
// changes a configuration goes through here first: re-signing a tree that does
// not currently verify would launder someone else's edit into an authentic one.
//
// choose settles which identity, and is consulted only when the device holds
// more than one — see config.ChooseFunc.
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
func (a *Auth) Token(ctx context.Context, scope string) (string, error) {
	if a.dev.Mobile {
		a.dev.say("Approve on your phone: " + scope)
		tok, err := a.client.AuthRemote(ctx, scope, hem.RemoteOpts{
			PollInterval: remotePoll,
			PollTimeout:  remoteTimeout,
			OnPending:    func() { a.dev.say("waiting for the phone") },
		})
		if err != nil {
			return "", Classify(err, KindAuth, "authorizing %s", scope)
		}
		return tok, nil
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
	tok, err := a.client.AuthPassword(ctx, pass, scope, a.expSecs)
	if err != nil {
		return "", Classify(err, KindAuth, "authorizing %s", scope)
	}
	return tok, nil
}

// Wipe drops the derived key. A session is short-lived next to a tunnel, but it
// holds the key only for as long as it is still asking for tokens.
func (a *Auth) Wipe() {
	if a != nil && a.client != nil {
		a.client.ClearKeys()
	}
}

// zero clears a buffer that held something worth clearing.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
