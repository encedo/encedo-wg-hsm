package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/config"
)

// deviceFlags are the flags every command that talks to a HEM accepts.
type deviceFlags struct {
	hem      *string
	broker   *string
	mobile   *bool
	insecure *bool
	expHours *int
	identity *string
}

func addDeviceFlags(fs *flag.FlagSet) *deviceFlags {
	return &deviceFlags{
		hem:      fs.String("hem", "", "HEM base URL (default "+defaultHEM+", or $WG_HEM_URL)"),
		broker:   fs.String("broker", "", "notification broker URL (default is the SDK's)"),
		mobile:   fs.Bool("mobile", false, "authorize with a mobile push instead of the passphrase"),
		insecure: fs.Bool("insecure", false, "skip TLS verification (self-signed PPA certificate)"),
		expHours: fs.Int("session", 1, "token lifetime in hours"),
		identity: fs.String("identity", "", "which interface key to use, by KID or a unique prefix (only asked when the device holds several)"),
	}
}

func (d *deviceFlags) url() string {
	if *d.hem != "" {
		return *d.hem
	}
	if u := os.Getenv("WG_HEM_URL"); u != "" {
		return u
	}
	return defaultHEM
}

// connect performs the checkin every session begins with and returns a client
// alongside an authenticator that will ask for the passphrase at most once.
func (d *deviceFlags) connect(ctx context.Context) (*hem.Client, *authenticator, error) {
	url := d.url()
	client := hem.NewClient(url, hem.Config{Broker: *d.broker, InsecureSkipVerify: *d.insecure})

	fmt.Fprintf(os.Stderr, "Connecting to %s...\n", url)
	if err := client.Checkin(ctx); err != nil {
		return nil, nil, classify(err, exitNetwork, "checkin")
	}
	return client, &authenticator{client: client, mobile: *d.mobile, expSecs: *d.expHours * 3600}, nil
}

// load connects and returns the authenticated configuration. Every command that
// changes a configuration goes through here first: re-signing a tree that does
// not currently verify would launder someone else's edit into an authentic one.
func (d *deviceFlags) load(ctx context.Context) (*hem.Client, *authenticator, *config.Tree, error) {
	client, auth, err := d.connect(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	tree, err := config.Load(ctx, client, auth.token, d.chooseIdentity)
	if err != nil {
		auth.wipe()
		return nil, nil, nil, classifyLoad(err)
	}
	return client, auth, tree, nil
}

// chooseIdentity settles which interface key to work on when the device holds
// more than one. It is not called otherwise, so the single-identity device — the
// only kind that exists today — never sees any of this.
func (d *deviceFlags) chooseIdentity(ids []config.Identity) (string, error) {
	if want := strings.TrimSpace(*d.identity); want != "" {
		return matchIdentity(ids, want)
	}
	return promptForIdentity(ids)
}

// matchIdentity resolves what was typed against the identities on offer,
// accepting a unique prefix as `--peer-pubkey` does. Ambiguity is refused rather
// than resolved in either direction: connecting as the wrong identity is not the
// kind of mistake that announces itself.
func matchIdentity(ids []config.Identity, want string) (string, error) {
	want = strings.ToLower(want)
	var found []config.Identity
	for _, id := range ids {
		if strings.HasPrefix(strings.ToLower(id.KID), want) {
			found = append(found, id)
		}
	}
	switch len(found) {
	case 1:
		return found[0].KID, nil
	case 0:
		return "", failf(exitUsage, "no interface key here starts with %q; the device holds %s",
			want, strings.Join(identityKIDs(ids), ", "))
	default:
		return "", failf(exitUsage, "%q matches %d interface keys (%s); give more of it",
			want, len(found), strings.Join(identityKIDs(found), ", "))
	}
}

// promptForIdentity asks, and — unlike the peer prompt — offers no default.
//
// The peer prompt defaults to the first because the stored order is the failover
// priority (§3.1), so "the first" means something. Identities have no order: the
// list is whatever the repository answered, sorted for stability alone. A default
// would connect as whichever identity happened to sort first, which is a decision
// nobody made.
func promptForIdentity(ids []config.Identity) (string, error) {
	fmt.Fprintln(os.Stderr, "This device holds several interface keys:")
	for i, id := range ids {
		fmt.Fprintf(os.Stderr, "  %d) %-20s %s  %s\n", i+1, id.Label, id.KID, addrList(id.Addrs))
	}
	fmt.Fprintf(os.Stderr, "Which one: ")

	line, err := readLine()
	if err != nil && err != io.EOF {
		return "", failf(exitUsage, "reading the identity selection: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", failf(exitUsage, "no identity chosen; answer with a number, or pass --identity")
	}
	n, err := strconv.Atoi(line)
	if err != nil || n < 1 || n > len(ids) {
		return "", failf(exitUsage, "%q is not one of the %d interface keys offered", line, len(ids))
	}
	return ids[n-1].KID, nil
}

// addrList renders the addresses a record claims, for a person choosing between
// identities. Unauthenticated, and shown only because two key identifiers side by
// side tell nobody anything.
func addrList(addrs []netip.Prefix) string {
	if len(addrs) == 0 {
		return "(unreadable record)"
	}
	parts := make([]string, 0, len(addrs))
	for _, a := range addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ", ")
}

func identityKIDs(ids []config.Identity) []string {
	kids := make([]string, 0, len(ids))
	for _, id := range ids {
		kids = append(kids, id.KID)
	}
	return kids
}
