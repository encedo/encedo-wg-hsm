package main

import (
	"context"
	"flag"
	"fmt"
	"os"

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
}

func addDeviceFlags(fs *flag.FlagSet) *deviceFlags {
	return &deviceFlags{
		hem:      fs.String("hem", "", "HEM base URL (default "+defaultHEM+", or $WG_HEM_URL)"),
		broker:   fs.String("broker", "", "notification broker URL (default is the SDK's)"),
		mobile:   fs.Bool("mobile", false, "authorize with a mobile push instead of the passphrase"),
		insecure: fs.Bool("insecure", false, "skip TLS verification (self-signed PPA certificate)"),
		expHours: fs.Int("session", 1, "token lifetime in hours"),
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
	tree, err := config.Load(ctx, client, auth.token)
	if err != nil {
		auth.wipe()
		return nil, nil, nil, classifyLoad(err)
	}
	return client, auth, tree, nil
}
