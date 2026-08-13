package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// cmdWipe removes every WG:* record from the device (§10.3).
//
// The interface key is a private key that exists nowhere else, so deleting it
// destroys the identity: the other end of the tunnel will have to be given a new
// public key. That is worth spelling out and worth a typed confirmation, not a
// y/n. Peer records are imported public keys and cost nothing to recreate.
func cmdWipe(args []string) error {
	fs := flag.NewFlagSet("wipe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	dev := addDeviceFlags(fs)
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	peersOnly := fs.Bool("peers-only", false, "delete the peer records but keep the identity key")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: wg-hem wipe [flags]

Deletes the WG:* records this client uses. Without --peers-only that includes
the identity key, whose private half exists only inside the device: once it is
gone the interface has a different public key and every peer must be told.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return &exitError{code: exitUsage, err: err}
	}

	ctx := context.Background()
	client, auth, err := dev.connect(ctx)
	if err != nil {
		return err
	}
	defer auth.Wipe()

	// Deliberately not config.Load: a configuration that fails its MAC is
	// exactly one someone might need to clear, so wiping must not depend on it
	// verifying. Records are found by prefix instead.
	ifs, err := listRecords(ctx, client, auth, descr.MagicInterface)
	if err != nil {
		return err
	}
	peers, err := listRecords(ctx, client, auth, descr.MagicPeer)
	if err != nil {
		return err
	}
	if *peersOnly {
		ifs = nil
	}
	if len(ifs)+len(peers) == 0 {
		fmt.Fprintln(os.Stderr, "Nothing to wipe: the device holds no WG:* records.")
		return nil
	}

	// Show the target before destroying it.
	fmt.Fprintln(os.Stderr, "The following keys will be deleted:")
	for _, e := range ifs {
		fmt.Fprintf(os.Stderr, "  %s  %-28s  identity key — private, not recoverable\n", e.KID, e.Label)
	}
	for _, e := range peers {
		fmt.Fprintf(os.Stderr, "  %s  %-28s  peer public key\n", e.KID, e.Label)
	}

	if !*yes {
		word := "wipe"
		if len(ifs) > 0 {
			word = "delete my identity key"
		}
		if !confirm(fmt.Sprintf("Type %q to confirm: ", word), word) {
			return failf(exitUsage, "cancelled")
		}
	}

	delTok, err := auth.Token(ctx, "keymgmt:del")
	if err != nil {
		return err
	}
	// Peers first: if this is interrupted, an interface record referencing a
	// deleted peer is a configuration that refuses to start, which is a safer
	// place to be interrupted than an orphaned identity key nobody can find.
	deleted := 0
	for _, e := range append(append([]hem.KeyEntry{}, peers...), ifs...) {
		if err := client.DeleteKey(ctx, delTok, e.KID); err != nil {
			return classify(err, exitDevice, "deleting %s (%d of %d done)", e.KID, deleted, len(ifs)+len(peers))
		}
		deleted++
	}
	fmt.Fprintf(os.Stderr, "Deleted %d key(s).\n", deleted)
	return nil
}

// listRecords finds every key whose descr starts with a magic, paging through
// the repository. It mirrors the loader's anonymous-first approach.
func listRecords(ctx context.Context, client *hem.Client, auth *session.Auth, magic string) ([]hem.KeyEntry, error) {
	pattern := []byte(magic)
	token := ""
	var all []hem.KeyEntry
	for offset := 0; ; {
		total, page, err := client.SearchKeys(ctx, token, pattern, offset, 50)
		if err != nil {
			if he, ok := err.(*hem.HemError); ok && token == "" && (he.Status == 401 || he.Status == 403) {
				if token, err = auth.Token(ctx, "keymgmt:search"); err != nil {
					return nil, err
				}
				continue
			}
			return nil, classify(err, exitDevice, "searching for %s records", magic)
		}
		all = append(all, page...)
		offset += len(page)
		if len(page) == 0 || offset >= total {
			return all, nil
		}
	}
}
