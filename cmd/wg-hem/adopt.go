package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/session"
)

// placePeer puts a peer's record into the device and returns its KID.
//
// A key identifier is a function of the key — SHA-1(pubkey)[:16] — so whether a
// peer is already in the repository is knowable before any write. That matters
// because one public key has exactly one record: the device refuses a second
// import of the same key, and a record already there may belong to another
// identity's configuration.
//
// So: import when the key is new, adopt when the record already says what this
// configuration wants, and refuse otherwise rather than overwrite. Overwriting
// would silently invalidate the MAC of whatever other identity references it —
// a failure that would surface on someone else's machine, at their next startup.
func placePeer(ctx context.Context, client *hem.Client, auth *session.Auth,
	p peerSpec, want [descr.Size]byte, adopt bool) (kid string, adopted bool, err error) {

	kid = descr.KID(p.PubKey)

	getTok, err := auth.Token(ctx, "keymgmt:get")
	if err != nil {
		return "", false, err
	}
	existing, err := client.GetPubKey(ctx, getTok, kid)
	if err != nil {
		// An identifier the device cannot resolve comes back as 406, not 404:
		// the firmware answers "not acceptable" where the status line would
		// suggest a permission problem. That it tracks existence rather than
		// permission was measured — the same key read with the same scope gives
		// 200 while it is in the repository and 406 once it has been deleted.
		if he, ok := err.(*hem.HemError); ok && (he.Status == 404 || he.Status == 406) {
			return importPeer(ctx, client, auth, p, want)
		}
		// Anything else — no permission to look, a device in a bad state — is
		// not evidence that the key is absent, and importing on a guess is how
		// half-written configurations happen. Import remains the authority in
		// either case: the device refuses a second import of the same public key.
		return "", false, classify(err, exitDevice, "checking whether peer %s is already in the device", kid)
	}
	if !bytes.Equal(existing.PubKey, p.PubKey) {
		return "", false, failf(exitDevice,
			"key %s holds a different public key than the one given; identifiers are derived from the key, so this should not happen", kid)
	}

	// The key is there. Whether its record is usable is the question.
	current, err := readPeerRecord(ctx, client, auth, kid)
	if err != nil {
		return "", false, err
	}
	if current == nil {
		return "", false, failf(exitUsage,
			"key %s is in the device but carries no %s record; it belongs to something other than this client", kid, descr.MagicPeer)
	}
	if *current == want {
		fmt.Fprintf(os.Stderr, "Peer %q is already in the device with these settings; reusing it.\n", p.Label)
		return kid, true, nil
	}

	// A record that differs cannot be edited into place without breaking any
	// other identity that references it, and cannot be duplicated because the
	// identifier is the key's.
	if !adopt {
		return "", false, failf(exitUsage,
			"peer %s is already in the device with different settings (%s).\n"+
				"One public key has one record, shared by every identity that references it, so changing it here would invalidate their configurations.\n"+
				"Pass --adopt to take the stored settings as they are, or use `wg-hem peer update` if this configuration owns the record.",
			kid, describeDifference(*current, want))
	}

	decoded, err := descr.DecodePeer(current[:])
	if err != nil {
		return "", false, failf(exitDevice, "peer record %s: %w", kid, err)
	}
	if len(decoded.PSKWrapped) > 0 {
		// The wrap is keyed by the owning identity's self-ECDH, so this record's
		// pre-shared key cannot be unwrapped by the identity adopting it.
		return "", false, failf(exitUsage,
			"peer %s carries a pre-shared key wrapped for another identity, which this one cannot unwrap.\n"+
				"A pre-shared key cannot be shared between identities: it would have to be wrapped twice, and one record holds one wrap.",
			kid)
	}
	fmt.Fprintf(os.Stderr, "Adopting peer %q as stored: %s\n", p.Label, decoded.Endpoint.String())
	return kid, true, nil
}

func importPeer(ctx context.Context, client *hem.Client, auth *session.Auth,
	p peerSpec, want [descr.Size]byte) (string, bool, error) {

	impTok, err := auth.Token(ctx, "keymgmt:imp")
	if err != nil {
		return "", false, err
	}
	kid, err := client.ImportKey(ctx, impTok, p.Label, keyType, p.PubKey, want[:], "")
	if err != nil {
		return "", false, classify(err, exitDevice, "importing peer %s", p.Label)
	}
	if expect := descr.KID(p.PubKey); kid != expect {
		return "", false, failf(exitDevice,
			"the device gave peer %s the identifier %s, but this client derives %s; references would not resolve",
			p.Label, kid, expect)
	}
	return kid, false, nil
}

// readPeerRecord fetches a key's stored record, or nil when it holds none that
// belongs to this client.
func readPeerRecord(ctx context.Context, client *hem.Client, auth *session.Auth, kid string) (*[descr.Size]byte, error) {
	pattern := []byte(descr.MagicPeer)
	token := ""
	for offset := 0; ; {
		total, page, err := client.SearchKeys(ctx, token, pattern, offset, 50)
		if err != nil {
			if he, ok := err.(*hem.HemError); ok && token == "" && (he.Status == 401 || he.Status == 403) {
				if token, err = auth.Token(ctx, "keymgmt:search"); err != nil {
					return nil, err
				}
				continue
			}
			return nil, classify(err, exitDevice, "searching for peer records")
		}
		for _, e := range page {
			if e.KID != kid {
				continue
			}
			rec, err := descr.Normalize(e.Descr)
			if err != nil {
				return nil, failf(exitDevice, "peer record %s: %w", kid, err)
			}
			return &rec, nil
		}
		offset += len(page)
		if len(page) == 0 || offset >= total {
			return nil, nil
		}
	}
}

// describeDifference names what a caller would have to change to match a stored
// record, so the refusal points at the disagreement instead of at two blobs.
func describeDifference(stored, want [descr.Size]byte) string {
	a, err1 := descr.DecodePeer(stored[:])
	b, err2 := descr.DecodePeer(want[:])
	if err1 != nil || err2 != nil {
		return "the stored record differs"
	}
	var diffs []string
	if a.Endpoint.String() != b.Endpoint.String() {
		diffs = append(diffs, fmt.Sprintf("endpoint %s vs %s", a.Endpoint.String(), b.Endpoint.String()))
	}
	if fmt.Sprint(a.AllowedIPs) != fmt.Sprint(b.AllowedIPs) {
		diffs = append(diffs, fmt.Sprintf("allowed-ips %v vs %v", a.AllowedIPs, b.AllowedIPs))
	}
	if a.Keepalive != b.Keepalive {
		diffs = append(diffs, fmt.Sprintf("keepalive %d vs %d", a.Keepalive, b.Keepalive))
	}
	if (len(a.PSKWrapped) > 0) != (len(b.PSKWrapped) > 0) {
		diffs = append(diffs, fmt.Sprintf("pre-shared key %t vs %t", len(a.PSKWrapped) > 0, len(b.PSKWrapped) > 0))
	}
	if len(diffs) == 0 {
		return "the stored record differs in padding or ordering"
	}
	out := "stored vs requested: "
	for i, d := range diffs {
		if i > 0 {
			out += ", "
		}
		out += d
	}
	return out
}
