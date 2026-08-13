package config

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

// A device may hold several interface records — several private keys, each with
// its own peers and its own configuration (§2). They do not interact: one MAC
// closes over one identity and the peers it names. The only thing multiplicity
// changes is that something has to choose, and the rule is the one §6.2 step 5
// already applies to peers — one is used without asking, several are offered.
//
// The order is forced rather than preferred. `keymgmt:use:<if_kid>` names one
// key, so the choice cannot come after the token that depends on it. Listing is
// therefore separate from loading, and cheap: search alone, which a device with
// allow_keysearch answers without any token at all.

// Identity is one interface record as the repository presents it, before it has
// been resolved or authenticated.
type Identity struct {
	KID   string
	Label string

	// Addrs is what the record says the tunnel's addresses are, decoded
	// locally and with nothing vouching for it. It is here so a person can tell
	// two identities apart in a list, and for no other purpose — acting on it
	// would be acting on unauthenticated bytes.
	//
	// Empty when the record does not decode. A listing that hid such a record
	// would be a listing that disagrees with the device, so it is shown with
	// what could be read; LoadIdentity is where the failure is reported, and
	// there it is an error rather than a gap.
	Addrs []netip.Prefix

	// Created is when the device says the key was made, and is what the list is
	// ordered by — see describe.
	Created int64
}

// ChooseFunc is asked which identity to use, and only when there is a real
// choice to make. It returns the KID it wants.
//
// A function rather than a rule, for the same reason peer selection is one: a
// terminal prints a list and reads a line, a window puts up a control, and a
// privileged component asked to load a named identity is never asked at all.
type ChooseFunc func([]Identity) (kid string, err error)

// Identities lists the interface records the device holds.
//
// It is what a window calls before it can offer anything, and it authenticates
// nothing — the MAC covers one identity and its peers, so there is no signature
// over "the set of identities" to check. What it returns is the repository's
// claim about what exists, which is exactly what a person is being asked to
// choose from.
func Identities(ctx context.Context, c *hem.Client, tok TokenFunc) ([]Identity, error) {
	entries, err := search(ctx, c, tok, descr.MagicInterface)
	if err != nil {
		return nil, err
	}
	return describe(entries), nil
}

// LoadIdentity loads and authenticates the identity with this KID.
//
// This is the privileged component's entry point: it is told which identity to
// bring up and reads the tree itself rather than being handed one. Naming it by
// KID rather than passing an Identity is deliberate — the name crosses a process
// boundary, and a KID is the only part of an Identity that means anything on the
// other side of one.
func LoadIdentity(ctx context.Context, c *hem.Client, tok TokenFunc, ifKID string) (*Tree, error) {
	entries, err := search(ctx, c, tok, descr.MagicInterface)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.KID == ifKID {
			return loadFrom(ctx, c, tok, e)
		}
	}
	return nil, fmt.Errorf("the device holds no %s record for identity %s", descr.MagicInterface, ifKID)
}

// describe turns what search returned into what a person can choose between,
// oldest identity first.
//
// Creation order is used because the device reports it and because it means
// something: the identity somebody has had longest is the one they will
// recognise, and a list ordered by when things happened reads like a history
// rather than like a hash. Sorting by label would have been stable and arbitrary
// — two runs against an unchanged device would agree, and the agreement would say
// nothing.
//
// The identifier breaks ties, because provisioning a batch by script can stamp
// two keys with the same second, and a list that reorders itself between runs is
// a list whose numbers cannot be answered with.
func describe(entries []hem.KeyEntry) []Identity {
	ids := make([]Identity, 0, len(entries))
	for _, e := range entries {
		id := Identity{KID: e.KID, Label: e.Label, Created: e.Created}
		if raw, err := descr.Normalize(e.Descr); err == nil {
			if iface, err := descr.DecodeInterface(raw[:]); err == nil {
				id.Addrs = iface.Addrs
			}
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].Created != ids[j].Created {
			return ids[i].Created < ids[j].Created
		}
		return ids[i].KID < ids[j].KID
	})
	return ids
}

// pick applies the choosing rule. It is separate from the device so the rule can
// be tested without one, which matters because every branch here is a way for
// somebody to end up connected as an identity they did not mean to be.
func pick(entries []hem.KeyEntry, choose ChooseFunc) (hem.KeyEntry, error) {
	switch len(entries) {
	case 0:
		return hem.KeyEntry{}, fmt.Errorf("no %s record in the device — run `wg-hem provision` first",
			descr.MagicInterface)
	case 1:
		return entries[0], nil
	}

	if choose == nil {
		return hem.KeyEntry{}, fmt.Errorf("the device holds %d interface records (%s) and there is nothing here to choose between them",
			len(entries), strings.Join(kidsOf(entries), ", "))
	}
	kid, err := choose(describe(entries))
	if err != nil {
		return hem.KeyEntry{}, err
	}
	for _, e := range entries {
		if e.KID == kid {
			return e, nil
		}
	}
	// Not a device fault and not the caller's either: whatever chose returned a
	// name for something that was not on the list it was given.
	return hem.KeyEntry{}, fmt.Errorf("identity %s was chosen, and the device holds no such interface record", kid)
}

func kidsOf(entries []hem.KeyEntry) []string {
	kids := make([]string, 0, len(entries))
	for _, e := range entries {
		kids = append(kids, e.KID)
	}
	return kids
}
