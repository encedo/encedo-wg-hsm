package config

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	hem "github.com/encedo/hem-sdk-go"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

// ifRecord builds a valid interface record with one address, so a test can tell
// what describe managed to read out of it.
func ifRecord(t *testing.T, addr string) []byte {
	t.Helper()
	iface := descr.Interface{
		Addrs:    []netip.Prefix{netip.MustParsePrefix(addr)},
		PeerRefs: []descr.PeerRef{{1, 2, 3, 4}},
	}
	raw, err := iface.Encode()
	if err != nil {
		t.Fatalf("encoding an interface record: %v", err)
	}
	return raw[:]
}

func TestPickWithNoRecordsSaysWhatToRun(t *testing.T) {
	_, err := pick(nil, nil)
	if err == nil {
		t.Fatal("an empty device was accepted")
	}
	if !strings.Contains(err.Error(), "provision") {
		t.Errorf("error is %q; a device with no configuration should say what to run", err)
	}
}

// The single-identity device is every device today, and it must never reach a
// chooser: a prompt where there is no choice is a prompt that trains people to
// press return.
func TestPickWithOneRecordDoesNotAsk(t *testing.T) {
	entries := []hem.KeyEntry{{KID: "aa", Label: "only"}}
	asked := false
	got, err := pick(entries, func([]Identity) (string, error) {
		asked = true
		return "", nil
	})
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if asked {
		t.Error("a single identity was put to a choice")
	}
	if got.KID != "aa" {
		t.Errorf("KID = %q, want aa", got.KID)
	}
}

func TestPickWithSeveralAndNobodyToAsk(t *testing.T) {
	entries := []hem.KeyEntry{{KID: "aa"}, {KID: "bb"}}
	_, err := pick(entries, nil)
	if err == nil {
		t.Fatal("two identities and no chooser was accepted; one would have been picked arbitrarily")
	}
	for _, kid := range []string{"aa", "bb"} {
		if !strings.Contains(err.Error(), kid) {
			t.Errorf("error %q does not name %s; the caller cannot pass --identity without the list", err, kid)
		}
	}
}

func TestPickReturnsTheChosenRecord(t *testing.T) {
	entries := []hem.KeyEntry{{KID: "aa", Label: "one"}, {KID: "bb", Label: "two"}}
	got, err := pick(entries, func(ids []Identity) (string, error) {
		if len(ids) != 2 {
			t.Fatalf("chooser was offered %d identities, want 2", len(ids))
		}
		return "bb", nil
	})
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	if got.KID != "bb" {
		t.Errorf("KID = %q, want bb", got.KID)
	}
}

func TestPickPropagatesTheChooserRefusal(t *testing.T) {
	want := errors.New("nobody answered")
	_, err := pick([]hem.KeyEntry{{KID: "aa"}, {KID: "bb"}}, func([]Identity) (string, error) {
		return "", want
	})
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want the chooser's own error", err)
	}
}

// A chooser naming something that was not on the list is a bug in the chooser,
// and the one place it can be caught before a token is minted against it.
func TestPickRefusesAnIdentityThatIsNotThere(t *testing.T) {
	_, err := pick([]hem.KeyEntry{{KID: "aa"}, {KID: "bb"}}, func([]Identity) (string, error) {
		return "cc", nil
	})
	if err == nil {
		t.Fatal("a KID the device does not hold was accepted")
	}
	if !strings.Contains(err.Error(), "cc") {
		t.Errorf("error %q does not name the identity that was chosen", err)
	}
}

func TestDescribeReadsTheAddressesAndSortsStably(t *testing.T) {
	entries := []hem.KeyEntry{
		{KID: "ff", Label: "work", Descr: ifRecord(t, "10.99.0.7/32")},
		{KID: "01", Label: "home", Descr: ifRecord(t, "10.1.1.5/24")},
		{KID: "02", Label: "home", Descr: ifRecord(t, "10.2.2.5/24")},
	}
	ids := describe(entries)

	// Label first, then KID: two runs against an unchanged device must offer the
	// same list in the same positions, or the numbers a person answers with mean
	// different things on different days.
	want := []string{"01", "02", "ff"}
	for i, kid := range want {
		if ids[i].KID != kid {
			t.Fatalf("position %d is %s, want %s (order: %v)", i, ids[i].KID, kid, kidsOfIdentities(ids))
		}
	}
	if got := ids[0].Addrs; len(got) != 1 || got[0].String() != "10.1.1.5/24" {
		t.Errorf("addresses of the first identity = %v, want [10.1.1.5/24]", got)
	}
}

// A record that will not decode is still a record the device holds. Hiding it
// would give a person a list that disagrees with their device; the failure
// belongs to loading it, where it can be explained.
func TestDescribeListsARecordItCannotRead(t *testing.T) {
	ids := describe([]hem.KeyEntry{{KID: "aa", Label: "broken", Descr: []byte("not a record")}})
	if len(ids) != 1 {
		t.Fatalf("described %d identities, want 1", len(ids))
	}
	if len(ids[0].Addrs) != 0 {
		t.Errorf("addresses = %v, want none: nothing in that record decoded", ids[0].Addrs)
	}
	if ids[0].KID != "aa" {
		t.Errorf("KID = %q, want aa", ids[0].KID)
	}
}

func kidsOfIdentities(ids []Identity) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.KID)
	}
	return out
}
