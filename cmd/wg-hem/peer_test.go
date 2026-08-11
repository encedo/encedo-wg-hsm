package main

import (
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

const peerKeyC = "PmcSQCFRJmFP8kbCC6IqTr8IQqmiWhBn8w1yzTQGpTA="

func runCmd(t *testing.T, fn func([]string) error, stdin string, args ...string) (stdout string, err error) {
	t.Helper()
	old := readPassphrase
	readPassphrase = func() ([]byte, error) { return []byte("passphrase"), nil }
	defer func() { readPassphrase = old }()

	if stdin != "" {
		sr, sw, perr := os.Pipe()
		if perr != nil {
			t.Fatalf("pipe: %v", perr)
		}
		io.WriteString(sw, stdin)
		sw.Close()
		oldStdin := os.Stdin
		os.Stdin = sr
		defer func() { os.Stdin = oldStdin; sr.Close() }()
	}

	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("pipe: %v", perr)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	err = fn(args)
	os.Stdout = oldStdout
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	return string(out), err
}

// storedRefs reads the peer references out of the interface record the device
// currently holds.
func storedRefs(t *testing.T, f *fakeHEM) []descr.PeerRef {
	t.Helper()
	f.mu.Lock()
	raw := f.stored[f.ifKID]
	f.mu.Unlock()
	rec, err := descr.DecodeInterface(raw)
	if err != nil {
		t.Fatalf("stored interface record: %v", err)
	}
	return rec.PeerRefs
}

func TestPeerAddResealsTheTree(t *testing.T) {
	requireRoom(t, 66) // a third reference alongside an address and the MAC
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)
	before := len(storedRefs(t, f))

	if _, err := runCmd(t, peerAdd, "",
		"-hem", srv.URL, "-broker", srv.URL,
		"-peer", "pubkey="+peerKeyC+",endpoint=192.0.2.5:51820,allowed-ips=10.9.0.0/24,label=third",
	); err != nil {
		t.Fatalf("peer add: %v", err)
	}

	refs := storedRefs(t, f)
	if len(refs) != before+1 {
		t.Fatalf("interface record has %d references, want %d", len(refs), before+1)
	}
	key, _ := base64.StdEncoding.DecodeString(peerKeyC)
	if refs[len(refs)-1] != descr.MakePeerRef(key) {
		t.Error("a new peer should land at the tail of the failover order")
	}

	// The whole tree is re-authenticated, so it must still verify.
	if _, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL); err != nil {
		t.Fatalf("the tree does not verify after peer add: %v", err)
	}
}

func TestPeerAddFirstTakesPriority(t *testing.T) {
	requireRoom(t, 66)
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	if _, err := runCmd(t, peerAdd, "",
		"-hem", srv.URL, "-broker", srv.URL, "-first",
		"-peer", "pubkey="+peerKeyC+",endpoint=192.0.2.5:51820,allowed-ips=10.9.0.0/24,label=preferred",
	); err != nil {
		t.Fatalf("peer add: %v", err)
	}

	key, _ := base64.StdEncoding.DecodeString(peerKeyC)
	if storedRefs(t, f)[0] != descr.MakePeerRef(key) {
		t.Error("--first should put the peer at the head of the failover order")
	}
}

// A record that cannot hold another reference has to be refused before the key
// is imported, or the device keeps a peer no configuration mentions.
func TestPeerAddRefusesWhenTheRecordIsFull(t *testing.T) {
	if descr.Size >= 128 {
		t.Skip("filling a 128-byte record would take more peers than the device's message limit allows")
	}
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)
	f.mu.Lock()
	before := len(f.imported)
	f.mu.Unlock()

	_, err := runCmd(t, peerAdd, "",
		"-hem", srv.URL, "-broker", srv.URL,
		"-peer", "pubkey="+peerKeyC+",endpoint=192.0.2.5:51820,allowed-ips=10.9.0.0/24",
	)
	if err == nil {
		t.Fatal("a peer that does not fit must be refused")
	}
	if !strings.Contains(err.Error(), "does not fit") {
		t.Errorf("error should say it does not fit, got: %v", err)
	}
	f.mu.Lock()
	after := len(f.imported)
	f.mu.Unlock()
	if after != before {
		t.Error("the key was imported even though the reference could not be stored")
	}
	if _, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL); err != nil {
		t.Errorf("the existing configuration should be untouched: %v", err)
	}
}

func TestPeerAddRejectsADuplicate(t *testing.T) {
	_, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	_, err := runCmd(t, peerAdd, "",
		"-hem", srv.URL, "-broker", srv.URL,
		"-peer", "pubkey="+peerKeyA+",endpoint=192.0.2.5:51820,allowed-ips=10.9.0.0/24",
	)
	if err == nil {
		t.Fatal("adding a peer that is already configured must be rejected")
	}
	if !strings.Contains(err.Error(), "already in the configuration") {
		t.Errorf("error should say the peer is already there, got: %v", err)
	}
}

func TestPeerRemoveKeepsTheImportedKeyByDefault(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	if _, err := runCmd(t, peerRemove, "",
		"-hem", srv.URL, "-broker", srv.URL, "-pubkey", peerKeyB,
	); err != nil {
		t.Fatalf("peer remove: %v", err)
	}

	refs := storedRefs(t, f)
	if len(refs) != 1 {
		t.Fatalf("interface record has %d references, want 1", len(refs))
	}
	// A peer record may be shared with another interface key, so dropping a
	// reference must not destroy it.
	f.mu.Lock()
	_, stillThere := f.peerKeys[peerKID(mustKey(t, peerKeyB))]
	f.mu.Unlock()
	if !stillThere {
		t.Error("the imported key should survive unless --delete-key was given")
	}

	if _, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL); err != nil {
		t.Fatalf("the tree does not verify after peer remove: %v", err)
	}
}

func TestPeerRemoveRefusesTheLastPeer(t *testing.T) {
	_, srv := newFakeHEM(t)
	provisionWithPSK(t, srv.URL) // one peer only

	_, err := runCmd(t, peerRemove, "",
		"-hem", srv.URL, "-broker", srv.URL, "-pubkey", peerKeyA,
	)
	if err == nil {
		t.Fatal("removing the only peer must be refused")
	}
	if !strings.Contains(err.Error(), "only peer") {
		t.Errorf("error should explain why, got: %v", err)
	}
}

func TestPeerUpdateChangesTheEndpoint(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	if _, err := runCmd(t, peerUpdate, "",
		"-hem", srv.URL, "-broker", srv.URL,
		"-peer", "pubkey="+peerKeyA+",endpoint=198.51.100.9:51820,allowed-ips=10.0.0.0/24,label=hq",
	); err != nil {
		t.Fatalf("peer update: %v", err)
	}

	out, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL)
	if err != nil {
		t.Fatalf("the tree does not verify after peer update: %v", err)
	}
	if !strings.Contains(out, "peer.0.endpoint 198.51.100.9:51820") {
		t.Errorf("the endpoint was not updated\n%s", out)
	}
	_ = f
}

// The point of the MAC is that a changed configuration stops verifying. A
// maintenance command must therefore refuse to re-sign one, or it would launder
// someone else's edit into an authentic configuration.
func TestPeerRefusesToResealATamperedTree(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)
	tamperPeerAllowedIPs(t, f, 0, "0.0.0.0/0")

	_, err := runCmd(t, peerAdd, "",
		"-hem", srv.URL, "-broker", srv.URL,
		"-peer", "pubkey="+peerKeyC+",endpoint=192.0.2.5:51820,allowed-ips=10.9.0.0/24",
	)
	if err == nil {
		t.Fatal("peer add must not re-sign a configuration that does not verify")
	}
	var ee *exitError
	if !asExit(err, &ee) || ee.code != exitIntegrit {
		t.Errorf("want exit code %d, got %v", exitIntegrit, err)
	}
}

func TestWipeShowsAndDeletesEverything(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	if _, err := runCmd(t, cmdWipe, "", "-hem", srv.URL, "-broker", srv.URL, "-yes"); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.deleted) != 3 {
		t.Fatalf("deleted %v, want the identity key and both peers", f.deleted)
	}
	// Peers go first: an interface record pointing at a deleted peer refuses to
	// start, which is a better state to be interrupted in than an orphan key.
	if f.deleted[len(f.deleted)-1] != f.ifKID {
		t.Errorf("the identity key should be deleted last, order was %v", f.deleted)
	}
}

func TestWipePeersOnlyKeepsTheIdentity(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	if _, err := runCmd(t, cmdWipe, "", "-hem", srv.URL, "-broker", srv.URL, "-yes", "-peers-only"); err != nil {
		t.Fatalf("wipe: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, kid := range f.deleted {
		if kid == f.ifKID {
			t.Error("--peers-only must not delete the identity key")
		}
	}
	if len(f.deleted) != 2 {
		t.Errorf("deleted %v, want both peer keys", f.deleted)
	}
}

func TestWipeNeedsTheTypedConfirmation(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	// Anything other than the exact phrase leaves the device untouched.
	_, err := runCmd(t, cmdWipe, "yes\n", "-hem", srv.URL, "-broker", srv.URL)
	if err == nil {
		t.Fatal("a wrong confirmation must cancel the wipe")
	}
	f.mu.Lock()
	deleted := len(f.deleted)
	f.mu.Unlock()
	if deleted != 0 {
		t.Errorf("%d keys were deleted despite the cancelled confirmation", deleted)
	}

	if _, err := runCmd(t, cmdWipe, "delete my identity key\n",
		"-hem", srv.URL, "-broker", srv.URL); err != nil {
		t.Fatalf("the exact phrase should proceed: %v", err)
	}
	f.mu.Lock()
	deleted = len(f.deleted)
	f.mu.Unlock()
	if deleted != 3 {
		t.Errorf("deleted %d keys, want 3", deleted)
	}
}

// Wiping has to work on a configuration that does not verify — that is one of
// the states an operator most needs to clear.
func TestWipeWorksOnATamperedTree(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)
	tamperPeerAllowedIPs(t, f, 0, "0.0.0.0/0")

	if _, err := runCmd(t, cmdWipe, "", "-hem", srv.URL, "-broker", srv.URL, "-yes"); err != nil {
		t.Fatalf("wipe must not depend on the MAC verifying: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.deleted) != 3 {
		t.Errorf("deleted %v, want everything", f.deleted)
	}
}

func mustKey(t *testing.T, b64 string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode %q: %v", b64, err)
	}
	return raw
}
