package main

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

// A second identity on the same peer servers is the point of the whole change:
// one public key has one record, so the second configuration cannot import it
// again and has to reference what is already there.
func TestSecondIdentityAdoptsExistingPeers(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	f.mu.Lock()
	firstIdentity := f.ifKID
	importsAfterFirst := len(f.imported)
	// A fresh identity key, as `provision` without --kid would create.
	f.ifKID = "11112222333344445555666677778888"
	f.stored = map[string][]byte{}
	f.mu.Unlock()

	// The same peers, described exactly as before.
	if _, err := runProvision(t,
		"-hem", srv.URL, "-broker", srv.URL,
		"-address", "10.0.0.8/32",
		"-peer", "pubkey="+peerKeyA+",endpoint=203.0.113.1:51820,allowed-ips=10.0.0.0/24,keepalive=25,label=hq",
		"-peer", "pubkey="+peerKeyB+",endpoint=vpn.example.com:51820,allowed-ips=0.0.0.0/0,label=backup",
	); err != nil {
		t.Fatalf("a second identity should reuse the peers already in the device: %v", err)
	}

	f.mu.Lock()
	imports := len(f.imported)
	f.mu.Unlock()
	if imports != importsAfterFirst {
		t.Errorf("%d peer records exist, want %d — the peers should have been reused, not re-imported",
			imports, importsAfterFirst)
	}
	if firstIdentity == f.ifKID {
		t.Fatal("the test did not actually switch identities")
	}

	// Both configurations authenticate against the same peer records.
	if _, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL); err != nil {
		t.Fatalf("the second identity's tree does not verify: %v", err)
	}
}

// Adopting silently would be worse than refusing: one record serves every
// identity that references it, so editing it to match new flags breaks the
// others' MACs — on their machines, at their next startup.
func TestAdoptRefusesDifferentSettings(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	f.mu.Lock()
	f.ifKID = "11112222333344445555666677778888"
	f.stored = map[string][]byte{}
	f.mu.Unlock()

	_, err := runProvision(t,
		"-hem", srv.URL, "-broker", srv.URL,
		"-address", "10.0.0.8/32",
		// Same key, different routes.
		"-peer", "pubkey="+peerKeyA+",endpoint=203.0.113.1:51820,allowed-ips=192.168.0.0/16,label=hq",
	)
	if err == nil {
		t.Fatal("a peer stored with different settings must not be silently reused")
	}
	if !strings.Contains(err.Error(), "different settings") {
		t.Errorf("error should say the settings differ, got: %v", err)
	}
	// The refusal has to name the disagreement, or the operator has two opaque
	// records and no idea which field to change.
	if !strings.Contains(err.Error(), "allowed-ips") {
		t.Errorf("error should name the field that differs, got: %v", err)
	}
}

func TestAdoptFlagTakesTheStoredSettings(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	f.mu.Lock()
	f.ifKID = "11112222333344445555666677778888"
	f.stored = map[string][]byte{}
	stored := f.imported[0].descr
	f.mu.Unlock()

	if _, err := runProvision(t,
		"-hem", srv.URL, "-broker", srv.URL, "-adopt",
		"-address", "10.0.0.8/32",
		"-peer", "pubkey="+peerKeyA+",endpoint=203.0.113.1:51820,allowed-ips=192.168.0.0/16,label=hq",
	); err != nil {
		t.Fatalf("--adopt should accept the stored record: %v", err)
	}

	// What the tree authenticates is the stored record, not the flags: the
	// device holds one record, and the MAC has to cover the bytes that are
	// actually there.
	f.mu.Lock()
	after := f.imported[0].descr
	f.mu.Unlock()
	if string(after) != string(stored) {
		t.Error("--adopt must not rewrite the record it adopted")
	}

	out, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL)
	if err != nil {
		t.Fatalf("the adopting tree does not verify: %v", err)
	}
	if !strings.Contains(out, "peer.0.allowed-ips 10.0.0.0/24") {
		t.Errorf("the configuration should report the stored routes, not the requested ones\n%s", out)
	}
}

// A pre-shared key is wrapped under the owning identity's self-ECDH, so a second
// identity cannot unwrap it. One record holds one wrap, so this cannot be fixed
// by adopting harder.
func TestAdoptRefusesAPeerWithAPSK(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionWithPSK(t, srv.URL)

	f.mu.Lock()
	f.ifKID = "11112222333344445555666677778888"
	f.stored = map[string][]byte{}
	f.mu.Unlock()

	_, err := runProvision(t,
		"-hem", srv.URL, "-broker", srv.URL, "-adopt",
		"-address", "10.0.0.8/32",
		"-peer", "pubkey="+peerKeyA+",endpoint=203.0.113.1:51820,allowed-ips=10.9.0.0/24,label=hq",
	)
	if err == nil {
		t.Fatal("a peer whose stored key is wrapped for another identity must be refused")
	}
	if !strings.Contains(err.Error(), "cannot unwrap") {
		t.Errorf("error should explain that the wrap belongs to another identity, got: %v", err)
	}
}

// The client derives identifiers itself; if that derivation ever stopped
// matching the device, every reference it resolves would be guesswork.
func TestLoadRejectsAMismatchedIdentifier(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	f.mu.Lock()
	// Leave the record's KID alone but hand back a different key behind it.
	kid := f.imported[0].kid
	f.peerKeys[kid] = []byte("a different 32-byte public key!!")
	f.mu.Unlock()

	_, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL)
	if err == nil {
		t.Fatal("a key whose KID does not match its content must stop the load")
	}
	if !strings.Contains(err.Error(), "SHA-1") {
		t.Errorf("error should name the derivation that disagrees, got: %v", err)
	}
}

func TestPeerAddAdoptsAnExistingRecord(t *testing.T) {
	requireRoom(t, 66)
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	// A record for a peer this configuration does not reference yet.
	key := mustKey(t, peerKeyC)
	rec, err := descr.Peer{
		Endpoint:   descr.Endpoint{Host: "third.example", Port: 51820},
		AllowedIPs: mustPrefixes(t, "10.9.0.0/24"),
	}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	f.mu.Lock()
	f.peerKeys[descr.KID(key)] = key
	f.imported = append(f.imported, importCall{kid: descr.KID(key), label: "third", pubKey: key, descr: rec[:]})
	before := len(f.imported)
	f.mu.Unlock()

	if _, err := runCmd(t, peerAdd, "",
		"-hem", srv.URL, "-broker", srv.URL,
		"-peer", "pubkey="+peerKeyC+",endpoint=third.example:51820,allowed-ips=10.9.0.0/24,label=third",
	); err != nil {
		t.Fatalf("peer add should reuse the stored record: %v", err)
	}

	f.mu.Lock()
	after := len(f.imported)
	f.mu.Unlock()
	if after != before {
		t.Error("the peer should have been reused, not imported again")
	}
	if _, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL); err != nil {
		t.Fatalf("the tree does not verify after adopting: %v", err)
	}
}

// A pre-shared key is wrapped per peer, so the same key produces a different
// ciphertext in each record and none of them is valid anywhere else. AES key
// wrap authenticates what it holds but not where it sits; the context is what
// supplies the position.
func TestPSKWrapIsBoundToItsPeer(t *testing.T) {
	requireRoom(t, 70) // two peers, each carrying a wrapped key
	f, srv := newFakeHEM(t)

	if _, err := runProvision(t,
		"-hem", srv.URL, "-broker", srv.URL,
		"-address", "10.0.0.7/32", "-psk", "generate",
		"-peer", "pubkey="+peerKeyA+",endpoint=203.0.113.1:51820,allowed-ips=10.0.0.0/24,label=hq",
		"-peer", "pubkey="+peerKeyB+",endpoint=198.51.100.1:51820,allowed-ips=10.1.0.0/24,label=backup",
	); err != nil {
		t.Fatalf("provision: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.wraps) != 2 {
		t.Fatalf("%d wrap calls, want one per peer", len(f.wraps))
	}
	ctxA := f.wraps[0]["ctx"]
	ctxB := f.wraps[1]["ctx"]
	if ctxA == ctxB {
		t.Error("both peers were wrapped under the same context, so a ciphertext would move between them")
	}
	for i, w := range f.wraps {
		key := peerKeyA
		if i == 1 {
			key = peerKeyB
		}
		want := base64.StdEncoding.EncodeToString(config.PSKContext(descr.KID(mustKey(t, key))))
		if w["ctx"] != want {
			t.Errorf("wrap %d context = %v, want the one naming that peer", i, w["ctx"])
		}
		// Same plaintext each time: it is one pre-shared key, wrapped twice.
		if w["msg"] != f.wraps[0]["msg"] {
			t.Errorf("wrap %d carried different key material", i)
		}
	}
}
