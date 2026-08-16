package main

import (
	"encoding/base64"
	"io"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func runVerify(t *testing.T, args ...string) (stdout string, err error) {
	t.Helper()
	old := readPassphrase
	readPassphrase = func() ([]byte, error) { return []byte("passphrase"), nil }
	defer func() { readPassphrase = old }()

	r, w, perr := os.Pipe()
	if perr != nil {
		t.Fatalf("pipe: %v", perr)
	}
	oldStdout := os.Stdout
	os.Stdout = w
	err = cmdVerify(args)
	os.Stdout = oldStdout
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	return string(out), err
}

// provisionInto runs a provisioning pass so the fake device holds a real,
// self-consistent tree for verify to read back.
func provisionInto(t *testing.T, srv string, extra ...string) {
	t.Helper()
	// This profile is sized to fit 64-byte records too: one address, no DNS,
	// and two peers whose records stay inside the tighter budget.
	args := append([]string{
		"-hem", srv, "-broker", srv,
		"-address", "10.0.0.7/32",
		"-peer", "pubkey=" + peerKeyA + ",endpoint=203.0.113.1:51820,allowed-ips=10.0.0.0/24,keepalive=25,label=hq",
		"-peer", "pubkey=" + peerKeyB + ",endpoint=vpn.example.com:51820,allowed-ips=0.0.0.0/0,label=backup",
	}, extra...)
	if _, err := runProvision(t, args...); err != nil {
		t.Fatalf("seed provisioning: %v", err)
	}
}

// provisionWithPSK seeds a tree whose single peer carries a wrapped key. On
// 64-byte firmware that record lands on exactly 64 bytes, which is why it has
// an IPv4 endpoint, one route and no keepalive - there is room for nothing else.
func provisionWithPSK(t *testing.T, srv string) {
	t.Helper()
	if _, err := runProvision(t,
		"-hem", srv, "-broker", srv,
		"-address", "10.0.0.7/32",
		"-psk", "generate",
		"-peer", "pubkey="+peerKeyA+",endpoint=203.0.113.1:51820,allowed-ips=0.0.0.0/0,label=hq",
	); err != nil {
		t.Fatalf("seed provisioning: %v", err)
	}
}

func TestVerifyReadsBackWhatProvisionWrote(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	out, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	want := []string{
		"interface.kid " + f.ifKID,
		"interface.pubkey " + base64.StdEncoding.EncodeToString(f.ifPub[:]),
		"interface.address 10.0.0.7/32",
		"interface.mtu 1420", // absent from the record, so the default applies
		"peer.0.label hq",
		"peer.0.endpoint 203.0.113.1:51820",
		"peer.0.allowed-ips 10.0.0.0/24",
		"peer.0.keepalive 25",
		"peer.0.psk false",
		"peer.1.label backup",
		"peer.1.endpoint vpn.example.com:51820",
	}
	for _, line := range want {
		if !strings.Contains(out, line) {
			t.Errorf("dump is missing %q\n--- got ---\n%s", line, out)
		}
	}

	// Peer order in the dump is the failover priority from the record, not
	// whatever order the device happened to return the records in.
	if strings.Index(out, "peer.0.label hq") > strings.Index(out, "peer.1.label backup") {
		t.Error("peers are not in reference order")
	}
}

func TestVerifyReportsATamperedRecord(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	// Widen a peer's AllowedIPs after the fact - the change an attacker with
	// write access to the repository would actually want to make, since it
	// redirects traffic without touching any key.
	tamperPeerAllowedIPs(t, f, 0, "0.0.0.0/0")

	_, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL)
	if err == nil {
		t.Fatal("a widened AllowedIPs must not verify")
	}
	var ee *exitError
	if !asExit(err, &ee) || ee.code != exitIntegrit {
		t.Errorf("want exit code %d for a failed integrity check, got %v", exitIntegrit, err)
	}
	if !strings.Contains(err.Error(), "failed authentication") {
		t.Errorf("error should say the configuration failed authentication, got: %v", err)
	}
}

func TestVerifyRejectsAnAddedPeer(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	// An extra peer record in the repository that the interface record does not
	// reference. Loading must not quietly widen the set it authenticates.
	extra, err := descr.Peer{
		Endpoint:   descr.Endpoint{Host: "attacker.example", Port: 51820},
		AllowedIPs: mustPrefixes(t, "0.0.0.0/0"),
	}.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	key, _ := base64.StdEncoding.DecodeString("PmcSQCFRJmFP8kbCC6IqTr8IQqmiWhBn8w1yzTQGpTA=")
	f.mu.Lock()
	f.imported = append(f.imported, importCall{kid: peerKID(key), label: "rogue", pubKey: key, descr: extra[:]})
	f.peerKeys[peerKID(key)] = key
	f.mu.Unlock()

	out, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL)
	if err != nil {
		t.Fatalf("an unreferenced record must be ignored, not fatal: %v", err)
	}
	if strings.Contains(out, "rogue") {
		t.Error("a peer the interface record does not reference must not appear in the configuration")
	}
	if strings.Count(out, "peer.") == 0 || strings.Contains(out, "peer.2.") {
		t.Errorf("expected exactly the two referenced peers\n%s", out)
	}
}

func TestVerifyFailsWhenAReferencedPeerIsGone(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	f.mu.Lock()
	f.imported = f.imported[:1] // the interface record still references two
	f.mu.Unlock()

	_, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL)
	if err == nil {
		t.Fatal("a missing referenced peer must stop the check")
	}
	if !strings.Contains(err.Error(), "not in the device") {
		t.Errorf("error should name the unresolved reference, got: %v", err)
	}
}

func TestVerifyWithPSK(t *testing.T) {
	_, srv := newFakeHEM(t)
	provisionWithPSK(t, srv.URL)

	out, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The dump reports that a key is present without unwrapping it: the check
	// is a diagnostic, and there is no reason for it to hold a PSK in memory.
	if !strings.Contains(out, "peer.0.psk true") {
		t.Errorf("expected the peer to report a stored PSK\n%s", out)
	}
	if strings.Contains(out, "psk=") {
		t.Error("verify must not print key material")
	}
}

// tamperPeerAllowedIPs rewrites a stored peer record in place, as an attacker
// with write access to the key repository would.
func tamperPeerAllowedIPs(t *testing.T, f *fakeHEM, idx int, cidr string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, err := descr.DecodePeer(f.imported[idx].descr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	rec.AllowedIPs = mustPrefixes(t, cidr)
	enc, err := rec.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	f.imported[idx].descr = enc[:]
}

func TestVerifyNeedsNoTokenWhenSearchIsOpen(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	f.mu.Lock()
	f.scopes = nil
	f.mu.Unlock()

	if _, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL); err != nil {
		t.Fatalf("verify: %v", err)
	}

	f.mu.Lock()
	scopes := strings.Join(f.scopes, ",")
	f.mu.Unlock()
	// An anonymous search means no keymgmt:search token is ever minted.
	if strings.Contains(scopes, "keymgmt:search") {
		t.Errorf("a device that answers an open search should not be asked for a search token: %s", scopes)
	}
	if !strings.Contains(scopes, "keymgmt:get") || !strings.Contains(scopes, "keymgmt:use:"+f.ifKID) {
		t.Errorf("scopes = %s, want keymgmt:get and keymgmt:use:<if>", scopes)
	}
}

func TestVerifyAsksForASearchTokenWhenTheDeviceRefuses(t *testing.T) {
	f, srv := newFakeHEM(t)
	provisionInto(t, srv.URL)

	f.mu.Lock()
	f.scopes = nil
	f.requireSearchToken = true
	f.mu.Unlock()

	if _, err := runVerify(t, "-hem", srv.URL, "-broker", srv.URL); err != nil {
		t.Fatalf("verify: %v", err)
	}
	f.mu.Lock()
	scopes := strings.Join(f.scopes, ",")
	f.mu.Unlock()
	if !strings.Contains(scopes, "keymgmt:search") {
		t.Errorf("a device that refuses an open search must be asked for a token: %s", scopes)
	}
}

func TestVerifyReportsAnUnreachableDevice(t *testing.T) {
	_, err := runVerify(t, "-hem", "http://127.0.0.1:1", "-broker", "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected a failure")
	}
	var ee *exitError
	if !asExit(err, &ee) || ee.code != exitNetwork {
		t.Errorf("want exit code %d for an unreachable device, got %v", exitNetwork, err)
	}
}
