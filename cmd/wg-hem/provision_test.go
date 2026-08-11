package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/encedo/encedo-wg-hsm/internal/config"
	"github.com/encedo/encedo-wg-hsm/internal/descr"
	"github.com/encedo/encedo-wg-hsm/internal/mac"
)

// requireRoom skips a scenario the configured record size cannot express. The
// 64-byte firmware leaves an interface record room for an address, two peer
// references and the MAC, and nothing else.
func requireRoom(t *testing.T, n int) {
	t.Helper()
	if descr.Size < n {
		t.Skipf("scenario needs %d-byte records, this build uses %d", n, descr.Size)
	}
}

// fakeHEM is enough of the device to run provisioning end to end: it records
// what it was asked to store so a test can check the bytes that would land in a
// real HEM, and it computes real HMACs so the read-back verification is not a
// rubber stamp.
type fakeHEM struct {
	mu sync.Mutex

	ifKID    string
	ifLabel  string
	ifPub    [32]byte
	macKey   []byte            // stands in for the self-ECDH key
	stored   map[string][]byte // kid -> descr
	peerKeys map[string][]byte // kid -> public key
	imported []importCall
	wraps    []map[string]any
	hashes   []map[string]any
	verifies []map[string]any
	updates  []map[string]any
	scopes   []string
	deleted  []string

	// requireSearchToken makes the device refuse an anonymous key search, as it
	// does when allow_keysearch is off.
	requireSearchToken bool
}

type importCall struct {
	kid    string
	label  string
	pubKey []byte
	descr  []byte
}

// peerKID mirrors the device: the identifier is the leading 16 bytes of the
// public key's SHA-1.
func peerKID(pubKey []byte) string {
	return descr.KID(pubKey)
}

// search answers a prefix search over the descr field, the way the device does:
// the pattern arrives as "^" followed by base64 of the bytes to match.
func (f *fakeHEM) search(w http.ResponseWriter, r *http.Request) {
	if f.requireSearchToken && r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	body := f.body(r)
	pattern, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(body["descr"].(string), "^"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	type entry struct {
		KID   string `json:"kid"`
		Label string `json:"label"`
		Type  string `json:"type"`
		Descr string `json:"descr"`
	}
	var list []entry
	switch string(pattern) {
	case descr.MagicInterface:
		if d, ok := f.stored[f.ifKID]; ok && bytes.HasPrefix(d, pattern) {
			list = append(list, entry{KID: f.ifKID, Label: f.ifLabel, Type: "PKEY,ECDH,CURVE25519",
				Descr: base64.StdEncoding.EncodeToString(d)})
		}
	case descr.MagicPeer:
		for _, imp := range f.imported {
			if bytes.HasPrefix(imp.descr, pattern) {
				list = append(list, entry{KID: imp.kid, Label: imp.label, Type: "ECDH,CURVE25519",
					Descr: base64.StdEncoding.EncodeToString(imp.descr)})
			}
		}
	}

	total := len(list)
	offset := 0
	if v, ok := body["offset"].(float64); ok {
		offset = int(v)
	}
	if offset > len(list) {
		offset = len(list)
	}
	list = list[offset:]

	resp := map[string]any{"offset": offset, "total": total, "listed": len(list), "list": list}
	out, _ := json.Marshal(resp)
	w.Write(out)
}

func newFakeHEM(t *testing.T) (*fakeHEM, *httptest.Server) {
	t.Helper()
	f := &fakeHEM{
		ifKID:    "aaaabbbbccccddddeeeeffff00001111",
		macKey:   []byte("self-ecdh-key-that-never-leaves!"),
		stored:   map[string][]byte{},
		peerKeys: map[string][]byte{},
	}
	// A deterministic Curve25519 public key for the identity.
	seed := bytes.Repeat([]byte{7}, 32)
	pub, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("deriving a test public key: %v", err)
	}
	copy(f.ifPub[:], pub)

	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeHEM) body(r *http.Request) map[string]any {
	raw, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	return m
}

func (f *fakeHEM) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	b64 := base64.StdEncoding.EncodeToString

	switch {
	case r.URL.Path == "/api/system/checkin" && r.Method == "GET":
		io.WriteString(w, `{"check":"challenge"}`)
	case r.URL.Path == "/checkin": // the broker leg
		io.WriteString(w, `{"checked":"ok"}`)
	case r.URL.Path == "/api/system/checkin" && r.Method == "POST":
		io.WriteString(w, `{"status":"OK"}`)

	case r.URL.Path == "/api/auth/token" && r.Method == "GET":
		// spk must be a usable X25519 point or the SDK cannot finish the eJWT.
		io.WriteString(w, `{"eid":"device-1","jti":"j","spk":"`+
			b64(curve25519.Basepoint)+`","exp":0,"lbl":"test"}`)
	case r.URL.Path == "/api/auth/token" && r.Method == "POST":
		body := f.body(r)
		// Record the scope so the test can check which authorities were asked for.
		if ejwt, ok := body["auth"].(string); ok {
			if parts := strings.Split(ejwt, "."); len(parts) == 3 {
				if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
					var claims struct {
						Scope string `json:"scope"`
					}
					_ = json.Unmarshal(payload, &claims)
					f.scopes = append(f.scopes, claims.Scope)
				}
			}
		}
		io.WriteString(w, `{"token":"jwt"}`)

	case r.URL.Path == "/api/keymgmt/create":
		body := f.body(r)
		f.ifLabel, _ = body["label"].(string)
		io.WriteString(w, `{"kid":"`+f.ifKID+`"}`)
	case strings.HasPrefix(r.URL.Path, "/api/keymgmt/get/"):
		kid := strings.TrimPrefix(r.URL.Path, "/api/keymgmt/get/")
		key := f.ifPub[:]
		if kid != f.ifKID {
			pk, ok := f.peerKeys[kid]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				io.WriteString(w, `{"error":"no such key"}`)
				return
			}
			key = pk
		}
		io.WriteString(w, `{"pubkey":"`+b64(key)+`","type":"PKEY,ECDH,CURVE25519","updated":1}`)
	case r.URL.Path == "/api/keymgmt/import":
		body := f.body(r)
		pk, _ := base64.StdEncoding.DecodeString(body["pubkey"].(string))
		d, _ := base64.StdEncoding.DecodeString(body["descr"].(string))
		label, _ := body["label"].(string)
		kid := peerKID(pk)
		// The device computes the identifier from the key and refuses a second
		// import of one it already holds.
		if _, exists := f.peerKeys[kid]; exists {
			w.WriteHeader(http.StatusNotAcceptable)
			io.WriteString(w, `{"error":"key already in repository"}`)
			return
		}
		f.peerKeys[kid] = pk
		f.imported = append(f.imported, importCall{kid: kid, label: label, pubKey: pk, descr: d})
		io.WriteString(w, `{"kid":"`+kid+`"}`)
	case r.URL.Path == "/api/keymgmt/search":
		f.search(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/keymgmt/delete/") && r.Method == "DELETE":
		kid := strings.TrimPrefix(r.URL.Path, "/api/keymgmt/delete/")
		f.deleted = append(f.deleted, kid)
		delete(f.stored, kid)
		delete(f.peerKeys, kid)
		for i, imp := range f.imported {
			if imp.kid == kid {
				f.imported = append(f.imported[:i:i], f.imported[i+1:]...)
				break
			}
		}
		io.WriteString(w, `{}`)
	case r.URL.Path == "/api/keymgmt/update":
		body := f.body(r)
		kid, _ := body["kid"].(string)
		f.updates = append(f.updates, body)
		d, _ := base64.StdEncoding.DecodeString(body["descr"].(string))
		// A peer's record lives with its import, so an update has to land there
		// or a later search would hand back the version before the change.
		updated := false
		for i, imp := range f.imported {
			if imp.kid == kid {
				f.imported[i].descr = d
				if label, ok := body["label"].(string); ok && label != "" {
					f.imported[i].label = label
				}
				updated = true
				break
			}
		}
		if !updated {
			f.stored[kid] = d
		}
		io.WriteString(w, `{}`)

	case r.URL.Path == "/api/crypto/cipher/wrap":
		body := f.body(r)
		f.wraps = append(f.wraps, body)
		io.WriteString(w, `{"wrapped":"`+b64(bytes.Repeat([]byte{0x5A}, descr.PSKWrappedLen))+`"}`)

	case r.URL.Path == "/api/crypto/hmac/hash":
		body := f.body(r)
		f.hashes = append(f.hashes, body)
		msg, _ := base64.StdEncoding.DecodeString(body["msg"].(string))
		io.WriteString(w, `{"mac":"`+b64(f.hmac(msg))+`"}`)
	case r.URL.Path == "/api/crypto/hmac/verify":
		body := f.body(r)
		f.verifies = append(f.verifies, body)
		msg, _ := base64.StdEncoding.DecodeString(body["msg"].(string))
		got, _ := base64.StdEncoding.DecodeString(body["mac"].(string))
		if !hmac.Equal(got, f.hmac(msg)) {
			w.WriteHeader(http.StatusNotAcceptable) // what the device returns
			return
		}
		io.WriteString(w, `{}`)

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeHEM) hmac(msg []byte) []byte {
	m := hmac.New(sha256.New, f.macKey)
	m.Write(msg)
	return m.Sum(nil)
}

// runProvision drives cmdProvision with the passphrase prompt stubbed out and
// stdout captured.
func runProvision(t *testing.T, args ...string) (stdout string, err error) {
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

	err = cmdProvision(args)

	os.Stdout = oldStdout
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	return string(out), err
}

const peerKeyA = "i14L0qgxykUZL7GVV2x/hBXwuvbcXbcv+TIEp60Pk0M="
const peerKeyB = "9Sq9OSCbaKMqvV6MDwo1sVoYUqyBRcqCPEHEHZ2Zvhc="

func TestProvisionWritesAnAuthenticatedTree(t *testing.T) {
	requireRoom(t, 70) // this profile carries DNS and an MTU as well
	f, srv := newFakeHEM(t)

	out, err := runProvision(t,
		"-hem", srv.URL, "-broker", srv.URL,
		"-address", "10.0.0.7/32",
		"-dns", "10.0.0.1",
		"-mtu", "1380",
		"-peer", "pubkey="+peerKeyA+",endpoint=203.0.113.1:51820,allowed-ips=10.0.0.0/24,keepalive=25,label=hq",
		"-peer", "pubkey="+peerKeyB+",endpoint=vpn.example.com:51820,allowed-ips=0.0.0.0/0,label=backup",
	)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	// stdout carries the public key and nothing else, so it can be piped.
	want := base64.StdEncoding.EncodeToString(f.ifPub[:])
	if strings.TrimSpace(out) != want {
		t.Errorf("stdout = %q, want just the public key %q", out, want)
	}

	if len(f.imported) != 2 {
		t.Fatalf("imported %d peers, want 2", len(f.imported))
	}
	if f.imported[0].label != "hq" || f.imported[1].label != "backup" {
		t.Errorf("labels = %q, %q", f.imported[0].label, f.imported[1].label)
	}

	// The peer records must decode to what was asked for on the command line.
	p0, err := descr.DecodePeer(f.imported[0].descr)
	if err != nil {
		t.Fatalf("peer 0 descr: %v", err)
	}
	if p0.Endpoint.String() != "203.0.113.1:51820" || p0.Keepalive != 25 {
		t.Errorf("peer 0 = %+v", p0)
	}
	if len(p0.AllowedIPs) != 1 || p0.AllowedIPs[0].String() != "10.0.0.0/24" {
		t.Errorf("peer 0 allowed-ips = %v", p0.AllowedIPs)
	}
	if p0.PSKWrapped != nil {
		t.Error("no PSK was requested, so none should be stored")
	}
	p1, err := descr.DecodePeer(f.imported[1].descr)
	if err != nil {
		t.Fatalf("peer 1 descr: %v", err)
	}
	if p1.Endpoint.String() != "vpn.example.com:51820" {
		t.Errorf("peer 1 endpoint = %s", p1.Endpoint.String())
	}

	// The interface record must be stored with a MAC and with the references in
	// the order the flags were given — that order is the failover priority.
	stored := f.stored[f.ifKID]
	if stored == nil {
		t.Fatal("no interface record was written")
	}
	ifRec, err := descr.DecodeInterface(stored)
	if err != nil {
		t.Fatalf("interface descr: %v", err)
	}
	if !ifRec.HasMAC {
		t.Fatal("the interface record was stored without a MAC")
	}
	if ifRec.MTU != 1380 || len(ifRec.Addrs) != 1 || ifRec.Addrs[0].String() != "10.0.0.7/32" {
		t.Errorf("interface record = %+v", ifRec)
	}
	keyA, _ := base64.StdEncoding.DecodeString(peerKeyA)
	keyB, _ := base64.StdEncoding.DecodeString(peerKeyB)
	if len(ifRec.PeerRefs) != 2 ||
		ifRec.PeerRefs[0] != descr.MakePeerRef(keyA) ||
		ifRec.PeerRefs[1] != descr.MakePeerRef(keyB) {
		t.Errorf("peer references are not in flag order: %x", ifRec.PeerRefs)
	}

	// The MAC key is the identity key against itself, never a peer's key.
	if len(f.hashes) != 1 {
		t.Fatalf("%d hmac/hash calls, want 1", len(f.hashes))
	}
	if f.hashes[0]["kid"] != f.ifKID || f.hashes[0]["ext_kid"] != f.ifKID {
		t.Errorf("hmac kid/ext_kid = %v/%v, want both %s",
			f.hashes[0]["kid"], f.hashes[0]["ext_kid"], f.ifKID)
	}

	// What was signed must be the canonical message over what was stored.
	var records []mac.PeerRecord
	for _, imp := range f.imported {
		var pr mac.PeerRecord
		copy(pr.PubKey[:], imp.pubKey)
		pr.Descr, err = descr.Normalize(imp.descr)
		if err != nil {
			t.Fatalf("normalize: %v", err)
		}
		records = append(records, pr)
	}
	storedNorm, err := descr.Normalize(stored)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	expected, err := mac.Canonical(f.ifPub, storedNorm, records)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	signed, _ := base64.StdEncoding.DecodeString(f.hashes[0]["msg"].(string))
	if !bytes.Equal(signed, expected) {
		t.Error("the signed message is not the canonical message over the stored records")
	}
	if !hmac.Equal(ifRec.MAC[:], f.hmac(expected)) {
		t.Error("the stored MAC does not match the canonical message")
	}

	// Every update carries a label beside the description: that is the shape the
	// reference suite uses, and a device rejected the description-only form.
	if len(f.updates) == 0 {
		t.Fatal("the interface record was never written")
	}
	for i, u := range f.updates {
		if label, _ := u["label"].(string); label == "" {
			t.Errorf("update %d sent no label: %v", i, u)
		}
	}

	// Provisioning verifies its own work before reporting success.
	if len(f.verifies) != 1 {
		t.Errorf("%d hmac/verify calls, want 1 — the written tree must be read back", len(f.verifies))
	}

	// Only the authorities the job needs, one token each.
	// keymgmt:get pays for the check that a peer is not already in the device,
	// which has to happen before an import that would be refused anyway.
	wantScopes := []string{"keymgmt:gen", "keymgmt:use:" + f.ifKID, "keymgmt:get", "keymgmt:imp", "keymgmt:upd"}
	if strings.Join(f.scopes, ",") != strings.Join(wantScopes, ",") {
		t.Errorf("scopes = %v, want %v", f.scopes, wantScopes)
	}
}

func TestProvisionWrapsThePSKUnderSelfECDH(t *testing.T) {
	f, srv := newFakeHEM(t)

	out, err := runProvision(t,
		"-hem", srv.URL, "-broker", srv.URL,
		"-address", "10.0.0.7/32",
		"-psk", "generate",
		"-peer", "pubkey="+peerKeyA+",endpoint=203.0.113.1:51820,allowed-ips=0.0.0.0/0",
	)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	if len(f.wraps) != 1 {
		t.Fatalf("%d wrap calls, want 1", len(f.wraps))
	}
	w := f.wraps[0]
	if w["kid"] != f.ifKID || w["ext_kid"] != f.ifKID {
		t.Errorf("wrap kid/ext_kid = %v/%v, want both %s — a peer's key would expose the KEK",
			w["kid"], w["ext_kid"], f.ifKID)
	}
	// The context names the peer the wrap belongs to, so a ciphertext lifted
	// into another peer's record derives a different key and fails to unwrap.
	wantCtx := config.PSKContext(descr.KID(mustKey(t, peerKeyA)))
	if w["ctx"] != base64.StdEncoding.EncodeToString(wantCtx) {
		t.Errorf("wrap ctx = %v, want %s", w["ctx"], wantCtx)
	}
	if len(wantCtx) > 64 {
		t.Errorf("the context is %d bytes, over the device's 64", len(wantCtx))
	}
	if w["alg"] != config.WrapAlg {
		t.Errorf("wrap alg = %v, want %s", w["alg"], config.WrapAlg)
	}
	// The PSK itself must never appear in a descr in the clear.
	sent, _ := base64.StdEncoding.DecodeString(w["msg"].(string))
	if len(sent) != pskLen {
		t.Errorf("wrapped %d bytes, want %d", len(sent), pskLen)
	}
	p, err := descr.DecodePeer(f.imported[0].descr)
	if err != nil {
		t.Fatalf("peer descr: %v", err)
	}
	if len(p.PSKWrapped) != descr.PSKWrappedLen {
		t.Fatalf("peer record has no wrapped PSK")
	}
	if bytes.Contains(f.imported[0].descr, sent) {
		t.Error("the plaintext PSK appears in the stored peer record")
	}

	// A generated key has to be shown, once, or the other end cannot use it.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "psk=") {
		t.Fatalf("stdout = %q, want the public key then psk=<base64>", out)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(lines[1], "psk="))
	if err != nil || len(raw) != pskLen {
		t.Errorf("psk line does not carry a %d-byte key: %v", pskLen, err)
	}
	if bytes.Equal(raw, make([]byte, pskLen)) {
		t.Error("the generated PSK is all zeros")
	}
}

func TestProvisionValidatesBeforeTouchingTheDevice(t *testing.T) {
	f, srv := newFakeHEM(t)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no address", []string{"-peer", "pubkey=" + peerKeyA + ",endpoint=1.2.3.4:1,allowed-ips=0.0.0.0/0"},
			"-address is required"},
		{"no peer", []string{"-address", "10.0.0.7/32"}, "-peer is required"},
		{"bad peer key", []string{"-address", "10.0.0.7/32", "-peer", "pubkey=zz,endpoint=1.2.3.4:1,allowed-ips=0.0.0.0/0"},
			"base64"},
		{"duplicate peer", []string{"-address", "10.0.0.7/32",
			"-peer", "pubkey=" + peerKeyA + ",endpoint=1.2.3.4:1,allowed-ips=0.0.0.0/0",
			"-peer", "pubkey=" + peerKeyA + ",endpoint=5.6.7.8:1,allowed-ips=10.0.0.0/8"},
			"duplicate public key"},
		{"psk on the command line", []string{"-address", "10.0.0.7/32", "-psk", "c2VjcmV0",
			"-peer", "pubkey=" + peerKeyA + ",endpoint=1.2.3.4:1,allowed-ips=0.0.0.0/0"},
			"visible in the process list"},
		// Enough routes to overflow any supported record size. The overflow has
		// to be caught before anything is stored, or a peer would be imported
		// with no interface record referencing it.
		{"peer over budget", []string{"-address", "10.0.0.7/32",
			"-peer", "pubkey=" + peerKeyA + ",endpoint=203.0.113.1:51820" +
				strings.Repeat(",allowed-ips=10.0.0.0/24", 18)},
			fmt.Sprintf("over the %d-byte limit", descr.Size)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-hem", srv.URL, "-broker", srv.URL}, tc.args...)
			_, err := runProvision(t, args...)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
			var ee *exitError
			if !asExit(err, &ee) || ee.code != exitUsage {
				t.Errorf("want exit code %d for a usage error, got %v", exitUsage, err)
			}
			f.mu.Lock()
			touched := len(f.imported) > 0 || len(f.stored) > 0
			f.mu.Unlock()
			if touched {
				t.Error("a rejected command must not have written anything to the device")
			}
		})
	}
}

func asExit(err error, target **exitError) bool {
	ee, ok := err.(*exitError)
	if ok {
		*target = ee
	}
	return ok
}
