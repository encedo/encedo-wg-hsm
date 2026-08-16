package ipc

import (
	"bytes"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The boundary's claim is that one scoped, expiring token crosses it and nothing
// else. That is a property of this struct, and a struct grows a field at a time
// - each one convenient, none obviously wrong on its own. So it is checked.
//
// There are exactly two exceptions and both are named here rather than let
// through by a looser pattern, so that adding a third has to be a decision
// somebody wrote down.
//
// Token is what the component acts with, and the reason it needs neither the
// passphrase nor the configuration. PubKeys is public by definition and by section 8,
// and carrying it is what keeps the token standing alone - without it the
// component would need keymgmt:get as well.
func TestRequestsCarryOneSecretAndNoOther(t *testing.T) {
	allowed := map[string]bool{"token": true, "pubkeys": true}
	banned := []string{"key", "pass", "secret", "psk", "seed", "auth", "phrase"}
	rt := reflect.TypeOf(Request{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		if allowed[name] {
			continue
		}
		for _, b := range banned {
			if strings.Contains(name, b) {
				t.Errorf("Request.%s looks like it carries a secret; the only one that crosses is the token",
					rt.Field(i).Name)
			}
		}
	}
}

// A message that tells a privileged process to stop verifying certificates is
// not the same act as a person typing a flag about their own session. The
// command line keeps --insecure; this must never grow one.
func TestNothingCanAskThePrivilegedSideToSkipTLS(t *testing.T) {
	rt := reflect.TypeOf(Request{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		for _, bad := range []string{"insecure", "skipverify", "notls", "trust"} {
			if strings.Contains(name, bad) {
				t.Errorf("Request.%s would let a request disable certificate verification in a root process",
					rt.Field(i).Name)
			}
		}
	}
}

func TestRequestRoundTrips(t *testing.T) {
	want := Request{
		Op:       OpStart,
		Build:    Current(),
		HEMURL:   "https://my.ence.do",
		Identity: "bd18991ec27721e35c91c48edc8de009",
		Peer:     "7b339a3540e3f7a1febb2d12fef1bf8d",
		Token:    "eyJhbGciOi.not.a.real.one",
	}
	b, err := Encode(want)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeRequest(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the request:\n got %+v\nwant %+v", got, want)
	}
}

func TestEventRoundTrips(t *testing.T) {
	when := time.Now().UTC().Truncate(time.Second)
	want := Msg{Type: TypeEvent, Event: &Event{
		State: "connected", Interface: "wg0",
		Peer: "blbx", PeerKID: "7b339a35", Endpoint: "185.200.244.117:51820",
		Rx: 860, Tx: 948,
		LastHandshake: when, ExpiresAt: when.Add(time.Hour),
		Notice: `Moved to "backup" - "hq" did not answer within 15s.`,
	}}
	b, err := Encode(want)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeMsg(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the event:\n got %+v\nwant %+v", *got.Event, *want.Event)
	}
}

func TestValidateRejects(t *testing.T) {
	full := func(mut func(*Request)) Request {
		r := Request{Op: OpStart, Build: Current(), HEMURL: "https://my.ence.do",
			Identity: "aa", Token: "t"}
		mut(&r)
		return r
	}
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"no address", full(func(r *Request) { r.HEMURL = "" }), "device"},
		{"no identity", full(func(r *Request) { r.Identity = "" }), "interface key"},
		{"no token", full(func(r *Request) { r.Token = "" }), "token"},
		{"no build", full(func(r *Request) { r.Build = Build{} }), "build"},
		{"refresh with no token", Request{Op: OpRefresh}, "token"},
		{"nonsense", Request{Op: "delete-everything"}, "unknown"},
	}
	for _, c := range cases {
		err := c.req.Validate()
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
	}
}

func TestValidateAccepts(t *testing.T) {
	ok := []Request{
		{Op: OpStart, Build: Current(), HEMURL: "https://my.ence.do", Identity: "aa", Token: "t"},
		{Op: OpStop},
		{Op: OpRefresh, Token: "t"},
	}
	for _, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("%s was refused: %v", r.Op, err)
		}
	}
}

// The record dialect is part of what makes two builds compatible, because the
// mismatch presents as a MAC failure - which reads as a tampered configuration
// rather than as a build-flag disagreement.
func TestBuildsOfDifferentDialectsDoNotMatch(t *testing.T) {
	a := Build{Release: "0.9.1", Descr: 128}
	b := Build{Release: "0.9.1", Descr: 64}
	if a.Matches(b) {
		t.Error("a 128-byte build accepted a 64-byte one; the failure would surface as a MAC error")
	}
	if !a.Matches(a) {
		t.Error("a build did not match itself")
	}
	if a.Matches(Build{Release: "0.9.2", Descr: 128}) {
		t.Error("two releases matched")
	}
}

func TestFramingRoundTripsOverAPipe(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	want := Request{Op: OpStop}
	go func() { _ = WriteMsg(client, want) }()

	raw, err := ReadMsg(server)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got, err := DecodeRequest(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Op != want.Op {
		t.Errorf("op = %q, want %q", got.Op, want.Op)
	}
}

// A component listening on a socket must not be persuadable into a large
// allocation by whatever can reach it.
func TestAnOversizedFrameIsRefusedBeforeAllocating(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xff, 0xff, 0xff, 0xff}) // four gigabytes, claimed
	if _, err := ReadMsg(&buf); err == nil {
		t.Fatal("a frame claiming 4 GiB was accepted")
	}
}

func TestWritingAnOversizedMessageIsRefused(t *testing.T) {
	var buf bytes.Buffer
	big := Request{Op: OpStart, Token: strings.Repeat("x", maxMessage+1)}
	if err := WriteMsg(&buf, big); err == nil {
		t.Fatal("a message past the limit was written")
	}
	if buf.Len() != 0 {
		t.Errorf("%d bytes were written before the refusal; a partial frame desynchronises the stream", buf.Len())
	}
}

// The handover is one token. Anything that made it a bundle again would be
// undoing the reason keymgmt:get was removed from the component's side.
func TestOnlyOneCredentialCrosses(t *testing.T) {
	rt := reflect.TypeOf(Request{})
	credentials := 0
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Type.Kind() == reflect.String && strings.Contains(strings.ToLower(f.Name), "token") {
			credentials++
		}
		if f.Type.Kind() == reflect.Map && strings.Contains(strings.ToLower(f.Name), "token") {
			t.Errorf("Request.%s is a bundle of tokens; the component holds one", f.Name)
		}
	}
	if credentials != 1 {
		t.Errorf("Request carries %d token fields, want exactly 1", credentials)
	}
}

// Public keys are not secrets - section 8 treats them and the records as public - so
// carrying them is what lets the token stand alone.
func TestPublicKeysMayCross(t *testing.T) {
	r := Request{Op: OpStart, Build: Current(), HEMURL: "https://my.ence.do",
		Identity: "aa", Token: "t",
		PubKeys: map[string]string{"aa": "AAAA", "bb": "BBBB"}}
	if err := r.Validate(); err != nil {
		t.Fatalf("a start carrying public keys was refused: %v", err)
	}
	b, err := Encode(r)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeRequest(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.PubKeys) != 2 || got.PubKeys["bb"] != "BBBB" {
		t.Errorf("public keys did not survive the wire: %v", got.PubKeys)
	}
}
