//go:build !windows

package helper

import (
	"net"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestRequestsCarryNothingSecret(t *testing.T) {
	// The boundary's whole claim is that the privileged side never learns a
	// secret. That is a property of this struct, and a struct grows a field at a
	// time — each one convenient, none of them alone obviously wrong. So it is
	// checked rather than intended.
	banned := []string{"key", "pass", "secret", "token", "psk", "seed", "auth"}
	rt := reflect.TypeOf(Request{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		for _, b := range banned {
			if strings.Contains(name, b) {
				t.Errorf("Request.%s looks like it carries a secret; the boundary is in the wrong place",
					rt.Field(i).Name)
			}
		}
	}
}

func TestRequestRoundTrips(t *testing.T) {
	want := Request{
		Op:     OpUp,
		Name:   "wg0",
		Addrs:  []netip.Prefix{netip.MustParsePrefix("10.99.0.7/32")},
		Routes: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")},
		Hosts:  []netip.Addr{netip.MustParseAddr("185.200.244.117")},
		DNS:    []string{"10.99.0.1"},
		MTU:    1420,
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

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{"unknown op", Request{Op: "reboot"}, "unknown operation"},
		{"no interface", Request{Op: OpUp}, "needs an interface name"},
		{"no hosts to pin", Request{Op: OpPin}, "needs at least one address"},
		{"mtu out of range", Request{Op: OpSetMTU, Name: "wg0", MTU: 70000}, "out of range"},
		{"invalid route", Request{Op: OpAddRoutes, Name: "wg0", Routes: []netip.Prefix{{}}}, "invalid route"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.Validate()
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	ok := []Request{
		{Op: OpUp, Name: "wg0", Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}},
		{Op: OpDown, Name: "wg0"},
		{Op: OpPin, Hosts: []netip.Addr{netip.MustParseAddr("1.2.3.4")}},
		{Op: OpSetMTU, Name: "wg0", MTU: 1420},
	}
	for _, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("%s should be accepted: %v", r.Op, err)
		}
	}
}

// TestDescriptorCrossesTheBoundary is the one that matters. Everything else the
// helper does could be a command with parsed output; the tunnel descriptor could
// not, and getting it across is the reason the helper is a process on a socket
// rather than a script.
//
// It needs no privilege: passing a descriptor is not privileged, only creating
// a tunnel one is. Any file proves the mechanism.
func TestDescriptorCrossesTheBoundary(t *testing.T) {
	priv, unpriv, err := socketPair(t)
	if err != nil {
		t.Fatalf("socket pair: %v", err)
	}

	payload := []byte("this stands in for a tunnel")
	tmp, err := os.CreateTemp(t.TempDir(), "fd-*")
	if err != nil {
		t.Fatalf("temp: %v", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := tmp.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- SendFD(priv, Response{OK: true, HasFD: true}, int(tmp.Fd()))
	}()

	resp, f, err := RecvFD(unpriv)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("send: %v", err)
	}
	if !resp.OK || !resp.HasFD {
		t.Fatalf("response did not announce the descriptor: %+v", resp)
	}
	defer f.Close()

	// The received descriptor must be a working handle in this process, not a
	// number that happened to survive the trip.
	got := make([]byte, len(payload))
	if _, err := f.Read(got); err != nil {
		t.Fatalf("reading through the received descriptor: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("read %q through the descriptor, want %q", got, payload)
	}
}

// TestRefusalTravels checks the unhappy path, which is the one a person meets:
// the helper declines and the reason has to arrive intact rather than as a bare
// failure.
func TestRefusalTravels(t *testing.T) {
	priv, unpriv, err := socketPair(t)
	if err != nil {
		t.Fatalf("socket pair: %v", err)
	}
	go func() {
		_ = SendFD(priv, Response{OK: false, Err: "no such interface"}, -1)
	}()

	_, f, err := RecvFD(unpriv)
	if f != nil {
		f.Close()
		t.Error("a refusal must not carry a descriptor")
	}
	if err == nil || !strings.Contains(err.Error(), "no such interface") {
		t.Errorf("the reason did not survive: %v", err)
	}
}

func socketPair(t *testing.T) (*net.UnixConn, *net.UnixConn, error) {
	t.Helper()
	a, b, err := unixSocketPair()
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b, nil
}
