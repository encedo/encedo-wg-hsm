package runtime

import (
	"bufio"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// A get-operation response as wireguard-go writes one: flat keys, each peer
// beginning at its public_key and owning everything until the next.
const sampleGet = `private_key=0000000000000000000000000000000000000000000000000000000000000000
listen_port=51820
public_key=8b5e0bd2a831ca45192fb195576c7f8415f0baf6dc5db72ff932048ceb0f9343
preshared_key=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
endpoint=203.0.113.1:51820
last_handshake_time_sec=1700000000
last_handshake_time_nsec=250000000
rx_bytes=4096
tx_bytes=8192
persistent_keepalive_interval=25
allowed_ip=0.0.0.0/0
protocol_version=1
errno=0

`

func TestParseStatus(t *testing.T) {
	st, err := parseStatus(bufio.NewReader(strings.NewReader(sampleGet)))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if st.ListenPort != 51820 {
		t.Errorf("ListenPort = %d, want 51820", st.ListenPort)
	}
	if len(st.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(st.Peers))
	}
	p := st.Peers[0]
	if got := hex.EncodeToString(p.PublicKey[:]); got != "8b5e0bd2a831ca45192fb195576c7f8415f0baf6dc5db72ff932048ceb0f9343" {
		t.Errorf("PublicKey = %s", got)
	}
	if p.Endpoint != "203.0.113.1:51820" {
		t.Errorf("Endpoint = %q", p.Endpoint)
	}
	if want := time.Unix(1700000000, 250000000); !p.LastHandshake.Equal(want) {
		t.Errorf("LastHandshake = %v, want %v", p.LastHandshake, want)
	}
	if p.RxBytes != 4096 || p.TxBytes != 8192 {
		t.Errorf("transfer = %d/%d, want 4096/8192", p.RxBytes, p.TxBytes)
	}
	if p.Keepalive != 25 {
		t.Errorf("Keepalive = %d, want 25", p.Keepalive)
	}
	if !p.HasPSK {
		t.Error("HasPSK = false, want true")
	}
}

// A tunnel that has never handshaken is the case worth telling apart: with the
// private key in the device, an interface whose HEM is unreachable comes up
// looking healthy and simply never completes one.
func TestParseStatusReportsNoHandshake(t *testing.T) {
	in := `public_key=8b5e0bd2a831ca45192fb195576c7f8415f0baf6dc5db72ff932048ceb0f9343
last_handshake_time_sec=0
last_handshake_time_nsec=0
rx_bytes=0
tx_bytes=0
errno=0

`
	st, err := parseStatus(bufio.NewReader(strings.NewReader(in)))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if !st.Peers[0].LastHandshake.IsZero() {
		t.Errorf("LastHandshake = %v, want the zero time", st.Peers[0].LastHandshake)
	}
}

func TestParseStatusSeparatesPeers(t *testing.T) {
	in := `public_key=1111111111111111111111111111111111111111111111111111111111111111
rx_bytes=1
public_key=2222222222222222222222222222222222222222222222222222222222222222
rx_bytes=2
last_handshake_time_sec=1700000000
errno=0

`
	st, err := parseStatus(bufio.NewReader(strings.NewReader(in)))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if len(st.Peers) != 2 {
		t.Fatalf("peers = %d, want 2", len(st.Peers))
	}
	if st.Peers[0].RxBytes != 1 || st.Peers[1].RxBytes != 2 {
		t.Errorf("counters landed on the wrong peers: %d, %d", st.Peers[0].RxBytes, st.Peers[1].RxBytes)
	}
	if !st.Peers[0].LastHandshake.IsZero() {
		t.Error("the second peer's handshake time was attributed to the first")
	}
	if st.Peers[1].LastHandshake.IsZero() {
		t.Error("the second peer lost its handshake time")
	}
}

// An all-zero preshared_key is how wireguard-go says "none"; reporting it as a
// key present would misdescribe the tunnel's protection.
func TestParseStatusTreatsAZeroPSKAsAbsent(t *testing.T) {
	in := `public_key=1111111111111111111111111111111111111111111111111111111111111111
preshared_key=` + strings.Repeat("0", 64) + `
errno=0

`
	st, err := parseStatus(bufio.NewReader(strings.NewReader(in)))
	if err != nil {
		t.Fatalf("parseStatus: %v", err)
	}
	if st.Peers[0].HasPSK {
		t.Error("HasPSK = true for an all-zero key")
	}
}

func TestParseStatusReportsAnErrno(t *testing.T) {
	in := "errno=1\n\n"
	if _, err := parseStatus(bufio.NewReader(strings.NewReader(in))); err == nil {
		t.Fatal("a non-zero errno was accepted")
	}
}

func TestParseStatusRejectsAMalformedKey(t *testing.T) {
	in := "public_key=nothex\nerrno=0\n\n"
	if _, err := parseStatus(bufio.NewReader(strings.NewReader(in))); err == nil {
		t.Fatal("a malformed public key was accepted")
	}
}

// A response cut short is an error, not an empty device: the difference is
// whether the caller may conclude the interface has no peers.
func TestParseStatusRejectsATruncatedResponse(t *testing.T) {
	in := "listen_port=51820\n"
	if _, err := parseStatus(bufio.NewReader(strings.NewReader(in))); err == nil {
		t.Fatal("a response with no terminating blank line was accepted")
	}
}
