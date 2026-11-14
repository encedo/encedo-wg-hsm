package runtime

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseServices(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\n" +
		"Wi-Fi\nThunderbolt Bridge\n*iPhone USB\nUSB 10/100/1000 LAN\n\n"
	want := []string{"Wi-Fi", "Thunderbolt Bridge", "USB 10/100/1000 LAN"}
	if got := parseServices(out); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseDNSServers(t *testing.T) {
	if got := parseDNSServers("There aren't any DNS Servers set on Wi-Fi.\n"); got != nil {
		t.Errorf("none set: got %q", got)
	}
	got := parseDNSServers("192.168.1.1\nfe80::1%en0\n2001:db8::53\n")
	want := []string{"192.168.1.1", "fe80::1%en0", "2001:db8::53"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSetArgs(t *testing.T) {
	if got := (macDNSEntry{Service: "Wi-Fi"}).setArgs(); got[len(got)-1] != "Empty" {
		t.Errorf("no servers should restore Empty, got %q", got)
	}
	got := (macDNSEntry{Service: "USB LAN", Servers: []string{"1.1.1.1", "8.8.8.8"}}).setArgs()
	want := []string{"networksetup", "-setdnsservers", "USB LAN", "1.1.1.1", "8.8.8.8"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMacDNSFileRoundTrip(t *testing.T) {
	old := macDNSFile
	macDNSFile = filepath.Join(t.TempDir(), "macos-dns.json")
	t.Cleanup(func() { macDNSFile = old })

	in := &macDNSSaved{PID: 42, Interface: "utun4", Services: []macDNSEntry{
		{Service: "Wi-Fi", Servers: []string{"192.168.1.1"}}, {Service: "Thunderbolt Bridge"}}}
	if err := writeMacDNS(in); err != nil {
		t.Fatal(err)
	}
	out, err := readMacDNS()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("got %+v, want %+v", out, in)
	}
}
