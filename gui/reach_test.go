package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"

	hem "github.com/encedo/hem-sdk-go"
)

// TestTheAdvancedPanelFits is the width twin of TestAdvancedHeightFits. A
// fixed-size window gives way to its content rather than clipping it, so one
// long line in the panel - a dial error, a long appliance address - took the
// window to two thousand pixels with nothing plugged in.
func TestTheAdvancedPanelFits(t *testing.T) {
	long := `GET https://appliance.branch-office.example.com:8443/api/system/version: Get "https://appliance.branch-office.example.com:8443/api/system/version": proxyconnect tcp: dial tcp 10.0.0.1:3128: i/o timeout`
	cases := []struct {
		name  string
		event Event
	}{
		{"stand-in", Event{State: NoModule}},
		{"long reason", Event{State: NoModule, HEM: "https://appliance.branch-office.example.com:8443", Reach: long}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := test.NewApp()
			defer a.Quit()

			u := &ui{app: a, sess: newFakeSession()}
			defer u.sess.Close()
			u.win = test.NewWindow(nil)
			defer u.win.Close()
			u.build()

			u.advBox.SetChecked(true)
			u.render(tc.event)

			if need := u.win.Content().MinSize().Width; need > windowWidth {
				t.Errorf("the panel needs %.1f of width and the window is %d:\n%s", need, windowWidth, u.advText.Text)
			}
		})
	}
}

func TestFoldKeepsEverything(t *testing.T) {
	for _, s := range []string{"", "short", "https://my.ence.do/api/system/version/with/no/spaces/at/all", "a b c d e f g h i j k l m n o p q r s t u v w x y z"} {
		lines := fold(s, 10)
		for _, l := range lines {
			if len([]rune(l)) > 10 {
				t.Errorf("%q: line %q is over 10", s, l)
			}
		}
		if strings.ReplaceAll(strings.Join(lines, ""), " ", "") != strings.ReplaceAll(s, " ", "") {
			t.Errorf("%q folded to %q, which lost something", s, lines)
		}
	}
}

// The messages are the SDK's as they arrive, the first from the screenshot that
// prompted this.
func TestReachReasonNamesTheCause(t *testing.T) {
	const pre = `GET https://my.ence.do/api/system/version: Get "https://my.ence.do/api/system/version": `
	cases := []struct {
		err  error
		want string
	}{
		{&hem.HemError{Code: "timeout", Message: pre + "context deadline exceeded"}, "no answer in 2s"},
		{&hem.HemError{Code: "network", Message: pre + "dial tcp: lookup my.ence.do: no such host"}, "the name does not resolve"},
		{&hem.HemError{Code: "network", Message: pre + "dial tcp: lookup my.ence.do: no such host is known."}, "the name does not resolve"},
		{&hem.HemError{Code: "network", Message: pre + "dial tcp 192.168.7.1:443: connect: connection refused"}, "refused the connection"},
		{&hem.HemError{Code: "network", Message: pre + "dial tcp 192.168.7.1:443: connectex: No connection could be made because the target machine actively refused it."}, "refused the connection"},
		{&hem.HemError{Code: "network", Message: pre + "dial tcp 192.168.7.1:443: connect: network is unreachable"}, "no route"},
		{&hem.HemError{Code: "network", Message: pre + "tls: failed to verify certificate: x509: certificate signed by unknown authority"}, "certificate not accepted: tls: failed to verify certificate: x509: certificate signed by unknown authority"},
		{&hem.HemError{Code: "network", Message: pre + "EOF"}, "EOF"},
	}
	for _, tc := range cases {
		if got := reachReason(tc.err); !strings.Contains(got, tc.want) {
			t.Errorf("%v\n  said %q, want it to contain %q", tc.err, got, tc.want)
		}
		if got := reachReason(tc.err); strings.Contains(got, "my.ence.do/api") {
			t.Errorf("%q repeats the address", got)
		}
	}
}
