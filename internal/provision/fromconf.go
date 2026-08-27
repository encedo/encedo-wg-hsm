package provision

import (
	"strconv"
	"strings"

	"github.com/encedo/encedo-wg-hsm/internal/session"
	"github.com/encedo/encedo-wg-hsm/internal/wgconf"
)

// FromConf turns a parsed WireGuard client configuration into parameters this
// package can write.
//
// The command line does not use it: `wg-hem import` goes through flags, because
// it lets somebody append provision's own flags after a `--` and have them mean
// what they always mean. A window has no flags to append, so it converts
// directly. TestFromConfAgreesWithTheFlags is what keeps the two paths saying
// the same thing.
//
// The label is asked for rather than derived. A .conf file has nowhere to carry
// a name for the peer, and the records are read by people afterwards - by
// `wg-hem status`, and by whoever is looking at a list of profiles a year from
// now.
func FromConf(c *wgconf.Conf, label string) (Params, error) {
	if strings.TrimSpace(label) == "" {
		return Params{}, session.Fail(session.KindUsage,
			"the peer needs a name - a .conf file does not carry one")
	}

	fields := []string{"label=" + label, "pubkey=" + c.PeerPubKey}
	if c.PeerEndpoint != "" {
		fields = append(fields, "endpoint="+c.PeerEndpoint)
	}
	for _, p := range c.PeerAllowed {
		fields = append(fields, "allowed-ips="+p.String())
	}
	if c.PeerKeepalive != 0 {
		fields = append(fields, "keepalive="+strconv.Itoa(c.PeerKeepalive))
	}
	// Through the same parser the flags go through, rather than by assigning
	// the fields across. The peer specification has rules - a missing endpoint,
	// an unroutable peer, a keepalive of zero - and a second way of building a
	// PeerSpec would be a second place for those rules to be absent.
	peer, err := ParsePeerSpec(strings.Join(fields, ","))
	if err != nil {
		return Params{}, session.Fail(session.KindUsage, "%w", err)
	}

	// The identity carries the peer's name too. Every identity provision writes
	// is otherwise labelled the same, which is invisible on a module holding
	// one and is exactly the problem on a module holding two: the window's
	// profile list then has two entries reading "wg-hem identity".
	p := Params{
		Addrs:      c.Addresses,
		DNS:        c.DNS,
		MTU:        c.MTU,
		ListenPort: c.ListenPort,
		Label:      label,
		Peers:      []PeerSpec{peer},
	}
	if err := p.Validate(); err != nil {
		return Params{}, err
	}
	return p, nil
}
