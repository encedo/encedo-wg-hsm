package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/encedo/encedo-wg-hsm/internal/descr"
)

// peerSpec is one --peer flag: a comma-separated list of key=value pairs.
//
//	pubkey=BASE64,endpoint=vpn.acme.com:51820,allowed-ips=0.0.0.0/0[,keepalive=25][,label=NAME]
//
// allowed-ips may be repeated to give a peer several ranges. Nothing here is
// secret - a peer's public key, endpoint and routes are all public - so unlike
// the PSK these may travel on the command line.
type peerSpec struct {
	PubKey     []byte
	Label      string
	Endpoint   descr.Endpoint
	AllowedIPs []netip.Prefix
	Keepalive  uint8
}

func parsePeerSpec(s string) (peerSpec, error) {
	var p peerSpec
	if strings.TrimSpace(s) == "" {
		return p, fmt.Errorf("empty --peer")
	}

	var seenEndpoint bool
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return p, fmt.Errorf("field %q is not key=value", field)
		}
		key = strings.TrimSpace(strings.ToLower(key))
		value = strings.TrimSpace(value)

		switch key {
		case "pubkey":
			raw, err := base64.StdEncoding.DecodeString(value)
			if err != nil {
				return p, fmt.Errorf("pubkey is not valid base64: %w", err)
			}
			if len(raw) != pubKeyLen {
				return p, fmt.Errorf("pubkey is %d bytes, a Curve25519 key is %d", len(raw), pubKeyLen)
			}
			p.PubKey = raw
		case "label":
			p.Label = value
		case "endpoint":
			ep, err := parseEndpoint(value)
			if err != nil {
				return p, err
			}
			p.Endpoint = ep
			seenEndpoint = true
		case "allowed-ips", "allowed-ip":
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return p, fmt.Errorf("allowed-ips %q: %w", value, err)
			}
			p.AllowedIPs = append(p.AllowedIPs, prefix.Masked())
		case "keepalive":
			n, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return p, fmt.Errorf("keepalive %q: must be 1..255 seconds", value)
			}
			if n == 0 {
				return p, fmt.Errorf("keepalive 0 means disabled; omit the field instead")
			}
			p.Keepalive = uint8(n)
		default:
			return p, fmt.Errorf("unknown field %q", key)
		}
	}

	if p.PubKey == nil {
		return p, fmt.Errorf("missing pubkey")
	}
	if !seenEndpoint {
		return p, fmt.Errorf("missing endpoint")
	}
	if len(p.AllowedIPs) == 0 {
		return p, fmt.Errorf("missing allowed-ips: a peer with no routes would receive no traffic")
	}
	if p.Label == "" {
		p.Label = "wg peer " + base64.StdEncoding.EncodeToString(p.PubKey)[:8]
	}
	return p, nil
}

// parseEndpoint accepts host:port with host being an IPv4 literal, a bracketed
// IPv6 literal, or a name to resolve at startup.
func parseEndpoint(s string) (descr.Endpoint, error) {
	var e descr.Endpoint
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return descr.Endpoint{IP: ap.Addr().Unmap(), Port: ap.Port()}, nil
	}
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return e, fmt.Errorf("endpoint %q: expected host:port", s)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return e, fmt.Errorf("endpoint %q: port must be 1..65535", s)
	}
	if host == "" {
		return e, fmt.Errorf("endpoint %q: missing host", s)
	}
	if len(host) > descr.MaxHostname {
		return e, fmt.Errorf("endpoint hostname is %d bytes, max %d", len(host), descr.MaxHostname)
	}
	return descr.Endpoint{Host: host, Port: uint16(port)}, nil
}

// record builds the peer's stored form. wrappedPSK is nil when the peer has no
// pre-shared key.
func (p peerSpec) record(wrappedPSK []byte) (descr.Peer, error) {
	rec := descr.Peer{
		Endpoint:   p.Endpoint,
		AllowedIPs: p.AllowedIPs,
		Keepalive:  p.Keepalive,
		PSKWrapped: wrappedPSK,
	}
	// Encoding here rather than at write time so an over-budget peer is
	// reported before anything is stored in the device.
	if _, err := rec.Encode(); err != nil {
		return rec, err
	}
	return rec, nil
}
