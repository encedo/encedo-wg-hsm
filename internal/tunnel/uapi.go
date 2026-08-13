package tunnel

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/encedo/encedo-wg-hsm/internal/config"
)

// uapiConfig renders the set-operation wireguard-go is configured with.
//
// private_key is 64 zeros: the fork's SetPrivateKey intercepts it and takes the
// public key from the injected session instead, because the real private key is
// in the device and stays there.
func uapiConfig(tree *config.Tree, peer *config.Peer, psk []byte) string {
	var sb strings.Builder

	sb.WriteString("private_key=" + strings.Repeat("0", 64) + "\n")
	if tree.Iface.ListenPort != 0 {
		fmt.Fprintf(&sb, "listen_port=%d\n", tree.Iface.ListenPort)
	}
	writePeer(&sb, peer, psk)

	sb.WriteString("\n")
	return sb.String()
}

// uapiReplacePeer swaps the active peer for another and leaves the interface's
// own settings alone. replace_peers drops the previous one, which is the point:
// two peers claiming the same AllowedIPs is not something WireGuard can route.
func uapiReplacePeer(peer *config.Peer, psk []byte) string {
	var sb strings.Builder
	sb.WriteString("replace_peers=true\n")
	writePeer(&sb, peer, psk)
	sb.WriteString("\n")
	return sb.String()
}

func writePeer(sb *strings.Builder, peer *config.Peer, psk []byte) {
	fmt.Fprintf(sb, "public_key=%s\n", hex.EncodeToString(peer.PubKey[:]))
	if !peer.Endpoint.IsZero() {
		fmt.Fprintf(sb, "endpoint=%s\n", peer.Endpoint.String())
	}
	for _, a := range peer.AllowedIPs {
		fmt.Fprintf(sb, "allowed_ip=%s\n", a)
	}
	if peer.Keepalive != 0 {
		fmt.Fprintf(sb, "persistent_keepalive_interval=%d\n", peer.Keepalive)
	}
	if len(psk) != 0 {
		fmt.Fprintf(sb, "preshared_key=%s\n", hex.EncodeToString(psk))
	}
}

func dnsServers(tree *config.Tree) []string {
	out := make([]string, 0, len(tree.Iface.DNS))
	for _, d := range tree.Iface.DNS {
		out = append(out, d.String())
	}
	return out
}
