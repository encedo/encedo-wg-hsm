package runtime

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DeviceStatus is what a running interface reports about itself over the UAPI
// socket — the same source `wg show` reads, and the only one that knows whether
// a handshake has actually happened.
type DeviceStatus struct {
	ListenPort uint16
	Peers      []PeerStatus
}

// PeerStatus is one peer's live state.
type PeerStatus struct {
	PublicKey [32]byte
	Endpoint  string

	// LastHandshake is the zero time when no handshake has completed yet. That
	// is the interesting case: with the private key in the device, a tunnel that
	// cannot reach its HEM comes up and simply never handshakes.
	LastHandshake time.Time

	RxBytes   uint64
	TxBytes   uint64
	Keepalive uint16
	HasPSK    bool
}

// Status asks the interface what it is doing. It returns an error when nothing
// is listening, which is how a caller learns the interface is not up.
func Status(ifname string) (*DeviceStatus, error) {
	conn, err := UAPIDial(ifname)
	if err != nil {
		return nil, fmt.Errorf("no interface %s is listening: %w", ifname, err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("get=1\n\n")); err != nil {
		return nil, fmt.Errorf("querying %s: %w", ifname, err)
	}
	return parseStatus(bufio.NewReader(conn))
}

// parseStatus reads the get-operation response. Keys arrive flat: everything
// after a public_key belongs to that peer until the next one.
func parseStatus(r *bufio.Reader) (*DeviceStatus, error) {
	st := &DeviceStatus{}
	var sec, nsec int64

	flush := func() {
		if len(st.Peers) == 0 {
			return
		}
		p := &st.Peers[len(st.Peers)-1]
		if sec != 0 || nsec != 0 {
			p.LastHandshake = time.Unix(sec, nsec)
		}
		sec, nsec = 0, 0
	}

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("reading the interface state: %w", err)
		}
		line = strings.TrimRight(line, "\n")
		if line == "" {
			flush()
			return st, nil
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "errno":
			if value != "0" {
				return nil, fmt.Errorf("the interface reported errno %s", value)
			}
		case "listen_port":
			if n, err := strconv.ParseUint(value, 10, 16); err == nil {
				st.ListenPort = uint16(n)
			}
		case "public_key":
			flush()
			var p PeerStatus
			raw, err := hex.DecodeString(value)
			if err != nil || len(raw) != len(p.PublicKey) {
				return nil, fmt.Errorf("the interface reported a malformed public key %q", value)
			}
			copy(p.PublicKey[:], raw)
			st.Peers = append(st.Peers, p)
		default:
			if len(st.Peers) == 0 {
				continue
			}
			p := &st.Peers[len(st.Peers)-1]
			switch key {
			case "endpoint":
				p.Endpoint = value
			case "last_handshake_time_sec":
				sec, _ = strconv.ParseInt(value, 10, 64)
			case "last_handshake_time_nsec":
				nsec, _ = strconv.ParseInt(value, 10, 64)
			case "rx_bytes":
				p.RxBytes, _ = strconv.ParseUint(value, 10, 64)
			case "tx_bytes":
				p.TxBytes, _ = strconv.ParseUint(value, 10, 64)
			case "persistent_keepalive_interval":
				if n, err := strconv.ParseUint(value, 10, 16); err == nil {
					p.Keepalive = uint16(n)
				}
			case "preshared_key":
				p.HasPSK = value != strings.Repeat("0", 64)
			}
		}
	}
}
