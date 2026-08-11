package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Interface holds the [Interface] section of a WireGuard config with HSM extensions.
type Interface struct {
	Address      netip.Prefix
	ListenPort   int
	HEMURL       string
	HEMKID       string
	HEMBrokerURL string   // optional broker URL; falls back to built-in default if empty
	DNS          []string // optional DNS servers (comma-separated in config)
	MTU          int      // optional MTU (0 = system default)
}

// Peer holds a [Peer] section of a WireGuard config.
// Either PublicKey or HEMKID must be set (HEMKID takes precedence).
//
// Addresses and prefixes are parsed here rather than carried as strings: a typo
// in AllowedIPs would otherwise surface while the interface is half up, with
// routes already installed and the default route possibly among them.
type Peer struct {
	PublicKey           string // base64 Curve25519 public key (standard WireGuard)
	HEMKID              string // HSM key ID of peer's public key (ext_kid in ECDH API)
	Endpoint            string
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

// Config holds the parsed WireGuard + HSM configuration.
type Config struct {
	Interface Interface
	Peers     []Peer
}

// ParseConfig parses a WireGuard config file extended with HEM_URL and HEM_KID fields.
func ParseConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := &Config{}
	var currentPeer *Peer
	var inInterface, inPeer bool

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section := line[1 : len(line)-1]

			// flush current peer before starting a new section
			if currentPeer != nil {
				if currentPeer.PublicKey == "" && currentPeer.HEMKID == "" {
					return nil, fmt.Errorf("peer is missing PublicKey or HEM_KID")
				}
				cfg.Peers = append(cfg.Peers, *currentPeer)
				currentPeer = nil
			}

			inInterface = false
			inPeer = false

			switch strings.ToLower(section) {
			case "interface":
				inInterface = true
			case "peer":
				inPeer = true
				currentPeer = &Peer{}
				// unknown sections are silently ignored
			}
			continue
		}

		// key = value
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])

		switch {
		case inInterface:
			switch key {
			case "PrivateKey":
				return nil, fmt.Errorf("PrivateKey must not be present in config — use HEM_KID instead")
			case "Address":
				prefix, err := netip.ParsePrefix(value)
				if err != nil {
					return nil, fmt.Errorf("invalid Address %q: %w", value, err)
				}
				cfg.Interface.Address = prefix
			case "ListenPort":
				port, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("invalid ListenPort: %w", err)
				}
				cfg.Interface.ListenPort = port
			case "HEM_URL":
				cfg.Interface.HEMURL = value
			case "HEM_KID":
				if err := validateKID(value); err != nil {
					return nil, err
				}
				cfg.Interface.HEMKID = value
			case "HEM_BROKER_URL":
				cfg.Interface.HEMBrokerURL = value
			case "DNS":
				for _, s := range strings.Split(value, ",") {
					if s = strings.TrimSpace(s); s != "" {
						cfg.Interface.DNS = append(cfg.Interface.DNS, s)
					}
				}
			case "MTU":
				mtu, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("invalid MTU: %w", err)
				}
				cfg.Interface.MTU = mtu
				// unknown keys silently ignored
			}

		case inPeer:
			switch key {
			case "PublicKey":
				currentPeer.PublicKey = value
			case "HEM_KID":
				if err := validateKID(value); err != nil {
					return nil, fmt.Errorf("peer HEM_KID: %w", err)
				}
				currentPeer.HEMKID = value
			case "Endpoint":
				currentPeer.Endpoint = value
			case "AllowedIPs":
				for _, cidr := range strings.Split(value, ",") {
					cidr = strings.TrimSpace(cidr)
					if cidr == "" {
						continue
					}
					prefix, err := netip.ParsePrefix(cidr)
					if err != nil {
						return nil, fmt.Errorf("invalid AllowedIPs %q: %w", cidr, err)
					}
					currentPeer.AllowedIPs = append(currentPeer.AllowedIPs, prefix)
				}
			case "PersistentKeepalive":
				ka, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("invalid PersistentKeepalive: %w", err)
				}
				currentPeer.PersistentKeepalive = ka
				// unknown keys silently ignored
			}
			// unknown section: silently ignored
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// flush last peer
	if currentPeer != nil {
		if currentPeer.PublicKey == "" && currentPeer.HEMKID == "" {
			return nil, fmt.Errorf("peer is missing PublicKey or HEM_KID")
		}
		cfg.Peers = append(cfg.Peers, *currentPeer)
	}

	// required fields
	if cfg.Interface.HEMURL == "" {
		return nil, fmt.Errorf("HEM_URL is required in [Interface]")
	}
	if cfg.Interface.HEMKID == "" {
		return nil, fmt.Errorf("HEM_KID is required in [Interface]")
	}

	return cfg, nil
}

// validateKID checks that kid is a 32-character hex string.
func validateKID(kid string) error {
	if len(kid) != 32 {
		return fmt.Errorf("HEM_KID must be a 32-character hex string, got %d characters", len(kid))
	}
	if _, err := hex.DecodeString(kid); err != nil {
		return fmt.Errorf("HEM_KID is not valid hex: %w", err)
	}
	return nil
}
