package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/encedo/encedo-wg-hsm/hem-sdk-go"
)

const brokerURL = "https://api.hem.com"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "up":
		if len(os.Args) != 4 {
			usage()
			os.Exit(1)
		}
		cmdUp(os.Args[2], os.Args[3])
	case "down":
		if len(os.Args) != 3 {
			usage()
			os.Exit(1)
		}
		cmdDown(os.Args[2])
	case "pubkey":
		if len(os.Args) != 3 {
			usage()
			os.Exit(1)
		}
		cmdPubkey(os.Args[2])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n  %s up <interface> <config>\n  %s down <interface>\n  %s pubkey <interface>\n",
		os.Args[0], os.Args[0], os.Args[0])
}

func cmdDown(ifname string) {
	if err := ifDown(ifname); err != nil {
		fmt.Fprintf(os.Stderr, "down: %v\n", err)
		os.Exit(1)
	}
}

func cmdPubkey(ifname string) {
	pubFile := "/var/run/wireguard/" + ifname + ".pub"
	data, err := os.ReadFile(pubFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pubkey: interface %s not running or pubkey not found (%v)\n", ifname, err)
		os.Exit(1)
	}
	fmt.Print(string(data))
}


func cmdUp(ifname, cfgPath string) {
	// 1. Parse config
	cfg, err := ParseConfig(cfgPath)
	if err != nil {
		fatal("config: %v", err)
	}
	if cfg.Interface.Address == "" {
		fatal("Address is required in [Interface]")
	}

	// 2. Encedo client + checkin
	broker := cfg.Interface.HEMBrokerURL
	if broker == "" {
		broker = brokerURL
	}
	client := hem.NewClient(cfg.Interface.HEMURL, broker, false)

	fmt.Fprintln(os.Stderr, "Connecting to HEM...")
	if err := client.Checkin(); err != nil {
		fatal("checkin: %v", err)
	}
	fmt.Fprintln(os.Stderr, "HEM connected")

	// 3. Auth — two tokens: lookup (keymgmt:get, short-lived) + ecdh (keymgmt:use:KID, long-lived)
	needsLookup := false
	for _, p := range cfg.Peers {
		if p.HEMKID != "" {
			needsLookup = true
			break
		}
	}
	ecdhScope := "keymgmt:use:" + cfg.Interface.HEMKID
	tokens, err := authInteractive(client, ecdhScope, needsLookup)
	if err != nil {
		fatal("auth: %v", err)
	}
	if needsLookup {
		fmt.Fprintln(os.Stderr, "Tokens OK")
	} else {
		fmt.Fprintln(os.Stderr, "Token OK")
	}

	// 4. GetPubKey (my key) — use ecdhToken (keymgmt:use:<KID> covers own key read)
	pubKeyB64, _, _, err := client.GetPubKey(tokens.ecdh, cfg.Interface.HEMKID)
	if err != nil {
		fatal("GetPubKey: %v", err)
	}
	pubKeyRaw, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		fatal("decode pubkey: %v", err)
	}
	var myPubKey device.NoisePublicKey
	copy(myPubKey[:], pubKeyRaw)
	fmt.Fprintf(os.Stderr, "HEM public key: %s\n", pubKeyB64)
	_ = os.MkdirAll("/var/run/wireguard", 0755)
	_ = os.WriteFile("/var/run/wireguard/"+ifname+".pub", []byte(pubKeyB64+"\n"), 0644)

	// 4b. Resolve peer public keys and build extKIDMap (peer pubkey → ext_kid)
	// Peers with HEM_KID: GetPubKey via lookupToken, ECDH fully internal.
	// Peers with PublicKey only: standard ECDH with pubkey value.
	extKIDMap := make(map[device.NoisePublicKey]string)
	for i, peer := range cfg.Peers {
		if peer.HEMKID == "" {
			continue
		}
		pkB64, _, _, err := client.GetPubKey(tokens.lookup, peer.HEMKID)
		if err != nil {
			fatal("GetPubKey peer HEM_KID %s...: %v", peer.HEMKID[:8], err)
		}
		pkRaw, err := base64.StdEncoding.DecodeString(pkB64)
		if err != nil {
			fatal("decode peer pubkey: %v", err)
		}
		cfg.Peers[i].PublicKey = pkB64
		var pk device.NoisePublicKey
		copy(pk[:], pkRaw)
		extKIDMap[pk] = peer.HEMKID
	}

	// 5. Inject HSM session — HSM must remain online for live ECDH during handshakes
	hsmClient := client
	hsmToken := tokens.ecdh
	hsmKID := cfg.Interface.HEMKID
	hsmDead := make(chan struct{}, 1)
	device.InjectHSMSession(&device.HSMSession{
		PublicKey: myPubKey,
		ECDH: func(pub device.NoisePublicKey) ([device.NoisePublicKeySize]byte, error) {
			// Static peer key with HEM_KID: fully internal ECDH, no key bytes in software
			if extKID, ok := extKIDMap[pub]; ok {
				return ecdhInternalWithRetry(hsmClient, hsmToken, hsmKID, extKID)
			}
			// Ephemeral key (per-handshake): standard ECDH with pubkey value
			pubB64 := base64.StdEncoding.EncodeToString(pub[:])
			result, err := ecdhWithRetry(hsmClient, hsmToken, hsmKID, pubB64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: HEM unreachable — shutting down interface: %v\n", err)
				select {
				case hsmDead <- struct{}{}:
				default:
				}
			}
			return result, err
		},
	})
	fmt.Fprintln(os.Stderr, "HEM online — live ECDH on every handshake.")

	// 7. Create TUN interface
	tdev, err := tun.CreateTUN(ifname, device.DefaultMTU)
	if err != nil {
		fatal("create TUN: %v", err)
	}
	if name, err := tdev.Name(); err == nil && name != "" {
		ifname = name
	}

	// 8. Create WireGuard device
	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", ifname))
	wgdev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	// 9. Configure via IpcSet
	if err := wgdev.IpcSet(buildUAPIConfig(cfg)); err != nil {
		fatal("IpcSet: %v", err)
	}

	// 10. Bring interface up with address
	if err := ifUp(ifname, cfg.Interface.Address); err != nil {
		fatal("ifUp: %v", err)
	}

	// 10a. MTU
	if cfg.Interface.MTU > 0 {
		if err := setMTU(ifname, cfg.Interface.MTU); err != nil {
			fatal("setMTU: %v", err)
		}
	}

	// 10b. Routes for AllowedIPs
	var allRoutes []string
	for _, p := range cfg.Peers {
		allRoutes = append(allRoutes, p.AllowedIPs...)
	}
	if err := addRoutes(ifname, allRoutes); err != nil {
		fatal("addRoutes: %v", err)
	}

	// 10c. DNS
	if err := setDNS(ifname, cfg.Interface.DNS); err != nil {
		fatal("setDNS: %v", err)
	}

	// 11. UAPI listener (enables: wg show wg1)
	uapiListener, err := uapiListen(ifname)
	if err != nil {
		fatal("UAPI listen: %v", err)
	}
	errs := make(chan error, 1)
	go func() {
		for {
			c, err := uapiListener.Accept()
			if err != nil {
				errs <- err
				return
			}
			go wgdev.IpcHandle(c)
		}
	}()

	fmt.Fprintf(os.Stderr, "Interface %s is up.\n", ifname)

	// 12. Wait for signal or device close
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case <-stop:
	case <-errs:
	case <-wgdev.Wait():
	case <-hsmDead:
		fmt.Fprintln(os.Stderr, "HEM token expired or HEM unreachable — bringing interface down.")
	}

	// 13. Cleanup
	uapiListener.Close()
	wgdev.Close()
	revertDNS(ifname)
	_ = ifDown(ifname)
	_ = os.Remove("/var/run/wireguard/" + ifname + ".pub")
	fmt.Fprintf(os.Stderr, "Interface %s down.\n", ifname)
}

// buildUAPIConfig builds the WireGuard UAPI set-operation string.
// private_key is all-zeros — intercepted by HSM patch in SetPrivateKey.
func buildUAPIConfig(cfg *Config) string {
	var sb strings.Builder

	sb.WriteString("private_key=" + strings.Repeat("0", 64) + "\n")
	if cfg.Interface.ListenPort != 0 {
		fmt.Fprintf(&sb, "listen_port=%d\n", cfg.Interface.ListenPort)
	}

	for _, peer := range cfg.Peers {
		peerRaw, _ := base64.StdEncoding.DecodeString(peer.PublicKey)
		fmt.Fprintf(&sb, "public_key=%s\n", hex.EncodeToString(peerRaw))
		if peer.Endpoint != "" {
			fmt.Fprintf(&sb, "endpoint=%s\n", peer.Endpoint)
		}
		for _, cidr := range peer.AllowedIPs {
			fmt.Fprintf(&sb, "allowed_ip=%s\n", cidr)
		}
		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

type tokenPair struct {
	lookup string // keymgmt:get — startup only, resolves peer pubkeys
	ecdh   string // keymgmt:use:<KID> — runtime ECDH
}

// authInteractive asks for session duration and auth method once, returns two tokens.
// If needsLookup is false, lookup token is not requested (no peer HEM_KID in config).
func authInteractive(client *hem.Client, ecdhScope string, needsLookup bool) (tokenPair, error) {
	fmt.Fprint(os.Stderr, "Session duration in hours [8]: ")
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(line)
	expSeconds := 8 * 3600
	if line != "" {
		if h, err := strconv.Atoi(line); err == nil && h > 0 {
			expSeconds = h * 3600
		}
	}

	fmt.Fprint(os.Stderr, "Auth method: [p]assword / [m]obile push [p]: ")
	choice, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	choice = strings.TrimSpace(strings.ToLower(choice))

	switch choice {
	case "m":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		var lookupToken string
		if needsLookup {
			fmt.Fprintln(os.Stderr, "Mobile auth #1 — peer key lookup (Ctrl+C = cancel)...")
			var err error
			lookupToken, err = client.AuthRemote(ctx, "keymgmt:get", 2*time.Second, 60*time.Second)
			if err != nil {
				return tokenPair{}, err
			}
		}
		if needsLookup {
			fmt.Fprintln(os.Stderr, "Mobile auth #2 — ECDH (Ctrl+C = cancel)...")
		} else {
			fmt.Fprintln(os.Stderr, "Mobile auth — ECDH (Ctrl+C = cancel)...")
		}
		ecdhToken, err := client.AuthRemote(ctx, ecdhScope, 2*time.Second, 60*time.Second)
		if err != nil {
			return tokenPair{}, err
		}
		return tokenPair{lookup: lookupToken, ecdh: ecdhToken}, nil
	default:
		fmt.Fprint(os.Stderr, "HEM password: ")
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return tokenPair{}, err
		}
		defer func() { for i := range passBytes { passBytes[i] = 0 } }()
		var lookupToken string
		if needsLookup {
			fmt.Fprintln(os.Stderr, "Auth #1 — peer key lookup...")
			lookupToken, err = client.AuthPassword(passBytes, "keymgmt:get", 120)
			if err != nil {
				return tokenPair{}, err
			}
		}
		if needsLookup {
			fmt.Fprintf(os.Stderr, "Auth #2 — ECDH, session %dh...\n", expSeconds/3600)
		} else {
			fmt.Fprintf(os.Stderr, "Auth — ECDH, session %dh...\n", expSeconds/3600)
		}
		ecdhToken, err := client.AuthPassword(passBytes, ecdhScope, expSeconds)
		if err != nil {
			return tokenPair{}, err
		}
		return tokenPair{lookup: lookupToken, ecdh: ecdhToken}, nil
	}
}

// ecdhInternalWithRetry calls HSM internal ECDH (ext_kid) with up to 3 attempts on error.
func ecdhInternalWithRetry(client *hem.Client, token, kid, extKid string) ([32]byte, error) {
	const maxRetries = 3
	const retryDelay = 2 * time.Second
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			fmt.Fprintf(os.Stderr, "HEM ECDH (internal) error: %v — retrying (%d/%d)...\n", lastErr, i, maxRetries-1)
			time.Sleep(retryDelay)
		}
		result, err := client.ECDHInternal(token, kid, extKid)
		if err == nil {
			var out [32]byte
			copy(out[:], result)
			return out, nil
		}
		lastErr = err
	}
	return [32]byte{}, fmt.Errorf("HEM ECDH (internal) unreachable after %d attempts: %w", maxRetries, lastErr)
}

// ecdhWithRetry calls HSM ECDH with up to 3 attempts on error.
func ecdhWithRetry(client *hem.Client, token, kid, pubB64 string) ([32]byte, error) {
	const maxRetries = 3
	const retryDelay = 2 * time.Second
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			fmt.Fprintf(os.Stderr, "HEM ECDH error: %v — retrying (%d/%d)...\n", lastErr, i, maxRetries-1)
			time.Sleep(retryDelay)
		}
		result, err := client.ECDH(token, kid, pubB64)
		if err == nil {
			var out [32]byte
			copy(out[:], result)
			return out, nil
		}
		lastErr = err
	}
	return [32]byte{}, fmt.Errorf("HEM ECDH unreachable after %d attempts: %w", maxRetries, lastErr)
}

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
