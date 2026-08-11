package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	hem "github.com/encedo/hem-sdk-go"

	// Aliased: the package is internal/runtime, and rt keeps it visibly apart
	// from the standard library's runtime wherever both might be read for one.
	rt "github.com/encedo/encedo-wg-hsm/internal/runtime"
)

// ecdhTimeout bounds a single HEM call on the handshake path. WireGuard
// retransmits its first message after 5 s, so an ECDH that has not answered
// well before then is better retried than waited on.
const ecdhTimeout = 3 * time.Second

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
	if err := rt.Down(ifname); err != nil {
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
	if !cfg.Interface.Address.IsValid() {
		fatal("Address is required in [Interface]")
	}

	// 2. Encedo client + checkin. An empty HEM_BROKER_URL leaves the SDK default.
	client := hem.NewClient(cfg.Interface.HEMURL, hem.Config{Broker: cfg.Interface.HEMBrokerURL})

	fmt.Fprintln(os.Stderr, "Connecting to HEM...")
	if err := client.Checkin(context.Background()); err != nil {
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
	myKey, err := client.GetPubKey(context.Background(), tokens.ecdh, cfg.Interface.HEMKID)
	if err != nil {
		fatal("GetPubKey: %v", err)
	}
	var myPubKey device.NoisePublicKey
	copy(myPubKey[:], myKey.PubKey)
	pubKeyB64 := base64.StdEncoding.EncodeToString(myKey.PubKey)
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
		peerKey, err := client.GetPubKey(context.Background(), tokens.lookup, peer.HEMKID)
		if err != nil {
			fatal("GetPubKey peer HEM_KID %s...: %v", peer.HEMKID[:8], err)
		}
		cfg.Peers[i].PublicKey = base64.StdEncoding.EncodeToString(peerKey.PubKey)
		var pk device.NoisePublicKey
		copy(pk[:], peerKey.PubKey)
		extKIDMap[pk] = peer.HEMKID
	}

	// 4c. Plan the routing while the host's resolver is still the host's own.
	// Once AllowedIPs owns the default route, a name lookup may be travelling
	// through the tunnel that the answer is needed to build.
	plan, err := rt.PlanRouting(runtimePeers(cfg.Peers), cfg.Interface.HEMURL)
	if err != nil {
		fatal("routing: %v", err)
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
				return ecdhWithRetry(hsmClient, hsmToken, hsmKID, hem.CryptoOpts{ExtKID: extKID})
			}
			// Ephemeral key (per-handshake): standard ECDH with pubkey value
			result, err := ecdhWithRetry(hsmClient, hsmToken, hsmKID, hem.CryptoOpts{PubKey: pub[:]})
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
	if err := rt.Up(ifname, []netip.Prefix{cfg.Interface.Address}); err != nil {
		fatal("bringing %s up: %v", ifname, err)
	}

	// 10a. MTU
	if cfg.Interface.MTU > 0 {
		if err := rt.SetMTU(ifname, cfg.Interface.MTU); err != nil {
			fatal("setting the MTU: %v", err)
		}
	}

	// From here on the routing table has been touched, so a failure has to put
	// it back rather than exit and leave the host without a default route. The
	// same teardown serves both ways out, so the abort path cannot drift from
	// the one that runs on Ctrl+C.
	exceptions := &rt.Pins{}
	teardown := func() {
		wgdev.Close()
		rt.RevertDNS(ifname)
		_ = rt.Down(ifname)
		exceptions.Restore()
		_ = os.Remove("/var/run/wireguard/" + ifname + ".pub")
	}
	fail := func(format string, args ...interface{}) {
		teardown()
		fatal(format, args...)
	}

	// 10b. Pin the endpoints the tunnel would otherwise swallow, before the
	// tunnel's own routes go in — no window in which the endpoint has no path.
	if err := exceptions.Add(plan.Endpoints); err != nil {
		fail("route exception: %v", err)
	}

	// 10c. Routes for AllowedIPs
	var allRoutes []netip.Prefix
	for _, p := range cfg.Peers {
		allRoutes = append(allRoutes, p.AllowedIPs...)
	}
	if err := rt.AddRoutes(ifname, allRoutes); err != nil {
		fail("installing routes: %v", err)
	}

	// 10d. DNS
	if err := rt.SetDNS(ifname, cfg.Interface.DNS); err != nil {
		fail("setting DNS: %v", err)
	}

	// 10e. With the routes in place, confirm the HEM is still there. It is
	// consulted at every handshake, so losing it is not a degraded tunnel — it
	// is one that stops at the first rekey, roughly two minutes in.
	if plan.HEMInside {
		if err := rt.ProbeHEM(client, plan.HEMHost); err != nil {
			fail("%v", err)
		}
	}

	// 11. UAPI listener (enables: wg show wg1)
	uapiListener, err := rt.UAPIListen(ifname)
	if err != nil {
		fail("UAPI listen: %v", err)
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
	teardown()
	fmt.Fprintf(os.Stderr, "Interface %s down.\n", ifname)
}

// runtimePeers reduces the parsed configuration to what the routing decision
// needs. The runtime package deliberately knows nothing about keys, HEM_KIDs or
// where the configuration came from — wg-hem feeds it the same shape from the
// records it reads out of the device.
func runtimePeers(peers []Peer) []rt.Peer {
	out := make([]rt.Peer, 0, len(peers))
	for _, p := range peers {
		out = append(out, rt.Peer{Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs})
	}
	return out
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

	// Both tokens are held for the life of the process, so nothing is gained by
	// leaving key material in the SDK cache once they have been issued.
	defer client.ClearKeys()

	switch choice {
	case "m":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		waiting := func() { fmt.Fprintln(os.Stderr, "Waiting for mobile confirmation...") }
		opts := hem.RemoteOpts{PollInterval: 2 * time.Second, PollTimeout: 60 * time.Second, OnPending: waiting}
		var lookupToken string
		if needsLookup {
			fmt.Fprintln(os.Stderr, "Mobile auth #1 — peer key lookup (Ctrl+C = cancel)...")
			var err error
			lookupToken, err = client.AuthRemote(ctx, "keymgmt:get", opts)
			if err != nil {
				return tokenPair{}, err
			}
		}
		if needsLookup {
			fmt.Fprintln(os.Stderr, "Mobile auth #2 — ECDH (Ctrl+C = cancel)...")
		} else {
			fmt.Fprintln(os.Stderr, "Mobile auth — ECDH (Ctrl+C = cancel)...")
		}
		ecdhToken, err := client.AuthRemote(ctx, ecdhScope, opts)
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
		defer func() {
			for i := range passBytes {
				passBytes[i] = 0
			}
		}()
		ctx := context.Background()
		ecdhPass := passBytes
		var lookupToken string
		if needsLookup {
			fmt.Fprintln(os.Stderr, "Auth #1 — peer key lookup...")
			lookupToken, err = client.AuthPassword(ctx, passBytes, "keymgmt:get", 120)
			if err != nil {
				return tokenPair{}, err
			}
			// nil password: the SDK reuses the key derived above rather than
			// running a second 600k-round PBKDF2 over the same passphrase.
			ecdhPass = nil
		}
		if needsLookup {
			fmt.Fprintf(os.Stderr, "Auth #2 — ECDH, session %dh...\n", expSeconds/3600)
		} else {
			fmt.Fprintf(os.Stderr, "Auth — ECDH, session %dh...\n", expSeconds/3600)
		}
		ecdhToken, err := client.AuthPassword(ctx, ecdhPass, ecdhScope, expSeconds)
		if err != nil {
			return tokenPair{}, err
		}
		return tokenPair{lookup: lookupToken, ecdh: ecdhToken}, nil
	}
}

// ecdhWithRetry calls HEM ECDH with up to 3 attempts on error. opts selects the
// peer key: ExtKID for a peer already imported into the HEM (both operands stay
// in-device), PubKey for a key seen on the wire — an ephemeral, in practice.
func ecdhWithRetry(client *hem.Client, token, kid string, opts hem.CryptoOpts) ([32]byte, error) {
	const maxRetries = 3
	const retryDelay = 2 * time.Second
	what := "ECDH"
	if opts.ExtKID != "" {
		what = "ECDH (internal)"
	}
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			fmt.Fprintf(os.Stderr, "HEM %s error: %v — retrying (%d/%d)...\n", what, lastErr, i, maxRetries-1)
			time.Sleep(retryDelay)
		}
		ctx, cancel := context.WithTimeout(context.Background(), ecdhTimeout)
		result, err := client.ECDH(ctx, token, kid, opts)
		cancel()
		if err == nil {
			var out [32]byte
			copy(out[:], result)
			return out, nil
		}
		lastErr = err
	}
	return [32]byte{}, fmt.Errorf("HEM %s unreachable after %d attempts: %w", what, maxRetries, lastErr)
}

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
