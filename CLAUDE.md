# wg-hsm — Claude Code Session Handoff

## Cel projektu

Fork wireguard-go integrujący Encedo HEM (EPA/PPA) jako backend kryptograficzny.
Klucz prywatny WireGuard **nigdy nie opuszcza HEM**.
HEM wykonuje ECDH na żądanie przy każdym handshake WireGuard (~co 3 minuty).

---

## Architektura — co robimy

### Problem z oryginalnym WireGuard
- `wg0.conf` zawiera `PrivateKey` w plaintext
- Kernel module Linux nie pozwala na żadną ingerencję
- Rozwiązanie: wireguard-go (userspace) + live HEM ECDH

### Nasze podejście
```
wg-quick-encedo up wg1
  → Parse config (HEM_URL, HEM_KID, peers)
  → Checkin HEM (sync RTC)
  → Auth hasłem lub mobile → JWT token (konfigurowalna długość, default 8h)
  → GetPubKey(myKID) → pub_i
  → Inject HSMSession{pub_i, ECDH func} do wireguard-go device
  → Start wireguard-go (TUN + UAPI)
  → HEM MUSI pozostać online — każdy handshake (~3min) = 2x ECDH call

runtime:
  → handshake initiation: hsmDH(peerStaticPub) → precomputedStaticStatic
  → handshake response:   hsmDH(peerEphemeralPub) → ConsumeMessageResponse DH
  → ECDH error: 3 próby co 2s → graceful shutdown interfejsu
```

### Dlaczego HEM musi być online cały czas
WireGuard Noise_IKpsk2 wymaga klucza prywatnego w DWÓCH miejscach przy każdym handshake:
1. `precomputedStaticStatic = DH(myPriv, peerStaticPub)` — przy dodaniu peera
2. `DH(myPriv, peerEphemeralPub)` — w `ConsumeMessageResponse` z NOWYM kluczem efemerycznym

Punkt 2 nie da się precompute — klucz efemeryczny serwera jest generowany świeżo przy każdym handshake.

---

## Format konfiguracji wg1.conf

Minimalny, rozszerzony o dwa pola w `[Interface]`.
Sekcja `[Peer]` — **bez zmian**, `PublicKey` zostaje.

```ini
[Interface]
Address = 10.1.1.5/24
HEM_URL = https://my.ence.do      # EPA lub PPA — identyczne API
HEM_KID = 5734bb276976fc1ae80030beafad6937  # 32-char hex

[Peer]
PublicKey = i14L0qgxykUZL7GVV2x/hBXwuvbcXbcv+TIEp60Pk0M=
Endpoint = 65.21.170.222:51820
AllowedIPs = 10.1.1.0/24
PersistentKeepalive = 25
```

Zasady:
- `PrivateKey` → **nigdy** w configu
- `ListenPort` → nie ustawiać jeśli klient za NAT (używa losowego portu)
- `HEM_URL` → jeden per plik
- `HEM_KID` → 32-znakowy hex string

---

## Encedo HEM API — pełna specyfikacja

### Base URL
```
https://<HEM_URL>     # np. https://my.ence.do (PPA) lub https://epa.company.com (EPA)
```
TLS 1.3 wymagany. HTTP 418 = brak TLS.
EPA i PPA mają **identyczne API**.

### 1. Checkin
```
GET  /api/system/checkin → {"check": "JWT_challenge"}
POST /api/system/checkin {"checked": "..."} → {"status": "OK"}
```
Wide open — bez Authorization. Wymaga backendu Encedo do obliczenia `checked`.

### 2. Auth hasłem
```
GET  /api/auth/token → {"exp":..., "spk":"base64", "jti":"base64", "lbl":"...", "eid":"base64"}
POST /api/auth/token {"auth": "..."} → {"token": "eyJ..."}
```

### 3. Get Public Key
```
GET /api/keymgmt/get/:kid
Authorization: Bearer TOKEN
→ {"pubkey": "base64", "type": "CURVE25519", "updated": timestamp}
```

### 4. ECDH — kluczowa operacja
```
POST /api/crypto/ecdh
Authorization: Bearer TOKEN
{"kid": "32hex", "pubkey": "base64", "alg": ""}
→ {"ecdh": "base64_32bytes"}
```
`alg: ""` = raw Curve25519, bez hash — identyczny wynik jak WireGuard DH.

---

## Patch wireguard-go — co zmieniliśmy

### Nowy plik: `device/hsm.go`
```go
type HSMSession struct {
    PublicKey NoisePublicKey
    ECDH      func(pub NoisePublicKey) ([NoisePublicKeySize]byte, error)
}

var hsmSession *HSMSession

func InjectHSMSession(s *HSMSession) { hsmSession = s }

func hsmDH(pub NoisePublicKey) ([NoisePublicKeySize]byte, error) {
    if hsmSession == nil || hsmSession.ECDH == nil {
        return [NoisePublicKeySize]byte{}, fmt.Errorf("no HSM session")
    }
    return hsmSession.ECDH(pub)
}
```

### Patch: `device/peer.go` — `precomputeSharedSecret`
```go
if ek2, err := hsmDH(pk); err == nil {
    handshake.precomputedStaticStatic = ek2
} else {
    handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
}
```

### Patch: `device/noise-protocol.go` — `ConsumeMessageResponse`
```go
// zamiast: ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
if hsmSession != nil {
    ss, err = hsmDH(msg.Ephemeral)
    if err != nil { return false }
} else {
    ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
    if err != nil { return false }
}
```

### Patch: `device/device.go` — `SetPrivateKey`
```go
if hsmSession != nil {
    device.staticIdentity.publicKey = hsmSession.PublicKey
    device.cookieChecker.Init(hsmSession.PublicKey)
    return nil
}
```

---

## Struktura projektu

```
wg-hsm/
  build.sh                        ← checkout wireguard-go + overlay patches + build dist/
  go.mod                          ← module github.com/encedo/wg-hsm
  README.md                       ← dokumentacja techniczna
  PRODUCT.md                      ← podsumowanie marketingowe
  CLAUDE.md                       ← ten plik

  hem-sdk-go/
    client.go                     ← Go SDK (package hem): Checkin, Auth, GetPubKey, ECDH

  wireguard-go-encedo/            ← TYLKO nasze pliki (4 szt.) — nakładka na upstream
    device/
      hsm.go                      ← NOWY: HSMSession + hsmDH
      device.go                   ← PATCH: SetPrivateKey
      peer.go                     ← PATCH: precomputedStaticStatic
      noise-protocol.go           ← PATCH: ConsumeMessageResponse

  wireguard-go/                   ← gitignored, generowany przez build.sh
                                    commit: f333402 (v0.0.20250522)

  cmd/
    wg-quick-encedo/
      main.go                     ← up / down / pubkey, auth interaktywna, retry ECDH
      config.go                   ← parser wg1.conf + HEM_URL/HEM_KID
      platform_linux.go           ← netlink, resolvectl, UAPI socket
      platform_darwin.go          ← ifconfig, route, utun
      platform_windows.go         ← netsh, Wintun named pipe
```

---

## Stan implementacji — v1

Przetestowane: klient Linux (XPS13, Polska) ↔ serwer Helsinki (65.21.170.222:51820)
- HEM: Encedo PPA na `https://my.ence.do`
- KID testowy: `5734bb276976fc1ae80030beafad6937`
- Pubkey klienta: `hLlI99/i0j7B+sPGkfSwil/Raqxe6VUhnR+42sDuwAI=`
- Serwer: standardowy WireGuard (kernel), klient: wg-hsm (wireguard-go + HEM)

## Zaimplementowane

- Routes (AllowedIPs → netlink/route/netsh per platform)
- MTU (netlink/ifconfig/netsh)
- DNS (resolvectl na Linux, no-op na macOS z ostrzeżeniem, netsh na Windows)
- HEM_BROKER_URL w [Interface] (fallback do `https://api.encedo.com`)
- `pubkey <ifname>` — odczyt klucza publicznego z `/var/run/wireguard/<ifname>.pub`
- Auth defaults: Enter = 8h + password
- Zerowanie wrażliwych danych (passBytes, seed, sharedSecret)

## TODO

- Token refresh — świadoma decyzja: nie robimy (wygaśnięcie = graceful shutdown, użytkownik restartuje ręcznie)
- Daemonize — świadoma decyzja: nie robimy (problem auth przy restarcie daemona bez interakcji)

---

## Ważne fakty techniczne

- `hsmSession == nil` → oryginalne wireguard-go bez zmian (wg0 działa normalnie)
- `wg show` nie pokazuje public key — bo private key = 0, `wg` nie może go wyliczyć. Normalne.
- `ListenPort` w configu klienta za NAT = problem (serwer próbuje dotrzeć na stały port). Nie ustawiać.
- DisableKeepAlives=true w HTTP kliencie (HEM embedded zamyka połączenia)
- private_key w UAPI = 64x"0" (interceptowane przez patch SetPrivateKey)
- Logger: LogLevelError (nie Verbose)
- ECDH retry: 3 próby, 2s delay, potem graceful shutdown
- Token expiry: pytanie przy starcie, default 8h, maksimum zależne od HEM

## Zarządzanie pamięcią — wrażliwe dane

Kolejność zerowania po `AuthPassword`:
1. `seed []byte` (PBKDF2) — zerowane natychmiast po `buildEjwt`
2. `sharedSecret []byte` (X25519) — zerowane w `buildEjwt` przez `defer` po HMAC
3. `passBytes` w `main.go` — zerowane przez `defer` po powrocie z `authInteractive` (po OBU wywołaniach AuthPassword)

`AuthPassword` przyjmuje `[]byte` (nie `string`) — brak kopii do immutable string.
`AuthPassword` NIE zeruje `password` wewnętrznie — bo needsLookup wywołuje ją dwa razy ze wspólnym slice.
Od momentu zwrócenia tokenów w pamięci żyją tylko JWT stringi.
