package hem

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"
)

const pbkdf2Iterations = 600_000

// HemError represents an error returned by the Encedo HSM API.
type HemError struct {
	Message string
	Code    string
	Status  int
	Data    interface{}
}

func (e *HemError) Error() string { return e.Message }

// Client is an Encedo HSM API client.
type Client struct {
	baseURL    string
	broker     string
	httpClient *http.Client
}

// NewClient creates a new Encedo HSM client.
// broker is the notification broker URL (e.g. "https://api.encedo.com").
// insecureSkipVerify disables TLS certificate verification (use for self-signed PPA certs).
func NewClient(hsmURL, broker string, insecureSkipVerify bool) *Client {
	return &Client{
		baseURL: strings.TrimRight(hsmURL, "/"),
		broker:  strings.TrimRight(broker, "/"),
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecureSkipVerify},
				DisableKeepAlives:   true,
			},
		},
	}
}

// req performs an HTTP request and unmarshals the JSON response into out.
// Mirrors #req() in hem-sdk.js.
func (c *Client) req(method, url string, body interface{}, token string, out interface{}) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return &HemError{Message: fmt.Sprintf("marshal request body: %v", err), Code: "encode_error"}
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return &HemError{Message: fmt.Sprintf("create request: %v", err), Code: "request_error"}
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &HemError{Message: fmt.Sprintf("network error: %v", err), Code: "network"}
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return &HemError{Message: fmt.Sprintf("read response: %v", err), Code: "read_error"}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var data interface{}
		_ = json.Unmarshal(respData, &data)
		return &HemError{
			Message: fmt.Sprintf("HEM %s %s -> HTTP %d", method, url, resp.StatusCode),
			Code:    fmt.Sprintf("http_%d", resp.StatusCode),
			Status:  resp.StatusCode,
			Data:    data,
		}
	}

	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(respData))
		dec.UseNumber()
		if err := dec.Decode(out); err != nil {
			return &HemError{Message: fmt.Sprintf("unmarshal response: %v", err), Code: "decode_error"}
		}
	}
	return nil
}

// Checkin performs the 3-step HSM clock synchronisation.
// Mirrors hemCheckin() in hem-sdk.js.
func (c *Client) Checkin() error {
	var step1 map[string]interface{}
	if err := c.req("GET", c.baseURL+"/api/system/checkin", nil, "", &step1); err != nil {
		return err
	}
	if _, ok := step1["check"]; !ok {
		return &HemError{Message: "HSM checkin failed (no check field)", Code: "checkin_error"}
	}

	var step2 map[string]interface{}
	if err := c.req("POST", c.broker+"/checkin", step1, "", &step2); err != nil {
		return err
	}
	if _, ok := step2["checked"]; !ok {
		return &HemError{Message: "broker checkin failed (no checked field)", Code: "broker_error"}
	}

	var step3 map[string]interface{}
	if err := c.req("POST", c.baseURL+"/api/system/checkin", step2, "", &step3); err != nil {
		return err
	}
	if _, ok := step3["status"]; !ok {
		return &HemError{Message: "HSM checkin step 3 failed (no status field)", Code: "checkin_error"}
	}
	return nil
}

// zeroBytes overwrites a byte slice with zeros to remove sensitive data from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// deriveX25519 runs PBKDF2-SHA256 on password with salt=eid and returns
// the seed and the derived X25519 public key in standard base64.
// Mirrors #deriveX25519() in hem-sdk.js.
func deriveX25519(password []byte, eid string) (seed []byte, pubKeyB64 string, err error) {
	seed = pbkdf2.Key(password, []byte(eid), pbkdf2Iterations, 32, sha256.New)
	pubKeyBytes, err := curve25519.X25519(seed, curve25519.Basepoint)
	if err != nil {
		zeroBytes(seed)
		return nil, "", fmt.Errorf("X25519 public key derivation: %w", err)
	}
	return seed, base64.StdEncoding.EncodeToString(pubKeyBytes), nil
}

// buildEjwt constructs the eJWT used for password authentication.
// Header: {"ecdh":"x25519","alg":"HS256","typ":"JWT"}
// Signature: HMAC-SHA256(header.payload, X25519(seed, devicePubKey))
// Mirrors #buildEjwt() in hem-sdk.js.
func buildEjwt(seed []byte, devicePubKeyB64 string, payload map[string]interface{}) (string, error) {
	hdrJSON, err := json.Marshal(map[string]string{"ecdh": "x25519", "alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	hdr := base64.RawURLEncoding.EncodeToString(hdrJSON)
	bdy := base64.RawURLEncoding.EncodeToString(payloadJSON)
	input := hdr + "." + bdy

	spkBytes, err := base64.StdEncoding.DecodeString(devicePubKeyB64)
	if err != nil {
		return "", fmt.Errorf("decode device public key: %w", err)
	}
	sharedSecret, err := curve25519.X25519(seed, spkBytes)
	if err != nil {
		return "", fmt.Errorf("X25519 shared secret: %w", err)
	}
	defer zeroBytes(sharedSecret)

	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write([]byte(input))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return input + "." + sig, nil
}

// AuthPassword authenticates with a local password and returns a JWT token.
// Mirrors authorizePassword() in hem-sdk.js.
func (c *Client) AuthPassword(password []byte, scope string, expSeconds int) (string, error) {
	var challenge struct {
		EID string `json:"eid"`
		SPK string `json:"spk"`
		JTI string `json:"jti"`
		Exp int64  `json:"exp"`
		Lbl string `json:"lbl"`
	}
	if err := c.req("GET", c.baseURL+"/api/auth/token", nil, "", &challenge); err != nil {
		return "", err
	}

	seed, pubKeyB64, err := deriveX25519(password, challenge.EID)
	if err != nil {
		return "", err
	}

	iat := time.Now().Unix() - 5
	payload := map[string]interface{}{
		"jti":   challenge.JTI,
		"aud":   challenge.SPK,
		"exp":   iat + int64(expSeconds),
		"iat":   iat,
		"iss":   pubKeyB64,
		"scope": scope,
	}

	ejwt, err := buildEjwt(seed, challenge.SPK, payload)
	zeroBytes(seed) // seed no longer needed — token is derived, only ejwt matters now
	if err != nil {
		return "", err
	}

	var resp struct {
		Token string `json:"token"`
	}
	if err := c.req("POST", c.baseURL+"/api/auth/token", map[string]string{"auth": ejwt}, "", &resp); err != nil {
		return "", err
	}
	if resp.Token == "" {
		return "", &HemError{Message: "no token in auth response", Code: "auth_failed"}
	}
	return resp.Token, nil
}

// AuthRemote authenticates via mobile push notification (broker polling).
// Mirrors authorizeRemote() in hem-sdk.js.
// If ctx is cancelled, returns ctx.Err() — caller should fall back to password auth.
func (c *Client) AuthRemote(ctx context.Context, scope string, pollInterval, pollTimeout time.Duration) (string, error) {
	// Step 1: broker session
	var session map[string]interface{}
	if err := c.req("GET", c.broker+"/notify/session", nil, "", &session); err != nil {
		return "", err
	}

	// Step 2: request auth from device (pass full session data + scope)
	session["scope"] = scope
	var challenge map[string]interface{}
	if err := c.req("POST", c.baseURL+"/api/auth/ext/request", session, "", &challenge); err != nil {
		return "", err
	}

	// Step 3: forward challenge to broker
	var event struct {
		EventID string `json:"eventid"`
	}
	if err := c.req("POST", c.broker+"/notify/event/new", challenge, "", &event); err != nil {
		return "", err
	}
	if event.EventID == "" {
		return "", &HemError{Message: "no eventid from broker", Code: "broker_error"}
	}

	// Step 4: poll
	deadline := time.Now().Add(pollTimeout)
	var result map[string]interface{}

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}

		fmt.Fprintf(os.Stderr, "Waiting for mobile confirmation...\n")

		pollReq, err := http.NewRequestWithContext(ctx, "GET",
			c.broker+"/notify/event/check/"+event.EventID, nil)
		if err != nil {
			return "", &HemError{Message: fmt.Sprintf("create poll request: %v", err), Code: "request_error"}
		}

		pollResp, err := c.httpClient.Do(pollReq)
		if err != nil {
			return "", &HemError{Message: fmt.Sprintf("broker poll network error: %v", err), Code: "network"}
		}

		if pollResp.StatusCode == 202 {
			pollResp.Body.Close()
			continue
		}
		if pollResp.StatusCode != 200 {
			pollResp.Body.Close()
			return "", &HemError{
				Message: fmt.Sprintf("broker poll HTTP %d", pollResp.StatusCode),
				Code:    fmt.Sprintf("http_%d", pollResp.StatusCode),
				Status:  pollResp.StatusCode,
			}
		}

		if err := json.NewDecoder(pollResp.Body).Decode(&result); err != nil {
			pollResp.Body.Close()
			return "", &HemError{Message: fmt.Sprintf("decode poll result: %v", err), Code: "decode_error"}
		}
		pollResp.Body.Close()
		break
	}

	if result == nil {
		return "", &HemError{Message: "remote auth timed out", Code: "timeout"}
	}

	// Step 5a: check denial
	if deny, _ := result["deny"].(bool); deny {
		return "", &HemError{Message: "auth denied by user", Code: "denied"}
	}
	authreply, _ := result["authreply"].(string)
	if authreply == "" {
		return "", &HemError{Message: "missing authreply", Code: "broker_error"}
	}

	// Step 5b: exchange authreply for JWT
	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := c.req("POST", c.baseURL+"/api/auth/ext/token",
		map[string]string{"authreply": authreply}, "", &tokenResp); err != nil {
		return "", err
	}
	if tokenResp.Token == "" {
		return "", &HemError{Message: "no token in ext/token response", Code: "auth_failed"}
	}
	return tokenResp.Token, nil
}

// GetPubKey retrieves the public key and metadata for a given key ID.
// Mirrors getPubKey() in hem-sdk.js.
func (c *Client) GetPubKey(token, kid string) (pubKey string, keyType string, updated int64, err error) {
	var resp struct {
		PubKey  string `json:"pubkey"`
		Type    string `json:"type"`
		Updated int64  `json:"updated"`
	}
	if err := c.req("GET", c.baseURL+"/api/keymgmt/get/"+kid, nil, token, &resp); err != nil {
		return "", "", 0, err
	}
	return resp.PubKey, resp.Type, resp.Updated, nil
}

// ECDH performs a Curve25519 ECDH operation on the HSM.
// kid is the private key ID (32-char hex) stored in the HSM.
// peerPubKeyBase64 is the peer's WireGuard public key in standard base64.
// Returns the raw 32-byte shared secret.
func (c *Client) ECDH(token, kid, peerPubKeyBase64 string) ([]byte, error) {
	body := map[string]string{
		"kid":    kid,
		"pubkey": peerPubKeyBase64,
	}
	var resp struct {
		ECDH string `json:"ecdh"`
	}
	if err := c.req("POST", c.baseURL+"/api/crypto/ecdh", body, token, &resp); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(resp.ECDH)
	if err != nil {
		return nil, fmt.Errorf("decode ECDH result: %w", err)
	}
	return raw, nil
}

// ECDHInternal performs ECDH entirely within the HSM between two stored keys.
// kid is the local private key, extKid is the peer's imported public key.
// Neither key value leaves the HSM.
func (c *Client) ECDHInternal(token, kid, extKid string) ([]byte, error) {
	body := map[string]string{
		"kid":     kid,
		"ext_kid": extKid,
	}
	var resp struct {
		ECDH string `json:"ecdh"`
	}
	if err := c.req("POST", c.baseURL+"/api/crypto/ecdh", body, token, &resp); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(resp.ECDH)
	if err != nil {
		return nil, fmt.Errorf("decode ECDH result: %w", err)
	}
	return raw, nil
}
