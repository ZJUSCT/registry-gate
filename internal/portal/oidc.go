package portal

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// oidcClient is a minimal OIDC relying-party client for one issuer:
// discovery, authorization-code exchange and RS256 ID-token verification.
// It is deliberately thin — the portal handler drives state, nonce and PKCE
// itself — so tests can stub the whole provider with an httptest server that
// serves discovery, the token endpoint and a JWKS.
type oidcClient struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	hc           *http.Client

	mu   sync.Mutex
	disc *oidcDiscovery
	keys *keySet
}

// oidcDiscovery is the subset of /.well-known/openid-configuration used here.
type oidcDiscovery struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
}

// discovery fetches (once) and caches the provider metadata.
func (c *oidcClient) discovery(ctx context.Context) (*oidcDiscovery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disc != nil {
		return c.disc, nil
	}
	endpoint := strings.TrimSuffix(c.issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: build discovery request: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch discovery %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: discovery %s: status %d", endpoint, resp.StatusCode)
	}
	var d oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return nil, fmt.Errorf("oidc: decode discovery: %w", err)
	}
	if d.AuthURL == "" || d.TokenURL == "" || d.JWKSURL == "" {
		return nil, errors.New("oidc: discovery document is missing endpoints")
	}
	c.disc = &d
	return c.disc, nil
}

// AuthCodeURL returns the provider authorization URL for an authorization-code
// flow with PKCE S256; state, nonce and challenge come from the caller.
func (c *oidcClient) AuthCodeURL(ctx context.Context, state, nonce, codeChallenge string) (string, error) {
	d, err := c.discovery(ctx)
	if err != nil {
		return "", err
	}
	scopes := c.scopes
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.clientID},
		"redirect_uri":          {c.redirectURI},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return d.AuthURL + "?" + q.Encode(), nil
}

// Exchange trades an authorization code (and PKCE verifier) for the ID token.
func (c *oidcClient) Exchange(ctx context.Context, code, codeVerifier string) (string, error) {
	d, err := c.discovery(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.redirectURI},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("oidc: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc: token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc: token endpoint: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("oidc: decode token response: %w", err)
	}
	if tok.IDToken == "" {
		return "", errors.New("oidc: token response has no id_token")
	}
	return tok.IDToken, nil
}

// Verify checks the ID token's RS256 signature (via the provider JWKS) and its
// iss/aud/exp/nonce claims, returning the subject: "preferred_username" when
// present, else "sub".
func (c *oidcClient) Verify(ctx context.Context, idToken, wantNonce string, now time.Time) (string, error) {
	d, err := c.discovery(ctx)
	if err != nil {
		return "", err
	}
	headB64, rest, ok := strings.Cut(idToken, ".")
	if !ok {
		return "", errors.New("oidc: malformed id_token")
	}
	payloadB64, sigB64, ok := strings.Cut(rest, ".")
	if !ok {
		return "", errors.New("oidc: malformed id_token")
	}
	var head struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeJSONSegment(headB64, &head); err != nil {
		return "", err
	}
	if head.Alg != "RS256" {
		return "", fmt.Errorf("oidc: unsupported id_token alg %q", head.Alg)
	}
	var claims struct {
		Issuer            string          `json:"iss"`
		Subject           string          `json:"sub"`
		Audience          json.RawMessage `json:"aud"`
		Expiry            int64           `json:"exp"`
		Nonce             string          `json:"nonce"`
		PreferredUsername string          `json:"preferred_username"`
	}
	if err := decodeJSONSegment(payloadB64, &claims); err != nil {
		return "", err
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", errors.New("oidc: malformed id_token signature")
	}
	signingInput := []byte(headB64 + "." + payloadB64)
	key, err := c.publicKey(ctx, d.JWKSURL, head.Kid)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(signingInput)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return "", errors.New("oidc: id_token signature verification failed")
	}

	if got, want := strings.TrimSuffix(claims.Issuer, "/"), strings.TrimSuffix(c.issuer, "/"); got != want {
		return "", fmt.Errorf("oidc: id_token iss = %q, want %q", got, want)
	}
	if !audienceContains(claims.Audience, c.clientID) {
		return "", fmt.Errorf("oidc: id_token aud %s does not contain client %q", strings.TrimSpace(string(claims.Audience)), c.clientID)
	}
	if now.Unix() >= claims.Expiry {
		return "", errors.New("oidc: id_token expired")
	}
	if claims.Nonce != wantNonce {
		return "", errors.New("oidc: id_token nonce mismatch")
	}
	subject := claims.PreferredUsername
	if subject == "" {
		subject = claims.Subject
	}
	if subject == "" {
		return "", errors.New("oidc: id_token has no subject claim")
	}
	return subject, nil
}

// audienceContains handles "aud" being either a string or an array.
func audienceContains(raw json.RawMessage, clientID string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return single == clientID
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == clientID {
				return true
			}
		}
	}
	return false
}

func decodeJSONSegment(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return fmt.Errorf("oidc: malformed id_token segment: %w", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("oidc: decode id_token segment: %w", err)
	}
	return nil
}

// keySet caches JWKS keys and refreshes them when a kid is unknown or the
// cache has expired.
type keySet struct {
	keys    map[string]*rsa.PublicKey
	expires time.Time
}

func (c *oidcClient) publicKey(ctx context.Context, jwksURL, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.keys != nil && now.Before(c.keys.expires) {
		if key, ok := c.keys.keys[kid]; ok {
			return key, nil
		}
	}
	if err := c.refreshKeys(ctx, jwksURL, now); err != nil {
		return nil, err
	}
	if key, ok := c.keys.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("oidc: no JWKS key for kid %q", kid)
}

// refreshKeys fetches the JWKS; caller holds c.mu.
func (c *oidcClient) refreshKeys(ctx context.Context, jwksURL string, now time.Time) error {
	if c.keys != nil && now.Before(c.keys.expires) {
		return nil // cache hit for the set itself (unknown kid stays unknown)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return fmt.Errorf("oidc: build jwks request: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: jwks status %d", resp.StatusCode)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return fmt.Errorf("oidc: decode jwks: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		exp := new(big.Int).SetBytes(e)
		if !exp.IsInt64() {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(exp.Int64()),
		}
	}
	if len(keys) == 0 {
		return errors.New("oidc: jwks has no usable RSA keys")
	}
	c.keys = &keySet{keys: keys, expires: now.Add(time.Hour)}
	return nil
}
