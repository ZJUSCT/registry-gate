// Package token issues and verifies registry-gate personal access tokens (PAT).
//
// A PAT is "zjum_" + base64url(rawJWT) where the JWT is Ed25519-signed (EdDSA) and
// carries: iss, sub (campus username), jti (token id, 16-byte hex), note, iat, nbf, exp.
// The prefix keeps tokens recognizable in logs and secret scanning; it is stripped
// before JWT parsing.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Prefix marks a registry-gate PAT.
const Prefix = "zjum_"

// Claims are the registry-gate PAT claims.
type Claims struct {
	Note string `json:"note,omitempty"`
	jwt.RegisteredClaims
}

// JTI returns the token id (hex string, also stored as Store token id).
func (c *Claims) JTI() string { return c.ID }

// Issuer issues PATs with a private key.
type Issuer struct {
	Key     ed25519.PrivateKey
	Kid     string
	Issuer  string
	NowFunc func() time.Time
}

// Issue returns the PAT string and its claims. ttl must be > 0.
func (i *Issuer) Issue(subject, note string, ttl time.Duration) (string, Claims, error) {
	if i.Key == nil {
		return "", Claims{}, errors.New("token: issuer key is nil")
	}
	if subject == "" {
		return "", Claims{}, errors.New("token: empty subject")
	}
	if ttl <= 0 {
		return "", Claims{}, errors.New("token: ttl must be positive")
	}
	now := time.Now
	if i.NowFunc != nil {
		now = i.NowFunc
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", Claims{}, fmt.Errorf("token: read random: %w", err)
	}
	claims := Claims{
		Note: note,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.Issuer,
			Subject:   subject,
			ID:        hex.EncodeToString(buf),
			IssuedAt:  jwt.NewNumericDate(now()),
			NotBefore: jwt.NewNumericDate(now()),
			ExpiresAt: jwt.NewNumericDate(now().Add(ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = i.Kid
	raw, err := t.SignedString(i.Key)
	if err != nil {
		return "", Claims{}, fmt.Errorf("token: sign: %w", err)
	}
	return Prefix + base64.RawURLEncoding.EncodeToString([]byte(raw)), claims, nil
}

// Verifier verifies PATs against a set of public keys by kid.
type Verifier struct {
	Keys    map[string]ed25519.PublicKey // kid -> public key
	Issuer  string                       // expected "iss" value (skip check if empty)
	NowFunc func() time.Time
}

// Verify parses and validates a PAT (with or without the "zjum_" prefix) and returns
// its claims. It checks algorithm (EdDSA), kid presence, signature, iss and exp.
// Revocation is the caller's responsibility (Store lookup by claims.ID).
func (v *Verifier) Verify(pat string) (*Claims, error) {
	if v == nil || len(v.Keys) == 0 {
		return nil, errors.New("token: no verification keys")
	}
	raw := strings.TrimPrefix(pat, Prefix)
	if raw == "" {
		return nil, errors.New("token: malformed PAT")
	}
	// PAT body is base64url (no dots); also tolerate a bare JWT being pasted.
	if !strings.Contains(raw, ".") {
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return nil, errors.New("token: malformed PAT")
		}
		raw = string(decoded)
	}
	parsed, err := jwt.ParseWithClaims(raw, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("token: unexpected signing method %v", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		key, ok := v.Keys[kid]
		if !ok {
			return nil, fmt.Errorf("token: unknown kid %q", kid)
		}
		return key, nil
	}, jwt.WithExpirationRequired(), jwt.WithIssuer(v.Issuer))
	if err != nil {
		return nil, fmt.Errorf("token: verify: %w", err)
	}
	claims, ok := parsed.Claims.(*Claims)
	if !ok || !parsed.Valid {
		return nil, errors.New("token: invalid claims")
	}
	return claims, nil
}
