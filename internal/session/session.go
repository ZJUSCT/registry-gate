// Package session provides HMAC-signed cookie sessions for the portal and
// admin web UIs.
//
// A session cookie's value is base64url(JSON payload) + "." +
// base64url(HMAC-SHA256 over the payload), so a client cannot modify the
// claims without invalidating the signature. Sessions expire 12 hours after
// issuance. Cookies are set with HttpOnly, Secure, SameSite=Lax and Path=/;
// the portal and admin UIs each instantiate a Store with a distinct cookie
// name (and secret).
package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// TTL is the session lifetime.
const TTL = 12 * time.Hour

// Session is the set of claims carried by one session cookie. Values holds
// at least "sub" (username) and "idp" (e.g. "gitlab" or "github").
type Session struct {
	Values  map[string]string
	Expires time.Time
}

// NewSession returns a Session carrying values and expiring after TTL from
// now.
func NewSession(values map[string]string) Session {
	return Session{Values: values, Expires: time.Now().Add(TTL)}
}

// Store issues and verifies session cookies signed with a shared secret.
type Store struct {
	secret []byte
	name   string
	now    func() time.Time
}

// New returns a Store signing cookies named name with secret. The secret
// should be at least 32 bytes of random data (one per deployed UI).
func New(secret []byte, name string) *Store {
	return &Store{secret: secret, name: name, now: time.Now}
}

// payload is the signed cookie body.
type payload struct {
	Values  map[string]string `json:"v"`
	Expires int64             `json:"e"` // unix seconds
}

// Get returns the session carried by the request's cookie. The second return
// value is false when the cookie is absent, malformed, tampered with, or
// expired.
func (s *Store) Get(r *http.Request) (Session, bool) {
	c, err := r.Cookie(s.name)
	if err != nil || c.Value == "" {
		return Session{}, false
	}
	body, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return Session{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Session{}, false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return Session{}, false
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(raw)
	if !hmac.Equal(mac.Sum(nil), got) {
		return Session{}, false
	}
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Session{}, false
	}
	if len(p.Values) == 0 {
		return Session{}, false
	}
	expires := time.Unix(p.Expires, 0)
	if !s.now().Before(expires) {
		return Session{}, false
	}
	return Session{Values: p.Values, Expires: expires}, true
}

// Set writes the session as a cookie on w. A zero Expires is replaced by
// now+TTL.
func (s *Store) Set(w http.ResponseWriter, sess Session) {
	if sess.Expires.IsZero() {
		sess.Expires = s.now().Add(TTL)
	}
	if sess.Values == nil {
		sess.Values = map[string]string{}
	}
	raw, err := json.Marshal(payload{Values: sess.Values, Expires: sess.Expires.Unix()})
	if err != nil {
		// map[string]string is always marshalable.
		panic(fmt.Sprintf("session: marshal payload: %v", err))
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(raw)
	value := base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     s.name,
		Value:    value,
		Path:     "/",
		Expires:  sess.Expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// Clear expires the session cookie on w.
func (s *Store) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0), // firmly in the past
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// RandomState returns n random bytes hex-encoded, for OAuth "state" values.
func RandomState(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("session: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
