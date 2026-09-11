package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// cookieFor encodes a session via a response recorder and returns the cookie.
func cookieFor(t *testing.T, s *Store, sess Session) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Set(rec, sess)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set wrote %d cookies, want 1", len(cookies))
	}
	return cookies[0]
}

func requestWith(t *testing.T, c *http.Cookie) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(c)
	return r
}

func TestRoundTrip(t *testing.T) {
	s := New([]byte("0123456789abcdef0123456789abcdef"), "rg_test")
	c := cookieFor(t, s, NewSession(map[string]string{"sub": "alice", "idp": "gitlab"}))

	if c.Name != "rg_test" {
		t.Errorf("cookie name = %q, want rg_test", c.Name)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("cookie attributes wrong: %+v", c)
	}

	got, ok := s.Get(requestWith(t, c))
	if !ok {
		t.Fatal("Get failed for a fresh cookie")
	}
	if got.Values["sub"] != "alice" || got.Values["idp"] != "gitlab" {
		t.Errorf("values = %v, want sub=alice idp=gitlab", got.Values)
	}
	if want := time.Now().Add(TTL); got.Expires.Sub(want) > time.Minute {
		t.Errorf("expiry = %v, want about %v", got.Expires, want)
	}
}

func TestGetNoCookie(t *testing.T) {
	s := New([]byte("secretsecretsecretsecret"), "rg_test")
	if _, ok := s.Get(httptest.NewRequest("GET", "/", nil)); ok {
		t.Fatal("Get succeeded without a cookie")
	}
}

func TestTamperDetection(t *testing.T) {
	s := New([]byte("0123456789abcdef0123456789abcdef"), "rg_test")
	c := cookieFor(t, s, NewSession(map[string]string{"sub": "alice"}))

	// Flip a character inside the signed payload.
	tampered := *c
	if tampered.Value[3] == 'A' {
		tampered.Value = tampered.Value[:3] + "B" + tampered.Value[4:]
	} else {
		tampered.Value = tampered.Value[:3] + "A" + tampered.Value[4:]
	}
	if _, ok := s.Get(requestWith(t, &tampered)); ok {
		t.Error("Get accepted a tampered payload")
	}

	// Truncated signature.
	trunc := *c
	if i := len(trunc.Value) - 1; i > 0 {
		trunc.Value = trunc.Value[:i]
	}
	if _, ok := s.Get(requestWith(t, &trunc)); ok {
		t.Error("Get accepted a truncated signature")
	}

	// Signed with a different secret (wrong key).
	other := New([]byte("ffffffffffffffffffffffffffffffff"), "rg_test")
	forged := cookieFor(t, other, NewSession(map[string]string{"sub": "alice"}))
	if _, ok := s.Get(requestWith(t, forged)); ok {
		t.Error("Get accepted a cookie signed with another secret")
	}
}

func TestExpiry(t *testing.T) {
	s := New([]byte("0123456789abcdef0123456789abcdef"), "rg_test")
	past := Session{Values: map[string]string{"sub": "alice"}, Expires: time.Now().Add(-time.Minute)}
	if _, ok := s.Get(requestWith(t, cookieFor(t, s, past))); ok {
		t.Error("Get accepted an expired session")
	}
	soon := Session{Values: map[string]string{"sub": "alice"}, Expires: time.Now().Add(time.Minute)}
	if _, ok := s.Get(requestWith(t, cookieFor(t, s, soon))); !ok {
		t.Error("Get rejected a session still valid for a minute")
	}

	// Frozen clock: session valid at issue time is invalid after TTL.
	frozen := time.Unix(1700000000, 0)
	s.now = func() time.Time { return frozen }
	c := cookieFor(t, s, Session{Values: map[string]string{"sub": "alice"}, Expires: frozen.Add(TTL)})
	s.now = func() time.Time { return frozen.Add(TTL - time.Second) }
	if _, ok := s.Get(requestWith(t, c)); !ok {
		t.Error("session should still be valid one second before expiry")
	}
	s.now = func() time.Time { return frozen.Add(TTL + time.Second) }
	if _, ok := s.Get(requestWith(t, c)); ok {
		t.Error("session should be expired one second after TTL")
	}
}

func TestClear(t *testing.T) {
	s := New([]byte("0123456789abcdef0123456789abcdef"), "rg_test")
	rec := httptest.NewRecorder()
	s.Clear(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Clear wrote %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != "rg_test" || c.Value != "" || c.MaxAge >= 0 {
		t.Errorf("clear cookie wrong: %+v", c)
	}
}
