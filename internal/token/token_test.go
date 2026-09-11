package token

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func newIssuer(t *testing.T) (*Issuer, *Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	iss := &Issuer{Key: priv, Kid: "test", Issuer: "zju-mirror"}
	ver := &Verifier{Keys: map[string]ed25519.PublicKey{"test": pub}, Issuer: "zju-mirror"}
	return iss, ver
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	iss, ver := newIssuer(t)
	pat, claims, err := iss.Issue("alice", "laptop", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if pat[:len(Prefix)] != Prefix {
		t.Fatalf("missing prefix: %q", pat)
	}
	if claims.Subject != "alice" || claims.ID == "" {
		t.Fatalf("bad claims: %+v", claims)
	}
	got, err := ver.Verify(pat)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "alice" || got.ID != claims.ID || got.Note != "laptop" {
		t.Fatalf("claims mismatch: %+v", got)
	}
	// body without prefix (base64url, no dots) must also verify
	if _, err := ver.Verify(pat[len(Prefix):]); err != nil {
		t.Fatalf("prefix-less PAT failed: %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	iss, ver := newIssuer(t)
	base := time.Now()
	iss.NowFunc = func() time.Time { return base.Add(-2 * time.Hour) }
	pat, _, err := iss.Issue("alice", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(pat); err == nil {
		t.Fatal("expired token verified")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	iss, _ := newIssuer(t)
	pat, _, err := iss.Issue("alice", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ver := &Verifier{Keys: map[string]ed25519.PublicKey{"test": otherPub}, Issuer: "zju-mirror"}
	if _, err := ver.Verify(pat); err == nil {
		t.Fatal("forged token verified")
	}
}

func TestVerifyUnknownKidAndGarbage(t *testing.T) {
	iss, ver := newIssuer(t)
	pat, _, err := iss.Issue("alice", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ver.Keys = map[string]ed25519.PublicKey{"other": ver.Keys["test"]}
	if _, err := ver.Verify(pat); err == nil {
		t.Fatal("unknown kid verified")
	}
	for _, bad := range []string{"", "zjum_", "zjum_%%%", "garbage"} {
		if _, err := ver.Verify(bad); err == nil {
			t.Fatalf("garbage verified: %q", bad)
		}
	}
}
