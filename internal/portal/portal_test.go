package portal

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/session"
	"github.com/ZJUSCT/registry-gate/internal/store"
	"github.com/ZJUSCT/registry-gate/internal/token"
)

const (
	testSecret = "0123456789abcdef0123456789abcdef"
	testBase   = "/token"
	testReg    = "https://reg.example.com"
)

// newTestPortal builds a portal handler over a fresh fake store and issuer.
func newTestPortal(t *testing.T, issuerURL string, st *fakeStore, maxTokens int) (http.Handler, *session.Store) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	sess := session.New([]byte(testSecret), sessionCookieName)
	h, err := Handler(Options{
		BasePath:         testBase,
		ExternalURL:      testReg,
		OIDCIssuer:       issuerURL,
		ClientID:         "cid",
		ClientSecret:     "csecret",
		MaxTokensPerUser: maxTokens,
		TokenTTL:         30 * 24 * time.Hour,
		MaxTokenTTL:      365 * 24 * time.Hour,
		SessionSecret:    []byte(testSecret),
		Store:            st,
		Issuer:           &token.Issuer{Key: priv, Kid: "test", Issuer: "zju-mirror"},
	}, quietLogger())
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	return h, sess
}

// issueViaForm creates a token through the HTTP form and returns the PAT.
func issueViaForm(t *testing.T, c *testClient, form string) string {
	t.Helper()
	status, _, body := c.post(testBase+"/tokens", form)
	if status != 200 {
		t.Fatalf("POST /tokens: status %d, body %s", status, body)
	}
	i := strings.Index(body, "zjum_")
	if i < 0 {
		t.Fatalf("POST /tokens: no PAT in body: %s", body)
	}
	end := strings.IndexByte(body[i:], '<')
	if end < 0 {
		t.Fatalf("POST /tokens: malformed PAT in body")
	}
	return body[i : i+end]
}

func TestHomeShowsLogin(t *testing.T) {
	h, _ := newTestPortal(t, "https://gitlab.example", newFakeStore(), 10)
	c := newTestClient(t, h)
	status, _, body := c.get(testBase + "/")
	if status != 200 || !strings.Contains(body, "Sign in with ZJU GitLab") {
		t.Fatalf("home without session: status %d, body %s", status, body)
	}
	// The bare base path must behave like the root.
	if status, _, _ = c.get(testBase); status != 200 {
		t.Fatalf("GET base path without trailing slash: status %d", status)
	}
	// The shared stylesheet is served under the base path.
	if status, _, css := c.get(testBase + "/static/style.css"); status != 200 || !strings.Contains(css, "--fg") {
		t.Fatalf("stylesheet: status %d len %d", status, len(css))
	}
}

func TestIssueToken(t *testing.T) {
	st := newFakeStore()
	h, sess := newTestPortal(t, "https://gitlab.example", st, 10)
	c := newTestClient(t, h)
	c.loginAs(sess, "alice")

	issueViaForm(t, c, "note=ci&ttl=7")

	status, _, body := c.post(testBase+"/tokens", "note=bad&ttl=999999")
	_ = body
	if status != 303 { // over MaxTokenTTL -> flash + redirect to dashboard
		t.Fatalf("issue over max ttl: status %d", status)
	}
	status, _, dash := c.get(testBase + "/")
	if !strings.Contains(dash, "must not exceed 365 days") {
		t.Fatalf("flash missing ttl error: %s", dash)
	}

	metas, _ := st.ListTokensBySubject(t.Context(), "alice")
	if len(metas) != 1 {
		t.Fatalf("stored %d tokens, want 1", len(metas))
	}
	m := metas[0]
	if m.Note != "ci" {
		t.Errorf("note = %q, want ci", m.Note)
	}
	ttl := m.ExpiresAt.Sub(m.IssuedAt)
	if ttl != 7*24*time.Hour {
		t.Errorf("ttl = %v, want 7d", ttl)
	}
	if m.JTI == "" || len(m.JTI) != 32 {
		t.Errorf("JTI = %q, want 16-byte hex", m.JTI)
	}

	// Result page shows the PAT once plus the docker login snippet.
	status, _, body = c.post(testBase+"/tokens", "note=pagecheck&ttl=")
	if status != 200 {
		t.Fatalf("issue default ttl: status %d", status)
	}
	if !strings.Contains(body, "zjum_") {
		t.Errorf("result page lacks the PAT: %s", body)
	}
	if !strings.Contains(body, "docker login "+testReg) {
		t.Errorf("result page lacks docker login snippet: %s", body)
	}
	// Default TTL applied.
	metas, _ = st.ListTokensBySubject(t.Context(), "alice")
	found := false
	for _, m := range metas {
		if m.Note == "pagecheck" && m.ExpiresAt.Sub(m.IssuedAt) == 30*24*time.Hour {
			found = true
		}
	}
	if !found {
		t.Errorf("default-TTL token not stored with 30d: %+v", metas)
	}
}

func TestMaxTokensEnforced(t *testing.T) {
	st := newFakeStore()
	h, sess := newTestPortal(t, "https://gitlab.example", st, 1)
	c := newTestClient(t, h)
	c.loginAs(sess, "alice")

	issueViaForm(t, c, "note=first&ttl=1")
	if status, _, _ := c.post(testBase+"/tokens", "note=second&ttl=1"); status != 303 {
		t.Fatalf("second issue should flash-redirect, got %d", status)
	}
	status, _, dash := c.get(testBase + "/")
	if status != 200 || !strings.Contains(dash, "maximum 1") {
		t.Fatalf("dashboard missing max-token error: status %d body %s", status, dash)
	}
	if n, _ := st.CountActiveBySubject(t.Context(), "alice", time.Now()); n != 1 {
		t.Fatalf("active tokens = %d, want 1", n)
	}
}

func TestRotate(t *testing.T) {
	st := newFakeStore()
	h, sess := newTestPortal(t, "https://gitlab.example", st, 10)
	c := newTestClient(t, h)
	c.loginAs(sess, "alice")

	issueViaForm(t, c, "note=laptop&ttl=30")
	old, _ := st.ListTokensBySubject(t.Context(), "alice")

	status, _, body := c.post(testBase+"/tokens/"+old[0].JTI+"/rotate", "")
	if status != 200 {
		t.Fatalf("rotate: status %d, body %s", status, body)
	}
	if !strings.Contains(body, "zjum_") {
		t.Fatalf("rotate result lacks new PAT: %s", body)
	}
	got, err := st.GetToken(t.Context(), old[0].JTI)
	if err != nil {
		t.Fatal(err)
	}
	if got.RevokedAt == nil {
		t.Error("old token not revoked after rotate")
	}
	metas, _ := st.ListTokensBySubject(t.Context(), "alice")
	if len(metas) != 2 {
		t.Fatalf("have %d tokens, want old+new", len(metas))
	}
}

func TestRevoke(t *testing.T) {
	st := newFakeStore()
	h, sess := newTestPortal(t, "https://gitlab.example", st, 10)
	c := newTestClient(t, h)
	c.loginAs(sess, "alice")

	issueViaForm(t, c, "note=doomed&ttl=1")
	m, _ := st.ListTokensBySubject(t.Context(), "alice")

	if status, _, _ := c.post(testBase+"/tokens/"+m[0].JTI+"/revoke", ""); status != 303 {
		t.Fatalf("revoke: want 303, got %d", status)
	}
	got, _ := st.GetToken(t.Context(), m[0].JTI)
	if got.RevokedAt == nil {
		t.Fatal("token not revoked")
	}
	if _, _, dash := c.get(testBase + "/"); !strings.Contains(dash, "Token revoked") {
		t.Fatalf("missing revoke flash: %s", dash)
	}
}

func TestForeignTokenForbidden(t *testing.T) {
	st := newFakeStore()
	h, sess := newTestPortal(t, "https://gitlab.example", st, 10)
	c := newTestClient(t, h)
	c.loginAs(sess, "alice")

	// Seed a token owned by bob directly in the store.
	bobMeta := st.issueDirect(t, "bob", "bob token", time.Hour)

	for _, action := range []string{"rotate", "revoke"} {
		status, _, body := c.post(testBase+"/tokens/"+bobMeta.JTI+"/"+action, "")
		if status != 404 {
			t.Fatalf("%s on foreign token: status %d, body %s", action, status, body)
		}
	}
	got, err := st.GetToken(t.Context(), bobMeta.JTI)
	if err != nil || got.RevokedAt != nil {
		t.Fatalf("foreign token was modified: %+v err %v", got, err)
	}
	// Unknown JTI is also a plain 404.
	if status, _, _ := c.post(testBase+"/tokens/deadbeef/revoke", ""); status != 404 {
		t.Fatalf("unknown token revoke: status %d", status)
	}
}

func TestUsagePage(t *testing.T) {
	st := newFakeStore()
	h, sess := newTestPortal(t, "https://gitlab.example", st, 10)
	c := newTestClient(t, h)
	c.loginAs(sess, "alice")

	now := time.Now()
	for i, rec := range []struct{ repo, decision, ip string }{
		{"docker.io/library/nginx", "allow_authed", "10.0.0.1"},
		{"ghcr.io/example/app", "allow_authed", "10.0.0.2"},
		{"", "allow_login_probe", "10.0.0.3"},
	} {
		st.InsertUsage(t.Context(), store.UsageRecord{Time: now.Add(-time.Duration(i) * time.Minute),
			Subject: "alice", Repo: rec.repo, Decision: rec.decision, IP: rec.ip})
	}
	st.InsertUsage(t.Context(), store.UsageRecord{Time: now, Subject: "bob",
		Repo: "quay.io/x/y", Decision: "deny_not_whitelisted", IP: "10.9.9.9"})

	status, _, body := c.get(testBase + "/usage")
	if status != 200 {
		t.Fatalf("usage: status %d", status)
	}
	for _, want := range []string{"docker.io/library/nginx", "ghcr.io/example/app", "allow_login_probe", "10.0.0.3"} {
		if !strings.Contains(body, want) {
			t.Errorf("usage page missing %q", want)
		}
	}
	if strings.Contains(body, "quay.io/x/y") || strings.Contains(body, "bob") {
		t.Error("usage page leaks other users' records")
	}
}

func TestLogout(t *testing.T) {
	h, sess := newTestPortal(t, "https://gitlab.example", newFakeStore(), 10)
	c := newTestClient(t, h)
	c.loginAs(sess, "alice")
	status, _, _ := c.post(testBase+"/logout", "")
	if status != 303 {
		t.Fatalf("logout: status %d", status)
	}
	ck := c.cookies[sessionCookieName]
	if ck == nil || ck.Value != "" {
		t.Fatalf("session cookie not cleared: %+v", ck)
	}
}

func TestOIDCFlow(t *testing.T) {
	oidc := newStubOIDC(t, "cid")
	st := newFakeStore()
	h, _ := newTestPortal(t, oidc.srv.URL, st, 10)
	c := newTestClient(t, h)

	// /login redirects to the provider with state, nonce and PKCE S256.
	status, hdr, _ := c.get(testBase + "/login")
	if status != 303 {
		t.Fatalf("login: status %d", status)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Path != "/authorize" {
		t.Fatalf("authorize path = %s", loc.Path)
	}
	q := loc.Query()
	if q.Get("client_id") != "cid" || q.Get("response_type") != "code" {
		t.Errorf("authorize query wrong: %s", q)
	}
	if q.Get("scope") != "openid" {
		t.Errorf("scope = %q, want openid", q.Get("scope"))
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Errorf("PKCE missing: %s", q)
	}
	state := q.Get("state")
	// The auth cookie carries state.nonce.verifier; verify challenge==S256(verifier).
	auth := c.cookies[authCookieName]
	if auth == nil {
		t.Fatal("auth cookie missing after /login")
	}
	parts := strings.Split(auth.Value, ".")
	if len(parts) != 3 || parts[0] != state {
		t.Fatalf("auth cookie %v does not match state %q", parts, state)
	}
	sum := sha256.Sum256([]byte(parts[2]))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); q.Get("code_challenge") != want {
		t.Fatalf("code_challenge %q != S256(verifier) %q", q.Get("code_challenge"), want)
	}
	oidc.Nonce.Store(parts[1])

	// Tampered state is rejected.
	if status, _, _ = c.get(testBase + "/callback?code=x&state=evil"); status != 400 {
		t.Fatalf("tampered state: status %d", status)
	}

	// Correct callback establishes the session.
	status, hdr, _ = c.get(testBase + "/callback?code=x&state=" + url.QueryEscape(state))
	if status != 303 || hdr.Get("Location") != testBase+"/" {
		t.Fatalf("callback: status %d location %q", status, hdr.Get("Location"))
	}
	if c.cookies[sessionCookieName] == nil || c.cookies[sessionCookieName].Value == "" {
		t.Fatal("no session cookie after callback")
	}

	// Dashboard shows the preferred_username ("alice"), not "sub" ("aliceuser").
	status, _, body := c.get(testBase + "/")
	if status != 200 || !strings.Contains(body, "Signed in as <strong>alice</strong>") {
		t.Fatalf("dashboard after OIDC: status %d body %s", status, body)
	}
}

func TestOIDCBadIDToken(t *testing.T) {
	oidc := newStubOIDC(t, "cid")
	h, _ := newTestPortal(t, oidc.srv.URL, newFakeStore(), 10)
	c := newTestClient(t, h)

	// /login then callback with a nonce that will not match the id_token.
	_, hdr, _ := c.get(testBase + "/login")
	loc, _ := url.Parse(hdr.Get("Location"))
	state := loc.Query().Get("state")
	oidc.Nonce.Store("wrong-nonce")

	status, _, body := c.get(testBase + "/callback?code=x&state=" + url.QueryEscape(state))
	if status != 401 || !strings.Contains(body, "Sign-in failed") {
		t.Fatalf("nonce mismatch: status %d body %s", status, body)
	}
	if c.cookies[sessionCookieName] != nil && c.cookies[sessionCookieName].Value != "" {
		t.Fatal("session granted despite nonce mismatch")
	}
}
