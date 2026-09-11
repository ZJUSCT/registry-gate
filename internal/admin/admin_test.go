package admin

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/store"
)

// oauthFlow drives /login and /callback once, returning the final callback
// response.
func oauthFlow(t *testing.T, c *testClient) (int, http.Header, string) {
	t.Helper()
	status, hdr, _ := c.get("/admin/login")
	if status != 303 {
		t.Fatalf("login: status %d", status)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Host != "github.com" || loc.Path != "/login/oauth/authorize" {
		t.Fatalf("authorize URL = %s", loc)
	}
	if got := loc.Query().Get("scope"); got != "read:user read:org" {
		t.Errorf("scope = %q", got)
	}
	state := loc.Query().Get("state")
	return c.get("/admin/callback?code=x&state=" + url.QueryEscape(state))
}

func TestAccessMatrix(t *testing.T) {
	cases := []struct {
		name        string
		allowedUser []string
		allowedOrg  []string
		login       string
		orgs        []string
		wantAllow   bool
	}{
		{"user allow case-insensitive", []string{"AdMiN"}, nil, "admin", nil, true},
		{"org allow case-insensitive", nil, []string{"ZJUSCT"}, "eve", []string{"zjusct", "other"}, true},
		{"user takes precedence no orgs", []string{"carol"}, []string{"ops"}, "carol", nil, true},
		{"no match user", []string{"carol"}, []string{"ops"}, "dave", []string{"zjusct"}, false},
		{"org case mismatch", nil, []string{"ZJUSCT"}, "eve", []string{"zjusct2"}, false},
		{"both lists empty deny everyone", nil, nil, "root", []string{"zjusct"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, gh := newTestAdmin(t, newFakeStore(), tc.allowedUser, tc.allowedOrg)
			gh.Login.Store(tc.login)
			gh.Orgs.Store(tc.orgs)
			c := newTestClient(t, h)

			status, _, body := oauthFlow(t, c)
			if tc.wantAllow {
				if status != 303 {
					t.Fatalf("callback: status %d, body %s", status, body)
				}
				if !c.hasSession() {
					t.Fatal("no admin session cookie after allowed callback")
				}
				// The dashboard is reachable with the new session.
				if status, _, body = c.get("/admin/"); status != 200 || !strings.Contains(body, "Overview") {
					t.Fatalf("dashboard: status %d body %s", status, body)
				}
			} else {
				if status != 403 || !strings.Contains(body, "Not an administrator") {
					t.Fatalf("callback: status %d body %s", status, body)
				}
				if c.hasSession() {
					t.Fatal("session granted to non-admin")
				}
			}
		})
	}
}

func TestCallbackStateTamper(t *testing.T) {
	h, _, gh := newTestAdmin(t, newFakeStore(), []string{"admin"}, nil)
	gh.Login.Store("admin")
	c := newTestClient(t, h)

	// Obtain a valid state cookie first, then send a mismatching state.
	c.get("/admin/login")
	status, _, body := c.get("/admin/callback?code=x&state=evil")
	if status != 400 || !strings.Contains(body, "state") {
		t.Fatalf("tampered state: status %d body %s", status, body)
	}
	// Missing state cookie entirely.
	c2 := newTestClient(t, h)
	if status, _, _ := c2.get("/admin/callback?code=x&state=whatever"); status != 400 {
		t.Fatalf("missing state cookie: status %d", status)
	}
}

func TestDashboard(t *testing.T) {
	st := newFakeStore()
	h, sess, _ := newTestAdmin(t, st, []string{"admin"}, nil)
	c := newTestClient(t, h)
	c.loginAs(sess, "admin")

	now := time.Now().UTC()
	yesterday := now.Add(-24 * time.Hour)
	used := now.Add(-2 * time.Hour)
	revokedAt := now.Add(-3 * time.Hour)

	// alice: two active (one used), one revoked. bob: one expired.
	st.seedToken(t, "alice", "a1", now.Add(-48*time.Hour), now.Add(200*time.Hour), nil, &used)
	st.seedToken(t, "alice", "a2", now.Add(-47*time.Hour), now.Add(200*time.Hour), nil, nil)
	st.seedToken(t, "alice", "a3", now.Add(-46*time.Hour), now.Add(200*time.Hour), &revokedAt, nil)
	st.seedToken(t, "bob", "b1", now.Add(-40*time.Hour), now.Add(-1*time.Hour), nil, nil) // expired

	usage := []struct {
		when     time.Time
		subject  string
		repo     string
		decision string
		ip       string
	}{
		{now.Add(-time.Hour), "alice", "docker.io/library/nginx", "allow_authed", "10.0.0.1"},
		{now.Add(-2 * time.Hour), "alice", "ghcr.io/x/y", "allow_login_probe", "10.0.0.1"},
		{now.Add(-3 * time.Hour), "anonymous", "quay.io/denied/img", "deny_not_whitelisted", "10.0.0.2"},
		{yesterday, "alice", "docker.io/old", "allow_authed", "10.0.0.1"},
	}
	for _, u := range usage {
		if err := st.InsertUsage(t.Context(), store.UsageRecord{
			Time: u.when, Subject: u.subject, Repo: u.repo, Decision: u.decision, IP: u.ip,
		}); err != nil {
			t.Fatal(err)
		}
	}

	status, _, body := c.get("/admin/")
	if status != 200 {
		t.Fatalf("dashboard: status %d body %s", status, body)
	}
	for _, want := range []string{
		"Active tokens", "Revoked tokens",
		"deny_not_whitelisted", // decision table + usage row
		"docker.io/library/nginx",
		"alice", "bob",
		"Users", "Recent usage",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	// Card numbers.
	if !strings.Contains(body, `<div class="num">2</div>`) { // active tokens
		t.Error("summary card shows wrong active token count")
	}
	// Users table rows link to per-user pages.
	if !strings.Contains(body, `href="/admin/users/alice"`) {
		t.Error("users table lacks link to alice")
	}
}

func TestDashboardPagination(t *testing.T) {
	st := newFakeStore()
	h, sess, _ := newTestAdmin(t, st, []string{"admin"}, nil)
	c := newTestClient(t, h)
	c.loginAs(sess, "admin")

	now := time.Now().UTC()
	for i := 0; i < 60; i++ {
		if err := st.InsertUsage(t.Context(), store.UsageRecord{
			Time:     now.Add(-time.Duration(i) * time.Minute),
			Subject:  "alice",
			Repo:     "docker.io/r/img",
			Decision: "allow_authed",
			IP:       "10.0.0.9",
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, _, p1 := c.get("/admin/")
	// Count usage rows via the unique per-record IP (the decision string also
	// appears in the summary table).
	if got := strings.Count(p1, ">10.0.0.9<"); got != usagePageSize {
		t.Errorf("page 1 shows %d usage rows, want %d", got, usagePageSize)
	}
	if !strings.Contains(p1, "page=2") {
		t.Error("page 1 lacks next-page link")
	}
	_, _, p2 := c.get("/admin/?page=2")
	if got := strings.Count(p2, ">10.0.0.9<"); got != 10 {
		t.Errorf("page 2 shows %d usage rows, want 10", got)
	}
	if strings.Contains(p2, "page=3") {
		t.Error("page 2 must not have a next link")
	}
}

func TestUserPageAndRevocation(t *testing.T) {
	st := newFakeStore()
	h, sess, _ := newTestAdmin(t, st, []string{"admin"}, nil)
	c := newTestClient(t, h)
	c.loginAs(sess, "admin")

	now := time.Now().UTC()
	st.seedToken(t, "alice", "a1", now.Add(-time.Hour), now.Add(200*time.Hour), nil, nil)
	st.seedToken(t, "alice", "a2", now.Add(-2*time.Hour), now.Add(200*time.Hour), nil, nil)
	st.seedToken(t, "bob", "b1", now.Add(-2*time.Hour), now.Add(200*time.Hour), nil, nil)

	status, _, body := c.get("/admin/users/alice")
	if status != 200 {
		t.Fatalf("user page: status %d body %s", status, body)
	}
	for _, want := range []string{"a1", "a2", "Revoke all tokens", "note-a1"} {
		if !strings.Contains(body, want) {
			t.Errorf("user page missing %q", want)
		}
	}
	if strings.Contains(body, "b1") {
		t.Error("user page leaks bob's token")
	}

	// Revoke one of alice's tokens.
	if status, hdr, _ := c.post("/admin/tokens/a1/revoke"); status != 303 || hdr.Get("Location") != "/admin/users/alice" {
		t.Fatalf("revoke: status %d location %q", status, hdr.Get("Location"))
	}
	m, err := st.GetToken(t.Context(), "a1")
	if err != nil || m.RevokedAt == nil {
		t.Fatalf("a1 not revoked: %+v err %v", m, err)
	}

	// Revoke all of bob's tokens via the user page action.
	if status, _, _ := c.post("/admin/users/bob/revoke-all"); status != 303 {
		t.Fatalf("revoke-all: status %d", status)
	}
	if m, _ := st.GetToken(t.Context(), "b1"); m.RevokedAt == nil {
		t.Error("b1 not revoked by revoke-all")
	}

	// Unknown token revocation is a 404.
	if status, _, _ := c.post("/admin/tokens/nope/revoke"); status != 404 {
		t.Errorf("unknown token revoke: status %d", status)
	}
}

func TestManagementRequiresSession(t *testing.T) {
	st := newFakeStore()
	h, _, _ := newTestAdmin(t, st, []string{"admin"}, nil)
	c := newTestClient(t, h)

	now := time.Now().UTC()
	st.seedToken(t, "alice", "a1", now.Add(-time.Hour), now.Add(200*time.Hour), nil, nil)

	for _, target := range []string{"/admin/tokens/a1/revoke", "/admin/users/alice/revoke-all"} {
		status, hdr, _ := c.post(target)
		if status != 303 || hdr.Get("Location") != "/admin/login" {
			t.Errorf("%s without session: status %d location %q", target, status, hdr.Get("Location"))
		}
	}
	if status, hdr, _ := c.get("/admin/users/alice"); status != 303 || hdr.Get("Location") != "/admin/login" {
		t.Errorf("user page without session: status %d location %q", status, hdr.Get("Location"))
	}
	if m, _ := st.GetToken(t.Context(), "a1"); m.RevokedAt != nil {
		t.Error("anonymous request revoked a token")
	}
}

func TestLogout(t *testing.T) {
	h, sess, _ := newTestAdmin(t, newFakeStore(), []string{"admin"}, nil)
	c := newTestClient(t, h)
	c.loginAs(sess, "admin")
	status, _, _ := c.post("/admin/logout")
	if status != 303 {
		t.Fatalf("logout: status %d", status)
	}
	if c.hasSession() {
		t.Fatal("session cookie not cleared")
	}
	// After logout the login page is shown again.
	if status, _, body := c.get("/admin/"); status != 200 || !strings.Contains(body, "Sign in with GitHub") {
		t.Fatalf("dashboard after logout: status %d body %s", status, body)
	}
}
