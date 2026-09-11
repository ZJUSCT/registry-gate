package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ZJUSCT/registry-gate/internal/session"
)

// stubGitHub fakes the pieces of GitHub the admin UI talks to: the OAuth
// token exchange and the REST endpoints /user and /user/orgs.
type stubGitHub struct {
	srv   *httptest.Server
	Login atomic.Value // string returned by /user
	Orgs  atomic.Value // []string returned by /user/orgs
}

func newStubGitHub(t *testing.T) *stubGitHub {
	t.Helper()
	s := &stubGitHub{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": "stub-access-token",
			"token_type":   "bearer",
		})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer stub-access-token" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		login, _ := s.Login.Load().(string)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"login": login})
	})
	mux.HandleFunc("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer stub-access-token" {
			http.Error(w, "bad token", http.StatusUnauthorized)
			return
		}
		orgs, _ := s.Orgs.Load().([]string)
		out := make([]map[string]string, 0, len(orgs))
		for _, o := range orgs {
			out = append(out, map[string]string{"login": o})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

// newTestAdmin builds an admin handler wired to the stub. It returns the
// handler, a session store compatible with its cookie, and the stub.
func newTestAdmin(t *testing.T, st *fakeStore, allowedUsers, allowedOrgs []string) (http.Handler, *session.Store, *stubGitHub) {
	t.Helper()
	gh := newStubGitHub(t)
	h, err := Handler(Options{
		BasePath:      "/admin",
		ExternalURL:   "https://reg.example.com",
		ClientID:      "cid",
		ClientSecret:  "csecret",
		AllowedUsers:  allowedUsers,
		AllowedOrgs:   allowedOrgs,
		GitHubAPIBase: gh.srv.URL,
		SessionSecret: []byte("0123456789abcdef0123456789abcdef"),
		Store:         st,
	}, quietLogger())
	if err != nil {
		t.Fatalf("Handler: %v", err)
	}
	srv := h.(*server)
	srv.gh.tokenURL = gh.srv.URL + "/oauth/token"
	sess := session.New([]byte("0123456789abcdef0123456789abcdef"), sessionCookieName)
	return h, sess, gh
}
