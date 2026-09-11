package gate

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/httpx"
	"github.com/ZJUSCT/registry-gate/internal/store"
	"github.com/ZJUSCT/registry-gate/internal/token"
	"github.com/ZJUSCT/registry-gate/internal/whitelist"
)

// recordedRequest captures what the fake Harbor saw.
type recordedRequest struct {
	Method        string
	URL           *url.URL
	Authorization string
}

type fakeHarbor struct {
	mu       sync.Mutex
	requests []recordedRequest
	status   int              // response status (default 200)
	body     string           // response body
	srv      *httptest.Server // the fake harbor
}

func newFakeHarbor(t *testing.T) *fakeHarbor {
	t.Helper()
	f := &fakeHarbor{status: http.StatusOK, body: `{"token":"harbor-token","expires_in":300,"issued_at":"now"}`}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, recordedRequest{
			Method:        r.Method,
			URL:           r.URL.Clone(),
			Authorization: r.Header.Get("Authorization"),
		})
		status, body := f.status, f.body
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	f.srv = srv
	return f
}

// testEnv bundles everything a gate test needs.
type testEnv struct {
	*Handler
	harbor *fakeHarbor
	store  *store.SQLite
	issuer *token.Issuer
}

func baseGateConfig(harborURL string) GateConfig {
	return GateConfig{
		Path:               "/service/token",
		AnonymousEnabled:   true,
		HarborBaseURL:      harborURL,
		HarborTokenPath:    "/service/token",
		RequestTimeout:     2 * time.Second,
		DenyMessage:        "DENY_MSG",
		LoginFailedMessage: "LOGIN_MSG",
		Projects: map[string]string{
			"docker.io":         "docker.io",
			"hub.docker.com":    "docker.io",
			"docker.elastic.co": "docker.elastic.co",
			"ghcr.io":           "ghcr.io",
		},
		PerIPRate:       httpx.Rate{Count: 1000, Window: time.Minute},
		PerUsernameRate: httpx.Rate{Count: 1000, Window: time.Minute},
	}
}

// newEnv builds a gate wired to a fake harbor, a real sqlite store and an
// inline whitelist.
func newEnv(t *testing.T, cfg GateConfig, inline []string) *testEnv {
	t.Helper()
	harbor := newFakeHarbor(t)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &token.Issuer{Key: priv, Kid: "test", Issuer: "zju-mirror"}
	verifier := &token.Verifier{Keys: map[string]ed25519.PublicKey{"test": pub}, Issuer: "zju-mirror"}

	wl, err := whitelist.New(nil, inline, whitelist.WithHotReload(false))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wl.Close)

	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg.HarborBaseURL = harbor.srv.URL
	h := New(cfg, wl, verifier, st, slog.New(slog.NewTextHandler(io.Discard, nil)), httpx.NewMetrics(), nil)
	return &testEnv{Handler: h, harbor: harbor, store: st, issuer: issuer}
}

func (f *fakeHarbor) lastRequest() recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return recordedRequest{}
	}
	return f.requests[len(f.requests)-1]
}

func (f *fakeHarbor) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// stop shuts the fake harbor down so connections are refused.
func (f *fakeHarbor) stop() { f.srv.Close() }

// issuePAT creates a valid PAT and registers it in the store.
func (e *testEnv) issuePAT(t *testing.T, subject string) string {
	t.Helper()
	pat, claims, err := e.issuer.Issue(subject, "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.CreateToken(context.Background(), store.TokenMeta{
		JTI: claims.JTI(), Subject: subject, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return pat
}

func doGet(h http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func doGetBasic(h http.Handler, target, user, pass string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.SetBasicAuth(user, pass)
	h.ServeHTTP(rec, req)
	return rec
}

// errorBody decodes the registry error schema.
func errorBody(t *testing.T, rec *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	var got struct {
		Errors []map[string]any `json:"errors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not the registry error schema: %v (%s)", err, rec.Body.String())
	}
	if len(got.Errors) != 1 {
		t.Fatalf("errors = %+v, want exactly one entry", got.Errors)
	}
	return got.Errors
}

// waitUsage polls the store until at least n records with the decision
// exist (gate writes usage asynchronously).
func (e *testEnv) waitUsage(t *testing.T, decision string, n int) []store.UsageRecord {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := e.store.ListUsage(context.Background(), 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		var hits []store.UsageRecord
		for _, r := range rows {
			if r.Decision == decision {
				hits = append(hits, r)
			}
		}
		if len(hits) >= n {
			return hits
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("usage rows with decision %q never reached %d", decision, n)
	return nil
}

func TestAnonAllowForwardsAnonymously(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	const query = "service=registry&scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull"
	rec := doGet(e.Handler, "/service/token?"+query)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if want := e.harbor.body; rec.Body.String() != want {
		t.Fatalf("body = %q, want verbatim %q", rec.Body.String(), want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	// The forwarded request must be anonymous and preserve the query.
	fwd := e.harbor.lastRequest()
	if fwd.Authorization != "" {
		t.Fatalf("Authorization forwarded: %q", fwd.Authorization)
	}
	if fwd.Method != http.MethodGet {
		t.Fatalf("forwarded method = %s", fwd.Method)
	}
	if got, want := fwd.URL.RawQuery, query; got != want {
		t.Fatalf("forwarded query = %q, want %q", got, want)
	}
	rows := e.waitUsage(t, DecisionAllowAnon, 1)
	if rows[0].Subject != "anonymous" || rows[0].Repo != "docker.io/library/nginx" {
		t.Fatalf("usage = %+v", rows[0])
	}
	if rows[0].Rule != "docker.io/library/nginx" {
		t.Fatalf("rule = %q", rows[0].Rule)
	}
}

func TestAnonDenyErrorSchemaAndChallenge(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	rec := doGet(e.Handler, "/service/token?service=registry&scope=repository%3Adocker.io%2Flibrary%2Funknown%3Apull")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); wa != `Basic realm="registry-gate"` {
		t.Fatalf("WWW-Authenticate = %q", wa)
	}
	errs := errorBody(t, rec)
	if errs[0]["code"] != "UNAUTHORIZED" || errs[0]["message"] != "DENY_MSG" {
		t.Fatalf("error = %+v", errs[0])
	}
	e.waitUsage(t, DecisionDenyNotWhitelisted, 1)
}

// The DaoCloud gotcha, end to end: "docker.io/*" is exactly one more
// segment and must NOT match "docker.io/library/nginx".
func TestDockerIoStarGotchaEndToEnd(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/*"})

	rec := doGet(e.Handler, "/service/token?scope=repository%3Adocker.io%2Fportainer%3Apull")
	if rec.Code != http.StatusOK || e.harbor.requestCount() != 1 {
		t.Fatalf("docker.io/portainer: status %d", rec.Code)
	}
	rec = doGet(e.Handler, "/service/token?scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("docker.io/library/nginx: status %d, want 401", rec.Code)
	}
	if e.harbor.requestCount() != 1 {
		t.Fatalf("denied request reached harbor")
	}
}

func TestDoubleStarRecursiveEndToEnd(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.elastic.co/**"})
	for _, repo := range []string{"docker.elastic.co/kibana", "docker.elastic.co/kibana/kibana", "docker.elastic.co/a/b/c"} {
		rec := doGet(e.Handler, "/service/token?scope=repository%3A"+url.QueryEscape(repo)+"%3Apull")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", repo, rec.Code)
		}
	}
}

func TestProjectAliasMapsWhitelistHost(t *testing.T) {
	// hub.docker.com/* scopes must be checked against the docker.io
	// whitelist entries.
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	rec := doGet(e.Handler, "/service/token?scope=repository%3Ahub.docker.com%2Flibrary%2Fnginx%3Apull")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestPATScopelessLoginProbe(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), nil)
	pat := e.issuePAT(t, "alice")
	rec := doGetBasic(e.Handler, "/service/token?service=registry", "alice", pat)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	// The probe is answered by the gate itself: the PAT doubles as the
	// probe token and Harbor must not be involved at all.
	var body struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if body.Token != pat || body.ExpiresIn <= 0 {
		t.Fatalf("probe response = %+v", body)
	}
	if n := e.harbor.requestCount(); n != 0 {
		t.Fatalf("probe was forwarded to harbor (%d requests)", n)
	}
	rows := e.waitUsage(t, DecisionAllowLoginProbe, 1)
	if rows[0].Subject != "alice" || rows[0].Repo != "" {
		t.Fatalf("usage = %+v", rows[0])
	}
	// MarkUsed is async; wait for it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m, err := e.store.GetToken(context.Background(), extractJTI(t, e, "alice"))
		if err != nil {
			t.Fatal(err)
		}
		if m.LastUsed != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("MarkUsed never stamped last_used")
}

func extractJTI(t *testing.T, e *testEnv, subject string) string {
	t.Helper()
	metas, err := e.store.ListTokensBySubject(context.Background(), subject)
	if err != nil || len(metas) != 1 {
		t.Fatalf("tokens for %s = %+v (%v)", subject, metas, err)
	}
	return metas[0].JTI
}

func TestPATRepoAllow(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	pat := e.issuePAT(t, "bob")
	// Not whitelisted, but authenticated users are not restricted.
	rec := doGetBasic(e.Handler, "/service/token?scope=repository%3Aghcr.io%2Focto%2Fapp%3Apull", "bob", pat)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if fwd := e.harbor.lastRequest(); fwd.Authorization != "" {
		t.Fatalf("Authorization forwarded: %q", fwd.Authorization)
	}
	rows := e.waitUsage(t, DecisionAllowAuthed, 1)
	if rows[0].Subject != "bob" {
		t.Fatalf("usage = %+v", rows[0])
	}
}

func TestPATNonRepositoryScopeAllowed(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), nil)
	pat := e.issuePAT(t, "bob")
	rec := doGetBasic(e.Handler, "/service/token?scope=registry%3Acatalog%3A*", "bob", pat)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRevokedPAT(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), nil)
	pat := e.issuePAT(t, "alice")
	jti := extractJTI(t, e, "alice")
	if err := e.store.RevokeToken(context.Background(), jti, time.Now()); err != nil {
		t.Fatal(err)
	}
	rec := doGetBasic(e.Handler, "/service/token?scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull", "alice", pat)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); wa == "" {
		t.Fatal("missing WWW-Authenticate on 401")
	}
	errs := errorBody(t, rec)
	if errs[0]["message"] != "LOGIN_MSG" {
		t.Fatalf("message = %v", errs[0]["message"])
	}
	e.waitUsage(t, DecisionDenyBadToken, 1)
}

func TestPATMissingFromStoreFailsClosed(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), nil)
	// Valid signature, but never registered (e.g. store wiped): deny.
	pat, _, err := e.issuer.Issue("alice", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rec := doGetBasic(e.Handler, "/service/token", "alice", pat)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestUnknownProject404(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})

	rec := doGet(e.Handler, "/service/token?scope=repository%3Aexample.com%2Ffoo%3Apull")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("anon unknown project: status %d", rec.Code)
	}
	errs := errorBody(t, rec)
	if errs[0]["code"] != "DENIED" || !strings.Contains(errs[0]["message"].(string), "upstream not mirrored") {
		t.Fatalf("anon error = %+v", errs[0])
	}

	pat := e.issuePAT(t, "alice")
	rec = doGetBasic(e.Handler, "/service/token?scope=repository%3Aexample.com%2Ffoo%3Apull", "alice", pat)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("authed unknown project: status %d", rec.Code)
	}
	e.waitUsage(t, DecisionDenyNoUpstream, 2)
}

func TestPostMethodNotAllowed(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), nil)
	rec := httptest.NewRecorder()
	e.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/service/token?service=registry", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
	if allow := rec.Header().Get("Allow"); allow != "GET" {
		t.Fatalf("Allow = %q", allow)
	}
	errs := errorBody(t, rec)
	if errs[0]["code"] != "UNSUPPORTED" {
		t.Fatalf("error = %+v", errs[0])
	}
	if e.harbor.requestCount() != 0 {
		t.Fatal("POST reached harbor")
	}
}

func TestUpstreamNon2xxFailsClosed(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	e.harbor.mu.Lock()
	e.harbor.status = http.StatusInternalServerError
	e.harbor.mu.Unlock()
	rec := doGet(e.Handler, "/service/token?scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	errs := errorBody(t, rec)
	if errs[0]["code"] != "UNAVAILABLE" {
		t.Fatalf("error = %+v", errs[0])
	}
}

func TestUpstreamUnreachableFailsClosed(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	e.harbor.stop()
	rec := doGet(e.Handler, "/service/token?scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	errs := errorBody(t, rec)
	if errs[0]["code"] != "UNAVAILABLE" {
		t.Fatalf("error = %+v", errs[0])
	}
}

func TestAuthFailureRateLimit(t *testing.T) {
	cfg := baseGateConfig("")
	cfg.PerIPRate = httpx.Rate{Count: 3, Window: time.Minute}
	e := newEnv(t, cfg, nil)

	for i := 0; i < 3; i++ {
		rec := doGetBasic(e.Handler, "/service/token?service=registry", "alice", "zjum_garbage")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i, rec.Code)
		}
	}
	rec := doGetBasic(e.Handler, "/service/token?service=registry", "alice", "zjum_garbage")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	errs := errorBody(t, rec)
	if errs[0]["code"] != "TOOMANYREQUESTS" {
		t.Fatalf("error = %+v", errs[0])
	}
	// A different client IP is unaffected by alice's per-IP failures.
	other := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/service/token?service=registry", nil)
	req.SetBasicAuth("bob", "zjum_garbage")
	req.RemoteAddr = "198.51.100.7:1111"
	e.Handler.ServeHTTP(other, req)
	if other.Code != http.StatusUnauthorized {
		t.Fatalf("other client: status %d, want 401 (ip-based limiter)", other.Code)
	}
}

func TestAnonDisabled(t *testing.T) {
	cfg := baseGateConfig("")
	cfg.AnonymousEnabled = false
	e := newEnv(t, cfg, []string{"docker.io/library/nginx"})
	rec := doGet(e.Handler, "/service/token?scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); wa != `Basic realm="registry-gate"` {
		t.Fatalf("WWW-Authenticate = %q", wa)
	}
	e.waitUsage(t, DecisionDenyAnonDisabled, 1)
}

func TestAnonRegistryScopeDenied(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), nil)
	rec := doGet(e.Handler, "/service/token?scope=registry%3Acatalog%3A*")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	e.waitUsage(t, DecisionDenyRegistryScope, 1)
}

func TestAnonScopelessChallenged(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), nil)
	rec := doGet(e.Handler, "/service/token?service=registry")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if wa := rec.Header().Get("WWW-Authenticate"); wa == "" {
		t.Fatal("missing WWW-Authenticate")
	}
}

func TestAllRepoScopesMustPass(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	rec := doGet(e.Handler,
		"/service/token?scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull&scope=repository%3Adocker.io%2Flibrary%2Fredis%3Apull")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (second scope not whitelisted)", rec.Code)
	}
	if e.harbor.requestCount() != 0 {
		t.Fatal("request reached harbor")
	}
}

func TestSpaceSeparatedScopes(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	// Both scopes in one, space-separated query value.
	rec := doGet(e.Handler,
		"/service/token?scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull+repository%3Adocker.io%2Flibrary%2Fnginx%3Apull")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestServiceAccountUsedForForwarding(t *testing.T) {
	cfg := baseGateConfig("")
	cfg.ServiceAccountUsername = "robot$gate"
	cfg.ServiceAccountPassword = "s3cret"
	e := newEnv(t, cfg, []string{"docker.io/library/nginx"})

	rec := doGet(e.Handler, "/service/token?scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("robot$gate:s3cret"))
	if got := e.harbor.lastRequest().Authorization; got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

func TestRefreshTokenNeverAdded(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	rec := doGet(e.Handler, "/service/token?scope=repository%3Adocker.io%2Flibrary%2Fnginx%3Apull")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "refresh_token") {
		t.Fatalf("gate added refresh_token: %s", rec.Body.String())
	}
	// Verbatim passthrough: byte-for-byte what Harbor produced.
	if rec.Body.String() != e.harbor.body {
		t.Fatalf("body modified: %q", rec.Body.String())
	}
}

func TestPingHandler(t *testing.T) {
	cfg := baseGateConfig("")
	cfg.ExternalURL = "https://mirror.example.org"
	e := newEnv(t, cfg, nil)
	ping := e.PingHandler()

	// Anonymous probe: 401 with a Bearer challenge pointing at the gate.
	rec := httptest.NewRecorder()
	ping.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon ping = %d", rec.Code)
	}
	want := `Bearer realm="https://mirror.example.org/service/token",service="harbor-registry"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}

	// Valid PAT bearer: 200.
	pat := e.issuePAT(t, "alice")
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.Header.Set("Authorization", "Bearer "+pat)
	ping.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authed ping = %d, body %s", rec.Code, rec.Body.String())
	}

	// Garbage bearer: 401.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v2", nil)
	req.Header.Set("Authorization", "Bearer nonsense")
	ping.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("garbage ping = %d", rec.Code)
	}

	// Anything deeper than the probe endpoint is not ours.
	rec = httptest.NewRecorder()
	ping.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v2/docker.io/library/nginx/manifests/latest", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deep path = %d, want 404", rec.Code)
	}
}

func TestPATAsUsername(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), []string{"docker.io/library/nginx"})
	pat := e.issuePAT(t, "alice")
	// GitHub-style: token in the username field, junk password.
	rec := doGetBasic(e.Handler, "/service/token?service=registry&scope=repository:docker.io/library/nginx:pull", pat, "x")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if e.harbor.lastRequest().Authorization != "" {
		t.Fatal("client credentials were forwarded")
	}
}

func TestFailedLoginMasksPATShapedUsername(t *testing.T) {
	e := newEnv(t, baseGateConfig(""), nil)
	// An invalid PAT-shaped username with a wrong password: both
	// candidates fail verification; the recorded subject must be masked
	// instead of persisting the token-shaped string.
	rec := doGetBasic(e.Handler, "/service/token?service=registry", token.Prefix+"invalid", "wrong")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	rows := e.waitUsage(t, DecisionDenyBadToken, 1)
	if rows[0].Subject != "pat" {
		t.Fatalf("recorded subject = %q, want masked %q", rows[0].Subject, "pat")
	}
}
