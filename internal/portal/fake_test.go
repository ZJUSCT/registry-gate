package portal

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/session"
	"github.com/ZJUSCT/registry-gate/internal/store"
)

// fakeStore is an in-memory store.Store for tests.
type fakeStore struct {
	mu     sync.Mutex
	tokens map[string]store.TokenMeta
	usage  []store.UsageRecord
}

func newFakeStore() *fakeStore {
	return &fakeStore{tokens: map[string]store.TokenMeta{}}
}

func (f *fakeStore) CreateToken(_ context.Context, m store.TokenMeta) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens[m.JTI] = m
	return nil
}

func (f *fakeStore) GetToken(_ context.Context, jti string) (store.TokenMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.tokens[jti]
	if !ok {
		return store.TokenMeta{}, store.ErrNotFound
	}
	return m, nil
}

func (f *fakeStore) ListTokensBySubject(_ context.Context, subject string) ([]store.TokenMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.TokenMeta
	for _, m := range f.tokens {
		if m.Subject == subject {
			out = append(out, m)
		}
	}
	sortMetas(out)
	return out, nil
}

func (f *fakeStore) ListAllTokens(_ context.Context) ([]store.TokenMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]store.TokenMeta, 0, len(f.tokens))
	for _, m := range f.tokens {
		out = append(out, m)
	}
	sortMetas(out)
	return out, nil
}

func (f *fakeStore) CountActiveBySubject(_ context.Context, subject string, now time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, m := range f.tokens {
		if m.Subject == subject && m.Active(now) {
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) RevokeToken(_ context.Context, jti string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.tokens[jti]
	if !ok {
		return store.ErrNotFound
	}
	if m.RevokedAt == nil {
		m.RevokedAt = &at
		f.tokens[jti] = m
	}
	return nil
}

func (f *fakeStore) RevokeAllBySubject(_ context.Context, subject string, at time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for jti, m := range f.tokens {
		if m.Subject == subject {
			if m.RevokedAt == nil {
				m.RevokedAt = &at
				f.tokens[jti] = m
			}
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) MarkUsed(_ context.Context, jti string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.tokens[jti]
	if !ok {
		return store.ErrNotFound
	}
	used := at
	m.LastUsed = &used
	f.tokens[jti] = m
	return nil
}

func (f *fakeStore) InsertUsage(_ context.Context, r store.UsageRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usage = append(f.usage, r)
	return nil
}

func (f *fakeStore) ListUsageBySubject(_ context.Context, subject string, limit int) ([]store.UsageRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.UsageRecord
	for i := len(f.usage) - 1; i >= 0 && len(out) < limit; i-- {
		if f.usage[i].Subject == subject {
			out = append(out, f.usage[i])
		}
	}
	return out, nil
}

func (f *fakeStore) ListUsage(_ context.Context, limit, offset int) ([]store.UsageRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.UsageRecord
	for i := len(f.usage) - 1; i >= 0; i-- {
		rec := f.usage[i]
		if offset > 0 {
			offset--
			continue
		}
		if len(out) == limit {
			break
		}
		out = append(out, rec)
	}
	return out, nil
}

func (f *fakeStore) UsageSummary(_ context.Context, since time.Time) (map[string]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int64{}
	for _, rec := range f.usage {
		if !rec.Time.Before(since) {
			out[rec.Decision]++
		}
	}
	return out, nil
}

func (f *fakeStore) PruneUsage(_ context.Context, before time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kept := f.usage[:0]
	var n int64
	for _, rec := range f.usage {
		if rec.Time.Before(before) {
			n++
		} else {
			kept = append(kept, rec)
		}
	}
	f.usage = kept
	return n, nil
}

func sortMetas(ms []store.TokenMeta) {
	sort.Slice(ms, func(i, j int) bool { return ms[i].IssuedAt.After(ms[j].IssuedAt) })
}

// issueDirect seeds a token row bypassing the HTTP flow.
func (f *fakeStore) issueDirect(t *testing.T, subject, note string, ttl time.Duration) store.TokenMeta {
	t.Helper()
	now := time.Now().UTC()
	m := store.TokenMeta{
		JTI:       "jti-" + subject,
		Subject:   subject,
		Note:      note,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
	if err := f.CreateToken(t.Context(), m); err != nil {
		t.Fatal(err)
	}
	return m
}

// testClient drives the handler directly, carrying cookies between requests
// (httptest is plain HTTP, so Secure cookies are attached by hand).
type testClient struct {
	t       *testing.T
	handler http.Handler
	cookies map[string]*http.Cookie
}

func newTestClient(t *testing.T, h http.Handler) *testClient {
	return &testClient{t: t, handler: h, cookies: map[string]*http.Cookie{}}
}

// do performs one request and returns status, headers and body. No redirect
// following: tests call do again with the Location.
func (c *testClient) do(method, target, body string) (int, http.Header, string) {
	c.t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rdr)
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	resp := rec.Result()
	for _, ck := range resp.Cookies() {
		c.cookies[ck.Name] = ck
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header, string(data)
}

func (c *testClient) get(target string) (int, http.Header, string) {
	return c.do(http.MethodGet, target, "")
}

func (c *testClient) post(target, form string) (int, http.Header, string) {
	return c.do(http.MethodPost, target, form)
}

// loginAs installs a portal session cookie for subject.
func (c *testClient) loginAs(sess *session.Store, subject string) {
	c.t.Helper()
	rec := httptest.NewRecorder()
	sess.Set(rec, session.NewSession(map[string]string{"sub": subject, "idp": "gitlab"}))
	for _, ck := range rec.Result().Cookies() {
		c.cookies[ck.Name] = ck
	}
}

// quietLogger discards log output.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
