package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *SQLite {
	t.Helper()
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func meta(jti, subject string, issued, expires time.Time) TokenMeta {
	return TokenMeta{JTI: jti, Subject: subject, IssuedAt: issued, ExpiresAt: expires}
}

func TestTokenCRUD(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now()
	base := now.Add(-time.Hour)

	if err := s.CreateToken(ctx, meta("a", "alice", base, now.Add(24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, meta("b", "alice", base.Add(time.Minute), now.Add(48*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, meta("c", "bob", base.Add(time.Second), now.Add(24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken(ctx, meta("a", "alice", base, now)); err == nil {
		t.Fatal("duplicate token accepted")
	}

	got, err := s.GetToken(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "alice" || got.RevokedAt != nil {
		t.Fatalf("GetToken = %+v", got)
	}
	if _, err := s.GetToken(ctx, "zz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetToken(zz) = %v, want ErrNotFound", err)
	}

	n, err := s.CountActiveBySubject(ctx, "alice", now)
	if err != nil || n != 2 {
		t.Fatalf("CountActive(alice) = %d, %v; want 2", n, err)
	}

	// Sorted newest-first.
	list, err := s.ListTokensBySubject(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].JTI != "b" {
		t.Fatalf("ListTokensBySubject = %+v", list)
	}
	all, err := s.ListAllTokens(ctx)
	if err != nil || len(all) != 3 {
		t.Fatalf("ListAllTokens = %d, %v", len(all), err)
	}

	if err := s.RevokeToken(ctx, "b", now); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(ctx, "zz", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RevokeToken(zz) = %v, want ErrNotFound", err)
	}
	n, _ = s.CountActiveBySubject(ctx, "alice", now)
	if n != 1 {
		t.Fatalf("CountActive after revoke = %d, want 1", n)
	}

	if err := s.MarkUsed(ctx, "a", now); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkUsed(ctx, "zz", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MarkUsed(zz) = %v, want ErrNotFound", err)
	}
	got, _ = s.GetToken(ctx, "a")
	if got.LastUsed == nil || !got.LastUsed.Equal(now) {
		t.Fatalf("LastUsed = %v", got.LastUsed)
	}

	if n, err := s.RevokeAllBySubject(ctx, "alice", now); err != nil || n != 1 {
		t.Fatalf("RevokeAll = %d, %v; want 1 (b already revoked)", n, err)
	}
	n, _ = s.CountActiveBySubject(ctx, "alice", now)
	if n != 0 {
		t.Fatalf("CountActive after revoke-all = %d", n)
	}
}

func TestUsageLifecycle(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	base := time.Now().Add(-time.Hour)

	subjects := []string{"anonymous", "alice", "bob"}
	decisions := []string{"allow_anon_by_rule", "allow_authed", "deny_not_whitelisted"}
	for i := 0; i < 30; i++ {
		r := UsageRecord{
			Time:     base.Add(time.Duration(i) * time.Minute),
			Subject:  subjects[i%3],
			IP:       "192.0.2.1",
			Repo:     "docker.io/library/nginx",
			Decision: decisions[i%3],
		}
		if err := s.InsertUsage(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	// Newest first.
	got, err := s.ListUsage(ctx, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("len = %d", len(got))
	}
	if !got[0].Time.After(got[4].Time) {
		t.Fatalf("not newest-first: %v then %v", got[0].Time, got[4].Time)
	}
	// Offset paging.
	page2, _ := s.ListUsage(ctx, 5, 5)
	if len(page2) != 5 {
		t.Fatalf("offset page len = %d", len(page2))
	}
	if !page2[0].Time.Equal(got[4].Time.Add(-time.Minute)) {
		t.Fatalf("offset paging broken: %v after %v", page2[0].Time, got[4].Time)
	}
	if over, _ := s.ListUsage(ctx, 5, 1000); len(over) != 0 {
		t.Fatalf("offset beyond end = %d", len(over))
	}

	alice, err := s.ListUsageBySubject(ctx, "alice", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(alice) != 10 {
		t.Fatalf("alice usage = %d, want 10", len(alice))
	}
	for _, r := range alice {
		if r.Subject != "alice" {
			t.Fatalf("foreign record %+v", r)
		}
	}

	summary, err := s.UsageSummary(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if summary["allow_anon_by_rule"] != 10 || summary["allow_authed"] != 10 || summary["deny_not_whitelisted"] != 10 {
		t.Fatalf("summary = %v", summary)
	}
}

func TestPruneUsage(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	base := time.Now()

	old := UsageRecord{Time: base.Add(-48 * time.Hour), Subject: "anonymous", Decision: "deny_not_whitelisted"}
	keep1 := UsageRecord{Time: base.Add(-2 * time.Hour), Subject: "alice", Decision: "allow_authed", Repo: "ghcr.io/x/y"}
	keep2 := UsageRecord{Time: base, Subject: "bob", Decision: "allow_login_probe"}
	for _, r := range []UsageRecord{old, keep1, keep2} {
		if err := s.InsertUsage(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	n, err := s.PruneUsage(ctx, base.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned = %d, want 1", n)
	}
	got, _ := s.ListUsage(ctx, 100, 0)
	if len(got) != 2 || got[1].Subject != "alice" || got[0].Subject != "bob" {
		t.Fatalf("after prune = %+v", got)
	}
	summary, _ := s.UsageSummary(ctx, base.Add(-24*time.Hour))
	if len(summary) != 2 || summary["deny_not_whitelisted"] != 0 {
		t.Fatalf("summary after prune = %v", summary)
	}

	// Inserts continue after pruning.
	if err := s.InsertUsage(ctx, UsageRecord{Time: base.Add(time.Minute), Subject: "carol", Decision: "allow_anon_by_rule", Repo: "quay.io/a"}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ListUsage(ctx, 100, 0)
	if len(got) != 3 {
		t.Fatalf("after post-prune insert = %+v", got)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gate.db")
	ctx := context.Background()
	now := time.Now()

	s1, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s1.CreateToken(ctx, meta("a", "alice", now, now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := s1.MarkUsed(ctx, "a", now); err != nil {
		t.Fatal(err)
	}
	if err := s1.InsertUsage(ctx, UsageRecord{Time: now, Subject: "alice", Decision: "allow_authed", Repo: "docker.io/x"}); err != nil {
		t.Fatal(err)
	}
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	m, err := s2.GetToken(ctx, "a")
	if err != nil {
		t.Fatal(err)
	}
	if m.LastUsed == nil || !m.LastUsed.Equal(now) {
		t.Fatalf("LastUsed not persisted: %+v", m)
	}
	got, _ := s2.ListUsage(ctx, 10, 0)
	if len(got) != 1 || got[0].Decision != "allow_authed" {
		t.Fatalf("usage not persisted: %+v", got)
	}
	summary, _ := s2.UsageSummary(ctx, now.Add(-time.Minute))
	if summary["allow_authed"] != 1 {
		t.Fatalf("summary not persisted: %v", summary)
	}
}

func TestOpenCreatesMissingDir(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenSQLite(filepath.Join(dir, "nested", "deep", "gate.db")); err != nil {
		t.Fatalf("nested dir: %v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			jti := string(rune('a' + i))
			_ = s.CreateToken(ctx, meta(jti, "user", time.Now(), time.Now().Add(time.Hour)))
			_ = s.MarkUsed(ctx, jti, time.Now())
			_ = s.InsertUsage(ctx, UsageRecord{Time: time.Now(), Subject: "user", Decision: "allow_authed"})
			_, _ = s.ListUsage(ctx, 10, 0)
			_, _ = s.ListAllTokens(ctx)
		}(i)
	}
	wg.Wait()
	all, _ := s.ListAllTokens(ctx)
	if len(all) != 8 {
		t.Fatalf("tokens = %d, want 8", len(all))
	}
}

func TestGetOrCreateSecret(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	a1, err := s.GetOrCreateSecret("portal_session_key")
	if err != nil {
		t.Fatal(err)
	}
	if len(a1) != 32 {
		t.Fatalf("generated secret len = %d, want 32", len(a1))
	}
	a2, err := s.GetOrCreateSecret("portal_session_key")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a1, a2) {
		t.Fatal("secret not stable across calls")
	}
	b, err := s.GetOrCreateSecret("admin_session_key")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a1, b) {
		t.Fatal("different names returned the same secret")
	}
}

func TestGetOrCreateSignKey(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	kid1, priv1, err := s.GetOrCreateSignKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kid1, "auto-") || len(priv1) != ed25519.PrivateKeySize {
		t.Fatalf("kid=%q privlen=%d", kid1, len(priv1))
	}
	kid2, priv2, err := s.GetOrCreateSignKey()
	if err != nil {
		t.Fatal(err)
	}
	if kid1 != kid2 || !priv1.Equal(priv2) {
		t.Fatal("sign key not stable across calls")
	}
}
