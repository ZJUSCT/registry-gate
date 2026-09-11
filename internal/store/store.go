// Package store defines the persistence contract of registry-gate.
// The sqlite implementation lives in store/sqlite.go (backend); portal/admin tests
// use in-memory fakes implementing this interface.
package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a token record does not exist.
var ErrNotFound = errors.New("store: not found")

// TokenMeta is the metadata row for an issued PAT. JTI equals the JWT id.
type TokenMeta struct {
	JTI       string
	Subject   string // campus username (portal) or github login (never: admin doesn't issue)
	Note      string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
	LastUsed  *time.Time
}

// Active reports whether the token is currently usable (not revoked, not expired).
func (m TokenMeta) Active(now time.Time) bool {
	return m.RevokedAt == nil && now.Before(m.ExpiresAt)
}

// UsageRecord is one gate decision. Written for every decision, anonymous included.
type UsageRecord struct {
	Time     time.Time
	Subject  string // "anonymous" or PAT subject
	IP       string
	Repo     string // repository scope name ("" for scopeless probes)
	Decision string // allow_anon_by_rule|allow_authed|allow_login_probe|deny_not_whitelisted|deny_bad_token|deny_no_upstream|deny_anon_disabled|deny_registry_scope
	Rule     string // whitelist line hit (anonymous allow), "" otherwise
}

// Store is the persistence interface. Implementations must be safe for concurrent use.
type Store interface {
	// Tokens
	CreateToken(ctx context.Context, m TokenMeta) error
	GetToken(ctx context.Context, jti string) (TokenMeta, error) // ErrNotFound if absent
	ListTokensBySubject(ctx context.Context, subject string) ([]TokenMeta, error)
	ListAllTokens(ctx context.Context) ([]TokenMeta, error)
	CountActiveBySubject(ctx context.Context, subject string, now time.Time) (int64, error)
	RevokeToken(ctx context.Context, jti string, at time.Time) error
	RevokeAllBySubject(ctx context.Context, subject string, at time.Time) (int64, error)
	MarkUsed(ctx context.Context, jti string, at time.Time) error

	// Usage
	InsertUsage(ctx context.Context, r UsageRecord) error
	ListUsageBySubject(ctx context.Context, subject string, limit int) ([]UsageRecord, error)
	ListUsage(ctx context.Context, limit, offset int) ([]UsageRecord, error)
	UsageSummary(ctx context.Context, since time.Time) (map[string]int64, error) // decision -> count
	PruneUsage(ctx context.Context, before time.Time) (int64, error)
}
