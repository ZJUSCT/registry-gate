// sqlite.go implements store.Store on a single SQLite database file via
// the pure-Go modernc.org/sqlite driver. WAL mode and a single pooled
// connection keep the single-writer, single-replica deployment safe.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // driver "sqlite"
)

// schema is the embedded migration applied on every Open (idempotent).
const schema = `
CREATE TABLE IF NOT EXISTS tokens (
  jti        TEXT PRIMARY KEY,
  subject    TEXT NOT NULL,
  note       TEXT NOT NULL DEFAULT '',
  issued_at  INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked_at INTEGER,
  last_used  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_tokens_subject ON tokens(subject);

CREATE TABLE IF NOT EXISTS usage (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  time     INTEGER NOT NULL,
  subject  TEXT NOT NULL,
  ip       TEXT NOT NULL DEFAULT '',
  repo     TEXT NOT NULL DEFAULT '',
  decision TEXT NOT NULL,
  rule     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_usage_time ON usage(time);
CREATE INDEX IF NOT EXISTS idx_usage_subject_time ON usage(subject, time DESC);

CREATE TABLE IF NOT EXISTS secrets (
  name  TEXT PRIMARY KEY,
  value BLOB NOT NULL
);
`

// SQLite is the sqlite-backed Store. All queries run through one pooled
// connection, which serializes writers (modernc's sqlite has no shared
// cache; this sidesteps SQLITE_BUSY entirely).
type SQLite struct {
	db *sql.DB
}

// OpenSQLite opens (creating if needed) the database at path and applies
// the schema. The parent directory is created when missing.
func OpenSQLite(path string) (*SQLite, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("store: create db dir: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping sqlite: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &SQLite{db: db}, nil
}

// Close closes the database.
func (s *SQLite) Close() error { return s.db.Close() }

// GetOrCreateSecret returns the secret stored under name, generating and
// persisting 32 random bytes on first use. It backs the session-cookie
// secrets, which are deployment-local and need no configuration; losing
// the database simply invalidates sessions.
func (s *SQLite) GetOrCreateSecret(name string) ([]byte, error) {
	for range 2 {
		var val []byte
		err := s.db.QueryRow(`SELECT value FROM secrets WHERE name = ?`, name).Scan(&val)
		switch {
		case err == nil:
			return val, nil
		case errors.Is(err, sql.ErrNoRows):
			buf := make([]byte, 32)
			if _, err := rand.Read(buf); err != nil {
				return nil, fmt.Errorf("store: generate secret: %w", err)
			}
			if _, err := s.db.Exec(`INSERT INTO secrets (name, value) VALUES (?, ?)`, name, buf); err == nil {
				return buf, nil
			}
			// Lost a concurrent insert race: fall through and re-read.
		default:
			return nil, fmt.Errorf("store: read secret %q: %w", name, err)
		}
	}
	return nil, fmt.Errorf("store: secret %q: unexpected insert conflict", name)
}

func ns(t time.Time) int64 { return t.UnixNano() }

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ns(*t)
}

// Tokens

// CreateToken inserts a token metadata row.
func (s *SQLite) CreateToken(_ context.Context, m TokenMeta) error {
	if m.JTI == "" {
		return errors.New("store: empty token id")
	}
	_, err := s.db.Exec(`INSERT INTO tokens (jti, subject, note, issued_at, expires_at, revoked_at, last_used)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		m.JTI, m.Subject, m.Note, ns(m.IssuedAt), ns(m.ExpiresAt), nullTime(m.RevokedAt), nullTime(m.LastUsed))
	return err
}

// GetToken returns one token metadata row; ErrNotFound if absent.
func (s *SQLite) GetToken(_ context.Context, jti string) (TokenMeta, error) {
	metas, err := s.queryTokens(`SELECT jti, subject, note, issued_at, expires_at, revoked_at, last_used
		FROM tokens WHERE jti = ?`, jti)
	if err != nil {
		return TokenMeta{}, err
	}
	if len(metas) == 0 {
		return TokenMeta{}, ErrNotFound
	}
	return metas[0], nil
}

// ListTokensBySubject returns the subject's tokens, newest first.
func (s *SQLite) ListTokensBySubject(_ context.Context, subject string) ([]TokenMeta, error) {
	return s.queryTokens(`SELECT jti, subject, note, issued_at, expires_at, revoked_at, last_used
		FROM tokens WHERE subject = ? ORDER BY issued_at DESC, jti`, subject)
}

// ListAllTokens returns every token, newest first.
func (s *SQLite) ListAllTokens(_ context.Context) ([]TokenMeta, error) {
	return s.queryTokens(`SELECT jti, subject, note, issued_at, expires_at, revoked_at, last_used
		FROM tokens ORDER BY issued_at DESC, jti`)
}

func (s *SQLite) queryTokens(query string, args ...any) ([]TokenMeta, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenMeta
	for rows.Next() {
		var m TokenMeta
		var issued, expires int64
		var revoked, lastUsed sql.NullInt64
		if err := rows.Scan(&m.JTI, &m.Subject, &m.Note, &issued, &expires, &revoked, &lastUsed); err != nil {
			return nil, err
		}
		m.IssuedAt = time.Unix(0, issued)
		m.ExpiresAt = time.Unix(0, expires)
		if revoked.Valid {
			t := time.Unix(0, revoked.Int64)
			m.RevokedAt = &t
		}
		if lastUsed.Valid {
			t := time.Unix(0, lastUsed.Int64)
			m.LastUsed = &t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CountActiveBySubject counts the subject's non-revoked, unexpired tokens.
func (s *SQLite) CountActiveBySubject(_ context.Context, subject string, now time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens
		WHERE subject = ? AND revoked_at IS NULL AND expires_at > ?`, subject, ns(now)).Scan(&n)
	return n, err
}

// RevokeToken marks a token revoked; ErrNotFound if absent.
func (s *SQLite) RevokeToken(_ context.Context, jti string, at time.Time) error {
	res, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE jti = ?`, ns(at), jti)
	if err != nil {
		return err
	}
	return rowsAffected(res, ErrNotFound)
}

// RevokeAllBySubject revokes all of the subject's tokens and returns how
// many were newly revoked.
func (s *SQLite) RevokeAllBySubject(_ context.Context, subject string, at time.Time) (int64, error) {
	res, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE subject = ? AND revoked_at IS NULL`, ns(at), subject)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// MarkUsed stamps a token's last-used time; ErrNotFound if absent.
func (s *SQLite) MarkUsed(_ context.Context, jti string, at time.Time) error {
	res, err := s.db.Exec(`UPDATE tokens SET last_used = ? WHERE jti = ?`, ns(at), jti)
	if err != nil {
		return err
	}
	return rowsAffected(res, ErrNotFound)
}

func rowsAffected(res sql.Result, notFound error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound
	}
	return nil
}

// Usage

// InsertUsage appends one decision record.
func (s *SQLite) InsertUsage(_ context.Context, r UsageRecord) error {
	_, err := s.db.Exec(`INSERT INTO usage (time, subject, ip, repo, decision, rule)
		VALUES (?, ?, ?, ?, ?, ?)`, ns(r.Time), r.Subject, r.IP, r.Repo, r.Decision, r.Rule)
	return err
}

// ListUsageBySubject returns the subject's newest records.
func (s *SQLite) ListUsageBySubject(_ context.Context, subject string, limit int) ([]UsageRecord, error) {
	return s.queryUsage(`SELECT time, subject, ip, repo, decision, rule FROM usage
		WHERE subject = ? ORDER BY id DESC LIMIT ?`, subject, limit)
}

// ListUsage returns records newest first with offset paging.
func (s *SQLite) ListUsage(_ context.Context, limit, offset int) ([]UsageRecord, error) {
	return s.queryUsage(`SELECT time, subject, ip, repo, decision, rule FROM usage
		ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
}

func (s *SQLite) queryUsage(query string, args ...any) ([]UsageRecord, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UsageRecord
	for rows.Next() {
		var r UsageRecord
		var t int64
		if err := rows.Scan(&t, &r.Subject, &r.IP, &r.Repo, &r.Decision, &r.Rule); err != nil {
			return nil, err
		}
		r.Time = time.Unix(0, t)
		out = append(out, r)
	}
	return out, rows.Err()
}

// UsageSummary returns decision -> count for records at or after since.
func (s *SQLite) UsageSummary(_ context.Context, since time.Time) (map[string]int64, error) {
	rows, err := s.db.Query(`SELECT decision, COUNT(*) FROM usage WHERE time >= ? GROUP BY decision`, ns(since))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var d string
		var n int64
		if err := rows.Scan(&d, &n); err != nil {
			return nil, err
		}
		out[d] = n
	}
	return out, rows.Err()
}

// PruneUsage deletes usage records strictly older than the cutoff.
func (s *SQLite) PruneUsage(_ context.Context, before time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM usage WHERE time < ?`, ns(before))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Compile-time check that SQLite satisfies Store.
var _ Store = (*SQLite)(nil)
