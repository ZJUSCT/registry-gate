package store

// signkey.go manages the PAT signing key: a deployment-local Ed25519 key
// generated on first use and persisted in the secrets table, exactly like
// the session-cookie secrets. Verification always uses this key's public
// half, so no key material ever appears in the configuration.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// signKeyBlob is the JSON persisted under the "pat_signing_key" secret.
type signKeyBlob struct {
	Kid        string `json:"kid"`
	PrivateKey string `json:"private_key"` // PKCS#8 PEM
}

// GetOrCreateSignKey returns the PAT signing key, generating and storing a
// fresh Ed25519 key on first use. The kid is random; rotation (retaining
// the old public half for unexpired PATs) is a future admin operation.
func (s *SQLite) GetOrCreateSignKey() (string, ed25519.PrivateKey, error) {
	for range 2 {
		var val []byte
		err := s.db.QueryRow(`SELECT value FROM secrets WHERE name = ?`, "pat_signing_key").Scan(&val)
		switch {
		case err == nil:
			kid, priv, perr := parseSignKey(val)
			if perr != nil {
				return "", nil, fmt.Errorf("store: sign key is corrupt: %w", perr)
			}
			return kid, priv, nil
		case errors.Is(err, sql.ErrNoRows):
			_, priv, gerr := ed25519.GenerateKey(rand.Reader)
			if gerr != nil {
				return "", nil, fmt.Errorf("store: generate sign key: %w", gerr)
			}
			der, merr := x509.MarshalPKCS8PrivateKey(priv)
			if merr != nil {
				return "", nil, merr
			}
			buf := make([]byte, 4)
			if _, rerr := rand.Read(buf); rerr != nil {
				return "", nil, rerr
			}
			data, jerr := json.Marshal(signKeyBlob{
				Kid:        fmt.Sprintf("auto-%x", buf),
				PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
			})
			if jerr != nil {
				return "", nil, jerr
			}
			if _, ierr := s.db.Exec(`INSERT INTO secrets (name, value) VALUES (?, ?)
				ON CONFLICT(name) DO NOTHING`, "pat_signing_key", data); ierr != nil {
				return "", nil, fmt.Errorf("store: save sign key: %w", ierr)
			}
			// Loop: re-read (ours, or a race winner's).
		default:
			return "", nil, fmt.Errorf("store: read sign key: %w", err)
		}
	}
	return "", nil, fmt.Errorf("store: sign key: unexpected state")
}

func parseSignKey(val []byte) (string, ed25519.PrivateKey, error) {
	var blob signKeyBlob
	if err := json.Unmarshal(val, &blob); err != nil {
		return "", nil, err
	}
	if blob.Kid == "" || blob.PrivateKey == "" {
		return "", nil, errors.New("incomplete key blob")
	}
	block, _ := pem.Decode([]byte(blob.PrivateKey))
	if block == nil {
		return "", nil, errors.New("no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", nil, fmt.Errorf("got %T, want Ed25519", key)
	}
	return blob.Kid, priv, nil
}
