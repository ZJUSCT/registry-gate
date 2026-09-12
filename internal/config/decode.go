package config

// decode.go maps the parsed YAML tree onto the Config struct. The schema
// is frozen (v0.3), so unknown keys are hard errors: a typo must fail at
// startup instead of silently enabling a default.

import (
	"fmt"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/httpx"
)

// section wraps a mapping node and tracks which keys were consumed so
// leftovers can be rejected.
type section struct {
	path string
	m    map[string]any
	used map[string]bool
}

func newSection(v any, path string) (*section, error) {
	if v == nil {
		return &section{path: path, m: map[string]any{}, used: map[string]bool{}}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config: %s: expected a mapping section", path)
	}
	return &section{path: path, m: m, used: map[string]bool{}}, nil
}

func (s *section) get(key string) any {
	s.used[key] = true
	return s.m[key]
}

// check fails when the section still contains unconsumed keys.
func (s *section) check() error {
	for k := range s.m {
		if !s.used[k] {
			return fmt.Errorf("config: %s: unknown key %q (schema v0.6 is frozen)", s.path, k)
		}
	}
	return nil
}

func (s *section) sub(key string) (*section, error) {
	return newSection(s.get(key), s.path+"."+key)
}

func typeErr(path string, v any, want string) error {
	return fmt.Errorf("config: %s: want %s, got %T(%v)", path, want, v, v)
}

func (s *section) str(key string) (string, error) {
	v := s.get(key)
	if v == nil {
		return "", nil
	}
	str, ok := v.(string)
	if !ok {
		return "", typeErr(s.path+"."+key, v, "string")
	}
	return str, nil
}

func (s *section) boolean(key string) (bool, error) {
	v := s.get(key)
	if v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, typeErr(s.path+"."+key, v, "bool")
	}
	return b, nil
}

func (s *section) integer(key string) (int, error) {
	v := s.get(key)
	if v == nil {
		return 0, nil
	}
	// yaml.v3 resolves integers as int; accept int64 as well.
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	default:
		return 0, typeErr(s.path+"."+key, v, "int")
	}
}

// duration reads a duration-valued string ("15s", "180d").
func (s *section) duration(key string) (time.Duration, error) {
	v := s.get(key)
	if v == nil {
		return 0, nil
	}
	str, ok := v.(string)
	if !ok {
		return 0, typeErr(s.path+"."+key, v, "duration string")
	}
	d, err := parseDurationLike(str)
	if err != nil {
		return 0, fmt.Errorf("config: %s.%s: %w", s.path, key, err)
	}
	return d, nil
}

// rate reads a rate string such as "20/min" plus offset.
func (s *section) rate(key string) (r httpx.Rate, err error) {
	v := s.get(key)
	if v == nil {
		return r, nil
	}
	str, ok := v.(string)
	if !ok {
		return r, typeErr(s.path+"."+key, v, "rate string")
	}
	r, err = httpx.ParseRate(str)
	if err != nil {
		return r, fmt.Errorf("config: %s.%s: %w", s.path, key, err)
	}
	return r, nil
}

func (s *section) strList(key string) ([]string, error) {
	v := s.get(key)
	if v == nil {
		return nil, nil
	}
	items, ok := v.([]any)
	if !ok {
		return nil, typeErr(s.path+"."+key, v, "list of strings")
	}
	out := make([]string, 0, len(items))
	for i, it := range items {
		str, ok := it.(string)
		if !ok {
			return nil, typeErr(fmt.Sprintf("%s.%s[%d]", s.path, key, i), it, "string")
		}
		out = append(out, str)
	}
	return out, nil
}

func (s *section) strMap(key string) (map[string]string, error) {
	v := s.get(key)
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, typeErr(s.path+"."+key, v, "mapping of string to string")
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		str, ok := val.(string)
		if !ok {
			return nil, typeErr(s.path+"."+key+"."+k, val, "string")
		}
		out[k] = str
	}
	return out, nil
}

// decode maps the YAML tree onto cfg with strict key checking.
func decode(root map[string]any, cfg *Config) error {
	known := map[string]bool{
		"server": true, "harbor": true, "gate": true, "whitelist": true,
		"projects": true, "auth": true, "storage": true, "portal": true,
		"admin": true, "observability": true, "log": true,
	}
	for k := range root {
		if !known[k] {
			return fmt.Errorf("config: unknown top-level key %q (schema v0.6 is frozen)", k)
		}
	}
	rootSec := &section{path: "", m: root, used: map[string]bool{}}
	if gate, ok := root["gate"].(map[string]any); ok {
		if anon, ok := gate["anonymous"].(map[string]any); ok && len(anon) > 0 {
			cfg.gateAnonConfigured = true
		}
	}

	if err := decodeServer(rootSec, &cfg.Server); err != nil {
		return err
	}
	if err := decodeHarbor(rootSec, &cfg.Harbor); err != nil {
		return err
	}
	if err := decodeGate(rootSec, &cfg.Gate); err != nil {
		return err
	}
	if err := decodeWhitelist(rootSec, &cfg.Whitelist); err != nil {
		return err
	}
	if err := decodeProjects(rootSec, &cfg.Projects); err != nil {
		return err
	}
	if err := decodeAuth(rootSec, &cfg.Auth); err != nil {
		return err
	}
	if err := decodeStorage(rootSec, &cfg.Storage); err != nil {
		return err
	}
	if err := decodePortal(rootSec, &cfg.Portal); err != nil {
		return err
	}
	if err := decodeAdmin(rootSec, &cfg.Admin); err != nil {
		return err
	}
	if err := decodeObservability(rootSec, &cfg.Observability); err != nil {
		return err
	}
	if err := decodeLog(rootSec, &cfg.Log); err != nil {
		return err
	}
	return rootSec.check()
}

func decodeServer(root *section, out *Server) error {
	s, err := root.sub("server")
	if err != nil {
		return err
	}
	if out.Listen, err = s.str("listen"); err != nil {
		return err
	}
	if out.MetricsListen, err = s.str("metrics_listen"); err != nil {
		return err
	}
	if out.ExternalURL, err = s.str("external_url"); err != nil {
		return err
	}
	if out.TrustedProxies, err = s.strList("trusted_proxies"); err != nil {
		return err
	}
	if out.RequestTimeout, err = s.duration("request_timeout"); err != nil {
		return err
	}
	return s.check()
}

func decodeHarbor(root *section, out *Harbor) error {
	s, err := root.sub("harbor")
	if err != nil {
		return err
	}
	if out.BaseURL, err = s.str("base_url"); err != nil {
		return err
	}
	if out.TokenPath, err = s.str("token_path"); err != nil {
		return err
	}
	if out.InsecureSkipVerify, err = s.boolean("insecure_skip_verify"); err != nil {
		return err
	}
	if v := s.get("service_account"); v != nil {
		sa, err := newSection(v, "harbor.service_account")
		if err != nil {
			return err
		}
		account := &HarborServiceAccount{}
		if account.Username, err = sa.str("username"); err != nil {
			return err
		}
		if account.Password, err = sa.str("password"); err != nil {
			return err
		}
		if err := sa.check(); err != nil {
			return err
		}
		out.ServiceAccount = account
	}
	return s.check()
}

func decodeGate(root *section, out *Gate) error {
	s, err := root.sub("gate")
	if err != nil {
		return err
	}
	if out.Path, err = s.str("path"); err != nil {
		return err
	}
	anon, err := s.sub("anonymous")
	if err != nil {
		return err
	}
	if out.Anonymous.Enabled, err = anon.boolean("enabled"); err != nil {
		return err
	}
	if err := anon.check(); err != nil {
		return err
	}
	if out.AnonymousRegistryScopes, err = s.str("anonymous_registry_scopes"); err != nil {
		return err
	}
	afl, err := s.sub("auth_failure_limit")
	if err != nil {
		return err
	}
	if out.AuthFailureLimit.PerIP, err = afl.rate("per_ip"); err != nil {
		return err
	}
	if out.AuthFailureLimit.PerUsername, err = afl.rate("per_username"); err != nil {
		return err
	}
	if err := afl.check(); err != nil {
		return err
	}
	if out.FailMode, err = s.str("fail_mode"); err != nil {
		return err
	}
	if out.DenyMessage, err = s.str("deny_message"); err != nil {
		return err
	}
	if out.LoginFailedMessage, err = s.str("login_failed_message"); err != nil {
		return err
	}
	return s.check()
}

func decodeWhitelist(root *section, out *Whitelist) error {
	s, err := root.sub("whitelist")
	if err != nil {
		return err
	}
	if out.Files, err = s.strList("files"); err != nil {
		return err
	}
	if out.Inline, err = s.strList("inline"); err != nil {
		return err
	}
	if out.Reload, err = s.boolean("reload"); err != nil {
		return err
	}
	return s.check()
}

func decodeProjects(root *section, out *Projects) error {
	s, err := root.sub("projects")
	if err != nil {
		return err
	}
	if out.Map, err = s.strMap("map"); err != nil {
		return err
	}
	return s.check()
}

func decodeAuth(root *section, out *Auth) error {
	s, err := root.sub("auth")
	if err != nil {
		return err
	}
	tok, err := s.sub("token")
	if err != nil {
		return err
	}
	if out.Token.Issuer, err = tok.str("issuer"); err != nil {
		return err
	}
	if out.Token.DefaultTTL, err = tok.duration("default_ttl"); err != nil {
		return err
	}
	if out.Token.MaxTTL, err = tok.duration("max_ttl"); err != nil {
		return err
	}
	if err := tok.check(); err != nil {
		return err
	}
	return s.check()
}

func decodeStorage(root *section, out *Storage) error {
	s, err := root.sub("storage")
	if err != nil {
		return err
	}
	sqlite, err := s.sub("sqlite")
	if err != nil {
		return err
	}
	if out.SqlitePath, err = sqlite.str("path"); err != nil {
		return err
	}
	if err := sqlite.check(); err != nil {
		return err
	}
	if out.UsageRetention, err = s.duration("usage_retention"); err != nil {
		return err
	}
	return s.check()
}

func decodePortal(root *section, out *Portal) error {
	s, err := root.sub("portal")
	if err != nil {
		return err
	}
	if out.Enabled, err = s.boolean("enabled"); err != nil {
		return err
	}
	if out.BasePath, err = s.str("base_path"); err != nil {
		return err
	}
	sso, err := s.sub("sso")
	if err != nil {
		return err
	}
	oidc, err := sso.sub("oidc")
	if err != nil {
		return err
	}
	if out.SSO.OIDC.Issuer, err = oidc.str("issuer"); err != nil {
		return err
	}
	if out.SSO.OIDC.ClientID, err = oidc.str("client_id"); err != nil {
		return err
	}
	if out.SSO.OIDC.ClientSecret, err = oidc.str("client_secret"); err != nil {
		return err
	}
	if out.SSO.OIDC.Scopes, err = oidc.strList("scopes"); err != nil {
		return err
	}
	if out.SSO.OIDC.RedirectURI, err = oidc.str("redirect_uri"); err != nil {
		return err
	}
	if err := oidc.check(); err != nil {
		return err
	}
	if err := sso.check(); err != nil {
		return err
	}
	if out.MaxTokensPerUser, err = s.integer("max_tokens_per_user"); err != nil {
		return err
	}
	return s.check()
}

func decodeAdmin(root *section, out *Admin) error {
	s, err := root.sub("admin")
	if err != nil {
		return err
	}
	if out.Enabled, err = s.boolean("enabled"); err != nil {
		return err
	}
	if out.BasePath, err = s.str("base_path"); err != nil {
		return err
	}
	gh, err := s.sub("github")
	if err != nil {
		return err
	}
	if out.GitHub.ClientID, err = gh.str("client_id"); err != nil {
		return err
	}
	if out.GitHub.ClientSecret, err = gh.str("client_secret"); err != nil {
		return err
	}
	if out.GitHub.AllowedUsers, err = gh.strList("allowed_users"); err != nil {
		return err
	}
	if out.GitHub.AllowedOrgs, err = gh.strList("allowed_orgs"); err != nil {
		return err
	}
	if err := gh.check(); err != nil {
		return err
	}
	return s.check()
}

func decodeLog(root *section, out *Log) error {
	s, err := root.sub("log")
	if err != nil {
		return err
	}
	if out.Level, err = s.str("level"); err != nil {
		return err
	}
	if out.Format, err = s.str("format"); err != nil {
		return err
	}
	return s.check()
}

func decodeObservability(root *section, out *Observability) error {
	s, err := root.sub("observability")
	if err != nil {
		return err
	}
	ol, err := s.sub("otel_logs")
	if err != nil {
		return err
	}
	if out.OtelLogs.Enabled, err = ol.boolean("enabled"); err != nil {
		return err
	}
	if out.OtelLogs.Endpoint, err = ol.str("endpoint"); err != nil {
		return err
	}
	if out.OtelLogs.Headers, err = ol.strMap("headers"); err != nil {
		return err
	}
	if out.OtelLogs.Timeout, err = ol.duration("timeout"); err != nil {
		return err
	}
	if out.OtelLogs.ServiceName, err = ol.str("service_name"); err != nil {
		return err
	}
	if out.OtelLogs.ServiceVersion, err = ol.str("service_version"); err != nil {
		return err
	}
	batch, err := ol.sub("batch")
	if err != nil {
		return err
	}
	if out.OtelLogs.MaxQueueSize, err = batch.integer("max_queue_size"); err != nil {
		return err
	}
	if out.OtelLogs.FlushInterval, err = batch.duration("flush_interval"); err != nil {
		return err
	}
	if err := batch.check(); err != nil {
		return err
	}
	if err := ol.check(); err != nil {
		return err
	}
	return s.check()
}
