package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseYAMLBasics(t *testing.T) {
	doc := `
# top comment
server:
  listen: "0.0.0.0:8080"          # trailing comment
  external_url: https://example.org
  trusted_proxies: ["10.0.0.0/8", "fd00::/8"]
  empty_list: []
  flag: true
  count: 42
  nothing:
keys:
  - kid: "a"
    private_key: /keys/a.pem
  - kid: "b"
    public_key: /keys/b.pub
seq:
- one
- two
nested:
  deeper:
    value: "x # not a comment"
`
	root, err := parseYAML([]byte(doc))
	if err != nil {
		t.Fatalf("parseYAML: %v", err)
	}
	srv := root["server"].(map[string]any)
	if srv["listen"] != "0.0.0.0:8080" {
		t.Errorf("listen = %v", srv["listen"])
	}
	if srv["external_url"] != "https://example.org" {
		t.Errorf("unquoted url = %v", srv["external_url"])
	}
	tp := srv["trusted_proxies"].([]any)
	if len(tp) != 2 || tp[0] != "10.0.0.0/8" || tp[1] != "fd00::/8" {
		t.Errorf("trusted_proxies = %v", tp)
	}
	if el := srv["empty_list"].([]any); len(el) != 0 {
		t.Errorf("empty_list = %v", el)
	}
	if srv["flag"] != true || srv["count"] != any(42) {
		t.Errorf("flag/count = %v/%v", srv["flag"], srv["count"])
	}
	if v, ok := srv["nothing"]; v != nil || !ok {
		t.Errorf("nothing = %v (%v)", v, ok)
	}
	keys := root["keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("keys len = %d", len(keys))
	}
	k0 := keys[0].(map[string]any)
	if k0["kid"] != "a" || k0["private_key"] != "/keys/a.pem" {
		t.Errorf("keys[0] = %v", k0)
	}
	k1 := keys[1].(map[string]any)
	if k1["public_key"] != "/keys/b.pub" {
		t.Errorf("keys[1] = %v", k1)
	}
	seq := root["seq"].([]any)
	if len(seq) != 2 || seq[0] != "one" || seq[1] != "two" {
		t.Errorf("seq = %v", seq)
	}
	nested := root["nested"].(map[string]any)["deeper"].(map[string]any)
	if nested["value"] != "x # not a comment" {
		t.Errorf("quoted # = %q", nested["value"])
	}
}

func TestParseYAMLErrors(t *testing.T) {
	for _, doc := range []string{
		"key: value\nkey: again\n", // duplicate key
		"a:\n\tb: 1\n",             // tab indent
		"a: [1, 2\n",               // unterminated flow
		"just a scalar\n",          // root not a mapping
		"a: \"unterminated\n",      // bad quote
		"a:\n  b: 1\n c: 2\n",      // ragged indent
		"a: 1\n  b: 2\n",           // unexpected indent
	} {
		if _, err := parseYAML([]byte(doc)); err == nil {
			t.Errorf("parseYAML(%q) accepted", doc)
		}
	}
}

func TestParseDurationLike(t *testing.T) {
	tests := []struct {
		in       string
		want     time.Duration
		wantFail bool
	}{
		{"15s", 15 * time.Second, false},
		{"1m", time.Minute, false},
		{"12h", 12 * time.Hour, false},
		{"180d", 180 * 24 * time.Hour, false},
		{"90d", 90 * 24 * time.Hour, false},
		{"1h30m", 90 * time.Minute, false},
		{"2d6h", 54 * time.Hour, false},
		{"1.5h", 90 * time.Minute, false},
		{"", 0, true},
		{"10", 0, true},
		{"5x", 0, true},
		{"d", 0, true},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		got, err := parseDurationLike(tt.in)
		if tt.wantFail {
			if err == nil {
				t.Errorf("parseDurationLike(%q) accepted", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDurationLike(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseDurationLike(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// materializeExample copies config.example.yaml into a temp file with all
// ${ENV} references satisfied via t.Setenv so the full Load path succeeds.
func materializeExample(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	raw, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HARBOR_SERVICE_ACCOUNT_PASSWORD", "robot-password")
	t.Setenv("GATE_GITLAB_CLIENT_SECRET", strings.Repeat("g", 32))
	t.Setenv("GATE_GITHUB_CLIENT_SECRET", strings.Repeat("h", 32))
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load(materializeExample(t))
	if err != nil {
		t.Fatalf("Load example config: %v", err)
	}

	if cfg.Server.Listen != "0.0.0.0:8080" || cfg.Server.MetricsListen != "0.0.0.0:9090" {
		t.Errorf("server = %+v", cfg.Server)
	}
	if cfg.Server.ExternalURL != "https://registry.mirrors.zjusct.io" {
		t.Errorf("external_url = %q", cfg.Server.ExternalURL)
	}
	if len(cfg.Server.TrustedProxies) != 2 || cfg.Server.RequestTimeout != 15*time.Second {
		t.Errorf("server extras = %+v", cfg.Server)
	}
	if cfg.Harbor.BaseURL != "https://harbor.mirrors.zjusct.io" || cfg.Harbor.TokenPath != "/service/token" {
		t.Errorf("harbor = %+v", cfg.Harbor)
	}
	if cfg.Harbor.ServiceAccount != nil {
		t.Errorf("service_account should be commented out")
	}
	if cfg.Gate.Path != "/service/token" || !cfg.Gate.Anonymous.Enabled || cfg.Gate.AnonymousRegistryScopes != "deny" || cfg.Gate.FailMode != "closed" {
		t.Errorf("gate = %+v", cfg.Gate)
	}
	if cfg.Gate.AuthFailureLimit.PerIP.Count != 20 || cfg.Gate.AuthFailureLimit.PerIP.Window != time.Minute {
		t.Errorf("per_ip = %+v", cfg.Gate.AuthFailureLimit.PerIP)
	}
	if cfg.Gate.AuthFailureLimit.PerUsername.Count != 10 {
		t.Errorf("per_username = %+v", cfg.Gate.AuthFailureLimit.PerUsername)
	}
	if len(cfg.Whitelist.Files) != 2 || cfg.Whitelist.Reload != true {
		t.Errorf("whitelist = %+v", cfg.Whitelist)
	}
	if len(cfg.Projects.Map) != 16 {
		t.Errorf("projects.map len = %d, want 16", len(cfg.Projects.Map))
	}
	if cfg.Projects.Map["hub.docker.com"] != "docker.io" {
		t.Errorf("alias mapping = %q", cfg.Projects.Map["hub.docker.com"])
	}
	if cfg.Auth.Token.Issuer != "zju-mirror" {
		t.Errorf("issuer = %q", cfg.Auth.Token.Issuer)
	}
	if cfg.Auth.Token.DefaultTTL != 180*24*time.Hour || cfg.Auth.Token.MaxTTL != 365*24*time.Hour {
		t.Errorf("ttls = %v/%v", cfg.Auth.Token.DefaultTTL, cfg.Auth.Token.MaxTTL)
	}
	if !cfg.Portal.Enabled || cfg.Portal.BasePath != "/token" || cfg.Portal.MaxTokensPerUser != 10 {
		t.Errorf("portal = %+v", cfg.Portal)
	}
	if cfg.Portal.SSO.OIDC.ClientSecret == "" {
		t.Errorf("portal client secret not substituted")
	}
	if !cfg.Admin.Enabled || cfg.Admin.BasePath != "/admin" {
		t.Errorf("admin = %+v", cfg.Admin)
	}
	if len(cfg.Admin.GitHub.AllowedOrgs) != 1 || cfg.Admin.GitHub.AllowedOrgs[0] != "ZJUSCT" {
		t.Errorf("allowed_orgs = %v", cfg.Admin.GitHub.AllowedOrgs)
	}
	if cfg.Admin.GitHub.ClientSecret == "" {
		t.Errorf("admin client secret not substituted")
	}
	if cfg.Log.Level != "info" || cfg.Log.Format != "json" {
		t.Errorf("log = %+v", cfg.Log)
	}
	if cfg.Storage.UsageRetention != 90*24*time.Hour {
		t.Errorf("usage_retention = %v", cfg.Storage.UsageRetention)
	}
	want := "https://registry.mirrors.zjusct.io/token"
	if got := cfg.PortalURL(); got != want {
		t.Errorf("PortalURL = %q, want %q", got, want)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimalConfig = `
server:
  listen: "127.0.0.1:8080"
  external_url: "https://registry.example.org"
harbor:
  base_url: "http://harbor.internal"
  token_path: "/service/token"
projects:
  map:
    docker.io: docker.io
auth:
  token:
    issuer: "test"
storage:
  sqlite:
    path: "/tmp/gate.db"
`

func TestLoadMinimalAppliesDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatalf("Load minimal: %v", err)
	}
	if cfg.Server.MetricsListen != "0.0.0.0:9090" || cfg.Server.RequestTimeout != 15*time.Second {
		t.Errorf("server defaults = %+v", cfg.Server)
	}
	if cfg.Gate.Path != "/service/token" || !cfg.Gate.Anonymous.Enabled {
		t.Errorf("gate defaults = %+v", cfg.Gate)
	}
	if cfg.Gate.AnonymousRegistryScopes != "deny" || cfg.Gate.FailMode != "closed" {
		t.Errorf("gate enum defaults = %+v", cfg.Gate)
	}
	if cfg.Gate.AuthFailureLimit.PerIP.Count != 20 || cfg.Gate.AuthFailureLimit.PerUsername.Count != 10 {
		t.Errorf("limit defaults = %+v", cfg.Gate.AuthFailureLimit)
	}
	if cfg.Storage.UsageRetention != 90*24*time.Hour {
		t.Errorf("retention default = %v", cfg.Storage.UsageRetention)
	}
	if !strings.Contains(cfg.Gate.DenyMessage, "{portal_url}") {
		t.Errorf("deny message default = %q", cfg.Gate.DenyMessage)
	}
	if cfg.Portal.BasePath != "/token" || cfg.Admin.BasePath != "/admin" {
		t.Errorf("base path defaults = %q %q", cfg.Portal.BasePath, cfg.Admin.BasePath)
	}
	if cfg.Log.Level != "info" || cfg.Log.Format != "json" {
		t.Errorf("log defaults = %+v", cfg.Log)
	}
}

func TestLoadValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		mut  func(s string) string
	}{
		{"no projects", func(s string) string {
			return strings.Replace(s, "projects:\n  map:\n    docker.io: docker.io\n", "", 1)
		}},
		{"unknown top key", func(s string) string { return s + "\nextra: 1\n" }},
		{"unknown nested key", func(s string) string {
			return strings.Replace(s, "harbor:\n", "harbor:\n  oops: 1\n", 1)
		}},
		{"bad external_url", func(s string) string {
			return strings.Replace(s, "https://registry.example.org", "not-a-url", 1)
		}},
		{"bad fail_mode", func(s string) string { return s + "\ngate:\n  fail_mode: open\n" }},
		{"bad scopes policy", func(s string) string { return s + "\ngate:\n  anonymous_registry_scopes: allow\n" }},
		{"bad trusted proxy", func(s string) string { return s + "\nserver:\n  trusted_proxies: [\"10.0.0.0/64\"]\n" }},
		{"bad log level", func(s string) string { return s + "\nlog:\n  level: verbose\n" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, tt.mut(minimalConfig))); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestLoadTTLValidation(t *testing.T) {
	bad := strings.Replace(minimalConfig, `    issuer: "test"`, `    issuer: "test"
    default_ttl: 400d
    max_ttl: 100d`, 1)
	if _, err := Load(writeConfig(t, bad)); err == nil {
		t.Fatal("default_ttl > max_ttl accepted")
	}
}

func TestLoadUnsetEnvRef(t *testing.T) {
	bad := strings.Replace(minimalConfig, "listen: \"127.0.0.1:8080\"", "listen: \"${GATE_TEST_DEFINITELY_UNSET}:8080\"", 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "GATE_TEST_DEFINITELY_UNSET") {
		t.Fatalf("unset env ref accepted: %v", err)
	}
}

func TestLoadEnvSubstitution(t *testing.T) {
	t.Setenv("GATE_TEST_PORT", "19999")
	t.Setenv("GATE_TEST_HOST", "harbor.internal")
	t.Setenv("GATE_TEST_REPO", "docker.io/library/nginx")
	body := strings.Replace(minimalConfig, "listen: \"127.0.0.1:8080\"", "listen: \"127.0.0.1:${GATE_TEST_PORT}\"", 1)
	body = strings.Replace(body, "base_url: \"http://harbor.internal\"", "base_url: \"http://${GATE_TEST_HOST}\"", 1)
	body += "whitelist:\n  inline:\n    - \"${GATE_TEST_REPO}\"\n"
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:19999" {
		t.Errorf("listen = %q", cfg.Server.Listen)
	}
	if cfg.Harbor.BaseURL != "http://harbor.internal" {
		t.Errorf("base_url = %q", cfg.Harbor.BaseURL)
	}
	if len(cfg.Whitelist.Inline) != 1 || cfg.Whitelist.Inline[0] != "docker.io/library/nginx" {
		t.Errorf("inline = %v", cfg.Whitelist.Inline)
	}
}

func TestLoadEnabledPortalRequiresSSO(t *testing.T) {
	body := minimalConfig + "\nportal:\n  enabled: true\n  base_path: /token\n"
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("enabled portal without oidc issuer/client accepted")
	}
}

func TestExpandMessage(t *testing.T) {
	got := ExpandMessage("go to {portal_url} then docker login {external_url}", "https://x/token", "https://x")
	want := "go to https://x/token then docker login https://x"
	if got != want {
		t.Fatalf("ExpandMessage = %q", got)
	}
}

func TestAnonymousEnabledDefault(t *testing.T) {
	tests := []struct {
		name  string
		extra string
		want  bool
	}{
		{"no gate section", "", true},
		{"gate section, no anonymous", "\ngate:\n  path: /service/token\n", true},
		{"anonymous enabled explicitly", "\ngate:\n  anonymous:\n    enabled: true\n", true},
		{"anonymous disabled explicitly", "\ngate:\n  anonymous:\n    enabled: false\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Load(writeConfig(t, minimalConfig+tt.extra))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Gate.Anonymous.Enabled != tt.want {
				t.Fatalf("anonymous.enabled = %v, want %v", cfg.Gate.Anonymous.Enabled, tt.want)
			}
		})
	}
}
