// Package config loads, validates and defaults the registry-gate
// configuration (frozen schema v0.5, see config.example.yaml). Parsing
// happens once at startup; there is no hot reload of the config itself.
//
// OAuth client secrets are configured inline; every string value may
// reference environment variables with ${NAME} (whole-value or embedded;
// unset variables are a startup error), which is how secrets are injected
// on Kubernetes. Everything key-like (PAT signing key, session-cookie
// secrets) is not configured at all: generated on first start and stored
// in the sqlite database.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ZJUSCT/registry-gate/internal/httpx"
)

// envRef matches an environment variable reference inside a config string.
var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// expandEnv substitutes ${NAME} references in every string of the parsed
// tree and returns the rewritten subtree. A referenced variable that is
// not set is an error: silently substituting an empty string would turn
// a missing secret into an empty credential.
func expandEnv(v any, path string) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			nv, err := expandEnv(val, path+"."+k)
			if err != nil {
				return nil, err
			}
			t[k] = nv
		}
		return t, nil
	case []any:
		for i, val := range t {
			nv, err := expandEnv(val, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, err
			}
			t[i] = nv
		}
		return t, nil
	case string:
		var missing []string
		replaced := envRef.ReplaceAllStringFunc(t, func(m string) string {
			name := strings.TrimSuffix(strings.TrimPrefix(m, "${"), "}")
			if val, ok := os.LookupEnv(name); ok {
				return val
			}
			missing = append(missing, name)
			return m
		})
		if len(missing) > 0 {
			return nil, fmt.Errorf("config: %s: unset environment variable(s): %s", path, strings.Join(missing, ", "))
		}
		return replaced, nil
	default:
		return v, nil
	}
}

// parseYAML parses the YAML document into a generic mapping tree
// (map[string]any with []any, string, bool, int, float64 and nil leaves).
func parseYAML(data []byte) (map[string]any, error) {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("config: parse yaml: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("config: empty document")
	}
	return root, nil
}

// Server is the [server] section.
type Server struct {
	Listen         string
	MetricsListen  string
	ExternalURL    string
	TrustedProxies []string
	RequestTimeout time.Duration
}

// HarborServiceAccount holds optional credentials used when forwarding to
// Harbor (only needed if the proxy projects become private).
type HarborServiceAccount struct {
	Username string
	Password string
}

// Harbor is the [harbor] section.
type Harbor struct {
	BaseURL            string
	TokenPath          string
	InsecureSkipVerify bool
	ServiceAccount     *HarborServiceAccount // nil unless configured
}

// GateAnonymous is the [gate.anonymous] section.
type GateAnonymous struct {
	Enabled bool
}

// AuthFailureLimit is the [gate.auth_failure_limit] section.
type AuthFailureLimit struct {
	PerIP       httpx.Rate
	PerUsername httpx.Rate
}

// Gate is the [gate] section.
type Gate struct {
	Path                    string
	Anonymous               GateAnonymous
	AnonymousRegistryScopes string // only "deny" is supported
	AuthFailureLimit        AuthFailureLimit
	FailMode                string // only "closed" is supported
	DenyMessage             string
	LoginFailedMessage      string
}

// Whitelist is the [whitelist] section.
type Whitelist struct {
	Files  []string
	Inline []string
	Reload bool
}

// Projects is the [projects] section.
type Projects struct {
	Map map[string]string // harbor project -> whitelist upstream host
}

// AuthToken is the [auth.token] section. The PAT signing key itself is
// NOT configured: it is generated on first start and stored in sqlite.
type AuthToken struct {
	Issuer     string
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// Auth is the [auth] section.
type Auth struct {
	Token AuthToken
}

// Storage is the [storage] section.
type Storage struct {
	SqlitePath     string
	UsageRetention time.Duration
}

// PortalOIDC is the [portal.sso.oidc] section.
type PortalOIDC struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
}

// PortalSSO is the [portal.sso] section.
type PortalSSO struct {
	OIDC PortalOIDC
}

// Portal is the [portal] section. The session-cookie secret is not
// configured: it is generated on first use and stored in sqlite.
type Portal struct {
	Enabled          bool
	BasePath         string
	SSO              PortalSSO
	MaxTokensPerUser int
}

// AdminGitHub is the [admin.github] section.
type AdminGitHub struct {
	ClientID     string
	ClientSecret string
	AllowedUsers []string
	AllowedOrgs  []string
}

// Admin is the [admin] section. The session-cookie secret is not
// configured: it is generated on first use and stored in sqlite.
type Admin struct {
	Enabled  bool
	BasePath string
	GitHub   AdminGitHub
}

// Log is the [log] section.
type Log struct {
	Level  string // debug|info|warn|error
	Format string // json|text
}

// Config is the complete configuration. It mirrors every key of
// config.example.yaml (v0.4).
type Config struct {
	Server    Server
	Harbor    Harbor
	Gate      Gate
	Whitelist Whitelist
	Projects  Projects
	Auth      Auth
	Storage   Storage
	Portal    Portal
	Admin     Admin
	Log       Log

	// gateAnonConfigured records whether the [gate.anonymous] subsection
	// carried a mapping, so a missing subsection can default
	// anonymous.enabled to true without overriding an explicit false.
	gateAnonConfigured bool
}

// Load reads path, parses (substituting ${NAME} environment references),
// validates, applies defaults and parses the inline key material. Any
// problem is fatal: registry-gate must not start with a partially
// understood configuration.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	root, err := parseYAML(data)
	if err != nil {
		return nil, err
	}
	if _, err := expandEnv(root, ""); err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := decode(root, cfg); err != nil {
		return nil, err
	}
	applyDefaults(cfg)
	if err := validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// PortalURL returns {external_url} + {portal.base_path}, the value
// substituted for {portal_url} in message templates.
func (c *Config) PortalURL() string {
	return strings.TrimSuffix(c.Server.ExternalURL, "/") + c.Portal.BasePath
}

// ExpandMessage substitutes {portal_url} and {external_url} placeholders
// in a configured message template.
func ExpandMessage(msg, portalURL, externalURL string) string {
	r := strings.NewReplacer("{portal_url}", portalURL, "{external_url}", externalURL)
	return r.Replace(msg)
}

// parseDurationLike extends time.ParseDuration with a "d" (day) unit,
// e.g. "180d", "90d", "15s", "1h30m", "2d6h".
func parseDurationLike(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	var total time.Duration
	var num strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || c == '.' {
			num.WriteByte(c)
			continue
		}
		if num.Len() == 0 {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		if c == 'd' {
			v, err := strconv.ParseFloat(num.String(), 64)
			if err != nil {
				return 0, fmt.Errorf("bad number in duration %q: %w", s, err)
			}
			total += time.Duration(v * float64(24*time.Hour))
			num.Reset()
			continue
		}
		// Classic units: hand the number plus the remaining tail to
		// time.ParseDuration.
		tail, err := time.ParseDuration(num.String() + s[i:])
		if err != nil {
			return 0, fmt.Errorf("bad duration %q: %w", s, err)
		}
		return total + tail, nil
	}
	if num.Len() > 0 {
		return 0, fmt.Errorf("duration %q is missing a unit", s)
	}
	return total, nil
}
