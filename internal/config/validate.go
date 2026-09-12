package config

// validate.go applies defaults and validates the decoded configuration.

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/httpx"
)

// applyDefaults fills in values for optional keys, mirroring the frozen
// example file so a minimal config stays small.
func applyDefaults(c *Config) {
	if c.Server.MetricsListen == "" {
		c.Server.MetricsListen = "0.0.0.0:9090"
	}
	if c.Server.RequestTimeout == 0 {
		c.Server.RequestTimeout = 15 * time.Second
	}
	if c.Gate.Path == "" {
		c.Gate.Path = "/service/token"
	}
	if !c.gateAnonConfigured {
		// [gate.anonymous] absent or empty: default to the frozen example
		// behavior (anonymous pulls enabled, subject to the whitelist).
		// An explicit "enabled: false" is still honored.
		c.Gate.Anonymous.Enabled = true
	}
	if c.Gate.AnonymousRegistryScopes == "" {
		c.Gate.AnonymousRegistryScopes = "deny"
	}
	if c.Gate.FailMode == "" {
		c.Gate.FailMode = "closed"
	}
	if c.Gate.AuthFailureLimit.PerIP.Count == 0 {
		c.Gate.AuthFailureLimit.PerIP = defaultRate(20, time.Minute)
	}
	if c.Gate.AuthFailureLimit.PerUsername.Count == 0 {
		c.Gate.AuthFailureLimit.PerUsername = defaultRate(10, time.Minute)
	}
	if c.Gate.DenyMessage == "" {
		c.Gate.DenyMessage = "Image not in the anonymous pull whitelist. Visit {portal_url} to sign in and get an access token, then run: docker login {external_url}"
	}
	if c.Gate.LoginFailedMessage == "" {
		c.Gate.LoginFailedMessage = "Invalid or expired access token. Visit {portal_url} to get a new one."
	}
	if c.Storage.UsageRetention == 0 {
		c.Storage.UsageRetention = 90 * 24 * time.Hour
	}
	if c.Auth.Token.DefaultTTL == 0 {
		c.Auth.Token.DefaultTTL = 180 * 24 * time.Hour
	}
	if c.Auth.Token.MaxTTL == 0 {
		c.Auth.Token.MaxTTL = 365 * 24 * time.Hour
	}
	if c.Portal.BasePath == "" {
		c.Portal.BasePath = "/token"
	}
	if len(c.Portal.SSO.OIDC.Scopes) == 0 {
		c.Portal.SSO.OIDC.Scopes = []string{"openid"}
	}
	if c.Admin.BasePath == "" {
		c.Admin.BasePath = "/admin"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "json"
	}
}

func defaultRate(count int, window time.Duration) httpx.Rate {
	return httpx.Rate{Count: count, Window: window}
}

// validate enforces the hard requirements from the SPEC.
func validate(c *Config) error {
	if c.Server.Listen == "" {
		return fmt.Errorf("config: server.listen is required")
	}
	if err := validateURL(c.Server.ExternalURL, "server.external_url"); err != nil {
		return err
	}
	if err := validateCIDRs(c.Server.TrustedProxies, "server.trusted_proxies"); err != nil {
		return err
	}
	if c.Server.RequestTimeout <= 0 {
		return fmt.Errorf("config: server.request_timeout must be positive")
	}

	if err := validateURL(c.Harbor.BaseURL, "harbor.base_url"); err != nil {
		return err
	}
	if !strings.HasPrefix(c.Harbor.TokenPath, "/") {
		return fmt.Errorf("config: harbor.token_path must start with '/'")
	}
	if sa := c.Harbor.ServiceAccount; sa != nil {
		if sa.Username == "" || sa.Password == "" {
			return fmt.Errorf("config: harbor.service_account needs both username and password")
		}
	}

	if !strings.HasPrefix(c.Gate.Path, "/") {
		return fmt.Errorf("config: gate.path must start with '/'")
	}
	if c.Gate.AnonymousRegistryScopes != "deny" {
		return fmt.Errorf("config: gate.anonymous_registry_scopes supports only \"deny\"")
	}
	if c.Gate.FailMode != "closed" {
		return fmt.Errorf("config: gate.fail_mode supports only \"closed\"")
	}

	if len(c.Projects.Map) == 0 {
		return fmt.Errorf("config: projects.map must contain at least one project")
	}
	for proj, host := range c.Projects.Map {
		if proj == "" || host == "" {
			return fmt.Errorf("config: projects.map has an empty project or host")
		}
		if strings.ContainsAny(host, "/:") {
			return fmt.Errorf("config: projects.map[%s]=%q must be a plain host", proj, host)
		}
	}

	if c.Auth.Token.Issuer == "" {
		return fmt.Errorf("config: auth.token.issuer is required")
	}
	if c.Auth.Token.DefaultTTL <= 0 {
		return fmt.Errorf("config: auth.token.default_ttl must be positive")
	}
	if c.Auth.Token.MaxTTL < c.Auth.Token.DefaultTTL {
		return fmt.Errorf("config: auth.token.max_ttl must be >= default_ttl")
	}

	if c.Storage.SqlitePath == "" {
		return fmt.Errorf("config: storage.sqlite.path is required")
	}
	if c.Storage.UsageRetention <= 0 {
		return fmt.Errorf("config: storage.usage_retention must be positive")
	}

	if c.Portal.Enabled {
		if !strings.HasPrefix(c.Portal.BasePath, "/") {
			return fmt.Errorf("config: portal.base_path must start with '/'")
		}
		if err := validateURL(c.Portal.SSO.OIDC.Issuer, "portal.sso.oidc.issuer"); err != nil {
			return err
		}
		if c.Portal.SSO.OIDC.ClientID == "" {
			return fmt.Errorf("config: portal.sso.oidc.client_id is required when portal is enabled")
		}
		if c.Portal.SSO.OIDC.ClientSecret == "" {
			return fmt.Errorf("config: portal.sso.oidc.client_secret is required when portal is enabled")
		}
		if c.Portal.SSO.OIDC.RedirectURI != "" {
			if err := validateURL(c.Portal.SSO.OIDC.RedirectURI, "portal.sso.oidc.redirect_uri"); err != nil {
				return err
			}
		}
		if c.Portal.MaxTokensPerUser <= 0 {
			return fmt.Errorf("config: portal.max_tokens_per_user must be positive")
		}
	}
	if c.Admin.Enabled {
		if !strings.HasPrefix(c.Admin.BasePath, "/") {
			return fmt.Errorf("config: admin.base_path must start with '/'")
		}
		if c.Admin.GitHub.ClientID == "" {
			return fmt.Errorf("config: admin.github.client_id is required when admin is enabled")
		}
		if c.Admin.GitHub.ClientSecret == "" {
			return fmt.Errorf("config: admin.github.client_secret is required when admin is enabled")
		}
	}

	if o := c.Observability.OtelLogs; o.Enabled {
		if err := validateURL(o.Endpoint, "observability.otel_logs.endpoint"); err != nil {
			return err
		}
		if o.ServiceName == "" {
			return fmt.Errorf("config: observability.otel_logs.service_name is required when enabled")
		}
		if o.MaxQueueSize < 0 || o.FlushInterval < 0 {
			return fmt.Errorf("config: observability.otel_logs.batch values must be positive")
		}
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("config: log.level must be one of debug|info|warn|error")
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("config: log.format must be json or text")
	}
	return nil
}

func validateURL(raw, name string) error {
	if raw == "" {
		return fmt.Errorf("config: %s is required", name)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("config: %s must be an http(s) URL, got %q", name, raw)
	}
	return nil
}

func validateCIDRs(cidrs []string, name string) error {
	for _, c := range cidrs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("config: %s: bad CIDR %q", name, c)
		}
	}
	return nil
}
