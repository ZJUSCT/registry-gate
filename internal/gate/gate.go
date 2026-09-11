// Package gate implements the registry-gate token endpoint: the decision
// flow in front of Harbor's token service described in SPEC.md.
//
// Anonymous pulls are limited to the whitelist (repository granularity);
// PAT holders can pull everything the mirror proxies. On allow, client
// credentials are stripped and the request is forwarded anonymously to
// Harbor with the original query preserved; the response is passed through
// verbatim. Everything else fails closed with registry error-schema bodies.
package gate

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/httpx"
	"github.com/ZJUSCT/registry-gate/internal/store"
	"github.com/ZJUSCT/registry-gate/internal/token"
	"github.com/ZJUSCT/registry-gate/internal/whitelist"
)

// Decision values (also stored in usage records and metrics labels).
const (
	DecisionAllowAnon          = "allow_anon_by_rule"
	DecisionAllowAuthed        = "allow_authed"
	DecisionAllowLoginProbe    = "allow_login_probe"
	DecisionDenyNotWhitelisted = "deny_not_whitelisted"
	DecisionDenyBadToken       = "deny_bad_token"
	DecisionDenyNoUpstream     = "deny_no_upstream"
	DecisionDenyAnonDisabled   = "deny_anon_disabled"
	DecisionDenyRegistryScope  = "deny_registry_scope"
)

// GateConfig is the gate's runtime configuration. It is deliberately
// defined here (not in internal/config) so the gate does not depend on the
// config package; main maps config.Config onto this struct.
type GateConfig struct {
	Path                   string
	AnonymousEnabled       bool
	ExternalURL            string // public base URL; builds the /v2/ ping challenge realm
	HarborBaseURL          string
	HarborTokenPath        string
	InsecureSkipVerify     bool
	ServiceAccountUsername string // optional; set when proxy projects are private
	ServiceAccountPassword string
	RequestTimeout         time.Duration
	DenyMessage            string
	LoginFailedMessage     string
	Projects               map[string]string // harbor project -> whitelist upstream host
	PerIPRate              httpx.Rate        // auth-failure limit per client IP (0 = unlimited)
	PerUsernameRate        httpx.Rate        // auth-failure limit per username (0 = unlimited)
}

// scope is one parsed token-endpoint scope:
// "repository:docker.io/library/nginx:pull" -> type repository, name
// docker.io/library/nginx. Actions are validated by Harbor when it issues
// the token; the gate only needs type and name.
type scope struct {
	typ  string
	name string
}

// Handler is the gate HTTP handler. Construct with New.
type Handler struct {
	cfg     GateConfig
	wl      *whitelist.List
	ver     *token.Verifier
	store   store.Store
	log     *slog.Logger
	met     *httpx.Metrics
	proxies *httpx.ProxyChecker
	perIP   *httpx.Limiter
	perUser *httpx.Limiter
	client  *http.Client
}

// New wires the gate. met and proxies may be nil (metrics discarded /
// nothing trusted). The whitelist, verifier and store must be non-nil.
func New(cfg GateConfig, wl *whitelist.List, ver *token.Verifier, st store.Store, logger *slog.Logger, met *httpx.Metrics, proxies *httpx.ProxyChecker) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	if met == nil {
		met = httpx.NewMetrics()
	}
	if proxies == nil {
		proxies = &httpx.ProxyChecker{}
	}
	var perIP, perUser *httpx.Limiter
	if cfg.PerIPRate.Count > 0 {
		perIP = httpx.NewLimiter(cfg.PerIPRate)
	}
	if cfg.PerUsernameRate.Count > 0 {
		perUser = httpx.NewLimiter(cfg.PerUsernameRate)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // configurable, cluster-internal use
	return &Handler{
		cfg:     cfg,
		wl:      wl,
		ver:     ver,
		store:   st,
		log:     logger,
		met:     met,
		proxies: proxies,
		perIP:   perIP,
		perUser: perUser,
		client:  &http.Client{Transport: tr},
	}
}

// ServeHTTP implements the decision flow from SPEC.md.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Fixed behavior: only GET; POST must answer 405 + Allow: GET so
	// containerd clients fall back to GET+Basic.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.respond(w, http.StatusMethodNotAllowed, "UNSUPPORTED",
			fmt.Sprintf("%s is not supported; use GET", r.Method))
		return
	}

	ip := h.proxies.ClientIP(r)
	scopes := parseScopes(r)

	user, pass, hasBasic := r.BasicAuth()
	if hasBasic {
		h.handleAuthenticated(w, r, ip, scopes, user, pass)
		return
	}
	h.handleAnonymous(w, r, ip, scopes)
}

// parseScopes collects every `scope` query parameter, each of which may
// contain several space-separated scope tokens.
func parseScopes(r *http.Request) []scope {
	var out []scope
	for _, raw := range r.URL.Query()["scope"] {
		for _, part := range strings.Fields(raw) {
			if s, ok := parseScope(part); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// parseScope splits "type:name:action[,action...]".
func parseScope(s string) (scope, bool) {
	typ, rest, ok := strings.Cut(s, ":")
	if !ok || typ == "" {
		return scope{}, false
	}
	name, _, ok := strings.Cut(rest, ":")
	if !ok || name == "" {
		return scope{}, false
	}
	return scope{typ: typ, name: name}, true
}

// handleAuthenticated runs the PAT branch: verify signature and expiry,
// then the store revocation check, then the scope policy.
func (h *Handler) handleAuthenticated(w http.ResponseWriter, r *http.Request, ip string, scopes []scope, user, pass string) {
	// The PAT normally travels in the password field (docker login).
	// Tolerate it in the username field as well (curl -u <token>, some
	// CI tooling): try the password first, then the username if it looks
	// like a PAT.
	pat := pass
	claims, err := h.verifyPAT(r, pat)
	if err != nil && pat != user && strings.HasPrefix(user, token.Prefix) {
		pat = user
		claims, err = h.verifyPAT(r, pat)
	}
	if err != nil {
		h.countAuthFailure(w, r, ip, user, scopes, err)
		return
	}

	subject := claims.Subject
	h.markUsed(claims.JTI())

	switch {
	case len(scopes) == 0:
		// docker login's credential probe. Answered by the gate itself:
		// the PAT is a signed JWT with a subject, so it doubles as the
		// probe token, which the /v2/ ping endpoint (also ours) accepts.
		// Harbor must not see this request: it answers anonymous
		// scopeless requests with 401 and does not know our PATs.
		h.allowProbe(w, r, ip, subject, pat, claims)
	case h.allProjectsKnown(scopes):
		h.allow(w, r, ip, subject, scopes, DecisionAllowAuthed, "")
	default:
		proj := h.firstUnknownProject(scopes)
		h.deny(w, r, ip, subject, scopes, DecisionDenyNoUpstream, "", firstRepo(scopes),
			http.StatusNotFound, "DENIED", "upstream not mirrored: "+proj)
	}
}

// verifyPAT verifies a PAT cryptographically and against the revocation
// table.
func (h *Handler) verifyPAT(r *http.Request, pat string) (*token.Claims, error) {
	claims, err := h.ver.Verify(pat)
	if err != nil {
		return nil, err
	}
	meta, err := h.store.GetToken(r.Context(), claims.JTI())
	if err != nil {
		return nil, err
	}
	if !meta.Active(time.Now()) {
		return nil, errors.New("token revoked or expired")
	}
	return claims, nil
}

// allProjectsKnown reports whether every repository scope's project is in
// the projects map (non-repository scopes are allowed for authenticated
// clients).
func (h *Handler) allProjectsKnown(scopes []scope) bool {
	return h.firstUnknownProject(scopes) == ""
}

// firstUnknownProject returns the first repository scope whose project is
// absent from the projects map, or "".
func (h *Handler) firstUnknownProject(scopes []scope) string {
	for _, s := range scopes {
		if s.typ != "repository" {
			continue
		}
		proj, _ := splitRepoName(s.name)
		if _, ok := h.cfg.Projects[proj]; !ok {
			return proj
		}
	}
	return ""
}

func firstRepo(scopes []scope) string {
	for _, s := range scopes {
		if s.typ == "repository" {
			return s.name
		}
	}
	return ""
}

// sanitizeSubject makes a basic-auth username safe to persist: a
// PAT-shaped username is masked (it is a live credential and must not
// leak into logs or the usage table), and anything very long is
// truncated so records stay renderable.
func sanitizeSubject(user string) string {
	if user == "" {
		return "anonymous"
	}
	if strings.HasPrefix(user, token.Prefix) {
		return "pat"
	}
	if len(user) > 64 {
		return user[:63] + "…"
	}
	return user
}

// countAuthFailure records a failed PAT verification (rate limited per IP
// and per username) and answers 401 or, once a limit is exceeded, 429.
func (h *Handler) countAuthFailure(w http.ResponseWriter, r *http.Request, ip, user string, scopes []scope, cause error) {
	ipOK := h.perIP == nil || h.perIP.Allow("ip:"+ip)
	userOK := h.perUser == nil || h.perUser.Allow("user:"+user)
	subject := sanitizeSubject(user)
	h.log.Warn("gate decision",
		"ip", ip, "subject", subject, "scopes", scopeNames(scopes),
		"decision", DecisionDenyBadToken, "rule", "", "error", cause.Error())
	h.met.IncDecision(DecisionDenyBadToken)
	h.recordUsage(store.UsageRecord{
		Subject: subject, IP: ip, Repo: firstRepo(scopes), Decision: DecisionDenyBadToken,
	})
	if !ipOK || !userOK {
		h.respond(w, http.StatusTooManyRequests, "TOOMANYREQUESTS",
			"Too many failed login attempts. Try again later.")
		return
	}
	h.respond(w, http.StatusUnauthorized, "UNAUTHORIZED", h.cfg.LoginFailedMessage)
}

// handleAnonymous runs the anonymous branch.
func (h *Handler) handleAnonymous(w http.ResponseWriter, r *http.Request, ip string, scopes []scope) {
	if !h.cfg.AnonymousEnabled {
		h.deny(w, r, ip, "anonymous", scopes, DecisionDenyAnonDisabled, "", firstRepo(scopes),
			http.StatusUnauthorized, "UNAUTHORIZED", h.cfg.DenyMessage)
		return
	}
	// Non-repository scopes (e.g. registry:catalog:*) are denied for
	// anonymous clients (anonymous_registry_scopes: deny).
	for _, s := range scopes {
		if s.typ != "repository" {
			h.deny(w, r, ip, "anonymous", scopes, DecisionDenyRegistryScope, "", s.name,
				http.StatusUnauthorized, "UNAUTHORIZED", h.cfg.DenyMessage)
			return
		}
	}
	if len(scopes) == 0 {
		// Anonymous probe without scopes: challenge for credentials.
		h.deny(w, r, ip, "anonymous", scopes, DecisionDenyNotWhitelisted, "", "",
			http.StatusUnauthorized, "UNAUTHORIZED", h.cfg.DenyMessage)
		return
	}
	rule := ""
	for _, s := range scopes {
		proj, rest := splitRepoName(s.name)
		host, mirrored := h.cfg.Projects[proj]
		if !mirrored {
			h.deny(w, r, ip, "anonymous", scopes, DecisionDenyNoUpstream, "", s.name,
				http.StatusNotFound, "DENIED", "upstream not mirrored: "+proj)
			return
		}
		if line, ok := h.wl.Match(host + "/" + rest); ok {
			if rule == "" {
				rule = line
			}
			continue
		}
		h.deny(w, r, ip, "anonymous", scopes, DecisionDenyNotWhitelisted, "", s.name,
			http.StatusUnauthorized, "UNAUTHORIZED", h.cfg.DenyMessage)
		return
	}
	h.allow(w, r, ip, "anonymous", scopes, DecisionAllowAnon, rule)
}

// splitRepoName splits "docker.io/library/nginx" into project and rest.
func splitRepoName(name string) (project, rest string) {
	i := strings.IndexByte(name, '/')
	if i < 0 {
		return name, ""
	}
	return name[:i], name[i+1:]
}

// allowProbe answers docker login's scopeless credential check with the
// PAT itself: it is a signed JWT whose subject authenticates the client
// on the /v2/ ping endpoint (PingHandler), which is also served by the
// gate. expires_in reflects the PAT's remaining lifetime.
func (h *Handler) allowProbe(w http.ResponseWriter, r *http.Request, ip, subject, pat string, claims *token.Claims) {
	h.log.Info("gate decision",
		"ip", ip, "subject", subject, "scopes", "", "decision", DecisionAllowLoginProbe, "rule", "")
	h.met.IncDecision(DecisionAllowLoginProbe)
	h.recordUsage(store.UsageRecord{
		Subject: subject, IP: ip, Decision: DecisionAllowLoginProbe,
	})
	expiresIn := int(time.Until(claims.ExpiresAt.Time).Seconds())
	if expiresIn < 1 {
		expiresIn = 1
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}{Token: pat, ExpiresIn: expiresIn})
}

// PingHandler answers the registry capability probe (exact "/v2" and
// "/v2/"), which docker login re-requests with the probe token. The gate
// owns this endpoint so the probe token can be a PAT instead of a
// Harbor-signed token; everything under /v2/<repo> still goes to Harbor.
// The challenge mirrors Harbor's (same realm and service name, here
// pointing at the gate's own token endpoint).
func (h *Handler) PingHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := strings.TrimSuffix(r.URL.Path, "/"); p != "/v2" && r.URL.Path != "/v2/" {
			http.NotFoundHandler().ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			h.respond(w, http.StatusMethodNotAllowed, "UNSUPPORTED",
				fmt.Sprintf("%s is not supported; use GET", r.Method))
			return
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer != "" {
			if _, err := h.verifyPAT(r, bearer); err == nil {
				w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				if r.Method == http.MethodGet {
					_, _ = io.WriteString(w, "{}")
				}
				return
			}
		}
		realm := strings.TrimSuffix(h.cfg.ExternalURL, "/") + h.cfg.Path
		w.Header().Set("Docker-Distribution-Api-Version", "registry/2.0")
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf("Bearer realm=%q,service=%q", realm, "harbor-registry"))
		httpx.WriteError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
	})
}

// allow logs the decision and forwards to Harbor anonymously.
func (h *Handler) allow(w http.ResponseWriter, r *http.Request, ip, subject string, scopes []scope, decision, rule string) {
	h.log.Info("gate decision",
		"ip", ip, "subject", subject, "scopes", scopeNames(scopes),
		"decision", decision, "rule", rule)
	h.met.IncDecision(decision)
	h.recordUsage(store.UsageRecord{
		Subject: subject, IP: ip, Repo: firstRepo(scopes), Decision: decision, Rule: rule,
	})
	h.forward(w, r)
}

// deny logs the decision and writes a registry error-schema response.
func (h *Handler) deny(w http.ResponseWriter, r *http.Request, ip, subject string, scopes []scope, decision, rule, repo string, status int, code, message string) {
	h.log.Info("gate decision",
		"ip", ip, "subject", subject, "scopes", scopeNames(scopes),
		"decision", decision, "rule", rule, "repo", repo, "status", status)
	h.met.IncDecision(decision)
	h.recordUsage(store.UsageRecord{
		Subject: subject, IP: ip, Repo: repo, Decision: decision, Rule: rule,
	})
	h.respond(w, status, code, message)
}

// respond writes the registry error schema; 401s carry the Basic
// challenge so docker/podman prompt for the PAT.
func (h *Handler) respond(w http.ResponseWriter, status int, code, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="registry-gate"`)
	}
	httpx.WriteError(w, status, code, message)
}

// forward re-issues the request to Harbor anonymously: the Authorization
// header is never copied, the original query is preserved. Harbor's JSON
// body is streamed back verbatim (the gate never adds refresh_token).
// Upstream errors and non-2xx statuses fail closed with 503.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.RequestTimeout)
	defer cancel()

	target := strings.TrimSuffix(h.cfg.HarborBaseURL, "/") + h.cfg.HarborTokenPath
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		h.upstreamFailure(w, err)
		return
	}
	if h.cfg.ServiceAccountUsername != "" {
		req.SetBasicAuth(h.cfg.ServiceAccountUsername, h.cfg.ServiceAccountPassword)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		h.upstreamFailure(w, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := fmt.Errorf("harbor answered %d", resp.StatusCode)
		h.upstreamFailure(w, err)
		return
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (h *Handler) upstreamFailure(w http.ResponseWriter, cause error) {
	h.log.Error("upstream failure", "error", cause.Error())
	h.met.IncUpstreamError()
	httpx.WriteError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "upstream registry unavailable")
}

// recordUsage inserts the decision record asynchronously; failures are
// logged but never affect the response (best effort).
func (h *Handler) recordUsage(rec store.UsageRecord) {
	rec.Time = time.Now()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := h.store.InsertUsage(ctx, rec); err != nil {
			h.log.Warn("usage insert failed", "error", err.Error())
		}
	}()
}

// markUsed stamps the token's last-used time asynchronously.
func (h *Handler) markUsed(jti string) {
	if jti == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := h.store.MarkUsed(ctx, jti, time.Now()); err != nil && !errors.Is(err, store.ErrNotFound) {
			h.log.Warn("mark used failed", "jti", jti, "error", err.Error())
		}
	}()
}

func scopeNames(scopes []scope) string {
	parts := make([]string, 0, len(scopes))
	for _, s := range scopes {
		parts = append(parts, s.typ+":"+s.name)
	}
	return strings.Join(parts, " ")
}
