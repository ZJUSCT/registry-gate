// Package admin serves the registry-gate administrator UI: GitHub OAuth
// sign-in restricted to configured users/orgs, token overview, usage
// statistics and revocation. Pages are server-rendered from embedded
// templates.
package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/session"
	"github.com/ZJUSCT/registry-gate/internal/store"
	"github.com/ZJUSCT/registry-gate/web"
)

// Options configures the admin Handler. The zero value is not usable; see
// Handler for the validation rules.
type Options struct {
	// BasePath is the URL prefix the admin UI is mounted under ("/admin").
	BasePath string
	// ExternalURL is the public base URL of the registry.
	ExternalURL string

	ClientID     string
	ClientSecret string

	// AllowedUsers and AllowedOrgs grant access (case-insensitive): a
	// GitHub login in AllowedUsers, or membership in any AllowedOrgs org.
	// When both are empty everyone is denied.
	AllowedUsers []string
	AllowedOrgs  []string

	// GitHubAPIBase is the REST API base URL; it exists so tests can stub
	// the API. Empty defaults to "https://api.github.com".
	GitHubAPIBase string

	SessionSecret []byte // >= 16 bytes; signs the admin session cookie
	Store         store.Store
}

// Default GitHub OAuth endpoints (classic OAuth app).
const (
	defaultGitHubAPI = "https://api.github.com"
	authorizePath    = "https://github.com/login/oauth/authorize"
	tokenPath        = "https://github.com/login/oauth/access_token"
	oauthScopes      = "read:user read:org"
)

const (
	sessionCookieName = "rg_admin_session"
	stateCookieName   = "rg_admin_auth"
	stateCookieTTL    = 10 * time.Minute
	// usagePageSize is the number of usage rows per dashboard page.
	usagePageSize = 50
)

// server holds the wired-up admin UI state.
type server struct {
	opt    Options
	base   string // BasePath without trailing slash ("" when "/")
	logger *slog.Logger
	sess   *session.Store
	gh     *githubClient
	tmpl   *templates
	mux    *http.ServeMux
	now    func() time.Time
}

// Handler builds the admin HTTP handler.
func Handler(opt Options, logger *slog.Logger) (http.Handler, error) {
	switch {
	case opt.BasePath == "" || opt.BasePath[0] != '/':
		return nil, errors.New("admin: BasePath must start with '/'")
	case opt.ExternalURL == "":
		return nil, errors.New("admin: ExternalURL is required")
	case strings.HasSuffix(opt.ExternalURL, "/"):
		return nil, errors.New("admin: ExternalURL must not end with '/'")
	case opt.ClientID == "":
		return nil, errors.New("admin: ClientID is required")
	case len(opt.SessionSecret) < 16:
		return nil, errors.New("admin: SessionSecret must be at least 16 bytes")
	case opt.Store == nil:
		return nil, errors.New("admin: Store is required")
	}
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	apiBase := opt.GitHubAPIBase
	if apiBase == "" {
		apiBase = defaultGitHubAPI
	}
	s := &server{
		opt:    opt,
		base:   strings.TrimSuffix(opt.BasePath, "/"),
		logger: logger,
		sess:   session.New(opt.SessionSecret, sessionCookieName),
		gh: &githubClient{
			apiBase:      strings.TrimSuffix(apiBase, "/"),
			authorizeURL: authorizePath,
			tokenURL:     tokenPath,
			clientID:     opt.ClientID,
			clientSecret: opt.ClientSecret,
			redirectURI:  opt.ExternalURL + strings.TrimSuffix(opt.BasePath, "/") + "/callback",
			hc:           &http.Client{Timeout: 15 * time.Second},
		},
		tmpl: tmpl,
		now:  time.Now,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.dashboard)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /users/{subject}", s.userPage)
	mux.HandleFunc("POST /users/{subject}/revoke-all", s.revokeAll)
	mux.HandleFunc("POST /tokens/{jti}/revoke", s.revoke)
	mux.Handle("GET /static/", web.Handler())
	s.mux = mux
	return s, nil
}

// ServeHTTP strips the configured BasePath before dispatching to the routes.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if s.base != "" {
		switch {
		case path == s.base:
			path = "/"
		case strings.HasPrefix(path, s.base+"/"):
			path = path[len(s.base):]
		default:
			http.NotFound(w, r)
			return
		}
	}
	if path == "" {
		path = "/"
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = path
	s.mux.ServeHTTP(w, r2)
}

// subject returns the signed-in GitHub login, if any.
func (s *server) subject(r *http.Request) (string, bool) {
	sess, ok := s.sess.Get(r)
	if !ok {
		return "", false
	}
	sub := sess.Values["sub"]
	if sub == "" {
		return "", false
	}
	return sub, true
}

// requireSession redirects anonymous browsers to the admin root.
func (s *server) requireSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	sub, ok := s.subject(r)
	if !ok {
		http.Redirect(w, r, s.base+"/login", http.StatusSeeOther)
		return "", false
	}
	return sub, true
}

// renderError renders the plain error page.
func (s *server) renderError(w http.ResponseWriter, status int, title, message string) {
	s.render(w, status, "error", errorData{
		Base: s.base, Title: title, Message: message,
	})
}

// fmtTime renders timestamps for the tables.
func fmtTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return fmtTime(*t)
}

// allowedLogin decides admin access: case-insensitive membership in
// AllowedUsers or AllowedOrgs. Both lists empty denies everyone.
func allowedLogin(login string, orgs, allowedUsers, allowedOrgs []string) bool {
	if len(allowedUsers) == 0 && len(allowedOrgs) == 0 {
		return false
	}
	for _, u := range allowedUsers {
		if strings.EqualFold(u, login) {
			return true
		}
	}
	for _, want := range allowedOrgs {
		for _, have := range orgs {
			if strings.EqualFold(want, have) {
				return true
			}
		}
	}
	return false
}
