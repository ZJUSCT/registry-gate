// Package portal serves the registry-gate user self-service UI: GitLab OIDC
// sign-in and personal-access-token (PAT) management (issue, rotate, revoke,
// usage log). Pages are server-rendered from embedded templates.
package portal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/session"
	"github.com/ZJUSCT/registry-gate/internal/store"
	"github.com/ZJUSCT/registry-gate/internal/token"
	"github.com/ZJUSCT/registry-gate/web"
)

// Options configures the portal Handler. The zero value is not usable; see
// Handler for the validation rules.
type Options struct {
	// BasePath is the URL prefix the portal is mounted under ("/token").
	BasePath string
	// ExternalURL is the public base URL of the registry ("https://registry.example.org").
	ExternalURL string

	OIDCIssuer       string // e.g. "https://gitlab.example.zju.edu.cn"
	ClientID         string
	ClientSecret     string
	RedirectURI      string // "" defaults to ExternalURL+BasePath+"/callback"
	Scopes           []string
	MaxTokensPerUser int           // <= 0 means unlimited
	TokenTTL         time.Duration // default TTL when the form leaves days empty
	MaxTokenTTL      time.Duration // upper bound; <= 0 means unlimited

	SessionSecret []byte // >= 16 bytes; signs the portal session cookie
	Store         store.Store
	Issuer        *token.Issuer // signs PATs
}

const (
	sessionCookieName = "rg_portal_session"
	authCookieName    = "rg_portal_auth" // carries state+nonce+PKCE verifier during OIDC
	authCookieTTL     = 10 * time.Minute
	// fallbackTTL applies when both TokenTTL and MaxTokenTTL are unset.
	fallbackTTL = 30 * 24 * time.Hour
)

// server holds the wired-up portal state.
type server struct {
	opt    Options
	base   string // BasePath without trailing slash ("" when "/")
	logger *slog.Logger
	sess   *session.Store
	oidc   *oidcClient
	tmpl   *templates
	mux    *http.ServeMux
	now    func() time.Time
}

// Handler builds the portal HTTP handler.
func Handler(opt Options, logger *slog.Logger) (http.Handler, error) {
	switch {
	case opt.BasePath == "" || opt.BasePath[0] != '/':
		return nil, errors.New("portal: BasePath must start with '/'")
	case opt.ExternalURL == "":
		return nil, errors.New("portal: ExternalURL is required")
	case strings.HasSuffix(opt.ExternalURL, "/"):
		return nil, errors.New("portal: ExternalURL must not end with '/'")
	case opt.OIDCIssuer == "":
		return nil, errors.New("portal: OIDCIssuer is required")
	case opt.ClientID == "":
		return nil, errors.New("portal: ClientID is required")
	case len(opt.SessionSecret) < 16:
		return nil, errors.New("portal: SessionSecret must be at least 16 bytes")
	case opt.Store == nil:
		return nil, errors.New("portal: Store is required")
	case opt.Issuer == nil || opt.Issuer.Key == nil:
		return nil, errors.New("portal: Issuer with a signing key is required")
	}
	tmpl, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	redirect := opt.RedirectURI
	if redirect == "" {
		redirect = opt.ExternalURL + strings.TrimSuffix(opt.BasePath, "/") + "/callback"
	}
	s := &server{
		opt:    opt,
		base:   strings.TrimSuffix(opt.BasePath, "/"),
		logger: logger,
		sess:   session.New(opt.SessionSecret, sessionCookieName),
		oidc: &oidcClient{
			issuer:       opt.OIDCIssuer,
			clientID:     opt.ClientID,
			clientSecret: opt.ClientSecret,
			redirectURI:  redirect,
			scopes:       opt.Scopes,
			hc:           &http.Client{Timeout: 15 * time.Second},
		},
		tmpl: tmpl,
		now:  time.Now,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("POST /tokens", s.issue)
	mux.HandleFunc("POST /tokens/{jti}/rotate", s.rotate)
	mux.HandleFunc("POST /tokens/{jti}/revoke", s.revoke)
	mux.HandleFunc("GET /usage", s.usage)
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

// subject returns the signed-in username, if any.
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

// requireSession renders a redirect for anonymous browsers. POSTs from a
// signed-out browser land here and bounce to the login page.
func (s *server) requireSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	sub, ok := s.subject(r)
	if !ok {
		http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
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

// defaultTTL resolves the TTL to use when the user did not ask for a specific
// duration.
func (s *server) defaultTTL() time.Duration {
	switch {
	case s.opt.TokenTTL > 0:
		return s.opt.TokenTTL
	case s.opt.MaxTokenTTL > 0:
		return s.opt.MaxTokenTTL
	default:
		return fallbackTTL
	}
}

// issueToken creates a PAT and stores its metadata.
func (s *server) issueToken(ctx context.Context, subject, note string, ttl time.Duration) (string, store.TokenMeta, error) {
	pat, claims, err := s.opt.Issuer.Issue(subject, note, ttl)
	if err != nil {
		return "", store.TokenMeta{}, fmt.Errorf("portal: issue PAT: %w", err)
	}
	meta := store.TokenMeta{
		JTI:       claims.ID,
		Subject:   subject,
		Note:      note,
		IssuedAt:  claims.IssuedAt.Time,
		ExpiresAt: claims.ExpiresAt.Time,
	}
	if err := s.opt.Store.CreateToken(ctx, meta); err != nil {
		return "", store.TokenMeta{}, fmt.Errorf("portal: persist PAT: %w", err)
	}
	return pat, meta, nil
}
