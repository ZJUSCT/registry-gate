package portal

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/session"
	"github.com/ZJUSCT/registry-gate/internal/store"
)

// --- page data -----------------------------------------------------------

type baseData struct {
	Title   string
	Base    string
	Subject string
	Flash   string
}

type loginData struct{ baseData }

type tokenRow struct {
	JTI      string
	Note     string
	Issued   string
	Expires  string
	LastUsed string
	Active   bool
	Revoked  bool
}

type dashboardData struct {
	baseData
	MaxTokens      int
	ActiveCount    int64
	Tokens         []tokenRow
	DefaultTTLDays int
	MaxTTLDays     int
}

type issuedData struct {
	baseData
	PAT      string
	Note     string
	Expires  string
	Registry string
}

type usageRow struct {
	Time     string
	Repo     string
	Decision string
	IP       string
}

type usageData struct {
	baseData
	Records []usageRow
	Limit   int
}

type errorData struct {
	baseData
	Message string
}

// fmtTime renders timestamps for the tables.
func fmtTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }

// --- authentication pages -------------------------------------------------

// home shows the login page or the dashboard depending on the session.
func (s *server) home(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subject(r)
	if !ok {
		s.render(w, http.StatusOK, "login", loginData{baseData{
			Title: "Sign in", Base: s.base,
		}})
		return
	}
	s.renderDashboard(w, r, sub)
}

// login starts the OIDC authorization-code flow (state + nonce + PKCE S256).
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	state, err := session.RandomState(16)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Sign-in failed", "Could not generate sign-in state.")
		return
	}
	nonce, err := session.RandomState(16)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Sign-in failed", "Could not generate sign-in state.")
		return
	}
	verifier, err := session.RandomState(32)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Sign-in failed", "Could not generate sign-in state.")
		return
	}
	challenge := s256Challenge(verifier)

	authURL, err := s.oidc.AuthCodeURL(r.Context(), state, nonce, challenge)
	if err != nil {
		s.logger.Error("portal: oidc discovery", "err", err)
		s.renderError(w, http.StatusBadGateway, "Sign-in unavailable",
			"The sign-in provider could not be reached. Please try again later.")
		return
	}
	// state/nonce/verifier are base64url and contain no ".".
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    state + "." + nonce + "." + verifier,
		Path:     s.base + "/callback",
		MaxAge:   int(authCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

// s256Challenge derives the PKCE code challenge (S256) from a verifier.
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// callback finishes the OIDC flow and establishes the portal session.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, why string, logArgs ...any) {
		s.logger.Warn("portal: oidc callback", logArgs...)
		s.renderError(w, status, "Sign-in failed", why)
	}
	c, err := r.Cookie(authCookieName)
	if err != nil || c.Value == "" {
		fail(http.StatusBadRequest, "Sign-in state is missing or expired. Start again from the portal.")
		return
	}
	state, nonce, verifier, ok := splitAuthCookie(c.Value)
	if !ok {
		fail(http.StatusBadRequest, "Sign-in state is malformed. Start again from the portal.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(r.URL.Query().Get("state"))) != 1 {
		fail(http.StatusBadRequest, "Sign-in state does not match.")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		if desc := r.URL.Query().Get("error_description"); desc != "" {
			fail(http.StatusBadRequest, "The sign-in provider reported: "+desc)
			return
		}
		fail(http.StatusBadRequest, "The sign-in provider returned no authorization code.")
		return
	}
	idToken, err := s.oidc.Exchange(r.Context(), code, verifier)
	if err != nil {
		fail(http.StatusBadGateway, "Could not exchange the authorization code. Please try again.", "err", err)
		return
	}
	sub, err := s.oidc.Verify(r.Context(), idToken, nonce, s.now())
	if err != nil {
		fail(http.StatusUnauthorized, "Sign-in could not be verified. Please try again.", "err", err)
		return
	}
	s.sess.Set(w, session.NewSession(map[string]string{"sub": sub, "idp": "gitlab"}))
	s.clearAuthCookie(w)
	http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
}

// splitAuthCookie decodes "state.nonce.verifier".
func splitAuthCookie(v string) (state, nonce, verifier string, ok bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func (s *server) clearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    "",
		Path:     s.base + "/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// logout clears the session cookie.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	s.sess.Clear(w)
	http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
}

// --- token management ------------------------------------------------------

// renderDashboard lists the user's tokens plus the issue form.
func (s *server) renderDashboard(w http.ResponseWriter, r *http.Request, sub string) {
	metas, err := s.opt.Store.ListTokensBySubject(r.Context(), sub)
	if err != nil {
		s.logger.Error("portal: list tokens", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"Your tokens could not be loaded.")
		return
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].IssuedAt.After(metas[j].IssuedAt) })
	now := s.now()
	rows := make([]tokenRow, 0, len(metas))
	for _, m := range metas {
		rows = append(rows, tokenRow{
			JTI:      m.JTI,
			Note:     m.Note,
			Issued:   fmtTime(m.IssuedAt),
			Expires:  fmtTime(m.ExpiresAt),
			LastUsed: fmtTimePtr(m.LastUsed),
			Active:   m.Active(now),
			Revoked:  m.RevokedAt != nil,
		})
	}
	active, err := s.opt.Store.CountActiveBySubject(r.Context(), sub, now)
	if err != nil {
		s.logger.Error("portal: count active tokens", "err", err)
	}
	s.render(w, http.StatusOK, "dashboard", dashboardData{
		baseData:       baseData{Title: "Your tokens", Base: s.base, Subject: sub, Flash: s.popFlash(w, r)},
		MaxTokens:      s.opt.MaxTokensPerUser,
		ActiveCount:    active,
		Tokens:         rows,
		DefaultTTLDays: int(s.defaultTTL() / (24 * time.Hour)),
		MaxTTLDays:     int(s.opt.MaxTokenTTL / (24 * time.Hour)),
	})
}

func fmtTimePtr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return fmtTime(*t)
}

// popFlash returns and clears a one-shot message previously stored on the
// session (used to report form errors after a redirect).
func (s *server) popFlash(w http.ResponseWriter, r *http.Request) string {
	sess, ok := s.sess.Get(r)
	if !ok {
		return ""
	}
	msg, present := sess.Values["flash"]
	if !present || msg == "" {
		return ""
	}
	delete(sess.Values, "flash")
	s.sess.Set(w, sess)
	return msg
}

// flash stores msg on the session and redirects to the dashboard.
func (s *server) flash(w http.ResponseWriter, r *http.Request, msg string) {
	sess, ok := s.sess.Get(r)
	if !ok {
		http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
		return
	}
	sess.Values["flash"] = msg
	s.sess.Set(w, sess)
	http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
}

// parseTTLDays validates the "ttl" form field (days). Empty selects the
// default TTL.
func (s *server) parseTTLDays(form string) (time.Duration, error) {
	if strings.TrimSpace(form) == "" {
		return s.defaultTTL(), nil
	}
	days, err := strconv.Atoi(strings.TrimSpace(form))
	if err != nil || days < 1 {
		return 0, errors.New("validity must be a whole number of days (at least 1)")
	}
	// Compare in days first: extreme values overflow when converted to a
	// time.Duration. Cap at ~100 years regardless of configuration.
	if s.opt.MaxTokenTTL > 0 {
		if maxDays := int(s.opt.MaxTokenTTL / (24 * time.Hour)); days > maxDays {
			return 0, fmt.Errorf("validity must not exceed %d days", maxDays)
		}
	} else if days > 36500 {
		return 0, errors.New("validity must not exceed 36500 days")
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

// issue creates a new PAT from the dashboard form.
func (s *server) issue(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.flash(w, r, "Malformed form submission.")
		return
	}
	note := strings.TrimSpace(r.PostFormValue("note"))
	if len(note) > 200 {
		s.flash(w, r, "Note must be at most 200 characters.")
		return
	}
	ttl, err := s.parseTTLDays(r.PostFormValue("ttl"))
	if err != nil {
		s.flash(w, r, err.Error())
		return
	}
	now := s.now()
	if max := s.opt.MaxTokensPerUser; max > 0 {
		count, err := s.opt.Store.CountActiveBySubject(r.Context(), sub, now)
		if err != nil {
			s.logger.Error("portal: count active tokens", "err", err)
			s.renderError(w, http.StatusInternalServerError, "Something went wrong",
				"Your tokens could not be counted.")
			return
		}
		if count >= int64(max) {
			s.flash(w, r, fmt.Sprintf(
				"You already have %d active tokens (maximum %d). Revoke one before issuing another.", count, max))
			return
		}
	}
	pat, meta, err := s.issueToken(r.Context(), sub, note, ttl)
	if err != nil {
		s.logger.Error("portal: issue token", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"The token could not be issued.")
		return
	}
	s.render(w, http.StatusOK, "issued", issuedData{
		baseData: baseData{Title: "Token created", Base: s.base, Subject: sub},
		PAT:      pat,
		Note:     note,
		Expires:  fmtTime(meta.ExpiresAt),
		Registry: s.opt.ExternalURL,
	})
}

// ownToken fetches the token {jti} and verifies it belongs to sub; it renders
// a 404 page otherwise (foreign tokens must not be distinguishable).
func (s *server) ownToken(w http.ResponseWriter, r *http.Request, sub string) (store.TokenMeta, bool) {
	meta, err := s.opt.Store.GetToken(r.Context(), r.PathValue("jti"))
	if err == nil && meta.Subject == sub {
		return meta, true
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("portal: get token", "err", err)
	}
	s.renderError(w, http.StatusNotFound, "Not found", "No such token.")
	return store.TokenMeta{}, false
}

// rotate revokes the token and issues a fresh one with the same note. The new
// PAT keeps the remaining validity of the old one (default TTL when the old
// token is no longer active).
func (s *server) rotate(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	meta, ok := s.ownToken(w, r, sub)
	if !ok {
		return
	}
	now := s.now()
	remaining := meta.ExpiresAt.Sub(now)
	if remaining <= 0 || s.opt.MaxTokenTTL > 0 && remaining > s.opt.MaxTokenTTL {
		remaining = s.defaultTTL()
	}
	// Replacing an active token frees its slot, so only rotating an inactive
	// token can exceed the per-user maximum.
	if max := s.opt.MaxTokensPerUser; max > 0 && !meta.Active(now) {
		count, err := s.opt.Store.CountActiveBySubject(r.Context(), sub, now)
		if err != nil {
			s.logger.Error("portal: count active tokens", "err", err)
			s.renderError(w, http.StatusInternalServerError, "Something went wrong",
				"Your tokens could not be counted.")
			return
		}
		if count >= int64(max) {
			s.flash(w, r, fmt.Sprintf(
				"You already have %d active tokens (maximum %d). Revoke one before issuing another.", count, max))
			return
		}
	}
	if err := s.opt.Store.RevokeToken(r.Context(), meta.JTI, now); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("portal: revoke token", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"The old token could not be revoked.")
		return
	}
	pat, newMeta, err := s.issueToken(r.Context(), sub, meta.Note, remaining)
	if err != nil {
		s.logger.Error("portal: issue rotated token", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"The replacement token could not be issued. The old token has been revoked.")
		return
	}
	s.render(w, http.StatusOK, "issued", issuedData{
		baseData: baseData{Title: "Token rotated", Base: s.base, Subject: sub},
		PAT:      pat,
		Note:     meta.Note,
		Expires:  fmtTime(newMeta.ExpiresAt),
		Registry: s.opt.ExternalURL,
	})
}

// revoke revokes one of the user's own tokens.
func (s *server) revoke(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	meta, ok := s.ownToken(w, r, sub)
	if !ok {
		return
	}
	if err := s.opt.Store.RevokeToken(r.Context(), meta.JTI, s.now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("portal: revoke token", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"The token could not be revoked.")
		return
	}
	s.flash(w, r, "Token revoked.")
}

// usage lists the user's recent registry requests.
func (s *server) usage(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	const limit = 200
	records, err := s.opt.Store.ListUsageBySubject(r.Context(), sub, limit)
	if err != nil {
		s.logger.Error("portal: list usage", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"Your usage could not be loaded.")
		return
	}
	rows := make([]usageRow, 0, len(records))
	for _, rec := range records {
		rows = append(rows, usageRow{
			Time:     fmtTime(rec.Time),
			Repo:     rec.Repo,
			Decision: rec.Decision,
			IP:       rec.IP,
		})
	}
	s.render(w, http.StatusOK, "usage", usageData{
		baseData: baseData{Title: "Your usage", Base: s.base, Subject: sub, Flash: s.popFlash(w, r)},
		Records:  rows,
		Limit:    limit,
	})
}
