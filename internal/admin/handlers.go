package admin

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/ZJUSCT/registry-gate/internal/session"
	"github.com/ZJUSCT/registry-gate/internal/store"
)

// --- page data -----------------------------------------------------------

type baseData struct {
	Title   string
	Base    string
	Subject string
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

type usageRow struct {
	Time     string
	Subject  string
	Repo     string
	Decision string
	IP       string
}

type userRow struct {
	Subject  string
	Active   int
	Revoked  int
	LastUsed string
}

type decisionCount struct {
	Decision string
	Count    int64
}

type summaryData struct {
	ActiveTokens  int64
	RevokedTokens int64
	AllowedToday  int64
	DeniedToday   int64
	Decisions     []decisionCount
}

type dashboardData struct {
	baseData
	Summary            summaryData
	Usage              []usageRow
	Users              []userRow
	Page               int
	PrevPage, NextPage int
	HasNext            bool
}

type userPageData struct {
	baseData
	Subject string
	Tokens  []tokenRow
	Usage   []usageRow
}

type errorData struct {
	baseData
	Message string
}

// decisionOrder fixes the display order of the per-decision table.
var decisionOrder = []string{
	"allow_anon_by_rule", "allow_authed", "allow_login_probe",
	"deny_not_whitelisted", "deny_bad_token", "deny_no_upstream",
	"deny_anon_disabled", "deny_registry_scope",
}

// dashboard renders the overview page (login page when signed out).
func (s *server) dashboard(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.subject(r)
	if !ok {
		s.render(w, http.StatusOK, "login", loginData{baseData{
			Title: "Sign in", Base: s.base,
		}})
		return
	}
	ctx := r.Context()
	now := s.now()

	all, err := s.opt.Store.ListAllTokens(ctx)
	if err != nil {
		s.logger.Error("admin: list tokens", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"Tokens could not be loaded.")
		return
	}
	var summary summaryData
	users := map[string]*userRow{}
	var userOrder []string
	for _, m := range all {
		u, seen := users[m.Subject]
		if !seen {
			u = &userRow{Subject: m.Subject}
			users[m.Subject] = u
			userOrder = append(userOrder, m.Subject)
		}
		if m.RevokedAt != nil {
			u.Revoked++
			summary.RevokedTokens++
		} else if m.Active(now) {
			u.Active++
			summary.ActiveTokens++
		}
		// lastUsed strings share the fixed "2006-01-02 15:04" format, so
		// comparing them lexicographically compares the timestamps.
		if m.LastUsed != nil && fmtTime(*m.LastUsed) > u.LastUsed {
			u.LastUsed = fmtTime(*m.LastUsed)
		}
	}
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	counts, err := s.opt.Store.UsageSummary(ctx, midnight)
	if err != nil {
		s.logger.Error("admin: usage summary", "err", err)
	} else {
		for decision, n := range counts {
			switch {
			case len(decision) >= 6 && decision[:6] == "allow_":
				summary.AllowedToday += n
			case len(decision) >= 5 && decision[:5] == "deny_":
				summary.DeniedToday += n
			}
		}
		summary.Decisions = orderDecisions(counts)
	}

	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 0 {
		page = p
	}
	records, err := s.opt.Store.ListUsage(ctx, usagePageSize+1, (page-1)*usagePageSize)
	if err != nil {
		s.logger.Error("admin: list usage", "err", err)
	}
	hasNext := len(records) > usagePageSize
	if hasNext {
		records = records[:usagePageSize]
	}
	usage := make([]usageRow, 0, len(records))
	for _, rec := range records {
		usage = append(usage, usageRow{
			Time: fmtTime(rec.Time), Subject: rec.Subject, Repo: rec.Repo,
			Decision: rec.Decision, IP: rec.IP,
		})
	}

	rows := make([]userRow, 0, len(userOrder))
	for _, subject := range userOrder {
		rows = append(rows, *users[subject])
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].LastUsed != rows[j].LastUsed {
			return rows[i].LastUsed > rows[j].LastUsed
		}
		return rows[i].Subject < rows[j].Subject
	})

	s.render(w, http.StatusOK, "dashboard", dashboardData{
		baseData: baseData{Title: "Overview", Base: s.base, Subject: sub},
		Summary:  summary,
		Usage:    usage,
		Users:    rows,
		Page:     page,
		PrevPage: page - 1,
		NextPage: page + 1,
		HasNext:  hasNext,
	})
}

// orderDecisions renders the summary map in a stable, meaningful order.
func orderDecisions(counts map[string]int64) []decisionCount {
	rank := func(d string) int {
		for i, known := range decisionOrder {
			if d == known {
				return i
			}
		}
		return len(decisionOrder)
	}
	out := make([]decisionCount, 0, len(counts))
	for d, n := range counts {
		out = append(out, decisionCount{Decision: d, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := rank(out[i].Decision), rank(out[j].Decision)
		if ri != rj {
			return ri < rj
		}
		return out[i].Decision < out[j].Decision
	})
	return out
}

// --- OAuth ----------------------------------------------------------------

// login starts the GitHub OAuth flow (state-protected).
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	state, err := session.RandomState(16)
	if err != nil {
		s.renderError(w, http.StatusInternalServerError, "Sign-in failed",
			"Could not generate sign-in state.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     s.base + "/callback",
		MaxAge:   int(stateCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, s.gh.authCodeURL(state), http.StatusSeeOther)
}

// callback finishes the GitHub OAuth flow and applies the access rule.
func (s *server) callback(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, why string, logArgs ...any) {
		s.logger.Warn("admin: oauth callback", logArgs...)
		s.renderError(w, status, "Sign-in failed", why)
	}
	deny := func(login string, orgs []string) {
		s.logger.Warn("admin: access denied", "login", login, "orgs", orgs)
		s.renderError(w, http.StatusForbidden, "Not an administrator",
			"Your GitHub account is not authorized to administer this service.")
	}
	c, err := r.Cookie(stateCookieName)
	if err != nil || c.Value == "" {
		fail(http.StatusBadRequest, "Sign-in state is missing or expired. Start again.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.URL.Query().Get("state"))) != 1 {
		fail(http.StatusBadRequest, "Sign-in state does not match.")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		fail(http.StatusBadRequest, "GitHub returned no authorization code.")
		return
	}
	accessToken, err := s.gh.exchange(r.Context(), code)
	if err != nil {
		fail(http.StatusBadGateway, "Could not verify your GitHub credentials.", "err", err)
		return
	}
	login, err := s.gh.fetchLogin(r.Context(), accessToken)
	if err != nil {
		fail(http.StatusBadGateway, "Could not fetch your GitHub profile.", "err", err)
		return
	}
	orgs, err := s.gh.fetchOrgs(r.Context(), accessToken)
	if err != nil {
		fail(http.StatusBadGateway, "Could not fetch your GitHub organizations.", "err", err)
		return
	}
	if !allowedLogin(login, orgs, s.opt.AllowedUsers, s.opt.AllowedOrgs) {
		deny(login, orgs)
		return
	}
	s.sess.Set(w, session.NewSession(map[string]string{"sub": login, "idp": "github"}))
	s.clearStateCookie(w)
	http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
}

func (s *server) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     s.base + "/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// logout clears the admin session cookie.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	s.sess.Clear(w)
	http.Redirect(w, r, s.base+"/", http.StatusSeeOther)
}

// --- management -------------------------------------------------------------

// tokenRows converts metadata into template rows.
func tokenRows(metas []store.TokenMeta, now time.Time) []tokenRow {
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
	return rows
}

// userPage shows one subject's tokens and usage.
func (s *server) userPage(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	subject := r.PathValue("subject")
	if subject == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	metas, err := s.opt.Store.ListTokensBySubject(ctx, subject)
	if err != nil {
		s.logger.Error("admin: list tokens", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"Tokens could not be loaded.")
		return
	}
	records, err := s.opt.Store.ListUsageBySubject(ctx, subject, 200)
	if err != nil {
		s.logger.Error("admin: list usage", "err", err)
	}
	usage := make([]usageRow, 0, len(records))
	for _, rec := range records {
		usage = append(usage, usageRow{
			Time: fmtTime(rec.Time), Subject: rec.Subject, Repo: rec.Repo,
			Decision: rec.Decision, IP: rec.IP,
		})
	}
	s.render(w, http.StatusOK, "user", userPageData{
		baseData: baseData{Title: "User " + subject, Base: s.base, Subject: admin},
		Subject:  subject,
		Tokens:   tokenRows(metas, s.now()),
		Usage:    usage,
	})
}

// revoke revokes a single token (any subject — admins act on all users).
func (s *server) revoke(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSession(w, r); !ok {
		return
	}
	jti := r.PathValue("jti")
	meta, err := s.opt.Store.GetToken(r.Context(), jti)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		s.logger.Error("admin: get token", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"The token could not be loaded.")
		return
	}
	if err := s.opt.Store.RevokeToken(r.Context(), jti, s.now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger.Error("admin: revoke token", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"The token could not be revoked.")
		return
	}
	http.Redirect(w, r, s.base+"/users/"+meta.Subject, http.StatusSeeOther)
}

// revokeAll revokes every token of a subject.
func (s *server) revokeAll(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSession(w, r); !ok {
		return
	}
	subject := r.PathValue("subject")
	if _, err := s.opt.Store.RevokeAllBySubject(r.Context(), subject, s.now()); err != nil {
		s.logger.Error("admin: revoke all", "err", err)
		s.renderError(w, http.StatusInternalServerError, "Something went wrong",
			"The tokens could not be revoked.")
		return
	}
	http.Redirect(w, r, s.base+"/users/"+subject, http.StatusSeeOther)
}
