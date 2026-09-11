package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// githubClient speaks the GitHub classic-OAuth flow: authorization redirect,
// code-for-token exchange, and the two REST calls needed for the access rule
// (GET /user, GET /user/orgs). Endpoints are fields so tests can stub them.
type githubClient struct {
	apiBase      string
	authorizeURL string
	tokenURL     string
	clientID     string
	clientSecret string
	redirectURI  string
	hc           *http.Client
}

// authCodeURL returns the GitHub authorization redirect for a state value.
func (g *githubClient) authCodeURL(state string) string {
	q := url.Values{
		"client_id":    {g.clientID},
		"redirect_uri": {g.redirectURI},
		"scope":        {oauthScopes},
		"state":        {state},
	}
	return g.authorizeURL + "?" + q.Encode()
}

// exchange trades an authorization code for an access token.
func (g *githubClient) exchange(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"client_id":     {g.clientID},
		"client_secret": {g.clientSecret},
		"code":          {code},
		"redirect_uri":  {g.redirectURI},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("github: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("github: token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("github: token endpoint: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("github: decode token response: %w", err)
	}
	if tok.AccessToken == "" {
		if tok.Error != "" {
			return "", fmt.Errorf("github: token endpoint: %s", tok.Error)
		}
		return "", errors.New("github: token response has no access_token")
	}
	return tok.AccessToken, nil
}

// fetchLogin returns the authenticated user's GitHub login.
func (g *githubClient) fetchLogin(ctx context.Context, accessToken string) (string, error) {
	var out struct {
		Login string `json:"login"`
	}
	if err := g.apiJSON(ctx, accessToken, "/user", &out); err != nil {
		return "", err
	}
	if out.Login == "" {
		return "", errors.New("github: /user response has no login")
	}
	return out.Login, nil
}

// fetchOrgs returns the logins of organizations the user belongs to.
func (g *githubClient) fetchOrgs(ctx context.Context, accessToken string) ([]string, error) {
	var out []struct {
		Login string `json:"login"`
	}
	if err := g.apiJSON(ctx, accessToken, "/user/orgs", &out); err != nil {
		return nil, err
	}
	orgs := make([]string, 0, len(out))
	for _, o := range out {
		orgs = append(orgs, o.Login)
	}
	return orgs, nil
}

// apiJSON performs an authenticated GET against the REST API.
func (g *githubClient) apiJSON(ctx context.Context, accessToken, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiBase+path, nil)
	if err != nil {
		return fmt.Errorf("github: build api request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	// GitHub's REST media type is vnd.github+json (vnd.api+json is the
	// unrelated JSON:API spec and yields 415 Unsupported Media Type).
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "registry-gate")
	resp, err := g.hc.Do(req)
	if err != nil {
		return fmt.Errorf("github: api %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github: api %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return fmt.Errorf("github: api %s: decode: %w", path, err)
	}
	return nil
}
