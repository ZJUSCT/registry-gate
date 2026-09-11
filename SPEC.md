# registry-gate SPEC (implementation contract)

A single Go binary gating Docker-registry token issuance in front of a stock Harbor
pull-through cache. **Anonymous pulls are limited to a whitelist; PAT holders can pull
everything; Harbor stays unmodified.**

Authoritative behavior/config reference:
- `config.example.yaml` (v0.5) in this repo — the config schema is frozen. Every config string supports ${NAME} env substitution (unset var = startup error); OAuth secrets are inline (no *_file indirections); the PAT signing key and session-cookie secrets are auto-generated on first start and stored in sqlite (nothing key-like is configurable).
- Background research: `~/src/project/260911_harbor-front-auth/` (Harbor & docker-client
  findings). Read `registry-gate-config-draft.md` for rationale; in case of conflict,
  this SPEC + config.example.yaml win.

## Fixed behaviors (hard-coded, NOT configurable)

0. The gate owns TWO endpoints: the token endpoint (`{gate.path}`) and the
   registry capability probe (exact `/v2` and `/v2/`). The probe is
   answered locally: anonymous gets a 401 Bearer challenge pointing at
   the gate's own token endpoint (`service="harbor-registry"` to match
   Harbor); a valid PAT bearer gets 200. Consequently docker login never
   needs a Harbor identity: a scopeless token request with a valid PAT is
   answered with the PAT itself (it is a signed JWT with a subject), and
   the client's retry of `GET /v2/` validates against the gate. In
   production Envoy routes exactly `/v2/` to the gate and `/v2/*` to
   Harbor; blobs and manifests never traverse the gate.

1. `POST` to the gate path → `405` with `Allow: GET` (containerd clients then fall back
   to GET+Basic; same as stock Harbor behavior).
2. On allow, the gate strips client credentials, forwards the request **anonymously** to
   `{harbor.base_url}{harbor.token_path}` preserving `service`/`scope` query params, and
   streams Harbor's JSON response back verbatim. The gate **never** adds a
   `refresh_token` field to any response.
3. Every non-2xx response body uses the registry error schema so docker/podman surface
   the message:
   `{"errors":[{"code":"<CODE>","message":"<msg>","detail":...}]}`
   with an appropriate `WWW-Authenticate` header (401 → `Basic realm="registry-gate"`).
4. PAT format: `zjum_` + base64url(rawJWT), Ed25519 (EdDSA), claims: `iss`, `sub`
   (campus username), `jti` (16-byte hex), `note`, `iat`, `nbf`, `exp`. Implemented in
   `internal/token` (already written — do not redesign).
5. Anonymous whitelist granularity is **repository-level** (token scopes carry no tags;
   whitelist lines containing `:` are a load-time error).

## Decision flow (gate)

```
request (GET) at gate path:
  scopes    ← parse all `scope` query params (repeatable, space-separated)
  identity  ← Basic header → PAT verify (signature/exp via internal/token,
              then store.GetToken for revocation; failure counted for rate limit)
              no credentials → anonymous

  PAT invalid/expired/revoked     → 401 UNAUTHORIZED + login_failed_message
  PAT valid, scopes empty         → allow (decision=allow_login_probe; docker login)
  PAT valid, project ∈ projects.map → allow (decision=allow_authed)
  PAT valid, project ∉ map        → 404 UNAUTHORIZED? NO → 404 with code
                                    "DENIED"/message "upstream not mirrored"
                                    (decision=deny_no_upstream)
  anonymous && !gate.anonymous.enabled → 401 (deny_anon_disabled)
  anonymous, any non-repository scope   → 401 (anonymous_registry_scopes=deny)
  anonymous, repository scope:
      key = projects.map[project] + "/" + repo
      match (exact | x/* | x/**)        → allow (allow_anon_by_rule, rule=hit line)
      no match                          → 401 + deny_message (deny_not_whitelisted)

  auth-failure rate limit exceeded → 429 (registry error schema)

  allow → strip Authorization, forward anonymously, pass through response
  harbor unreachable / non-2xx upstream:
      fail_mode=closed → 503 UNAVAILABLE
```

Scope parsing detail: `scope=repository:docker.io/library/nginx:pull` → resource type
`repository`, name `docker.io/library/nginx`, actions `pull`. A scope may list multiple
actions (`pull,push`). Project = first `/`-segment of name. **All** repository scopes in
a request must pass the policy. Unknown scope types (e.g. `registry:catalog:*`) follow
`anonymous_registry_scopes` for anonymous, allowed for authenticated.

## Whitelist semantics (`internal/whitelist`)

Identical to DaoCloud `hack/verify-allows.sh`:
- line `host/path/**` → name starts with `host/path/` (recursive)
- line `host/path/*`  → name starts with `host/path/` AND remainder contains no `/`
- otherwise exact string equality
- blank lines and `#` comments ignored; `:` in a line → validation error
- multiple files + `inline` merged, deduplicated; hot reload on file change (fsnotify or
  1s mtime poll) and SIGHUP; invalid new content → keep previous table, log error,
  increment `registry_gate_whitelist_reload_errors_total`
- matcher must be safe for concurrent use; expose `Match(name string) (line string, ok bool)`

## Packages & ownership

| Path | Owner | Contents |
|---|---|---|
| `internal/token` | done (main session) | PAT issue/verify (Ed25519 JWT) |
| `internal/store/store.go` | done (main session) | `Store` interface + record types |
| `cmd/registry-gate` | backend agent | main: config load, wiring, HTTP mux |
| `internal/config` | backend agent | yaml load+validate, defaults, reload-free |
| `internal/whitelist` | backend agent | parser/matcher/reload + tests |
| `internal/httpx` | backend agent | registry error schema writer, client-IP (trusted proxies), logging middleware, in-memory sliding-window rate limiter, /metrics /healthz |
| `internal/gate` | backend agent | gate handler + tests (httptest fake harbor) |
| `internal/store/sqlite.go` | backend agent | modernc.org/sqlite implementation of Store |
| `internal/session` | frontend agent | HMAC cookie sessions (secret from file; HttpOnly, Secure, SameSite=Lax, 12h) |
| `internal/portal` | frontend agent | user UI (GitLab OIDC) |
| `internal/admin` | frontend agent | admin UI (GitHub OAuth) |
| `web/` | frontend agent | html templates (go:embed), minimal CSS |

**Backend agent does not touch** `internal/portal`, `internal/admin`, `internal/session`, `web/`.
**Frontend agent does not touch** anything else. Neither edits `go.mod`/`go.sum` (deps are pre-declared).
`main.go` wiring contract (backend implements now, frontend packages arrive later):

```go
// backend main wires:
//   mux.Handle(cfg.Gate.Path, gate.Handler(cfg, wl, verifier, store))
//   portal/admin: mounted at their base paths via a small interface so the binary
//   builds before those packages exist:
type pageHandler interface{ ServeHTTP(http.ResponseWriter, *http.Request) }
// until frontend lands, serve 503 placeholder at portal/admin base paths
// (a TODO comment marks the merge point).
```

## Portal (user UI) — English, minimal, server-rendered

All under `{portal.base_path}` (default `/token`), session via `internal/session`
(claims: `sub` username, `idp=gitlab`). GitLab OIDC: discovery from issuer
`/.well-known/openid-configuration`, authorization-code + state + nonce + PKCE(S256),
scopes from config (`openid`). Redirect URI: `portal.sso.oidc.redirect_uri` or default
`{server.external_url}{portal.base_path}/callback`.

- `GET /`                → no session: login page (one button "Sign in with GitLab");
                           session: dashboard
- `GET /login`           → start OIDC
- `GET /callback`        → finish OIDC (on failure: error page)
- `POST /tokens`         → issue PAT (form: note, ttl ≤ auth.token.max_ttl, default
                           default_ttl). PAT shown **once** on a result page with
                           copy-paste `docker login` snippet
- `POST /tokens/{jti}/rotate` → revoke + issue new (same note), show new PAT once
- `POST /tokens/{jti}/revoke` → revoke
- `GET /usage`           → own recent usage records (repo, decision, time, ip), newest first
- Dashboard: list own tokens (note, issued, expires, last used, revoked state, actions)

Enforce `portal.max_tokens_per_user` (count non-expired, non-revoked).

## Admin UI — English, minimal, server-rendered

All under `{admin.base_path}` (default `/admin`). GitHub OAuth (classic OAuth app):
authorization-code + state; scopes `read:user read:org`. After exchange, with user
token: `GET https://api.github.com/user` (login), `GET https://api.github.com/user/orgs`
(list of `login`). Access rule: `allowed_users` (case-insensitive equality on login) OR
`allowed_orgs` (case-insensitive intersection with orgs) → admin session cookie
(`sub` github login, `idp=github`); both lists empty → **deny everyone**. Denied → 403
page "not an administrator" + log.

- `GET /``/login``/callback``/logout`
- Dashboard: summary cards (tokens active/revoked, pulls allowed/denied today,
  whitelist entries + last reload), recent usage (all users, paged), users table
  (subject, idp, active tokens, last used, "revoke all")
- User detail: their tokens (with revoke), their usage records
- Whitelist page: files, entry count, per-file entry counts, last reload time/errors
  (read-only view; list itself lives in Git, not edited here)

## Store interface (frozen — implemented by backend, consumed by frontend tests via a fake)

See `internal/store/store.go`. Usage records are inserted by the gate for **every
decision** (subject=`anonymous` or PAT sub) — this is what portal/admin display.

## Testing / quality bar (both agents)

- `go build ./...`, `go vet ./...` clean; `go test ./...` green.
- Whitelist: table-driven tests incl. `docker.io/*` NOT matching
  `docker.io/library/nginx`, `**` recursive, exact, reload-on-invalid keeps old table.
- Gate handler: httptest fake harbor — anonymous allow/deny, PAT allow (scopeless
  probe + repo), revoked PAT, unknown project 404, POST→405, error-schema shape,
  WWW-Authenticate on 401, forwarded request has no Authorization header and preserves
  scope query.
- Frontend handlers tested against a fake Store (portal issue/rotate/revoke flows,
  admin access rule matrix incl. empty-lists-deny, org case-insensitivity).
- Commits: conventional style, small steps, meaningful messages. Sign-off not required
  locally.
