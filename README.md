> [!WARNING]
> 该项目目前完全由 AI 开发维护，尚无维护者进行 Review！

# registry-gate

A minimal authz gate that sits in front of **any Docker Registry v2-compatible
registry** whose token endpoint follows the distribution token-auth spec: the gate
takes over that endpoint and decides who may obtain pull tokens. The registry itself
stays unmodified, and `/v2/*` traffic is never inspected — clients hold short-lived,
repo-scoped bearer tokens issued by the backend.

- **Anonymous** pulls: only whitelisted repositories (DaoCloud `allows.txt` format).
- **PAT holders** (campus SSO via GitLab OIDC): pull everything.
- Admin panel (GitHub OAuth): view tokens and usage records, revoke credentials.

Validated and adapted against **Harbor** today (running as a pull-through cache); the
gate itself is registry-agnostic — any backend with a token endpoint that issues
anonymous tokens for public projects works the same way. See `SPEC.md` and
`config.example.yaml`.

## Quick start

```sh
cp config.example.yaml config.yaml  # edit
go run ./cmd/registry-gate -config config.yaml
```

## Status

Work in progress. Layout and contract: `SPEC.md`.
