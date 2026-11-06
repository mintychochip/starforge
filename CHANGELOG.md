# Changelog

## 0.1.0

First release: git over HTTP and SSH with Trails, agent session traces,
search, webhooks, and mirrors, on SQLite or Postgres.

### Features by area

- **Git hosting (M0):** smart HTTP, local accounts, personal access tokens,
  user-owned repositories with collaborators, code and history browsing,
  repository rename redirects, archive, and soft-delete with a 7-day restore
  window, plus a REST API (`/api/v1`, OpenAPI 3.1 at
  `/api/v1/openapi.json`).
- **Accounts and auth:** invite-only registration (`invite`, `open`,
  `domains`, and `sso` modes), email verification and password reset,
  TOTP two-factor authentication with recovery codes, OIDC single sign-on
  (authorization-code flow with PKCE, `link_by_email`, `auto_create`),
  OAuth device flow for the CLI.
- **Sessions (M1):** Trace Format v1 (session metadata and normalized
  events, JSON Schemas), secret redaction with per-repository and site
  rules, content-addressed zstd segment storage with quotas, capture
  adapters for Claude Code, Codex, Pi and omp, OpenCode (v2 SQLite store),
  and Gemini CLI, read from each agent's own store directory (see
  `docs/user/sessions.md`), session viewer with in-session search and split
  view, quarantine on high-confidence redaction hits,
  publish/unpublish/delete, export/import bundles. Only sessions whose
  working directory lies inside the repository are captured; sessions with
  no known working directory are never attributed. Antigravity CLI sessions
  are not captured (see README "Known gaps").
- **Trails (M2):** per-repository numbered Trails with comments, labels,
  assignees, and review requests; changes via `refs/for/*` (agit) with
  revisions, reviews, threaded comments, and pending (draft) reviews;
  commit statuses, fail-closed merge gates, `merge`/`squash`/`fast_forward`
  merges; branch and tag protection; webhooks (`push`, `trail`, `review`,
  `check`, `session`) with signed deliveries, a delivery log, and
  redelivery; dashboard sections and Trail/session/code search (Tantivy,
  `git grep` over the default branch).
- **Organizations and SSH (M3):** orgs, teams, and base permissions with
  repository transfer; git over SSH (`ssh://git@…`) with user and deploy
  keys and fingerprint registry.
- **Mirrors and import (M4):** one-time import and continuous pull/push
  mirrors over a sealed-credential store and SSRF-checked URL policy;
  GitHub issue/pull-request metadata import preserving numbers.
- **Operations (M5):** `starforged backup`/`restore`, `doctor` (with
  `--fix`), `/healthz`/`/readyz`/`/metrics` (Prometheus, bearer token),
  text or JSON logs (`log.format`/`log.level`), audit log (`/admin/audit`,
  `GET /api/v1/admin/audit`), abuse controls under `[limits]` with
  `429` + `X-RateLimit-*` on the API, SQLite reader pool (WAL, read-only
  readers), static musl release tarballs (`scripts/build-release.sh`),
  the OCI image (`Containerfile`, Alpine, non-root, `/data` volume),
  cargo-dist installers for `starforge`, and Playwright browser tests
  (`tests/browser/`).
- **CLI:** `starforge` — `auth login` (device flow, scopes `repo:read
  trail:write session:upload`), `enable`/`disable` (git hooks plus the
  Claude Code `SessionEnd` hook, which runs `starforge hook session-end`),
  `status`, `doctor`, `sync`, `sessions list/show/link/unlink/publish/
  unpublish/delete`, `export`/`import`, and `trail
  list/show/create/comment/push/checkout/review/merge`. Server discovery
  uses `GET /.well-known/starforge.json`; the advertised `api_url` must
  share the origin of the repository's remote (or of `git config
  starforge.server`), and plain `http` is accepted only for loopback.
- **Configuration:** `server.base_url` must be an origin
  (`https://forge.example.com`); Starforge cannot be served under a path
  prefix.

### Migrations

Applied automatically at startup (`database.auto_migrate`, default `true`)
or by hand with `starforged migrate`. Migrations are forward-only: back up
before upgrading (see `docs/admin/backup-and-restore.md`).

| Migration | Purpose |
|---|---|
| 0001 | Initial schema (users, tokens, repositories) |
| 0002 | Background jobs queue |
| 0003 | Email verification and one-time emailed links |
| 0004 | Single-use sign-up invites |
| 0005 | Repository rename redirects |
| 0006 | Repository archive flag |
| 0007 | Repository soft-delete with restore window |
| 0008 | Session ingest (sessions, segments, commit links, blobs) |
| 0009 | OAuth device-flow one-time codes |
| 0010 | Trails |
| 0011 | Per-repo Trail number sequences |
| 0012 | Changes, revisions, reviews, review threads |
| 0013 | Commit checks, gate rules, webhooks, webhook deliveries |
| 0014 | Rewrite stored webhook subscriptions to spec event types |
| 0015 | Per-attempt webhook delivery-log columns |
| 0016 | Per-Trail review requests |
| 0017 | Dashboard assignee-lookup indexes |
| 0018 | Trail commit cache and Trail↔session links |
| 0019 | Per-reader viewed state for change files |
| 0020 | One pending review per author per change |
| 0021 | Organizations, membership, teams, team repositories |
| 0022 | Branch protection on gate rules |
| 0023 | Tag protection |
| 0024 | SSH keys and deploy keys |
| 0025 | TOTP 2FA, recovery codes, OIDC identities, login challenges |
| 0026 | Git import and mirrors |
| 0027 | GitHub metadata import |
| 0028 | Audit indexes |
| 0029 | Atomic SSH fingerprint registry |
| 0034 | Fingerprint registry rows cascade with their key rows |

Note: migration numbers 0030–0033 do not exist; the series jumps from 0029
to 0034.

### Upgrade note

Migrations are forward-only; there is no downgrade path. Back up first
(`starforged backup`), then restart the new binary. `starforged doctor`
reports whether migrations are up to date, and `restore` refuses a backup
whose schema is newer than the binary.
