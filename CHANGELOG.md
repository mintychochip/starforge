# Changelog

## 0.1.0-rc.1

First release candidate of the 0.1.0 line: git over HTTP and SSH with Trails,
agent session traces, search, webhooks, mirrors, notifications, releases,
and opt-in CI runners with sandboxed jobs, on SQLite or Postgres.

### Features by area

- **Git hosting (M0):** smart HTTP, local accounts, personal access tokens,
  user-owned repositories with collaborators, code and history browsing
  (including per-file history at `/commits/{ref}/{path}`), repository rename
  redirects, archive, and soft-delete with a 7-day restore window, plus a
  REST API (`/api/v1`, OpenAPI 3.1 at `/api/v1/openapi.json`).
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
  view, a per-repository sessions list with agent/state filters and the
  subagent hierarchy (omp nested sessions link to their parent), fallback
  titles and `files_touched` from real tool-call records (repo-relative
  paths only; absolute paths outside the workdir are dropped), quarantine on
  high-confidence redaction hits, publish/unpublish/delete, export/import
  bundles. Only sessions whose
  working directory lies inside the repository are captured; sessions with
  no known working directory are never attributed. Antigravity CLI sessions
  are not captured (see README "Known gaps"). The server completes a session
  that stays `receiving` for 24 hours without activity, so an upload whose
  client never sends `complete` still becomes searchable.
- **Trails (M2):** per-repository numbered Trails with comments, labels,
  assignees, and review requests; changes via `refs/for/*` (agit) with
  revisions, reviews, threaded comments, and pending (draft) reviews;
  commit statuses, fail-closed merge gates, `merge`/`squash`/`fast_forward`
  merges; branch and tag protection; webhooks (`push`, `trail`, `review`,
  `check`, `session`; `ci` added in M6) with signed deliveries, a delivery
  log, and redelivery; dashboard sections and Trail/session/code search (Tantivy,
  `git grep` over the default branch). The Branches page links each
  branch's commits and opens a Trail from a branch, tracking it as a change.
- **Notifications:** an inbox (`/notifications`, unread badge in the nav)
  and optional email for Trail activity: comments, reviews and inline
  threads, merges, closes and reopens, and @mentions reach participants;
  assignments and review requests reach their target; new changes and
  revisions reach watchers. Users watch or ignore repositories and
  subscribe to or unsubscribe from Trails; nobody is notified about a
  repository they cannot read, nor about their own actions. Email needs
  `mail.url`, a verified address, and the per-user setting (on by default).
  The API has `/user/notifications` and repository and Trail subscription
  routes. Read notifications are deleted after 90 days, all after 365.
- **Downloads and releases:** any branch, tag, or commit downloads as a zip
  or tar.gz archive (`/{owner}/{repo}/archive/{ref}.zip`, links on the
  repository home and the tags page, and the API). Releases attach a
  title, Markdown notes, draft and prerelease flags, and uploaded asset
  files (up to 1 GiB each) to a tag; creating a release for a missing tag
  creates it at a branch or commit, protected tags need Maintain, drafts
  are visible to writers only, and deleting a release keeps its tag. Web
  pages under `/{owner}/{repo}/releases` and API routes under
  `/repos/{owner}/{repo}/releases` and `release-assets`.
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
- **Public-instance hardening:** `[limits]` gains `max_push_bytes` (git's
  `receive.maxInputSize` for HTTP and SSH pushes), `max_repo_bytes` (the
  pre-receive hook counts the repository plus the incoming objects, so a
  push that would cross the limit is refused whole; pull mirrors and
  imports stop fetching at the limit), and `git_per_ip_per_minute` (one
  per-IP window for git smart HTTP requests, which answers `429` with
  `Retry-After`, and SSH public-key auth attempts); `[audit]
  retention_days` deletes older audit rows in the daily prune; `[backup]
  dir`, `interval_hours`, and `keep` run scheduled backups while serving
  (rotation touches only `starforge-backup-*` directories, a failed run
  leaves no partial copy, and `serve` refuses an unwritable directory); a
  systemd unit (`packaging/systemd/starforged.service`) ships in the
  release tarballs. Every new setting defaults to off.
- **CI runners and sandboxes (M6):** opt-in `.starforge/ci.toml` jobs
  triggered by pushes, Trail changes, or manually; self-hosted runners
  with lease fences and per-job tokens; sandboxed execution through
  `starforge-sandboxd` (`podman`/gVisor) or the real E2B v2 API;
  artifacts with BLAKE3 CAS and 30-day retention; sealed repo secrets
  injected only by the egress proxy; per-job agent sessions linked to the
  run; the `ci` webhook event (`queued`/`started`/`finished`/
  `canceled`); and usage by supplier — native runner minutes and artifact
  storage metered and limited by Starforge (`[ci.limits]`), and a linked
  Depot repository's usage read from Depot's API with its limits left to
  Depot (`GET /repos/{owner}/{repo}/ci/usage`). External CI statuses and
  webhooks are unchanged, and the server never runs job code. The
  repository nav has CI and Compare tabs; repository admins manage CI
  secrets on a settings page as well as through the API; the OCI image
  ships `starforge-runner` and `starforge-sandboxd`. The never-read server
  keys `sandbox.local.egress.proxy_listen` and `ca_dir` are removed (the
  daemon's `--egress-dir` and `--egress-ca-dir` flags set them); an
  environment override for either now fails startup as an unknown key.
- **CI secret delivery and sandbox egress:** sandboxes keep
  `--network none`. `starforge-sandboxd --egress-dir` mounts a
  per-sandbox directory at `/run/starforge/egress`; the daemon copies its
  own static binary in and starts `forward`, which listens on
  `127.0.0.1:3128` and creates a Unix socket the host daemon connects
  into with a connection pool. The proxy forwards HTTPS `CONNECT` and
  absolute-form plain HTTP; a bare `host` entry permits ports 80 and 443
  only, and a `host:port` entry permits exactly that port. The runner
  resolves secrets after its git credential and adds the values to its
  log-scrub list; the server resolves secrets for a job-token sandbox
  create and passes host/header bindings to the local daemon.
  Per-repository policies `ci_allow_secrets_on_refs_for` and
  `ci_env_secrets` (both off by default) gate `refs/for` trust and the
  E2B-only environment opt-in. The proxy dials only addresses that pass
  its policy: loopback, private, link-local, and other special-use
  addresses are refused even for an allowlisted name, except the forge's
  own `host:port` and ranges the operator allows with
  `--egress-allow-cidr`. A secret header is injected only when the inner
  `Host` matches the bound host; a Trail job gets secrets only after an
  approval of its own revision; the runner never writes its credential
  URL into git config; a sandbox's workspace volume is removed with the
  sandbox. The hourly cleanup deletes expired artifacts and collects
  zero-ref blobs.
- **CI end-to-end:** `scripts/ci-e2e.sh` runs a real server, runner,
  sandboxd, and rootless podman through a fixture job. It proves the
  HTTPS clone and sync through the per-sandbox proxy, the artifact, and
  the linked session. The proxy keeps the socket open for a client's
  authenticated CONNECT retry; the daemon sets `GIT_SSL_CAINFO`; the
  runner initializes the checkout in place because `/workspace` holds the
  CA directory; a job finish links every session bound by `ci_job_id`.
- **CLI:** `starforge` — `auth login` (device flow, scopes `repo:read
  trail:write session:upload`), `auth ssh-key add` (one-time `repo:write`
  device flow; both tokens are revoked and never stored), `enable`/`disable`
  (git hooks plus the Claude Code `SessionEnd` hook, which runs `starforge
  hook session-end`; `enable` configures only agents it detects), `status`,
  `doctor`, `sync`, `spool prune` (drop uploaded session blobs, `--dry-run`),
  `sessions list/show/link/unlink/backfill-links/publish/unpublish/delete`,
  `export`/`import`, `runner` (self-hosted CI runner), `sandbox
  run/exec/cp/kill` (a local developer loop against `starforge-sandboxd`),
  and `trail list/show/create/comment/push/checkout/review/merge`. Server discovery
  uses `GET /.well-known/starforge.json`; the advertised `api_url` must
  share the origin of the repository's remote (or of `git config
  starforge.server`), and plain `http` is accepted only for loopback.
- **Configuration:** `server.base_url` must be an origin
  (`https://forge.example.com`); Starforge cannot be served under a path
  prefix.
- **Documentation:** maintainer technical documentation in
  `docs/technical/`, written in ASD-STE100 Simplified Technical English and
  checked by `scripts/ste_check.py` (the mechanical STE rules, source
  paths, links, the index, and coverage of every workspace crate and
  configuration key, nested tables included) in CI and `scripts/check.sh`.

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
| 0035 | Rerun requests for deduplicated jobs |
| 0036 | CI runners, jobs, logs, artifacts, job sessions and tokens |
| 0037 | Sandboxes and sandbox-second usage windows |
| 0038 | CI secrets and one-time artifact tokens |
| 0039 | CI usage per job attempt and CI supplier links |
| 0040 | Per-repository CI secret policy and secret host/header bindings |
| 0041 | Notifications, repository watches, Trail subscriptions, per-user email setting |
| 0042 | Releases and release assets |
| 0043 | Drop queued rows of two removed no-op job kinds |

Note: migration numbers 0030–0033 do not exist; the series jumps from 0029
to 0034.

### Upgrade note

Migrations are forward-only; there is no downgrade path. Back up first
(`starforged backup`), then restart the new binary. `starforged doctor`
reports whether migrations are up to date, and `restore` refuses a backup
whose schema is newer than the binary.
