# Starforge M6 (CI runners and sandboxed agent execution) Implementation Plan

> **For agentic workers:** Implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in self-hosted CI and sandboxed coding-agent execution to Starforge, built on the existing commit statuses, checks/gates, webhooks, job queue, and session capture. This is additive: external CI keeps reporting through the GitHub-compatible status API and webhooks, and no server-side agent or LLM call is introduced.

**Scope:** M6a runner control plane; M6b sandbox provider API; M6c CI triggers, artifacts, secrets; M6d agent-in-sandbox capture and the E2B adapter; M6e hardening, docs, and release.

**Depends on:** v0.1.0 at `9106a5b` (statuses `crates/starforged-api/src/statuses.rs`, checks `crates/starforged-core/src/checks.rs`, gates `gates.rs`, webhooks `webhooks.rs`, jobs `jobs.rs`, session ingest `crates/starforged-api/src/sessions.rs`, CLI sync `crates/starforge-cli/src/commands/sync.rs`).

**Supersedes:** spec D13 (`docs/superpowers/specs/2026-11-03-starforge-design.md:66`) and the §2 non-goal "CI runners" (`:36`) **additively**. The external-CI path remains the compatibility contract; M6e amends the spec text and §14.

## Decisions (rulings)

1. **Additive supersession of D13.** Runners are opt-in per repository. A repository with no runner and no `.starforge/ci.toml` behaves exactly as v0.1.0. External CI keeps using `POST /repos/{owner}/{repo}/statuses/{sha}` and webhooks.
2. **No workflow engine.** The job spec is a typed `.starforge/ci.toml` read at the commit SHA: a list of jobs, each with an image/template, commands, env, secrets, artifacts, and a timeout. No YAML DAG, matrix, expressions, or cross-job dependencies.
3. **The server never executes untrusted code.** Runners and sandboxes are external processes. The server owns the control plane (API, DB, queue, gates); a runner owns job execution; a sandbox provider owns isolation.
4. **Two providers, one sandbox API.** The server exposes an E2B-shaped sandbox API and calls a configured provider: `local` (`starforge-sandboxd`, a separate daemon with container-runtime access) or `e2b` (remote `api.e2b.app`). The runner uses the same server API. The server and sandboxd share a wire-protocol crate (`starforge-sandbox-protocol`, MIT/Apache) so neither depends on `starforged-*`.
5. **Starforge-native runner protocol.** Borrow GitHub/GitLab shapes (one-time registration, outbound long-poll, chunked trace, authorize-then-upload artifacts, per-job token, cancel header) but do not claim GitHub-runner wire compatibility. GitHub Actions users keep the statuses/webhooks path.
6. **Four token kinds, four auth paths.**
   - Registration token: random, hashed, 1 h TTL, one-time, repo-scoped (`runner_registration_tokens`).
   - Runner auth token: random, hashed, shown once (`runners.token_hash`), used by a dedicated `RunnerAuth` extractor, not `ApiAuth`; its own rate-limit budget (long-poll counted once per request).
   - Per-job token: random, hashed (`ci_job_tokens`), bound to `(job, repo, commit)`, TTL = deadline + 10 min, revoked at finish; used by a `JobAuth` extractor. Scopes are fixed (`session:upload`, `repo:read`, `sandbox:run`).
   - Artifact token: one-time HMAC-signed, bound to `(job, name, size, sha256)`, 10 min TTL.
   Upload authorization for a job token uses a new `IngestAuth::CiJob { job_id, repo_id, commit_sha }` path: the job was authorized at creation, sessions it uploads carry `ci_job_id` and `uploader_id = ci_jobs.created_by`; the job token may write only those sessions. The user-facing `authorize_upload` (≥`Write`) is unchanged for PATs.
7. **Secrets are sealed with a distinct key domain and never logged.** Repo secrets use XChaCha20-Poly1305 via the existing `SealedBox` with HKDF info `ci-secrets-v1` under `secret_key` (not the webhook key). The spec stores secret *names*, never values. Secrets are injected only for runs on protected branches or Trails with maintainer approval; `refs/for` runs get none unless the repo sets `ci.allow_secrets_on_refs_for = true`. Preferred injection is an egress proxy that adds headers on outbound HTTPS (E2B-style); env injection is the fallback, with server-side log scrubbing and ephemeral sandboxes.
8. **Local isolation v1 = rootless containers, fully hardened.** `starforge-sandboxd` uses rootless podman with no host mounts, dropped capabilities, `no-new-privileges`, read-only root, seccomp, cgroup limits, and default-deny egress. Its control socket is a 0600 token file plus `SO_PEERCRED` peer checks; the token rotates on restart. gVisor and Firecracker are later provider runtimes behind the same wire protocol; no GPU in v1.
9. **CI results use a dedicated internal status path.** A job writes context `ci/<job-name>` through `Core::submit_ci_status` (creator handle `ci`, no user `Write` check, archived-repo refusal, `check` webhook dispatch). The user-facing `submit_status` is unchanged. Canceled jobs write `error` with description `canceled by <user>` (GitHub-compatible states stay unchanged).
10. **No new git namespaces.** A runner pushes only `refs/heads/*` or `refs/for/*`. The runner obtains a short-lived git credential from `POST /api/v1/ci/jobs/{id}/git-credential` (runner auth, TTL = job, repo-scoped) or uses an operator-configured deploy key; the agent never receives a long-lived PAT.
11. **Migrations 0036–0039**, SQLite and Postgres in lockstep, forward-only. New crates `starforge-runner`, `starforge-sandboxd`, `starforge-sandbox-protocol` are `MIT OR Apache-2.0` and never depend on `starforged-*`. No new external crates beyond `reqwest`/`serde`/`tokio`/`axum` already in the tree; the sandbox daemon may use the `podman` CLI (no new crate).
12. **No HA, no Windows server, no server-side agents/LLM calls.** The single-process deployment model and §11.2 stand.
13. **`ci_jobs` is a separate table, not the internal `jobs` queue.** The internal queue's `claim_next` is for in-process workers and has no runner identity or fencing; `ci_jobs` reuses the lease/attempt *pattern* with configurable constants (`ci.lease_secs = 60`, `ci.max_attempts = 3`) and a per-claim `lease_token` fence. Every trace/result/artifact call must present the fence; a stale fence is `409`.
14. **The `ci` webhook event is added** (run queued/started/finished/canceled). This requires extending `EVENT_TYPES`, `normalize_events`, `check_events`, the hook-create docs/tests, OpenAPI, and spec §10.4. The existing `check` event still covers status transitions.

## Architecture

```
 push / trail / manual
        │
        ▼
 Core::ci_trigger ──► ci_jobs (queued) ──► check context pending
        ▲                                      │
        │ long-poll claim + lease_token        │
 starforge-runner ─────────────────────────────┘
        │  claim payload: spec + per-job token + sandbox policy + fence
        ├──► POST /api/v1/sandboxes ──► provider (sandboxd local | E2B)
        ├──► sandbox exec / files / ports
        ├──► PATCH /runners/jobs/{id}/trace (Content-Range, fence)
        ├──► POST /runners/jobs/{id}/artifacts/authorize + PUT
        └──► PUT /runners/jobs/{id} (state, exit, session ULIDs, fence)
                 │
                 ├──► checks (ci/<job>) ──► gates / merge
                 ├──► webhook `ci` + `check`
                 └──► ci_job_sessions ──► commit / Trail pages

 agent inside sandbox ──► starforge CLI ──► session upload (per-job token)
```

- **Control plane:** `starforged` (API + Core + DB + job queue). New modules: `core/ci.rs`, `core/sandboxes.rs`, `api/ci.rs`, `api/sandboxes.rs`, `api/runner_auth.rs`, `db/ci.rs`, `db/sandboxes.rs`.
- **Runner:** new `crates/starforge-runner` (MIT/Apache): protocol client, job executor, sandbox client. A `starforge runner` subcommand runs it; a standalone binary is also built.
- **Local provider:** new `crates/starforge-sandboxd` (MIT/Apache): HTTP over a Unix socket, token + peer-credential auth, rootless podman, no server-crate dependencies.
- **Protocol crate:** new `crates/starforge-sandbox-protocol` (MIT/Apache): request/response types shared by the server and sandboxd.
- **E2B provider:** server-side adapter using `reqwest`; the API key is sealed in config or a secret row.
- **Agent capture:** the sandbox image ships `git`, `starforge`, and the agent CLI; the runner injects the per-job token and `starforge.server`/`starforge.repo` git config; `starforge sync` uploads before destroy.

## Data model (migrations 0036–0039, both engines)

### 0036_ci_runners.sql

| Table | Columns (essential) |
|---|---|
| `runners` | `id, repo_id, name, token_hash, token_hint, labels TEXT(JSON), ephemeral, paused, max_concurrent, version, last_seen_at, created_at, revoked_at` |
| `runner_registration_tokens` | `id, repo_id, token_hash, labels TEXT(JSON), created_by, expires_at, used_at` |
| `ci_jobs` | `id, repo_id, trail_id?, change_id?, revision_id?, commit_sha, base_sha?, job_name, spec TEXT(JSON), state (queued/claimed/running/succeeded/failed/canceled), runner_id?, attempts, run_at, lease_until?, lease_token?, deadline, exit_code?, checksum?, cancel_requested, created_by, last_error, created_at, started_at?, finished_at?` |
| `ci_job_logs` | `id, job_id, start_offset, end_offset, blake3, created_at` (append-only chunks, ≤100 MiB/job) |
| `ci_artifacts` | `id, job_id, name, size, blake3, sha256?, created_at, expires_at` |
| `ci_job_sessions` | `job_id, session_ulid, created_at` (PK both) |
| `ci_job_tokens` | `id, job_id, token_hash, token_hint, expires_at, revoked_at` |

Also: `ALTER TABLE sessions ADD COLUMN ci_job_id INTEGER REFERENCES ci_jobs(id) ON DELETE SET NULL` + index. Create `ci_jobs` before the `sessions` ALTER inside 0036. Indexes: `ci_jobs(state, run_at)`, `ci_jobs(repo_id, commit_sha)`, `ci_jobs(runner_id, state)`, unique `(repo_id, commit_sha, job_name)` for `state IN ('queued','claimed','running')`, `ci_job_logs(job_id, start_offset)`, `ci_job_tokens(token_hash)`, `sessions(ci_job_id)`.

### 0037_sandboxes.sql

| Table | Columns |
|---|---|
| `sandboxes` | `id, provider, external_id, job_id?, owner_id, repo_id, state (creating/running/paused/killed/error), template, cpu, mem_mb, disk_gb, idempotency_key, metadata TEXT(JSON), created_at, expires_at, last_seen_at` |
| `sandbox_usage` | `id, owner_id, repo_id, window_start, seconds, created_at` |

Unique `(owner_id, idempotency_key)`; index `sandboxes(state, expires_at)`, `sandboxes(job_id)`.

### 0038_ci_secrets.sql

| Table | Columns |
|---|---|
| `ci_secrets` | `id, repo_id, name, sealed_value, created_by, created_at, updated_at`, unique `(repo_id, name)` |

### 0039_ci_usage.sql

| Table | Columns |
|---|---|
| `ci_usage` | `id, repo_id, user_id, window_start, runs, sandbox_seconds, log_bytes, artifact_bytes` |

No new `checks`/`webhooks` tables: CI results reuse `checks`; new webhook events reuse `webhook_deliveries`.

## API surface

All routes are under `/api/v1`, use the `{error:{code,message,details}}` envelope, are wired in `crates/starforged-api/src/lib.rs::router()`, carry a `utoipa::path` attribute, and are listed in `openapi.rs`. They go through Core.

### Runner control plane

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/repos/{owner}/{repo}/runners/registration-token` | PAT `repo:write` + Core ≥Admin | Mint a 1 h one-time registration token (labels, ephemeral) |
| POST | `/runners/register` | registration token (no Bearer) | Register a runner; return `runner_id` + auth token once |
| GET | `/repos/{owner}/{repo}/runners` | PAT `repo:write` + ≥Maintain | List runners (no hashes) |
| DELETE | `/runners/{id}` | PAT `repo:write` + ≥Admin | Revoke a runner |
| POST | `/runners/jobs/request` | `RunnerAuth` | Long-poll (≤50 s) claim: 201 job payload or 204 |
| PATCH | `/runners/jobs/{id}/trace` | `RunnerAuth` + fence | Append log chunk (`Content-Range`), 202/416 |
| PUT | `/runners/jobs/{id}` | `RunnerAuth` + fence | Finish: `{state, exit_code, checksum, session_ulids}` |
| POST | `/runners/jobs/{id}/artifacts/authorize` | `RunnerAuth` + fence | Mint a one-time artifact upload token |
| PUT | `/runners/jobs/{id}/artifacts/{name}` | artifact token | Upload one artifact (size-capped) |
| POST | `/ci/jobs/{id}/git-credential` | `RunnerAuth` + fence | Short-lived repo-scoped git credential |
| GET | `/repos/{owner}/{repo}/ci/runs` | PAT `repo:read` | List runs (keyset `after`/`limit`) |
| GET | `/repos/{owner}/{repo}/ci/runs/{id}` | PAT `repo:read` | Run detail (logs URL, artifacts, sessions) |
| POST | `/repos/{owner}/{repo}/ci/runs` | PAT `repo:write` + ≥Write | Manual trigger `{ref, job?}` |
| POST | `/repos/{owner}/{repo}/ci/runs/{id}/cancel` | PAT `repo:write` + ≥Write | Request cancel |

### Sandbox API (E2B-shaped)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/sandboxes` | PAT `sandbox:run` + `repo_for` (user permission), or `JobAuth` | Create `{template, timeout_s, cpu, mem_mb, disk_gb, envs?, network{allow_out,deny_out,secret_headers}, metadata{job_id,trail_id}, idempotency_key}` |
| GET | `/sandboxes/{id}` | owner/admin or the job's runner | State, expiry, provider |
| DELETE | `/sandboxes/{id}` | owner/admin or the job's runner | Kill |
| POST | `/sandboxes/{id}/pause` / `resume` / `timeout` | owner/admin or the job's runner | Lifecycle |
| POST | `/sandboxes/{id}/exec` | owner/admin or the job's runner | Exec; SSE stdout/stderr + exit code (stream cap) |
| GET/PUT/DELETE | `/sandboxes/{id}/files?path=` | owner/admin or the job's runner | Read/write/list/delete (relative paths only, size-capped) |
| GET | `/sandboxes/{id}/ports/{port}/url` | owner/admin or the job's runner | Signed, short-lived URL |

### Scopes and auth

- Add `Scope::SandboxRun = "sandbox:run"` to `Scope::ALL` (arity 6), `parse_scopes`, `grants` (admin implies all; `repo:write` does **not** imply `sandbox:run`), the token-create UI (`pages/tokens.rs`), the OpenAPI security sweep, and the device-flow scope parser. `starforge auth login` keeps `CLI_SCOPES`; users mint a PAT with `sandbox:run` when they need the sandbox API.
- `RunnerAuth` and `JobAuth` are new extractors in `crates/starforged-api/src/runner_auth.rs`; they do not go through `ApiAuth`/`authenticate_token`. The rate-limit middleware must recognize them and use separate budgets (runner claims are not charged to the PAT 5,000/h bucket; long-poll counts once).
- Add `ApiError::RangeNotSatisfiable` (416) for trace range mismatches; add the OpenAPI response.

### Job spec (`.starforge/ci.toml`)

```toml
version = 1

[triggers]
push = ["main", "release/*"]
trail = ["opened", "updated"]

[[job]]
name = "test"
image = "docker.io/library/rust:1.85"   # or template = "starforge/rust"
commands = ["cargo test --workspace"]
timeout = "30m"
env = { RUST_BACKTRACE = "1" }
secrets = ["CARGO_REGISTRY_TOKEN"]
artifacts = ["target/nextest/**"]
```

Validation: image/template allowlist from config; commands non-empty; timeout ≤4 h; artifacts ≤1 GiB; secret names must exist for the repo and be allowed by the trust rule; no host mounts, privileged, or arbitrary devices; artifact globs must be relative, non-empty, and must not escape the workspace. The spec is read from the commit tree, never the working tree; a malformed spec fails the run with a `ci` check `error` and a clear description. Secret values are never stored in `ci_jobs.spec`.

## Security model

| Threat | Mitigation |
|---|---|
| Untrusted repo code escapes | Sandbox only; rootless containers, no host mounts, dropped caps, no-new-privileges, read-only root, seccomp; gVisor/Firecracker behind the provider protocol |
| Rogue runner / stolen runner token | One-time 1 h registration token, hashed auth token, per-runner revocation, labels/groups scoping, audit; per-claim `lease_token` fence on every trace/result/artifact call |
| Stolen per-job token | Bound to `(job, repo, commit)`, short TTL, revoked at finish; `IngestAuth::CiJob` writes only sessions with that `ci_job_id`; no user `Write` bypass |
| Secret exfiltration by a committer | Secrets only on protected branches / approved Trails by default; per-repo allowlist; egress-proxy header injection; env fallback with scrub; ephemeral sandbox; never in audit/logs; spec stores names only |
| Log injection / split secrets | `Content-Range` validation, 100 MiB cap, ANSI/control stripping, per-chunk idempotency, scrub with an overlap window across chunks, server-side full-log recheck on finish |
| Artifact traversal / swap | Name charset/length rules, relative paths only, size cap, authorize token bound to `(job, name, size, sha256)`, one-time, blob store (no filesystem paths), auth on download, expiry |
| Sandbox file traversal | Relative paths only, no `..`/absolute/symlink following, size caps |
| Sandbox egress widening | Caller cannot widen: the server enforces the repo/org policy and provider allowlist; `secret_headers` only for allowlisted destinations; default-deny |
| Cross-tenant access | Every route goes through Core permission checks; sandboxes are owner/admin or the job's runner; runner claims are repo-scoped |
| Quota exhaustion | Concurrent runs/sandboxes per repo/user, sandbox minutes/hour, log/artifact bytes, runner count; `429` with `Retry-After`; admission inside a transaction/unique constraint |
| Cancel race | `canceled` wins; a late `PUT` with a stale/mismatched fence is `409`; the runner kills the sandbox; GC kills expired sandboxes |
| Replay | One-time claim, lease + fence, job-bound tokens, idempotency keys on sandbox create |
| Blob GC | Logs/artifacts use the CAS blob store with explicit refcount increment/decrement; GC skips live refs |

Audit: runner register/revoke, job cancel, secret create/rotate, sandbox create/kill. Not per-log-chunk or per-status.

## Tasks

### M6-0 — Foundations (before M6a)

- [ ] **F1: `JobPrincipal`.** One type for every CI actor: `{ job_id, user_id, repo_id, commit_sha }`, resolved from `ci_jobs.created_by` (pusher / Trail author / manual caller) and capped to the job's repo and commit. If the user loses read/write access before the job finishes, the job token is revoked and the job fails with `error` ("triggering user lost access"); upload volume counts against that user (or the repo for a system-triggered run). Tests: principal resolution, access-loss revocation, cross-repo denial.
- [ ] **F2: one auth path.** `RunnerAuth` and `JobAuth` extractors beside `ApiAuth`; a shared `CiPrincipal` enum; the rate-limit middleware recognizes all three and keeps separate budgets. Tests: runner/job token accepted only on their routes, PATs unchanged.
- [ ] **F3: internal system paths.** `Core::submit_ci_status(principal, …)`, `Core::mint_git_credential(principal, …)`, and `IngestAuth::CiJob(principal)`; no user `Write` check, but the principal is capped and every path is audited. Tests: system status writes, credential minting, job uploads, denial after access loss.
- [ ] **F4: `ci` webhook event.** Extend `EVENT_TYPES`, `normalize_events`, `check_events`, hook-create docs/tests, OpenAPI, and spec §10.4. Tests: subscribe/deliver/redeliver `ci`.
- [ ] **F5: `sandbox:run` scope plumbing.** `Scope::ALL` (arity 6), `parse_scopes`, `grants` (admin implies all; `repo:write` does not imply it), token-create UI, device-flow scope parser, OpenAPI security sweep. Tests: PAT creation, scope enforcement, no implicit grant.

### M6a — Runner control plane

- [ ] **A0: spec parser/validator.** `.starforge/ci.toml` at the commit SHA; typed `CiSpec`/`CiJobSpec`; limits; clear errors. Tests: valid/invalid specs, path traversal, oversized values, secret names only.
- [ ] **A1: schema + db module.** Add `0036_ci_runners.sql` to both engines (including `sessions.ci_job_id`), and `crates/starforged-db/src/ci.rs` (runners, registration tokens, jobs, logs, artifacts, job-session links, job tokens). Tests: migration parity, unique/dedupe constraints, claim/lease SQL on SQLite and Postgres.
- [ ] **A2: runner auth + registration.** `RunnerAuth` extractor and rate-limit budget; registration tokens (hashed, 1 h, one-time), runner registration (auth token shown once, hashed), list/revoke. API routes + `Scope`/permission checks + OpenAPI `runner_auth`. Tests: token replay, cross-repo registration, revoke, long-poll budget.
- [ ] **A3: claim/lease/fence + job token.** Long-poll claim (`201`/`204`, ≤50 s), labels match, repo scope, lease 60 s renewed by trace/put, per-claim `lease_token`, expired lease requeue (max 3 attempts) then fail. Mint/revoke `ci_job_tokens`; `JobAuth` extractor. Tests: concurrent claims, lease expiry, wrong labels, cross-repo, stale fence.
- [ ] **A4: logs.** `PATCH /runners/jobs/{id}/trace` with `Content-Range`, append-only chunks, 416 on mismatch, 100 MiB cap, control/ANSI stripping, per-chunk idempotency, overlap-window secret scrub + full-log recheck on finish. Tests: ranges, overflow, injection, split-secret scrub, retried chunk.
- [ ] **A5: results + checks + webhooks.** `Core::submit_ci_status` (creator `ci`, no user `Write` check, archived refusal), `PUT /runners/jobs/{id}` writes `ci/<job>` statuses (`pending` at enqueue, `success`/`failure`/`error` at result), emits `ci` webhooks (extend `EVENT_TYPES`, `normalize_events`, `check_events`, hook docs/tests, OpenAPI, spec §10.4) and `check` webhooks, links sessions. Tests: gate with `required_contexts = ["ci/test"]` blocks/permits merge; canceled → `error` description; `ci` hook delivery.
- [ ] **A6: cancel + job GC.** Cancel request, `Job-Status: canceled` on the next trace/put, runner kills the sandbox; canceled-wins + stale-fence `409`; expired jobs GC; audit rows. Tests: cancel race, late result, GC.

### M6b — Sandbox provider API

- [ ] **B1: protocol crate + provider trait + config.** `crates/starforge-sandbox-protocol` (MIT/Apache) wire types; `[sandbox]` config (`provider`, `local.socket`, `local.token_file`, `e2b.api_url`, `e2b.api_key`, limits, default TTL), `#[serde(default)]`, env overrides, docs rows. Server-side provider trait in `starforged-core/src/sandboxes.rs`.
- [ ] **B2: local provider daemon.** New `crates/starforge-sandboxd` (MIT/Apache): Unix-socket HTTP, 0600 token file + `SO_PEERCRED`, rootless podman, image allowlist, no host mounts, dropped caps, no-new-privileges, read-only root, seccomp, cgroup limits, default-deny network, exec/files/kill, TTL. Tests: fake runtime unit tests; a real podman smoke test gated by `STARFORGE_TEST_SANDBOX=1`.
- [ ] **B3: E2B adapter.** `reqwest` client for create/get/kill/exec/files/ports; sealed API key; idempotency; error mapping. Tests: a local fake E2B server (axum) covering create/exec/kill and error paths.
- [ ] **B4: sandbox API.** Routes, `sandbox:run` scope + `repo_for`, owner/admin/job-runner checks, idempotency key, path validation, network policy enforcement, quotas (concurrent, minutes/hour), audit. Tests: auth matrix, quota 429, lifecycle, exec stream cap, file caps, traversal.
- [ ] **B5: sandbox GC + admin UI.** Expired-sandbox GC (moved here from M6a), `/admin/sandboxes` list/kill, run detail link; docs. Tests: page 200/403/404, GC.

### M6c — CI triggers, artifacts, secrets

- [ ] **C1: triggers.** Post-receive push (branch globs), Trail change opened/updated (revision), manual API; `ci_jobs.created_by` is the trigger actor (pusher / Trail author) or the repo owner for manual runs; dedupe per `(repo, commit, job)`; supersede on a new revision when `ci.cancel_superseded = true` (default false for pushes, true for Trail revisions). Tests: trigger matrix, dedupe, supersede, attribution.
- [ ] **C2: artifacts.** Authorize/upload/download, CAS blob store reuse with refcounts, BLAKE3 identity (+ optional client SHA-256), size cap, expiry 30 d, GC. Tests: traversal names, oversize, auth, expiry, blob GC.
- [ ] **C3: secrets.** Sealed repo secrets CRUD (≥Admin) with HKDF `ci-secrets-v1`; trust rule (protected branches / approved Trails; `refs/for` only with `ci.allow_secrets_on_refs_for`); per-job resolution for the runner; egress-proxy header injection (local provider) or env fallback; log scrubbing. Tests: seal/open, no plaintext in DB/logs/spec, cross-repo denial, refs/for denial.
- [ ] **C4: checks/gates/webhooks/UI.** `ci/<job>` statuses via `submit_ci_status`, `ci` webhook event, run pages, gate panel link. Tests: gate integration, webhook payload/signature, page states.
- [ ] **C5: CI integration tests.** Trigger → job → fake runner → status → gate; artifact and secret paths; SQLite + Postgres.

### M6d — Agent-in-sandbox capture + E2B

- [ ] **D1: per-job upload auth.** `IngestAuth::CiJob(JobPrincipal)` in `crates/starforged-core/src/ingest.rs` (job/repo/commit binding, `sessions.ci_job_id`, uploader = `ci_jobs.created_by`), `authorize_session_write` for job tokens, session routes. The job token is revoked when the principal loses access; upload volume counts against the principal. Tests: job token upload, cross-job/cross-repo denial, access-loss revocation, user PAT unchanged.
- [ ] **D2: sandbox image contract.** Document and test the env/mount contract: `HOME`, agent dirs, `STARFORGE_TOKEN`, `starforge.server`/`starforge.repo` git config, repo checkout, git binary, writable spool. Provide `packaging/sandbox/Containerfile` (git + starforge + one agent) and a `packaging/sandbox/README.md`.
- [ ] **D3: CLI in sandbox.** `starforge sync` works with `starforge.server` set and no remote; `sessions link`/trailer links the job's commit; no interactive login. Tests: hermetic sandbox fixture.
- [ ] **D4: runner executor + git credential.** Claim → create sandbox → checkout → run steps → stream logs → `starforge sync` → artifact upload → result; `POST /ci/jobs/{id}/git-credential` or operator deploy key; push the result branch. Tests: fake sandbox provider; failure/timeout/cancel paths.
- [ ] **D5: job↔session links.** `ci_job_sessions` rows from the result; commit/Trail/run pages show the job and its sessions; §6.4 applies. Tests: unreadable session hidden, job page counts.
- [ ] **D6: E2B end-to-end.** Fake E2B server + runner; create/exec/files/kill; a coding-agent fixture uploads a session with the per-job token. Tests: full flow, provider error mapping.
- [ ] **D7: full end-to-end.** A local runner + sandboxd runs a fixture repo's `ci.toml`, streams logs, uploads an artifact, writes a check, and a gate permits merge; the agent session is visible on the commit/Trail. Tests: SQLite + Postgres.

### M6e — Hardening, docs, release

- [ ] **E1: E2B wire-compat alias (optional).** Evaluate `/v2/sandboxes` compatibility with the E2B SDK; add an alias only if a smoke test passes. Otherwise document the mapping.
- [ ] **E2: admin/docs.** Runners/jobs/sandboxes admin pages; `docs/user/ci.md`, `docs/admin/ci.md`, `docs/admin/sandboxes.md`, `docs/format/ci-v1.md`; config table; README/CHANGELOG.
- [ ] **E3: OpenAPI + security tests.** Every route in `lib.rs` + `openapi.rs` (including `runner_auth`/`job_auth` schemes); auth matrix (no token, wrong scope, cross-repo); log injection; artifact traversal; secret leakage; quota; runner replay/fence; sandbox escape assumptions documented.
- [ ] **E4: spec amendment.** Update spec §2/D13/§10.4/§14 to record the additive supersession, the `ci` event, and M6; note external CI remains supported.
- [ ] **E5: release gate.** SQLite + Postgres full gate, browser tests, docs-smoke; release tarballs + image; instance upgrade; CHANGELOG migration table (0036–0039).

## Acceptance criteria

1. A repo admin mints a registration token, registers a runner, and the runner claims a job on push; logs stream; `ci/<job>` appears in the commit status and gate panel; a gate requiring it blocks and then permits merge.
2. A sandbox is created via the API, execs a command, reads/writes a file, and is killed; quotas return 429; the local provider refuses host mounts, privileged requests, and egress widening.
3. A coding agent runs in a sandbox, captures a session, uploads it with the per-job token, and the commit/Trail/run page shows the session; no long-lived PAT is present in the sandbox.
4. The E2B adapter passes the fake-server end-to-end test; the local provider passes the podman smoke test when enabled.
5. Security tests cover runner token replay, stale-fence results, cross-repo claims, log injection, split-secret scrubbing, artifact traversal/swap, secret leakage, and quota exhaustion.
6. SQLite and Postgres suites pass; OpenAPI lists every route and auth scheme; docs and CHANGELOG updated; the spec amendment is committed.

## Open questions (resolve before implementation)

- Runner distribution: `starforge runner` subcommand vs a standalone `starforge-runner` binary; recommended both (library + subcommand, standalone binary from the same crate).
- Sandbox local runtime: rootless podman v1; gVisor/Firecracker after the API stabilizes.
- Secret injection: egress proxy preferred; env fallback. Confirm the local provider can run a proxy sidecar or use the runner as the proxy.
- Artifact storage: CAS blob store with refcounts and a 30 d expiry; confirm quota accounting.
- Whether a CI job may push a branch: recommended runner-pushed only; an agent-requested short-lived git credential is a later extension.
- E2B SDK wire compatibility: verify before promising it; otherwise document the mapping.

## Testing strategy

- Unit/property tests for spec parsing, token hashing, range parsing, quota arithmetic.
- Integration tests in `crates/starforged/tests/` for runner protocol, sandbox API, CI triggers, artifacts, secrets, checks/gates, and agent capture; SQLite + Postgres.
- A fake E2B server and a fake sandbox provider for deterministic tests; a real podman smoke test behind `STARFORGE_TEST_SANDBOX=1`.
- Security corpus: log injection, split secrets, artifact names, token replay, stale fences, cross-repo access, secret scrubbing.
- Browser tests for the admin run/sandbox pages; docs-smoke for the new CLI/runner flow.

## Migration and docs checklist

- [ ] `0036_ci_runners.sql` (incl. `sessions.ci_job_id`), `0037_sandboxes.sql`, `0038_ci_secrets.sql`, `0039_ci_usage.sql` in both engines.
- [ ] `docs/admin/configuration.md` rows for `[ci]`/`[sandbox]`.
- [ ] `docs/user/ci.md` (authoring `.starforge/ci.toml`, runners, artifacts, secrets).
- [ ] `docs/admin/ci.md` (runner registration, sandboxd, E2B, quotas, audit).
- [ ] `docs/format/ci-v1.md` (job spec + result/webhook payloads).
- [ ] README "Known gaps" updated (CI runners are now opt-in, not a non-goal).
- [ ] CHANGELOG migration table 0036–0039.
