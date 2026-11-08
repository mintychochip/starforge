# CI

Starforge CI is opt-in per repository. A repository with no
`.starforge/ci.toml` behaves exactly as before: external CI keeps
reporting through the commit-status API and webhooks (`POST
/repos/{owner}/{repo}/statuses/{sha}`). When you add the spec below, a
registered runner claims each job, runs it in a sandbox, streams logs,
and writes one check per job named `ci/<job-name>` — which gates can
require, exactly like an external CI context.

## Writing `.starforge/ci.toml`

The spec is read from the commit tree of the repository (never the
working tree), so every commit carries the CI definition it runs with.
A malformed spec fails the run with a `ci/spec` check `error` and a clear
description. The file is at most 256 KiB, holds at most 100 jobs, and
every key must be known — unknown fields are rejected.

```toml
version = 1

[triggers]
push = ["main", "release/*"]
trail = ["opened", "updated"]

[[job]]
name = "test"
image = "docker.io/library/rust:1.85"
commands = ["cargo test --workspace"]
timeout = "30m"
env = { RUST_BACKTRACE = "1" }
secrets = ["CARGO_REGISTRY_TOKEN"]
artifacts = ["target/nextest/**"]
runs_on = ["linux"]
```

- `version` must be `1`.
- `[triggers] push` takes branch globs (`main`, `release/*`); `trail`
  takes `opened` and/or `updated` for Trail changes. Omit a section to
  disable that trigger.
- `[[job]]` (the singular `job` key is an accepted alias) defines one
  job. `name` must be unique in the file. Exactly one of `image` /
  `template` names what runs: an image reference
  (`docker.io/library/rust:1.85`) or a template name
  (`starforge/rust`). The local sandbox daemon only runs images on its
  operator-configured allowlist.
- `commands` is a non-empty list of shell commands, run in order in the
  sandbox at `/workspace`.
- `timeout` is `90s`, `30m`, `1h`, or bare seconds; the default is 1
  hour and the maximum is 4 hours. It counts from the moment a runner
  claims the job, so time spent waiting for a runner does not count; a
  job still running past it fails with `the job exceeded its timeout`.
- `env` injects plain environment variables into the job.
- `secrets` lists secret **names** (never values) for the job. Delivery
  is wired (see [Secrets](#secrets)): a missing or forbidden name
  resolves nothing and is not an error.
- `artifacts` lists globs for files the runner harvests on completion:
  relative paths only, no `..`; each artifact upload is capped at 1 GiB.
- `runs_on` lists runner labels that may claim the job (empty means any
  runner for the repo).
- `matrix` expands one job into one job per combination of its values
  (see [Matrix](#matrix)).

No host mounts, privileged containers, or arbitrary devices are
expressible — a job only ever runs inside its sandbox.

### Matrix

A job can expand into several jobs with `[job.matrix]`:

```toml
[[job]]
name = "test"
image = "docker.io/library/rust:1.85"
commands = ["cargo test"]
[job.matrix]
os = ["linux", "mac"]
rust = ["1.85", "1.90"]
```

This enqueues four jobs. Each expanded job has `os` and `rust` in its
environment and a name like `test-0-os-linux-rust-1-85`. The check
context is `ci/<expanded-name>`. A gate can require one combination or
the base job's combinations. A manual run with `--job test` enqueues
every combination of `test` (never a different job such as
`test-fast`). The spec allows at most 8 keys, 16 values per key, 64
expanded jobs per job, and 256 jobs after expansion in the whole file.

## Triggers

A push to a matching branch, a Trail change opened/updated, or a manual
trigger enqueues the jobs at that commit. One run per `(repo, commit,
job)`: re-triggering the same commit does not duplicate a queued or
running job. A new Trail revision supersedes the change's older active
jobs (queued/claimed/running jobs of older revisions are canceled);
pushes do not. The triggering user (pusher / Trail author / manual
caller) is recorded as the job's creator.

```shell
# Manual trigger (repo:write, at least Write)
curl -X POST "$SERVER/api/v1/repos/$OWNER/$REPO/ci/runs" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ref": "main"}'

# List runs and get one run's detail (logs, artifacts, sessions)
curl "$SERVER/api/v1/repos/$OWNER/$REPO/ci/runs?limit=50" \
  -H "Authorization: Bearer $TOKEN"
curl "$SERVER/api/v1/repos/$OWNER/$REPO/ci/runs/$JOB_ID" \
  -H "Authorization: Bearer $TOKEN"

# Request cancellation
curl -X POST "$SERVER/api/v1/repos/$OWNER/$REPO/ci/runs/$JOB_ID/cancel" \
  -H "Authorization: Bearer $TOKEN"
```

Each run writes a `ci/<job-name>` commit status (`pending` at enqueue,
`success` / `failure` / `error` at the end; a canceled job writes
`error` with description `canceled by <user>`) and emits the `ci`
webhook event, so gates and hooks react to native CI the same way they
react to external CI.

## Runners

A runner is a machine the repo admin registers (see
[Admin: CI](../admin/ci.md)). Jobs only run when a runner whose labels
match `runs_on` is online; otherwise they stay queued. The runner
itself is what an agent session inside a job uploads with: the agent
runs in the sandbox image (`packaging/sandbox/`), and
The runner puts the per-job token in `STARFORGE_TOKEN` and sets the
`starforge.server` / `starforge.repo` git config, so `starforge sync`
there needs no interactive login and no long-lived PAT. The session
appears on the commit / Trail / run page. The egress proxy forwards
HTTPS `CONNECT` only, so use an `https://` server and repo URL; a plain
`http://` origin or a non-443 port is not proxied.

## Artifacts

Files matching a job's `artifacts` globs are uploaded after a
successful run (authorize-then-PUT, download authenticated). Artifacts
expire after 30 days; an expired artifact can no longer be downloaded.
Expired artifacts are deleted by the hourly cleanup. Artifact names
must be relative and stay inside the workspace.

## Secrets

Repo secrets are created and rotated by repo admins (at least Admin).
In the web UI, open the repository's **CI secrets** settings page
(`/{owner}/{repo}/settings/ci-secrets`): it lists each secret's name,
proxy host and header, redaction flag, and timestamps; it adds or rotates
a secret and deletes one. A rotate with blank Host and Header keeps the
existing proxy binding. Values stay write-only there, exactly as with the
API below.
```shell
curl -X POST "$SERVER/api/v1/repos/$OWNER/$REPO/ci/secrets" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name": "CARGO_REGISTRY_TOKEN", "value": "…", "host": "crates.io", "header": "Authorization"}'
curl "$SERVER/api/v1/repos/$OWNER/$REPO/ci/secrets" \
  -H "Authorization: Bearer $TOKEN"
curl -X DELETE "$SERVER/api/v1/repos/$OWNER/$REPO/ci/secrets/CARGO_REGISTRY_TOKEN" \
  -H "Authorization: Bearer $TOKEN"
```

Values are sealed (XChaCha20-Poly1305) and never stored or logged in
plaintext; the spec carries names only. Secrets resolve only for runs
on protected branches or approved Trails; `refs/for` runs get none
unless the repository opts in (see below). A missing or forbidden
name resolves nothing and is not an error.

Each secret accepts optional `host` and `header` fields on create.
`host` is an exact DNS name (lowercase, no scheme, port, or wildcard);
`header` is a safe request header (hop-by-hop names are rejected).
`host` defaults to empty and `header` defaults to `Authorization`.
List and resolve responses include both fields. A secret with an
empty host is not proxy-injected; it still registers for session
redaction. Values never enter the sandbox environment or filesystem
on the local provider — the egress proxy injects them as headers for
the bound host only. A secret's value is registered for dynamic
redaction in the job's sessions, so it cannot appear in session text,
logs, or search results.

A repository Admin sets the per-repository secret policy with
`PATCH /api/v1/repos/{owner}/{repo}`:

```shell
curl -X PATCH "$SERVER/api/v1/repos/$OWNER/$REPO" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ci_allow_secrets_on_refs_for": true, "ci_env_secrets": false}'
```

Both fields default to off. `ci_allow_secrets_on_refs_for` lets
`refs/for` runs resolve secrets. `ci_env_secrets` is an E2B-only
opt-in: with it on, the E2B provider injects the values as
environment variables instead of through the proxy. Delivery is
wired: the runner resolves a job's secrets after its git credential,
adds the values to its log-scrub list, and the server resolves secrets
for a job-token sandbox create and passes the bindings to the local
daemon, which injects only for the named host and header.

## Usage and quotas

Who meters CI usage and enforces its limits depends on who runs the
compute:

- **Native runners** (registered with Starforge): Starforge meters each
  job attempt's runner time and the repository's unexpired artifacts. The
  server operator may set quotas (`[ci.limits]`): when the month's runner
  minutes are used up, new runs are not queued and the job's `ci/<job>`
  check says why and when the quota resets (an existing check on that
  commit is left as it is); an artifact upload past the storage quota is
  refused. The minutes quota is best-effort: an attempt's minutes count
  when it ends, so runs already queued or running when it fills still
  finish and count toward it.
- **Depot**: a repository admin links the repository to its name in
  Depot (`owner/name`). Starforge then reads that repository's usage from
  Depot's API. Depot's plan allowances and usage caps apply and are
  enforced by Depot; Starforge does not limit Depot work.

```shell
# This month's usage per supplier (at least Maintain)
curl "$SERVER/api/v1/repos/$OWNER/$REPO/ci/usage" \
  -H "Authorization: Bearer $TOKEN"

# Link (or relink) the repository to Depot (at least Admin)
curl -X PUT "$SERVER/api/v1/repos/$OWNER/$REPO/ci/suppliers/depot" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"external_ref": "acme/app"}'

# Unlink
curl -X DELETE "$SERVER/api/v1/repos/$OWNER/$REPO/ci/suppliers/depot" \
  -H "Authorization: Bearer $TOKEN"
```

Each supplier's report lists metrics with `used` and, when Starforge
enforces one, `limit`; `enforced_by` says who enforces the limits.
Native metrics are `runner_minutes`, `attempts`, and `artifact_bytes`;
Depot metrics are `depot_ci_vcpu_minutes`, `depot_ci_minutes`,
`depot_ci_attempts`, `github_actions_minutes`, and `github_actions_jobs`
for the linked repository. If Depot cannot be reached, its report carries
an `error` and the native report is unaffected. Maintainers also see the
report on the repository's CI page (**Usage this month**).

The normative spec — limits, run states, check descriptions, and the
`ci`/`check` webhook payloads — is [CI Format v1](../format/ci-v1.md).
