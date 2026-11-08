# CI Format v1 — Job Spec and Run Events

Normative specification of `.starforge/ci.toml` (version 1), the run
lifecycle, and the `ci`/`check` webhook payloads. The Rust implementation
is `starforged-core::ci_spec::{CiSpec, CiJobSpec}` and
`starforged-core::ci`; the authoring guide is [CI](../user/ci.md) and the
operator guide is [Admin: CI](../admin/ci.md). The webhook envelope
itself is specified in [Events v1](events-v1.md).

## The spec file

The spec is read from the **commit tree**, never the working tree, so a
commit always runs with the definition it carries. The file is at most
256 KiB. Unknown keys are rejected at every level (`deny_unknown_fields`).

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

| Key | Type | Rules |
|---|---|---|
| `version` | integer | Must be `1`. |
| `triggers.push` | array of globs | Branch globs; at most 100 entries, 256 chars each. Empty/absent disables push runs. |
| `triggers.trail` | array | `opened` and/or `updated`. Empty/absent disables Trail runs. Both trigger lists empty means manual-only. |
| `jobs` (alias `job`) | array of tables | At most 100 jobs; `name` unique. |
| `jobs[].name` | string | 1–64 chars of `[A-Za-z0-9_-]`; the check context is `ci/<name>`. |
| `jobs[].image` / `jobs[].template` | string | Exactly one; 256 chars, validated as an image reference. The local sandbox daemon additionally enforces its image allowlist. |
| `jobs[].commands` | array of strings | Non-empty; at most 100 commands, 4096 chars each; run in order at `/workspace`. |
| `jobs[].timeout` | string | `90s`, `30m`, `1h`, or bare seconds; at most 4 hours. Default 1 hour. Counted from the moment a runner claims the job, so time spent waiting for a runner does not count. |
| `jobs[].env` | table | At most 64 entries; key 128 chars, value 4096 chars. Plain values only. |
| `jobs[].secrets` | array of names | At most 32 names, 128 chars each. Secret **names**, never values; the trust rule is applied at resolution. The optional `host`/`header` binding is set on the secret, not in the spec. |
| `jobs[].artifacts` | array of globs | At most 32; relative, non-empty, no `..`, 256 chars; each artifact at most 1 GiB, retained 30 days. |
| `jobs[].runs_on` | array of labels | At most 16 labels, 64 chars each; empty means any runner for the repo. |
| `jobs[].matrix` | table of arrays | At most 8 keys, 16 values per key, 64 expanded jobs; keys match `[A-Za-z_][A-Za-z0-9_]*`, values 1–4096 chars. Matrix values are added to the job `env` (a matrix value overrides a same-named `env` entry). The expanded name is `<name>-<index>-<key>-<value>...`, sanitized to `[A-Za-z0-9_-]` and at most 64 chars. The whole file expands to at most 256 jobs. |

A malformed or invalid spec fails the run with a `ci/spec` check in state
`error` and a description naming the first validation failure.

## Run lifecycle

One run is one `(repo, commit, job)` row. A push, a Trail `opened`/
`updated`, or a manual trigger enqueues the jobs whose triggers match;
re-triggering the same commit does not duplicate a queued or running job.

| State | Meaning |
|---|---|
| `queued` | Waiting for a runner whose labels match `runs_on`. |
| `claimed` | A runner holds the lease and the per-claim fence. |
| `running` | The runner is streaming logs / executing. |
| `succeeded`, `failed`, `error` | Terminal runner result. |
| `canceled` | Canceled by a user, superseded by a newer Trail revision, or reaped after a cancel request. |

Each run writes the commit status `ci/<job-name>`:

| Transition | Check state | Description |
|---|---|---|
| Enqueue | `pending` | — |
| Finish `succeeded` | `success` | Optional runner checksum. |
| Finish `failed` | `failure` | — |
| Finish `error` | `error` | — |
| User cancel | `error` | `canceled by <handle>` (written at request time, so the gate does not wait for the runner). |
| Supersede | `error` | `superseded by a newer revision`. |
| Lease expiry with attempts left | — | The job returns to `queued`; the check stays `pending`. |
| Lease expiry out of attempts | `failure` | `the runner stopped before finishing`. |
| Timeout passed while still claimed or running | `failure` | `the job exceeded its timeout` (60 seconds after the deadline; the runner normally reports its own timeout first). |
| Native minutes quota used up when the run would be queued | `error` | `the CI minutes quota for this month (<N> minutes) is used up; it resets on <YYYY-MM-DD>`. No job is created and no `ci` event is sent. |

The server sweeps claimed and running jobs every 30 seconds for expired
leases (3 attempts per job) and passed deadlines. A job failed by the
sweep has its job token and git credential revoked; its runner's next
call answers `409`.

A canceled job wins over a late trace or finish. A terminal check is
never overwritten by a later runner acknowledgement.

## Webhook payloads

The `ci` event covers the run lifecycle; the existing `check` event still
covers status transitions. Both use the [Events v1](events-v1.md)
envelope (event name, `action`, `sender`, `at`, and the subject under the
key named by the event).

### `ci`

| `action` | When | `ci.state` |
|---|---|---|
| `queued` | A job is enqueued. | `queued` |
| `started` | A runner claims the job. | `claimed` |
| `finished` | A runner reports `succeeded`/`failed`/`error`. | the terminal state |
| `canceled` | A cancel, supersede, or reaped cancel becomes terminal. | `canceled` |

Subject fields:

| Field | Type | Notes |
|---|---|---|
| `ci_job_id` | integer | The run id. |
| `job_name` | string | The spec job name. |
| `commit_sha` | string | The commit the run is for. |
| `state` | string | See the table above. |
| `runner_id` | integer or null | Set from `started` onward. |
| `exit_code` | integer or null | Present on `finished` when the runner reported one. |
| `created_by` | integer or null | The triggering user (pusher, Trail author, manual caller). |

### `check`

The `check` event carries the usual `sha`, `context`, `state`,
`target_url`, `description`, `creator`, plus `ci_job_id` for a native CI
status. A gate that requires `ci/<job-name>` blocks until the check is
`success`; `failure` and `error` do not satisfy it.

## Runner result

`PUT /api/v1/runners/jobs/{id}` (runner token plus the
`X-Starforge-Fence` header) accepts:

```json
{
  "state": "succeeded",
  "exit_code": 0,
  "checksum": "blake3:…",
  "session_ulids": ["01J…"]
}
```

`state` is `succeeded`, `failed`, or `error`; `exit_code` and `checksum`
are optional; `session_ulids` link captured agent sessions to the run.

While a job runs, the runner renews its 60-second lease with
`POST /api/v1/runners/jobs/{id}/heartbeat` (runner token plus the
`X-Starforge-Fence` header; `204` on success, `409` for a stale fence or
a canceled job). Log traces renew the lease too; the heartbeat covers a
command that produces no output for more than a minute.

## Artifacts

An artifact's run-detail metadata is `name`, `size`, `blake3`, optional
`sha256`, and `expires_at`. The content is addressed by BLAKE3 in the CAS;
no filesystem path is exposed. Uploads authorize first
(`POST /runners/jobs/{id}/artifacts/authorize`, one-time `sfa_` token)
and then PUT the bytes; downloads are authenticated.
