# CI administration

This guide covers operating Starforge's opt-in CI: runner registration,
the local sandbox daemon, the E2B adapter, quotas, audit, and the
sandbox image contract. For authoring jobs, see
[User: CI](../user/ci.md).

## Runner registration

Runners are per-repository and registered out of band — the server
never executes job code itself.

1. A repo admin (at least Admin) mints a one-time registration token
   (random, hashed, 1 h TTL, repo-scoped):

   ```shell
   curl -X POST "$SERVER/api/v1/repos/$OWNER/$REPO/runners/registration-token" \
     -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"labels": ["linux"], "ephemeral": false}'
   ```
2. On the runner host, exchange the registration token for the runner's
   auth token (no Bearer needed; the registration token is one-time):

   ```shell
   curl -X POST "$SERVER/api/v1/runners/register" \
     -H 'Content-Type: application/json' \
     -d '{"registration_token": "<registration token>", "name": "ci-01", "labels": ["linux"]}'
   ```

   The response carries the runner's auth token once (store it
   securely; it is only ever shown again as a hint). It is hashed
   server-side (`runners.token_hash`) and used by the dedicated
   `RunnerAuth` extractor — not `ApiAuth` — with its own rate-limit
   budget (long-polls count once per request). The registration token
   cannot be reused.

3. Run the runner:

   ```shell
   starforge runner \
     --server "$SERVER" --token "$STARFORGE_RUNNER_TOKEN" \
     --label linux --runtime podman
   ```

   (`--token` also reads `STARFORGE_RUNNER_TOKEN`; `--dry-run` prints
   the execution plan with no network access.)
4. List and revoke from the API (at least Maintain to list, at least
   Admin to revoke):

   ```shell
   curl "$SERVER/api/v1/repos/$OWNER/$REPO/runners" \
     -H "Authorization: Bearer $TOKEN"
   curl -X DELETE "$SERVER/api/v1/runners/$RUNNER_ID" \
     -H "Authorization: Bearer $TOKEN"
   ```

The runner binary is the `starforge runner` subcommand (a standalone
binary is built from the same crate). It long-polls
`POST /runners/jobs/request` (up to 50 s), and per job: mints the
short-lived git credential (`POST /ci/jobs/{id}/git-credential`, or
uses an operator-configured deploy key), creates a sandbox through the
server sandbox API with the per-job token, checks out the commit,
runs the job commands, streams logs (`PATCH /runners/jobs/{id}/trace`
with `Content-Range`), runs `starforge sync` in the sandbox, uploads
artifacts, and finishes (`PUT /runners/jobs/{id}`).

Every trace/result/artifact call carries the per-claim `lease_token`
fence; a stale fence answers `409` and the job is fenced out.
The claim lease is 60 seconds, renewed by trace/put activity. An
expired lease requeues the job (up to 3 attempts), after which the
job fails.

## `starforge-sandboxd`

The local provider is a Rust daemon (MIT OR Apache-2.0, no
`starforged-*` dependencies) serving HTTP over a Unix socket
(default `/run/starforge/sandboxd.sock`). Its control socket is a
`0600` token file (default `/run/starforge/sandboxd.token`, rotating
on restart) plus `SO_PEERCRED` peer-credential checks.

It runs rootless podman containers with no host mounts, dropped
capabilities, `no-new-privileges`, a read-only root, seccomp, cgroup
limits, and default-deny egress. Runtime selection: `podman` (stable
default) or `gvisor` (`runsc`, opt-in). Firecracker and Kata are later
adapters behind the same wire protocol and report as unavailable.
Impossibly-by-design requests (host mounts, privileged, egress
widening) are refused, and sandbox TTLs are enforced.

Server-side configuration (`[sandbox]`, see
[Configuration](configuration.md)):

| Key | Default |
|---|---|
| `sandbox.provider` | `local` (or `e2b`) |
| `sandbox.local.socket` | `/run/starforge/sandboxd.sock` |
| `sandbox.local.token_file` | `/run/starforge/sandboxd.token` |
| `sandbox.local.egress.proxy_listen` | `127.0.0.1:8888` |
| `sandbox.local.egress.ca_dir` | `/run/starforge/sandbox-ca` |
| `sandbox.local.egress.allowlist` | `[]` |
| `sandbox.e2b.api_url` | `https://api.e2b.dev` |
| `sandbox.e2b.api_key` | (sealed; never logged or rendered) |
| `sandbox.limits.max_concurrent_per_user` / `max_concurrent_per_repo` | `0` (disabled) |
| `sandbox.limits.sandbox_seconds_per_hour` | `0` (disabled) |
| `sandbox.default_ttl_secs` | `3600` |

## E2B adapter

The E2B adapter is a server-side Rust `reqwest` client (create / get /
kill / exec / files / ports) with a sealed API key, idempotent create,
and provider error mapping. It sits behind the same provider trait as
the local daemon, so `GET /sandboxes/runtimes` reports the configured
runtimes and their availability, and a job runs on any runtime without
changing the runner. The adapter targets an E2B-shaped gateway, not
`api.e2b.dev`: real E2B uses `/v2/sandboxes` for the control plane and
envd for exec/files/ports, while this adapter's data-plane routes are
Starforge's own REST shape. It is not a wire-compatibility promise.

## Egress proxy and per-sandbox CA

Each sandbox's outbound HTTPS goes through a Rust MITM proxy in
sandboxd. The proxy terminates TLS with a per-sandbox CA whose X.509
name constraints cover only the allowlisted destinations, and installs
that CA in the sandbox trust store (`SSL_CERT_FILE` /
`NODE_EXTRA_CA_CERTS` plus the system bundle). Secret header injection
happens only when the `CONNECT` host matches the secret's binding
host; non-allowlisted hosts are refused, DNS is pinned before connect,
CA keys are `0600` and destroyed with the sandbox, and secret values
never enter the sandbox environment or filesystem.

## Quotas

Admission is enforced in-transaction and answers `429` with
`Retry-After` when exceeded:

- Concurrent sandboxes per user / per repo
  (`sandbox.limits.max_concurrent_per_user`,
  `sandbox.limits.max_concurrent_per_repo`);
- Sandbox-seconds per user per hour
  (`sandbox.limits.sandbox_seconds_per_hour`);
- CI usage (`ci_usage`): runs, sandbox-seconds, log bytes, and
  artifact bytes per repo/user/window;
- Logs cap at 100 MiB per job; artifacts at 1 GiB per job, 30-day
  expiry with CAS-blob GC.

## Audit

Audited actions: runner registration and revocation, job enqueue /
cancel / finish, secret create / rotate / resolve, sandbox create /
kill. Per-log-chunk and per-status events are not audited. Audit
details never carry token hashes, secret values, or sealed material.

## Sandbox image contract

`packaging/sandbox/` builds the reference image every job runs in;
see its README for the exact contract. In short: Alpine + `git` + the
`starforge` CLI + one agent CLI (staged by the operator), non-root
`sandbox` user, workspace `/workspace`, `HOME` / `STARFORGE_HOME` set,
agent stores under `$HOME`, `STARFORGE_TOKEN` carrying only the
per-job token (bound to `(job, repo, commit)`, revoked at finish),
`starforge.server` / `starforge.repo` git config, the per-sandbox CA
in the trust store, and the egress proxy environment. The server
enforces the repo/org policy and provider allowlist — a caller cannot
widen egress or attach secret headers to unlisted destinations.
