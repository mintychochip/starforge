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
with `Content-Range`), runs `starforge sync` in the sandbox with the
per-job token in `STARFORGE_TOKEN` and the `starforge.server` /
`starforge.repo` git config, uploads artifacts, and finishes
(`PUT /runners/jobs/{id}`).

Every trace/result/artifact call carries the per-claim `lease_token`
fence; a stale fence answers `409` and the job is fenced out.
The claim lease is 60 seconds, renewed by trace activity and by the
runner's 30-second heartbeat (`POST /runners/jobs/{id}/heartbeat`, same
fence; `204`, or `409` for a stale fence or a canceled job), so a quiet
command cannot let the lease expire. The server sweeps claimed and
running jobs every 30 seconds: an expired lease requeues the job (up to
3 attempts), after which the job fails, and a job still running 60
seconds past its timeout (counted from the claim) is failed and its
credentials revoked.

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
| `sandbox.local.egress.allowlist` | `[]` |
| `sandbox.e2b.api_url` | `https://api.e2b.dev` |
| `sandbox.e2b.api_key` | (sealed; never logged or rendered) |
| `sandbox.limits.max_concurrent_per_user` / `max_concurrent_per_repo` | `0` (disabled) |
| `sandbox.limits.sandbox_seconds_per_hour` | `0` (disabled) |
| `sandbox.default_ttl_secs` | `3600` |

The egress directory and the CA directory are `starforge-sandboxd`
flags, not server config: `--egress-dir` (required for egress) holds one
subdirectory per sandbox, `<dir>/<id>/` (mode `0777`, removed with the
sandbox), mounted into the container at `/run/starforge/egress` with
`:Z`; `--egress-ca-dir` (default `/run/starforge/egress-ca`) sets the
per-sandbox CA directory. One more sandboxd flag widens egress:
`--egress-allow-cidr CIDR` (repeatable) allows one special-use address
range per occurrence. Without it the proxy refuses every special-use
address except the forge's own `host:port`. The daemon reads only its
own flags; the server only reads `sandbox.local.egress.allowlist`.

## Egress proxy and per-sandbox CA

Each sandbox's outbound traffic goes through a Rust MITM proxy in
sandboxd. The proxy terminates TLS with a per-sandbox CA whose X.509
name constraints cover only the allowlisted destinations, and installs
that CA in the sandbox trust store (`SSL_CERT_FILE` /
`NODE_EXTRA_CA_CERTS` plus the system bundle). Secret header injection
happens only when the request `Host` (and, for absolute-form requests,
the request authority) matches the secret's binding host; a mismatch
answers `403`. Non-allowlisted hosts are refused, DNS is pinned before
connect, CA keys are `0600` and destroyed with the sandbox, and secret
values never enter the sandbox environment or filesystem.

Sandboxes keep `--network none`. The daemon mounts the per-sandbox
egress directory at `/run/starforge/egress` (`:Z`), copies its own
binary into `/workspace/.starforge-proxy/sandboxd`, and starts it
detached:

```shell
starforge-sandboxd forward --listen 127.0.0.1:3128 --unix /run/starforge/egress/shim.sock
```

The forwarder listens on `127.0.0.1:3128` for sandbox clients and
creates the Unix socket. The host daemon connects into that socket and
keeps a pool of four idle connections; each sandbox TCP client is
paired with one pooled connection. SELinux denies a container process
connecting to a host-owned socket, while the host may connect to a
socket the container creates. The sandbox gets `HTTP_PROXY`,
`HTTPS_PROXY`, `http_proxy`, and `https_proxy` set to
`http://127.0.0.1:3128`, plus the CA variables. The daemon must be a
static binary because it runs inside the sandbox; the release musl
binary is.

The image must provide `/bin/sh`, `mkdir`, `chmod`, and `realpath -m`
(the daemon runs them inside the container), and a writable and
executable `/workspace`. The sandbox image README lists the full
contract.

The proxy forwards HTTPS `CONNECT` and absolute-form plain HTTP to
allowlisted hosts. A bare `host` allowlist entry permits ports 80 and
443 only; a `host:port` entry permits exactly that port.
`--egress-https-port` adds a private HTTPS port. The daemon sets
`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and `GIT_SSL_CAINFO` to the
per-sandbox CA, and `--egress-upstream-ca` trusts a private upstream
CA. With egress disabled the container stays `--network none`. Secret
values never enter the sandbox.

After DNS resolution the proxy dials only addresses that pass the
policy. Loopback, private, link-local, CGNAT, multicast, reserved, and
unique-local addresses (and their IPv4-mapped forms) are refused, even
for an allowlisted name or IP literal. The only exceptions are the
forge's own `host:port` (declared by the server per job sandbox) and
ranges the operator allows with the repeatable sandboxd flag
`--egress-allow-cidr CIDR`. A repository secret bound to an internal
host therefore needs that host's range in `--egress-allow-cidr`.

A Trail job gets secrets only after an approval of its own revision. The
runner fetches with the credential URL without storing it in git config,
and the sandbox's workspace volume is removed with the sandbox.

For a job-token sandbox create, the server resolves the job's
secrets itself, records them in `ci_job_secrets`, and passes the
host/header/value bindings to the local daemon over the Unix socket
(never into the sandbox). The daemon injects a value only when the
request's `secret_headers` names the same host and header. The
runner also resolves after its git credential and adds the values to
its log-scrub list.

### Repository secret policy

A repository Admin sets two policies with
`PATCH /api/v1/repos/{owner}/{repo}`, for example
`{"ci_allow_secrets_on_refs_for": true, "ci_env_secrets": false}`
(the body may also carry `refs_for_access`). Both default to off.
`ci_allow_secrets_on_refs_for` opts `refs/for` runs in to secret
resolution. `ci_env_secrets` is an E2B-only opt-in: only the E2B
provider injects values as environment variables. Each secret binds
delivery with `host` (default empty) and `header` (default
`Authorization`). An empty host is not proxy-injected but still
registers for session redaction. Changes are audited as
`ci.secret.policy` (values only, never secret material).

## Quotas

Sandbox quotas answer `429` with `Retry-After` when exceeded:

- Concurrent sandboxes per user / per repo
  (`sandbox.limits.max_concurrent_per_user`,
  `sandbox.limits.max_concurrent_per_repo`);
- Sandbox-seconds per user per hour
  (`sandbox.limits.sandbox_seconds_per_hour`).

CI usage and its limits belong to whoever runs the compute:

- **Native runners.** Starforge meters each job attempt's runner
  wall-clock time, recorded in `ci_usage` when the attempt ends (finish,
  cancel, lease expiry, timeout, or runner revocation), and the
  repository's unexpired artifacts. It enforces `[ci.limits]` per
  repository: `minutes_per_month` (calendar month, UTC) when a run is
  queued — a refused run gets an `error` `ci/<job>` check naming the reset
  date unless the commit already has that check, and a manual trigger
  answers `422` — and `artifact_bytes` when an upload is authorized and
  again when its bytes arrive (`422`). The minutes quota is best-effort:
  an attempt counts when it ends (a reaped attempt at its lease end), so
  runs already queued or running when it fills still finish and count.
- **Depot.** A repository admin links the repository
  (`PUT /api/v1/repos/{owner}/{repo}/ci/suppliers/depot` with its Depot
  name, `owner/name`). Starforge reads its usage from Depot's
  `depot.core.v1.UsageService/GetUsage` with the organization token in
  `ci.depot.api_token`. Depot's API exposes no limits: plan allowances and
  usage caps are set and enforced in Depot, and Starforge only reports.

Per-item caps apply to every run: logs cap at 100 MiB per job;
artifacts at 1 GiB each, with a 30-day expiry. An expired artifact can no
longer be downloaded and stops counting toward `ci.limits.artifact_bytes`.
The hourly cleanup deletes expired artifact rows (up to 1000 per pass)
and collects zero-ref blobs.

## Audit

Audited actions: runner registration and revocation, job enqueue /
cancel / finish, quota refusals (`ci.job.quota`), supplier link and
unlink (`ci.supplier.link`, `ci.supplier.unlink`), secret create /
rotate / resolve, secret policy change (`ci.secret.policy`), sandbox
create / kill. Per-log-chunk and per-status
events are not audited. Audit details never carry token hashes, secret
values, or sealed material.

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
