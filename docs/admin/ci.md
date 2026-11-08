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
server sandbox API with the per-job token, checks out the job commit in
place from the claim's `clone_url` (`{base_url}/{owner}/{repo}.git`,
falling back to `--repo-url` when the claim omits it) with the git token
as the `x-access-token` password for http and https (`git init`, fetch
the commit, checkout, reset origin to the credential-free URL, exclude
`.starforge-proxy/` — the workspace holds the forwarder), runs the job
commands, streams logs (`PATCH /runners/jobs/{id}/trace` with
`Content-Range`), runs `starforge sync` in the sandbox, uploads
artifacts, and finishes (`PUT /runners/jobs/{id}`). `clone_url` carries
no credentials. The runner never receives repository secret values: the
server resolves them and sends them to the sandbox daemon directly. On
sandbox-create or provider failure the runner writes the scrubbed error
into the job log before finishing the job failed. `POST
/runners/jobs/{id}/secrets` no longer exists; values never reach runners.

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
The egress socket directory and the CA directory are
`starforge-sandboxd` flags, not server config: `--egress-dir` (required
for egress) sets the directory holding one subdirectory per sandbox,
`<dir>/<sandbox id>/` (mode `0777`, removed with the sandbox), mounted
into the container at `/run/starforge/egress` with `:Z`; `--egress-ca-dir`
(default `/run/starforge/egress-ca`) sets the per-sandbox CA directory.
`--egress-listen` no longer exists. The daemon reads only its own flags;
the server only reads `sandbox.local.egress.allowlist`.

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

Each sandbox's outbound traffic goes through a Rust MITM proxy in
sandboxd. Podman create keeps `--network none` and mounts the per-sandbox
directory `<dir>/<id>/` (mode `0777`) into the container at
`/run/starforge/egress` (`--volume <dir>/<id>:/run/starforge/egress:Z`).
The sandbox environment sets `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`,
and `https_proxy` to `http://127.0.0.1:3128` with no `NO_PROXY`, plus
the existing CA variables. The daemon copies its own executable
(`std::env::current_exe()`) into the container at
`/workspace/.starforge-proxy/` with `podman cp` (the binary exceeds
`MAX_FILE_BYTES`, so `file_write` cannot carry it), makes it executable,
and starts the forwarder detached with `podman exec -d` before the
sandbox reports ready:

```shell
starforge-sandboxd forward --listen 127.0.0.1:3128 --unix /run/starforge/egress/shim.sock
```

The forwarder listens on both ports: TCP `127.0.0.1:3128` for sandbox
clients and the Unix socket it creates at
`/run/starforge/egress/shim.sock`. The direction is reversed from a
host-owned socket: SELinux on Fedora/RHEL denies a container process
connecting to a host process's socket, while the host process may
connect to a socket the container creates. The daemon therefore connects
INTO the container's socket and keeps a pool of 4 idle pooled
connections. Each TCP client in the sandbox is paired with one pooled
connection, and the daemon serves that connection under the egress
proxy policy; a used connection is replaced at once. If the pool cannot
connect within 10 seconds, sandbox creation fails. Egress is enabled
only when `--egress-dir` is set. Sandbox file reads and writes use tar
streams through `podman cp`.

The proxy terminates TLS with a per-sandbox CA whose X.509 name
constraints cover only the allowlisted destinations, and installs that
CA in the sandbox trust store (`SSL_CERT_FILE` / `NODE_EXTRA_CA_CERTS`
plus the system bundle). Secret header injection happens only when the
request host matches the secret's binding host; non-allowlisted hosts
are refused, DNS is pinned before connect, CA keys are `0600` and
destroyed with the sandbox, and secret values never enter the sandbox
environment or filesystem. The proxy forwards absolute-form plain HTTP
(`GET http://host[:port]/path HTTP/1.1`, any method) to origin-form
with the same allowlist, denylist, DNS pinning, and secret-header
injection as CONNECT, so plain-HTTP forges work too. Allowlist entries
are `host` (any port) or `host:port` (exactly that port).

Job sandboxes additionally allow the forge `host:port` from the server's
`base_url` (port defaults by scheme), so the runner's in-sandbox
checkout, `starforge sync`, and job downloads reach the forge. The
network policy carries `secret_values` (`host`, `header`, `value` per
entry; `Debug` redacts `value`) from the server, merged with the
daemon's `--secret-binding` flags: a value applies only to a host named in
`secret_headers` and allowed. Only the server may add values — the
daemon refuses any create request that carries `secret_values` from a
caller.

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
longer be downloaded and stops counting toward `ci.limits.artifact_bytes`;
the hourly cleanup deletes its row, and its blob once no unexpired
artifact shares it.

## Audit

Audited actions: runner registration and revocation, job enqueue /
cancel / finish, quota refusals (`ci.job.quota`), supplier link and
unlink (`ci.supplier.link`, `ci.supplier.unlink`), secret create /
rotate / resolve, sandbox create / kill. Per-log-chunk and per-status
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
