# Reference sandbox image

`Containerfile` in this directory builds the reference image a CI job's
coding agent runs in: Alpine with `git`, the `starforge` CLI, and one
agent CLI (Pi), as the non-root `sandbox` user, with the repository
checked out at `/workspace`. It is the image contract the runner and
`starforge-sandboxd` build on; the server never runs it — runners and
sandboxes are external processes (plan decision 3).

## Contents

| Component | Source |
|---|---|
| Base | `docker.io/library/alpine:3` |
| `git`, `ca-certificates`, `bash`, `zstd` | `apk` |
| `starforge` binary | The static musl release tarball from `scripts/build-release.sh` (same artifact and layout as the server image in the repo root) |
| `pi` agent binary | **Staged by the operator** into `target/agent-bin/pi` before the build — Starforge does not build or vendor the agent |

No secrets, credentials, or registry tokens are baked in. The image must
stay buildable and publishable with no access to any Starforge server.

## Build

```shell
scripts/build-release.sh            # builds the starforge tarballs
mkdir -p target/agent-bin
install -m 0755 /path/to/pi target/agent-bin/pi
podman build --build-arg STARFORGE_TARGET=x86_64-unknown-linux-musl \
  -t starforge-sandbox:0.1.0-pre.1 -f packaging/sandbox/Containerfile .
```

## Runtime contract

Everything below is set by the runner / `starforge-sandboxd` at sandbox
creation, not by the image. The image only guarantees the layout and the
tools that consume it.

| Name | Value / source | Purpose |
|---|---|---|
| User | `sandbox` (non-root) | All job commands run unprivileged; no host mounts, dropped capabilities, read-only root, seccomp (enforced by sandboxd, not the image) |
| Workspace | `/workspace` (volume) | The repository checkout; the runner clones/checks out the job's commit here |
| `HOME` | `/home/sandbox` | Agent stores and git config live here (see below) |
| `STARFORGE_HOME` | `/home/sandbox/.starforge` | CLI state root; agent capture roots derive from it unless overridden per-agent |
| Agent dirs | `$HOME/.pi/agent/sessions/` (Pi; omp shares the Pi adapter) | `starforge sync` ingest discovers native transcripts here. Other adapters resolve under the same base: `.claude/projects/`, `.codex/sessions/`, `.gemini/tmp/`, `.local/share/opencode` / `.config/opencode` |
| `STARFORGE_TOKEN` | Per-job token, injected by the runner | Authenticates `starforge sync` uploads. Bound to `(job, repo, commit)`, TTL = job deadline + 10 min, revoked at finish. It is the **only** credential in the sandbox — no long-lived PAT, no stored credentials file, no interactive login |
| `starforge.server` | `git config` in the checkout | Server origin `starforge sync` uploads to. Wins outright in server resolution — no remote is probed or needed |
| `starforge.repo` | `git config` in the checkout | `owner/repo` the uploads are scoped to |
| Writable spool | `<git-common-dir>/starforge/sessions/` | Where `starforge sync` spools and records uploads before the sandbox is destroyed |
| Proxy env | `HTTPS_PROXY` / `https_proxy` / `HTTP_PROXY` / `http_proxy` = `http://127.0.0.1:3128` | The in-sandbox forwarder. The sandbox has `--network none` and no other route |
| Egress forwarder | `/workspace/.starforge-proxy/sandboxd` (copied by sandboxd), `/run/starforge/egress` (mounted) | The daemon copies its static binary in and starts `forward`; the host connects into its socket with a connection pool |
| CA trust | `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, and `GIT_SSL_CAINFO` → `/workspace/.starforge-proxy/ca.pem`, plus the system bundle | The per-sandbox CA, installed by sandboxd into the trust store so TLS verifies inside the sandbox. CA keys live on the daemon host (`0600`) and are destroyed with the sandbox |

`starforge sync` in the sandbox needs no interactive login: the token
comes from the environment, the server and repo from git config, and
discovery (the well-known document) is anonymous. The hermetic proof is
`crates/starforge-cli/tests/sandbox_sync.rs`.

## What the image never contains

- Repo secrets — they reach the sandbox only as egress-proxy header
  injection for allowlisted destinations (or, with the explicit per-repo
  opt-in `ci.env_secrets`, as environment variables for providers
  without a proxy). Values never enter the image, env, or filesystem by
  default.
- The runner token, registration tokens, or any long-lived PAT.
- A git remote pointing at the server: `starforge.server` replaces it,
  so the checkout works with no remote configured.
