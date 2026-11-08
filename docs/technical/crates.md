# Workspace crates

<!-- ste-sources
Cargo.toml
crates/starforge-capture
crates/starforge-cli
crates/starforge-format
crates/starforge-redact
crates/starforge-runner
crates/starforge-sandbox-protocol
crates/starforge-sandboxd
crates/starforged-api
crates/starforged-blob
crates/starforged-core
crates/starforged-db
crates/starforged-git
crates/starforged-index
crates/starforged-ssh
crates/starforged-web
crates/starforged
crates/starforged/src/lib.rs
crates/starforged-core/src/lib.rs
crates/starforge-runner/src/lib.rs
crates/starforge-sandbox-protocol/src/lib.rs
crates/starforge-sandboxd/src/lib.rs
-->
## Purpose

This page lists every crate in the workspace.
The workspace root declares `members` as `crates/*`.
The root file lives at `Cargo.toml`.
Each row states the job, modules, dependencies, and tests.

## Scope

This page covers crate boundaries only.
It does not describe behavior inside each crate.
Linked pages describe the behavior.
The [architecture page](architecture.md) describes the process model.
The [storage and database page](storage-and-database.md) describes stored state.

## Design

Server code and client code have different licenses.
The workspace package license is AGPL-3.0-or-later.
`publish` is false for every server crate.
The seven client crates publish separately.
Those seven crates use MIT OR Apache-2.0.
The split keeps the server under copyleft.

The client format stays reusable by other tools.

Jobs live in `starforged-core`.
No separate jobs crate exists.
`starforged-core/src/jobs.rs` owns the `Job` enum.
`start_workers` spawns the in-process workers.
The `starforged` binary calls `start_workers` at startup.

Dependency direction follows the layer rule.
`starforged-web` depends on `starforged-core`.
`starforged-api` depends on `starforged-core`.
`starforged-ssh` depends on `starforged-core`.
`starforged` depends on every server crate.
`starforged-core` depends on storage crates only.

`starforged-core` also depends on `starforge-sandbox-protocol`.
`starforged-core` depends on `starforged-db`.
`starforged-core` depends on `starforged-git`.
`starforged-core` depends on `starforged-blob`.
`starforged-core` depends on `starforged-index`.

`starforged-core` also depends on the two client crates.
The client crates share Trace Format v1 and redaction rules.

```mermaid
flowchart BT
    starforged --> starforged-web
    starforged --> starforged-api
    starforged --> starforged-ssh
    starforged --> starforged-core
    starforged-web --> starforged-core
    starforged-web --> starforge-format
    starforged-api --> starforged-core
    starforged-ssh --> starforged-core
    starforged-ssh --> starforged-git
    starforged-web --> starforged-git
    starforged-core --> starforged-db
    starforged-core --> starforged-git
    starforged-core --> starforged-blob
    starforged-core --> starforged-index
    starforged-core --> starforge-format
    starforged-core --> starforge-redact
    starforged-core --> starforge-sandbox-protocol
    starforge-cli --> starforge-capture
    starforge-cli --> starforge-format
    starforge-capture --> starforge-format
    starforge-cli --> starforge-redact
    starforge-runner --> starforge-sandbox-protocol
    starforge-sandboxd --> starforge-sandbox-protocol
```

## Interfaces

The table below is the reference for dependency review.
Relevant build files live in each crate directory.

| Crate | Job | Key modules | Main dependencies | Tests |
|---|---|---|---|---|
| `starforge-format` | Trace Format v1 encode | `agent`, `events`, `segments`, `session` | `blake3`, `serde`, `serde_json`, `ulid`, `zstd` | `tests/v1_fixtures.rs` |
| `starforge-redact` | Secret redaction engine | `detectors`, `json`, `rules` | `regex`, `blake3`, `starforge-format` | `tests/corpus.rs` |
| `starforge-capture` | Agent transcript adapters | `adapter`, `agents`, `cursor`, `discover` | `rusqlite`, `starforge-format` | `tests/` golden files |
| `starforge-cli` | `starforge` command client | `api`, `auth`, `cli`, `commands`, `discovery`, `git`, `hooks`, `ingest`, `queue`, `spool`, `upload` | `clap`, `reqwest`, `starforge-capture`, `starforge-format`, `starforge-redact` | `tests/` end to end |
| `starforged-core` | Domain rules and service layer | `accounts`, `ci`, `ci_spec`, `ci_usage`, `ci_usage_depot`, `jobs`, `mail`, `permission`, `ingest`, `sandboxes`, `sandboxes_e2b`, `trails`, `gitaccess`, `metrics` | `starforged-db`, `starforged-git`, `starforged-blob`, `starforged-index`, `starforge-format`, `starforge-redact`, `starforge-sandbox-protocol`, `argon2`, `lettre` | `src/` unit tests |
| `starforged-db` | Relational persistence both engines | `audit`, `changes`, `ci`, `jobs`, `repos`, `sandboxes`, `sessions`, `trails`, `users`, `web_sessions` | `sqlx`, `thiserror` | `src/` unit tests |
| `starforged-git` | Repositories on disk | `blame`, `command`, `diff`, `grep`, `http`, `init`, `merge`, `refpolicy`, `write` | `gix`, `tokio`, `serde` | `src/` unit tests |
| `starforged-ssh` | Git over SSH server | `command`, `server` | `russh`, `starforged-core`, `starforged-git` | `src/` unit tests |
| `starforged-web` | HTML pages and smart HTTP | `auth`, `error`, `githttp`, `highlight`, `markdown`, `pages`, `views` | `axum`, `askama`, `starforged-core`, `starforged-git`, `syntect` | `starforged/tests/` integration |
| `starforged-api` | JSON REST API | `admin`, `auth`, `changes`, `ci`, `ci_auth`, `openapi`, `repos`, `sandboxes`, `sessions`, `trails` | `axum`, `utoipa`, `starforged-core` | `starforged/tests/` integration |
| `starforged-blob` | Content addressed blob store | `BlobStore`, `FsBlobStore`, `BlobError` | `blake3`, `tokio`, `thiserror` | `tests/store.rs` |
| `starforged-index` | Tantivy search index | `SearchIndex`, `TrailDoc`, `EventDoc` | `tantivy`, `thiserror` | `src/` unit tests |
| `starforged` | Server binary and setup | `admin`, `backup`, `config`, `doctor`, `hook`, `index_cmd`, `init`, `restore`, `serve` | `starforged-api`, `starforged-web`, `starforged-ssh`, `starforged-core`, `clap`, `axum` | `tests/` integration |
| `starforge-runner` | CI runner binary and job executor | `Executor`, `Client`, `HttpSandboxProvider`, `FakeSandboxProvider` | `clap`, `reqwest`, `starforge-sandbox-protocol`, `tokio` | `src/` unit tests |
| `starforge-sandbox-protocol` | Shared sandbox wire types | `CreateSandboxRequest`, `ExecRequest`, `FileOp`, `NetworkPolicy`, `SecretValue`, `ProviderError` | `serde`, `serde_json`, `thiserror` | `src/` unit tests |
| `starforge-sandboxd` | Local sandbox daemon | `DaemonState`, `podman`, `proxy`, `forward` | `axum`, `starforge-sandbox-protocol`, `tokio`, `nix` | `src/` unit tests |

`starforge-format` defines `Event` and `SessionMeta`.
`starforge-format` also defines segment split and assemble.
`starforge-capture` normalizes native agent transcripts.
`starforge-capture` passes adapter roots as parameters.
The capture crate reads no environment variables.
The capture crate reads no clock values.

`starforge-cli` ships the `starforge` binary.
The CLI captures sessions and uploads segments.
The CLI manages hooks and the spool queue.
The CLI talks to a server over HTTPS.

`starforged` ships the `starforged` binary.
The library half builds the HTTP app in process.
`crates/starforged/src/lib.rs` exports each module.
Integration tests use that library surface.

`starforge-sandbox-protocol` defines the wire types for sandbox providers.
The wire types include create, exec, file, state, and error types.
The crate depends on no `starforged-*` crate.
`starforged-core` and `starforge-sandboxd` both depend on it.
`starforge-runner` also depends on it.

`starforge-sandboxd` ships the local sandbox daemon binary.
The daemon serves an HTTP control plane over a Unix socket.
The daemon runs rootless podman containers through `podman`.
The daemon runs a per-sandbox egress proxy through `proxy`.
The daemon runs the in-sandbox forwarder through `forward`.
The containers keep `--network none`.

The daemon mounts the per-sandbox egress directory into each container.
The forwarder listens on `127.0.0.1:3128` inside the container.
The forwarder also listens on the Unix socket it creates.
The daemon connects into that socket and keeps 4 idle connections.
The flag `--egress-dir` sets the socket directory.

`starforge-runner` ships the `starforge-runner` binary.
The same executor also runs inside the `starforge` command.
`Executor` claims jobs, runs job commands in a sandbox, and finishes jobs.
`Executor` checks out the commit in place from the claim `clone_url`.
`Executor` falls back to `--repo-url` when the claim omits the URL.
`FakeSandboxProvider` supports tests and dry runs.

`starforged-core` holds the CI control plane in `ci` and `ci_spec`.
`starforged-core` holds sandbox control in `sandboxes` and `sandboxes_e2b`.
`starforged-core` holds CI usage in `ci_usage` and `ci_usage_depot`.
`starforged-api` exposes CI and sandbox routes.
`starforged-web` renders CI pages and admin sandbox pages.
`starforged-db` stores CI and sandbox state.

## Failure behavior

The server never starts from a half wired dependency graph.
`starforged-core` has no upward dependency.
Lower crates never import `starforged-core`.
Any import reversal breaks the dependency direction.
Cargo rejects the import cycle at build time.
The license split isolates permissive client code.

The copyleft boundary sits at the server crate edge.

## Verification

Run the checker in the working directory:

```bash
python3 scripts/ste_check.py docs/technical/crates.md
```

Unit tests live in `src/` for most server crates.
Integration tests live in `crates/starforged/tests/`.
Client integration tests live in each client crate `tests/`.
The `testing` features expose test helpers.
`starforged-core` exposes `mail::testing` through `testing`.
`starforged-db` exposes `testing` helpers through `testing`.

## Related

- [architecture documentation](architecture.md)
- [configuration documentation](configuration.md)
- [storage and database documentation](storage-and-database.md)
- [git hosting documentation](git-hosting.md)
- [sessions documentation](sessions.md)
- [trace and redaction documentation](trace-and-redaction.md)
- [cli documentation](cli.md)
