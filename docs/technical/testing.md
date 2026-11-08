# Testing

<!-- ste-sources
scripts/check.sh
.github/workflows/ci.yml
crates/starforged-db/src/testing.rs
crates/starforged/tests/common/mod.rs
crates/starforged/tests/e2e_binary.rs
crates/starforged/tests/api_ci_jobs.rs
crates/starforged/tests/api_ci_runners.rs
crates/starforged/tests/api_ci_runs.rs
crates/starforged/tests/api_ci_usage.rs
crates/starforged/tests/api_sandboxes.rs
crates/starforged/tests/ci_e2e.rs
crates/starforged/tests/ci_security.rs
crates/starforged/tests/web_ci.rs
scripts/browser-tests.sh
scripts/docs-smoke.sh
scripts/build-release.sh
scripts/ci-e2e.sh
scripts/https_proxy.py
tests/browser/playwright.config.ts
-->

## Purpose

This page describes the test layers in the Starforge workspace. It explains what each layer proves and what each layer does not prove. It covers the local gate, the continuous integration jobs, the browser suite, and the release artifacts.

## Scope

This page covers the Rust test suite, the Playwright browser tests, the docs smoke script, and the release build scripts. It does not cover the checker for the technical documents. It does not cover server startup or production operations.

## Test layers

The workspace has seven test layers. The table lists each layer and its home directory.

| Layer | Home |
|---|---|
| Unit tests | Inside every `src/` tree with `#[cfg(test)]` |
| Property tests | `proptest` cases in format, core, and git crates |
| Integration tests | `crates/starforged/tests/` and `crates/starforge-cli/tests/` |
| Binary end-to-end tests | `e2e_binary.rs` in the server and CLI crates |
| Golden adapter tests | `crates/starforge-capture/tests/` |
| Browser tests | `tests/browser/` |
| Docs smoke test | `scripts/docs-smoke.sh` |

Unit tests live inline in source files. Crates without a `tests/` directory rely on these tests. Most cover small pure functions and state machines. They do not replace cross-crate request tests.

Property tests use the `proptest` crate, version 1.12.0. The workspace defines the dependency in `Cargo.toml`. Cases live in `starforge-format/src/segments.rs`, `starforged-core/src/permission.rs`, `starforged-core/src/read.rs`, and `starforged-git/src/refpolicy.rs`. The format crate also holds ULID round-trip cases in `starforge-format/tests/v1_fixtures.rs`. Contract tests live in `crates/starforge-redact/tests/corpus.rs` and `crates/starforged-blob/tests/store.rs`.

Integration tests exercise the full server in process. The server crate holds about 113 test files. The CLI crate holds 17 test files. The capture crate holds 7 test files. They cover the API, the web interface, search, mirrors, import, backup, and SSH git transport.

M6 adds `api_ci_jobs.rs`, `api_ci_runners.rs`, `api_ci_runs.rs`, `api_ci_usage.rs`, and `api_sandboxes.rs`. M6 also adds `ci_e2e.rs`, `ci_security.rs`, and `web_ci.rs` for CI and sandbox behavior. Unit tests in `crates/starforged-core/src/ci.rs` and `crates/starforged-core/src/ci_spec.rs` cover job specs and usage metering.

Binary end-to-end tests spawn real binaries. The server test file is `crates/starforged/tests/e2e_binary.rs`. The CLI test file is `crates/starforge-cli/tests/e2e_binary.rs`. They prove the process boundary, not just the library boundary.

The real CI end-to-end test is `scripts/ci-e2e.sh`. It starts a server, the runner, `starforge-sandboxd`, and rootless podman. It runs a fixture `.starforge/ci.toml`, clones and syncs through the per-sandbox egress proxy over HTTPS, and checks the artifact and the linked session. `scripts/https_proxy.py` is the local HTTPS origin it uses. The script runs only when `STARFORGE_TEST_SANDBOX` equals `1`.

Golden adapter tests prove per-agent parsing. Each adapter has one test file in `crates/starforge-capture/tests/`. The adapters are `claude`, `codex`, `gemini`, `opencode`, and `pi`. The `fixtures/` directory holds one directory per agent and version. Each fixture holds `transcript.*`, `expected.jsonl`, and `meta.json`.

## Test harness

`crates/starforged-db/src/testing.rs` holds `TestDb`. `TestDb::new()` creates a throwaway database for every test. It reads `STARFORGE_TEST_PG_URL`. When the variable holds a Postgres URL, it creates a fresh database named `sf_test_<hex>` in Postgres. Otherwise it creates a SQLite file in a temp directory. It always connects and runs migrations in `Db::connect` and `migrate`.

`create_empty_pg_database()` returns a fresh empty Postgres database. It panics when `STARFORGE_TEST_PG_URL` is unset. Restore tests use it as their target database.

`crates/starforged/tests/common/mod.rs` holds `TestServer`. `TestServer` runs the server in process. It binds `127.0.0.1:0` for a random port. It uses a temp data directory. It uses a random SSH port. Rate limits stay zeroed, because suites sign in dozens of users from `127.0.0.1`.

The harness also holds three helpers. `fake_github.rs` stubs GitHub. `fake_oidc.rs` stubs OIDC. `pg_shims.rs` runs Postgres client commands inside a test container. The container name comes from `STARFORGE_TEST_PG_CONTAINER`.

The harness keeps test state in temp directories. Git helpers disable system and global git configuration with `GIT_CONFIG_NOSYSTEM` and `GIT_CONFIG_GLOBAL`. They do not clear `HOME`, and the tests write no state there.

## What each layer proves

The unit layer proves small invariants. It proves pure functions return the right values. It proves state machines reject bad transitions. It does not prove cross-crate behavior.

The property layer proves invariants against many generated inputs. It proves permission math takes the maximum source. It proves refname classification matches the policy. It proves segment serde round-trips. It does not prove server integration.

The integration layer proves the full request path. It proves the API, the web interface, and git transport work with a real database. It proves the SQL and the migrations pass on both engines. It does not prove real binary startup or real process signals.

The binary layer proves the process boundary. It proves `starforged init` and `starforged serve` work as a user runs them. It proves the CLI commits carry the `Starforge-Session:` trailer. It proves redaction replaces secrets with fingerprints. It proves a second sync sends zero requests.

The golden layer proves adapter fidelity. It proves each agent format parses into the right events. It proves unknown formats stay unverified. It does not prove the trace viewer renders correctly.

The browser layer proves rendered behavior. It proves keyboard flow in the session viewer. It proves split view swaps commits without navigation. It proves the merge gate blocks and then permits a merge. It does not prove Rust unit behavior.

The docs smoke layer proves the documented quickstart. It builds both binaries fresh. It runs init, serve, push, clone, device sign-in, and Trail push. It does not belong to continuous integration.

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `next` and `main` and on pull requests. The runner is `ubuntu-24.04`. The workflow has six jobs.

| Job | Command |
|---|---|
| `fmt` | `cargo fmt --all -- --check` |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `test-sqlite` | `cargo test --workspace` |
| `test-postgres` | `cargo test --workspace` with `STARFORGE_TEST_PG_URL` |
| `docs` | `python3 scripts/ste_check.py --strict` and the checker unit tests |
| `browser` | `scripts/browser-tests.sh` with Node 22 and Chromium |

The Postgres job uses a service container with image `postgres:17`. It maps port 5432. It sets `STARFORGE_TEST_PG_URL` to `postgres://postgres:starforge@127.0.0.1:5432/postgres`. The browser job installs Python packages `zstandard` and `blake3`. It runs `npm ci` and Playwright with Chromium. Then it runs `scripts/browser-tests.sh`.

The local gate is `scripts/check.sh`. It runs the format check, the clippy gate, and the workspace tests. It runs the document checker and the checker unit tests. With `STARFORGE_TEST_PG=1`, it also starts a Postgres 17 container and reruns the suite against Postgres.

The Postgres container needs `--shm-size=1g`. Hundreds of concurrent migrations drain the 64 MiB default `/dev/shm`. The wait loop polls `pg_isready` up to 60 times at 0.5 second intervals. A trap stops the container on exit.

Dual-engine parity is mandatory. The same suite must pass on SQLite and on Postgres 17. SQLite-only backup tests return early under Postgres. Postgres-only tests print `SKIP` when `STARFORGE_TEST_PG_URL` is unset.

## Browser tests

`tests/browser/` holds the Playwright suite. `playwright.config.ts` pins Chromium as the only project. The config sets `workers: 1` and `retries: 0`. It sets a 120 second timeout.

The base URL is `STARFORGE_BROWSER_BASE_URL` when set. Otherwise it comes from the `baseUrl` value in the `SEED_MANIFEST` file, default `.seed-manifest.json`. Otherwise it falls back to `http://127.0.0.1:4177`.

`package.json` pins `@playwright/test` 1.63.0 and Node 22 or newer. `scripts/browser-tests.sh` builds `starforged`. It starts it on a free port with a temp data directory. It disables SSH with `STARFORGE__SSH__ENABLED=false`. It polls `/healthz` for health, then runs `seed.py`.

`seed.py` creates users `alice` and `bob` through the admin CLI. It creates a repository through the API. It performs a real git push. It ingests a session. It creates a Trail and a change. The harness writes the base URL and seed data into `.seed-manifest.json`.

`viewer.spec.ts` holds 4 tests. Keyboard `Tab` reaches the search box. Search highlights hits. Search results include a `#turn-` link. A `mark` element highlights text.

A `details` element expands a tool call. Split view swaps commits through the ES module without navigation. One test checks the page stays complete with JavaScript disabled.

`merge.spec.ts` holds 1 test. Gates first show `Gates failing` and `Approvals: 0`, with merge disabled. Bob then approves. The page then shows `All gates pass`. Alice then merges with the `merge` method. Both badges show `merged` on the change and the Trail.

## Docs smoke test

`scripts/docs-smoke.sh` runs the documented quickstart end to end. It builds both binaries on every run. A stale binary must never pass. It uses absolute binary paths, because the script changes directory into a temp workdir. It probes a free port for the server.

The script runs `init`, then `admin user create`, then `serve`. It polls `/healthz` for health. It creates an admin token. It creates a repository through the API. It pushes and clones over HTTP. It runs the CLI device flow and approves it through the web with a CSRF cookie jar.

It pushes a Trail change. It checks the Trail through the API. A trap cleans up the server and the sign-in processes.

## Release artifacts

`scripts/build-release.sh` builds static tarballs. It requires `cargo`, `zig`, and `cargo-zigbuild`. It builds `x86_64` and `aarch64` musl targets. It builds the `starforged` and `starforge-cli` packages.

It writes deterministic tarballs into `target/release-artifacts/`. It also writes `SHA256SUMS`. It deletes stale artifacts first.

`dist-workspace.toml` configures cargo-dist 0.34.0. Releases contain only the CLI. Every server crate sets `dist = false`. Installers are `shell`, `homebrew`, and `msi`. Targets are linux-gnu, apple-darwin, and windows-msvc, each for `x86_64` and `aarch64`.

`.github/workflows/release.yml` runs on version tags and pull requests. The `plan` job computes the artifact matrix. The `build-local-artifacts` and `build-global-artifacts` jobs build artifacts. The `host` job creates the GitHub release. The `announce` job performs no release action.

## Running a subset

Run one crate with `cargo test -p <crate>`. Run one test file with `cargo test --test <name>`. Run one test by name with `cargo test <name>`. Use `-- --nocapture` to see test output.

Six environment variables select test engines and harnesses:

| Variable | Effect |
|---|---|
| `STARFORGE_TEST_PG` | Selects the Postgres rerun in `scripts/check.sh` |
| `STARFORGE_TEST_PG_URL` | Selects the engine for the whole suite |
| `STARFORGE_TEST_PG_CONTAINER` | Selects the Postgres shim container name |
| `STARFORGE_BROWSER_BASE_URL` | Selects the browser suite base URL |
| `SEED_MANIFEST` | Selects the browser seed manifest path |
| `CARGO_TARGET_DIR` | Selects the target directory for build scripts |

Browser tests need Node 22 and Python packages. Install them in `tests/browser/` with `npm ci`. Install Chromium with `npx playwright install --with-deps chromium`. Run the suite with `scripts/browser-tests.sh`. The script seeds and tears down everything.

The docs smoke needs the Rust toolchain, git, curl, and python3. Run it with `scripts/docs-smoke.sh`. The release build needs `zig` and `cargo-zigbuild`. The browser suite stays out of `scripts/check.sh`, because Node stays optional.

## Failure behavior

The browser harness fails fast when `/healthz` never becomes healthy. It dumps `serve.log` after 60 polls at 0.5 second intervals. The docs smoke fails on an empty token, a bad clone, a bad device code, or a bad CSRF cookie. `check.sh` traps the container stop on exit, even on failure. `build-release.sh` fails hard when a required tool does not exist.

## Verification

Run the local gate before you submit changes:

```bash
scripts/check.sh
```

Run the full gate including Postgres with this command:

```bash
STARFORGE_TEST_PG=1 scripts/check.sh
```

Run the document checker with this command:

```bash
python3 scripts/ste_check.py --strict
python3 -m unittest discover -s scripts/tests
```

## Related

See [architecture](./architecture.md) for the crate layer map behind the suite. See [operations](./operations.md) for startup, health, and backup procedures that the smoke test exercises.
