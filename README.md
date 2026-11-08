# Starforge

A self-hostable git forge built around agent-assisted development. It hosts
git over HTTP and SSH with local accounts, personal access tokens,
user-owned repositories with collaborators, code and history browsing, a
REST API, Trails (issue-like objects with changes, revisions, reviews, and
gates), agent session traces with redaction, search, webhooks, mirrors, and
opt-in CI runners with sandboxed jobs.
See `docs/superpowers/specs/2026-11-03-starforge-design.md`.

## Requirements

- git 2.38 or newer
- Rust 1.99.1 (pinned in `rust-toolchain.toml`; rustup installs it automatically)

## Quick start

Build and run (see [Install](docs/admin/install.md) for other options):

```bash
cargo build --release
./target/release/starforged init --data-dir ./data
printf 'a long password\n' | ./target/release/starforged admin user create --handle me --admin --password-stdin
./target/release/starforged serve
```

Open http://127.0.0.1:3000, sign in (user `me` with the password from the
previous step), create a repository under **New repository** and a personal
access token at `/settings/tokens`, then:

```bash
git push http://me:<token>@127.0.0.1:3000/me/<repository>.git main
```

Log the `starforge` CLI in with the device flow (it prints a code; approve
it in the browser at the printed `/oauth/device` page), then push a Trail
change from a clone. The login covers the CLI's API calls; git itself
authenticates with the clone URL's token (or a credential helper, or SSH):

```bash
starforge auth login http://127.0.0.1:3000
git clone http://me:<token>@127.0.0.1:3000/me/<repository>.git
cd <repository>
git checkout -b smoke
echo change > change.txt && git add change.txt && git commit -m "smoke change"
starforge trail push --title "smoke change"
```

### Static binary

```bash
scripts/build-release.sh
tar -xzf target/release-artifacts/starforged-0.1.0-x86_64-unknown-linux-musl.tar.gz
./x86_64-unknown-linux-musl/starforged init --data-dir ./data
```

### OCI image

```bash
podman build --build-arg STARFORGE_TARGET=x86_64-unknown-linux-musl -t starforge:0.1.0 .
podman run --rm -p 3000:3000 -p 2222:2222 -v starforge-data:/data starforge:0.1.0
```

## Documentation

- Administration: [docs/admin/](docs/admin/) — install, configuration,
  database, reverse proxy and TLS, SSH, SSO and 2FA, mirrors and import,
  backup and restore, upgrades and migrations, doctor, monitoring, abuse
  controls, site administration.
- User guide: [docs/user/](docs/user/) — getting started, repositories and
  SSH keys, Trails, sessions, search, orgs and teams, API and webhooks,
  and [CI](docs/user/ci.md).
- CI administration: [docs/admin/ci.md](docs/admin/ci.md) — runner
  registration, `starforge-sandboxd`, E2B, quotas, and audit.
- Technical documentation: [docs/technical/](docs/technical/) — architecture,
  crates, storage, git hosting, Trails, web and API, sessions, search,
  webhooks, import, CLI, operations, security, and tests. These pages use
  ASD-STE100 Simplified Technical English.
- Trace format: [docs/format/README.md](docs/format/README.md).

## Development

```bash
scripts/check.sh                      # fmt, clippy, tests on SQLite
STARFORGE_TEST_PG=1 scripts/check.sh  # also on Postgres 17 via podman or docker
scripts/docs-smoke.sh                 # run the documented quick start end to end
```

## Known gaps

Explicit v0.1.0 non-goals and deferrals (program rulings):

- **Fluent message catalog (§10.6):** English strings stay in templates.
  Moving every template string into Fluent is a large retrofit with no
  user-visible change for an English-only release. Cost: translation later
  needs the retrofit.
- **htmx (§3 D12):** pages are plain server-rendered forms with the one JS
  module. Nothing in the spec's behavior requires htmx. Cost: none
  functional.
- **Per-response CSP nonce (§11.1):** the CSP forbids inline scripts entirely
  and serves scripts only from the origin, which is stricter than a nonce
  allowance. Cost: none.
- **CI runners are opt-in:** a repository with no `.starforge/ci.toml`
  behaves exactly as before, and external CI keeps reporting through the
  status API and webhooks. The server never executes job code: operators
  run `starforge-runner` and `starforge-sandboxd`. The E2B adapter is
  E2B-shaped, not a wire-compatibility promise; Firecracker and Kata are
  reserved runtime names for a later release. Local sandbox egress uses
  pasta host-loopback mapping; the proxy forwards HTTPS `CONNECT` only
  (plain HTTP and non-443 ports are not proxied), and host loopback ports
  are reachable directly. Use an `https://` server and repo URL, and keep
  untrusted services off host loopback. Of external
  CI suppliers, only Depot is integrated, and only to read usage; GitHub
  Actions, Namespace, Blacksmith, and Buildkite usage is not read. Cost:
  those runtimes and suppliers need an adapter, not a config change.
- **Antigravity CLI capture:** current Antigravity CLI releases keep sessions
  under `~/.gemini/antigravity-cli/brain/<id>/` in an undocumented, closed
  format, which the Gemini adapter does not read. Gemini CLI sessions are
  captured. Cost: Antigravity sessions are not uploaded until a later
  release adds the format.

## License

See `LICENSE.md`: the server is AGPL-3.0-or-later; the CLI and trace format
(MIT OR Apache-2.0) are dual-licensed.
