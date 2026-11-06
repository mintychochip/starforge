# Starforge

A self-hostable git forge built around agent-assisted development. It hosts
git over HTTP and SSH with local accounts, personal access tokens,
user-owned repositories with collaborators, code and history browsing, a
REST API, Trails (issue-like objects with changes, revisions, reviews, and
gates), agent session traces with redaction, search, webhooks, and mirrors.
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
change from a clone:

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
  SSH keys, Trails, sessions, search, orgs and teams, API and webhooks.
- Trace format: [docs/format/README.md](docs/format/README.md).

## Development

```bash
scripts/check.sh                      # fmt, clippy, tests on SQLite
STARFORGE_TEST_PG=1 scripts/check.sh  # also on Postgres 17 via podman or docker
scripts/docs-smoke.sh                 # run the documented quick start end to end
```

## Known gaps

Explicit v0.1.0 non-goals (program rulings):

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



## License

See `LICENSE.md`: the server is AGPL-3.0-or-later; the CLI and trace format
(MIT OR Apache-2.0) are dual-licensed.
