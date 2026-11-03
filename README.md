# Starforge

A self-hostable git forge built around agent-assisted development. Milestone M0 provides git hosting over
HTTP, local accounts, personal access tokens, user-owned repositories with collaborators, code and history
browsing, and a small REST API. Trails and agent session traces arrive in M1–M2; see
`docs/superpowers/specs/2026-11-03-starforge-design.md`.

## Requirements

- git 2.38 or newer
- Rust 1.99.1 (pinned in `rust-toolchain.toml`; rustup installs it automatically)

## Run it

```bash
cargo build --release
./target/release/starforged init --data-dir ./data
printf 'a long password\n' | ./target/release/starforged admin user create --handle me --admin --password-stdin
./target/release/starforged serve
```

Open http://127.0.0.1:3000, sign in, create a token under **Tokens** and a repository under **New repository**, then:

```bash
git push http://me:<token>@127.0.0.1:3000/me/<repository>.git main
```

## Configuration

`starforged init` writes `starforged.toml`:

| Key | Meaning |
|---|---|
| `server.http_addr` | Address to bind, e.g. `127.0.0.1:3000` |
| `server.base_url` | Public URL without a trailing slash; `https://` turns on secure cookies |
| `database.url` | Empty for SQLite in the data directory, or a `postgres://` URL |
| `database.auto_migrate` | Migrate the schema at startup (default `true`) |
| `storage.data_dir` | Repositories, SQLite database, and runtime files |
| `security.secret_key` | 64 hex characters; losing it logs everyone out |

Any key can be overridden with an environment variable such as `STARFORGE__SERVER__HTTP_ADDR` or
`STARFORGE__DATABASE__URL`. `STARFORGE_CONFIG` sets the config file path.

## API

`/api/v1` accepts `Authorization: Bearer <token>`: `GET /user`, `POST /user/repos`, `GET /repos/{owner}/{repo}`,
and `GET`/`PUT`/`DELETE /repos/{owner}/{repo}/collaborators[/{handle}]`. Errors use
`{"error": {"code", "message"}}`.

## Development

```bash
scripts/check.sh                      # fmt, clippy, tests on SQLite
STARFORGE_TEST_PG=1 scripts/check.sh  # also on Postgres 17 via podman or docker
```

## License

See `LICENSE.md`: the server is AGPL-3.0-or-later; the CLI and trace format (from M1) are MIT OR Apache-2.0.
