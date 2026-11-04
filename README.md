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

Open http://127.0.0.1:3000, sign in, create a token under **Settings → Tokens** and a repository under **New repository**, then:

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
| `registration.mode` | Who can sign up: `invite` (default; invite links only), `open`, or `domains` |
| `registration.allowed_domains` | Email domains that `domains` mode accepts, e.g. `["example.com"]` |
| `mail.url` | Empty for no email; `smtp://user:pass@host:587` (STARTTLS), `smtps://user:pass@host:465`, or `file:///dir` (writes `.eml` files) |
| `mail.from` | Sender, e.g. `Starforge <forge@example.com>` |

Any key can be overridden with an environment variable such as `STARFORGE__SERVER__HTTP_ADDR` or
`STARFORGE__DATABASE__URL`. `STARFORGE_CONFIG` sets the config file path.

## Accounts and email

New instances are invite-only: sign-up needs an invite link from a site admin. Until the admin pages ship, create
accounts with `starforged admin user create`. Set `registration.mode = "open"` to let anyone sign up, or `"domains"`
with `registration.allowed_domains` to accept only addresses at those domains (this mode requires email).

Email is optional. With `[mail]` configured, new accounts confirm their address before they can sign in, the sign-in
page offers "Forgot password?", and invites can be emailed. `smtp://` always uses STARTTLS;
`smtp://localhost:25?tls=none` is accepted only for a mail server on the same machine. Check the settings with:

```bash
./target/release/starforged admin mail test --to you@example.com
```

For local development, `url = "file:///tmp/starforge-mail"` writes each message to that directory instead of sending
it.

Signed-in users manage their display name, email address, password, sessions, and tokens under **Settings**, and
can delete their account there once they own no repositories.

## Repositories

New repositories can start with a README. Each repository has a **Settings** tab for maintainers and admins:
maintainers change the description and the default branch (new clones check it out); admins also change the
visibility, manage collaborators, rename, archive, and delete.

- **Renaming** keeps the old name working: pages, `git clone`/`fetch`/`push`, and API reads that use it are
  redirected to the new name, as long as the person asking can read the repository. A repository created with an
  old name takes the name over.
- **Archived** repositories stay readable and refuse pushes until they are unarchived.
- **Deleted** repositories disappear at once. Their owner can restore them from **Settings → Repositories** for 7
  days; then a daily job removes them for good.

The code views show branches, tags, comparisons between two refs (`/{owner}/{repo}/compare/{base}...{head}`), and
syntax-highlighted files with linkable line numbers (`#L42`). After each push, a background job runs
`git maintenance run --auto` for the repository.

## Site administration

Admins manage the instance under **Admin** (`/admin`): instance counts with the sign-up mode and mail
status, then **Users**, **Invites**, **Repositories**, and **Jobs** tabs. Users can be created
(pre-verified), suspended, granted or revoked admin, deleted, or issued a password reset; invites are
created and revoked; deleted repositories are restored or purged before the daily job removes them for
good; failed background jobs are retried or dropped.

Every `/admin` page and action answers 404 to anyone who is not a site admin, so the area is
indistinguishable from a missing page. Guards refuse to suspend or delete yourself, and the last active
admin cannot be suspended, demoted, or deleted. Each admin action is recorded in the audit log.

## API

`/api/v1` accepts `Authorization: Bearer <token>`: `GET /user`, `POST /user/repos` (with `"readme": true` for a
first commit), `GET /repos/{owner}/{repo}` (including `archived`), and
`GET`/`PUT`/`DELETE /repos/{owner}/{repo}/collaborators[/{handle}]`. Reads of a renamed repository answer `301`
with the new location.
Errors use `{"error": {"code", "message"}}`.

## Trace format and redaction

`docs/format/` is the normative spec for Trace Format v1: session metadata, normalized
events, and the JSON Schemas uploads are validated against. Two crates implement it:
`starforge-format` (encoding, segmentation, agent-output delimiters) and
`starforge-redact` (secret scrubbing), both MIT OR Apache-2.0.
Redaction replaces matches with `[redacted:<detector>]` using the built-in detectors
(private-key, cloud-credential, known-token, credentialed-url, connection-string,
authorization, high-entropy, plus optional email/phone PII), extended per repository
with `.starforge/redact.toml`. The rule-set fingerprint travels with each session, so a
high-confidence hit on the server's re-scan quarantines the upload until a repo admin
releases or purges it.

## Development

```bash
scripts/check.sh                      # fmt, clippy, tests on SQLite
STARFORGE_TEST_PG=1 scripts/check.sh  # also on Postgres 17 via podman or docker
```

## License

See `LICENSE.md`: the server is AGPL-3.0-or-later; the CLI and trace format (from M1) are MIT OR Apache-2.0.
