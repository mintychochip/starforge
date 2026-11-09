# Contributing

## Build and test

```bash
cargo build --release
scripts/check.sh                      # fmt, clippy, tests on SQLite, docs
STARFORGE_TEST_PG=1 scripts/check.sh  # also on Postgres 17
```

`scripts/check.sh` runs the full workspace on SQLite and the SQL-sensitive
packages on Postgres. The Postgres mode starts a `postgres:17` container on
port 55439 with podman or docker. `STARFORGE_GATE_FULL_PG=1` runs the whole
workspace on Postgres instead.

Targeted tests:

```bash
cargo nextest run -p starforged --test merge_changes
cargo nextest run -p starforge-cli --test checkpoints
cargo nextest run -p starforged --test checkpoint_e2e
```

## Style

- Rust: `cargo fmt` and `cargo clippy --workspace --all-targets -- -D
  warnings`. No new warnings.
- Technical documentation under `docs/technical/` uses ASD-STE100 Simplified
  Technical English. Run `python3 scripts/ste_check.py --strict` after edits.
- User and admin documentation uses plain English and the same facts.
- Commit messages: one topic per commit, a short imperative subject, and a
  body that names the behavior and the tests.

## Licensing

The server crates (`starforged-*`) are AGPL-3.0-or-later. The CLI, trace
format, capture, redaction, runner, sandbox protocol, sandbox daemon, and CI
spec crates are MIT OR Apache-2.0. A `starforge-*` crate must never depend on
a `starforged-*` crate.

## Pull requests

- Keep the change focused; split unrelated work.
- Add or update the tests that exercise the changed behavior.
- Update the owning page under `docs/` and the `CHANGELOG.md` entry.
- Run `scripts/check.sh` (or the targeted subset) before you request review.
