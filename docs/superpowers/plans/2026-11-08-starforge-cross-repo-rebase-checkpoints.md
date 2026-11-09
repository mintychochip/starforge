# Implementation plan — cross-repo changes, rebase merge, checkpoints

- **Date:** 2026-11-08
- **Design:** `docs/superpowers/specs/2026-11-08-starforge-cross-repo-rebase-checkpoints-design.md`
- **Status:** in progress.

## Task 1 — Rebase merge [FR-010..FR-013]

- [x] Add `rebase` to `MERGE_METHODS` (`crates/starforged-core/src/merge.rs:35`)
      and `ALLOWED_METHODS` (`crates/starforged-core/src/gate_rules.rs:26`).
- [x] Add `commit_tree_as` (author + committer) to
      `crates/starforged-git/src/write.rs`.
- [x] Add `rebase_onto` and `merge_tree_with_base` to
      `crates/starforged-git/src/merge.rs`.
- [x] Add `build_rebase` and the `merge_change` branch in
      `crates/starforged-core/src/merge.rs`.
- [x] Tests in `crates/starforged/tests/merge_changes.rs`:
      linear replay, author/message preservation, trailer, conflict,
      non-linear refusal, gate allowed-methods.
- [x] Docs: `docs/user/trails.md`, `docs/technical/trails.md`, CHANGELOG.

**Verify:** `cargo nextest run -p starforged --test merge_changes`.

## Task 2 — Cross-repository changes [FR-001..FR-006]

- [x] Migration `0046_cross_repo_changes.sql` (sqlite + postgres):
      `change_sources(change_id PK, source_repo_id, source_branch, created_at)`.
- [x] `crates/starforged-db/src/changes.rs`: `ChangeSourceRow`,
      `insert_change_source`, `change_source`, `delete_change_source`.
- [x] `crates/starforged-git/src/write.rs`: `fetch_branch` (local path,
      temporary ref) and `object_exists`.
- [x] `crates/starforged-core/src/changes.rs`:
      `create_cross_repo_change`, `refresh_cross_repo_change`,
      `source_view`, leak rule, `change_view` source field.
- [x] `crates/starforged-core/src/merge.rs`: source read check.
- [x] API: `POST /trails/{n}/changes`, `POST /trails/{n}/changes/{k}/refresh`,
      source in change JSON, OpenAPI.
- [x] Web: add-change form on the Trail changes tab; source label on rows.
- [x] CLI: `starforge trail change add|refresh`.
- [x] Tests: `crates/starforged/tests/cross_repo_changes.rs`, API/web cases.
- [x] Docs: user/technical trails, API, CLI, CHANGELOG.

**Verify:** `cargo nextest run -p starforged --test cross_repo_changes`.

## Task 3 — Session checkpoints [FR-020..FR-026]

- [x] Migration `0047_session_checkpoints.sql` (sqlite + postgres).
- [x] `crates/starforged-db/src/sessions.rs`: checkpoint row + CRUD.
- [x] `crates/starforged-core/src/ingest.rs`: `put_checkpoint`,
      `list_checkpoints`, `get_checkpoint`; ref verification; privacy rule.
- [x] Ref policy: `refs/starforge/checkpoints/<ulid>/<n>` classification,
      shape validation, reserved namespace, write requirement.
- [x] API: `GET/PUT /sessions/{ulid}/checkpoints[/{n}]`, OpenAPI.
- [x] Web: checkpoints panel on the session page.
- [x] CLI git helpers: temp-index tree snapshot, commit-tree, ref update,
      fetch, read-tree, status.
- [x] CLI spool: `checkpoints.json` + CRUD.
- [x] CLI commands: `checkpoint create`, `rewind`, `resume`.
- [x] Hooks: post-commit and session-end checkpoint creation.
- [x] Sync: push checkpoint refs and upload metadata.
- [x] Tests: `crates/starforge-cli/tests/checkpoints.rs`,
      `crates/starforged/tests/api_checkpoints.rs`, and the end-to-end
      `crates/starforged/tests/checkpoint_e2e.rs` (real binary, hooks, sync,
      fresh-clone rewind).
- [x] Docs: user/technical sessions, CLI, CHANGELOG.

**Verify:** `cargo nextest run -p starforge-cli --test checkpoints` and the
server checkpoint tests and `checkpoint_e2e`.

## Task 4 — Validation

- [x] `cargo fmt --all -- --check`
- [x] `cargo clippy --workspace --all-targets -- -D warnings`
- [x] `STARFORGE_TEST_PG=1 scripts/check.sh`
- [x] Update CHANGELOG migration table and README if needed.

## Verification result

`STARFORGE_TEST_PG=1 scripts/check.sh` passed on the final tree: `cargo fmt
--check`, `cargo clippy --workspace --all-targets -- -D warnings`, the full
SQLite nextest suite (including `checkpoint_e2e`), doctests,
`ste_check.py --strict`, the checker unit tests, and the Postgres 17 subset
(`starforged-db` plus the SQL-sensitive integration binaries; the new
migrations 0046 and 0047 ran on Postgres). The PG subset now includes
`cross_repo_changes`, `api_checkpoints`, `merge_changes`, and
`checkpoint_e2e`; it ran 91 tests, all passed. A separate direct Postgres run
of those four binaries also passed 29/29. Targeted suites for the new
features also passed: `merge_changes`, `cross_repo_changes`,
`api_checkpoints`, `api_changes`, `web_changes`, `web_merge_security`,
`api_sessions`, `web_session`, `web_sessions`, `hook_cli`, `openapi`,
`api_gate_rules`, and the CLI `checkpoints`, `trail`, `hooks`, `spool`,
`upload`, and `hook_session_end` suites.

`checkpoint_e2e` is the full user flow: the real `starforge` binary installs
hooks, the prepare hook writes the trailer, the post-commit hook creates the
checkpoint, `starforge sync` pushes the ref and metadata with a
`repo:read` + `session:upload` token (no `repo:write`), the API lists the
checkpoint, and a fresh clone runs `rewind` and gets the checkpoint files. It
runs in about 2 seconds on SQLite and 9 seconds on Postgres.

The checkpoint commit carries no `Starforge-Session` trailer, and the push
scan skips `refs/starforge/*`, so a checkpoint push cannot create a synthetic
session commit link or a push event. The e2e test asserts that
`GET …/sessions/{ulid}/links` never lists the checkpoint commit.

## Test notes

- The first Postgres run of `cross_repo_changes` failed because the target and
  source work repos had separate initial commits, so their histories were
  unrelated and the merge correctly answered `409`. The test now clones the
  target and pushes the source from that clone, so both repositories share the
  initial commit and the merge is clean.
- `append_trailers` appends the trailer without a blank line for a one-line
  `-m` message, so `git log --format=%s` folds the trailer into the subject.
  The checkpoint label uses the first line of `%B` instead. Changing
  `append_trailers` is existing behavior and is left alone.
