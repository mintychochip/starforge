# Cross-repository changes, rebase merge, and session checkpoints — design

- **Date:** 2026-11-08
- **Status:** Implemented. The plan is `docs/superpowers/plans/2026-11-08-starforge-cross-repo-rebase-checkpoints.md`.
- **Parent spec:** `docs/superpowers/specs/2026-11-03-starforge-design.md`.
- **Scope:** three features that the parent spec listed as v0.1.0 non-goals. This
  document supersedes those three non-goal entries; every other non-goal stands.

## 1. Goal

Add three capabilities to the existing Trail and session systems:

1. A Trail change whose head branch lives in a different repository
   (cross-repository change).
2. A `rebase` merge method that replays the change's commits onto the base
   branch and fast-forwards it.
3. Session checkpoints: git snapshots of the working tree at commit and
   session boundaries, with server-side listing, `rewind`, and `resume`.

## 2. Scope

**In scope:** schema migrations, core domain logic, API routes, web pages,
CLI commands and hooks, ref policy, docs, changelog, tests.

**Out of scope (unchanged non-goals):** forks as first-class objects,
multi-repository Trails, Git LFS, live session streaming, server-side LLM
calls, checkpoint compatibility with Entire's format or API, and Windows
server support.

## 3. Functional requirements

### 3.1 Cross-repository changes

- **FR-001:** A user with `write` on a target repository and `read` on a source
  repository shall open a change on a target Trail whose head is a branch in
  the source repository. The server shall fetch the source branch's objects
  into the target repository before recording the revision.
- **FR-002:** The server shall refuse a cross-repository change when the
  source repository is not public and the target repository is more visible
  than the source. This prevents copying private code into a target
  repository with a wider audience. Source admin permission does not bypass
  the rule.
- **FR-003:** A cross-repository change shall store its source repository and
  source branch in a `change_sources` row; the `changes` row keeps its
  existing shape.
- **FR-004:** Refreshing a cross-repository change shall fetch the source
  branch again and append a revision only when the head SHA changed.
- **FR-005:** Merging a cross-repository change shall require the actor to
  read the source repository in addition to `write` on the target.
- **FR-006:** The change API and page shall expose the source as
  `{owner, repo, branch}`; the CLI shall open and refresh cross-repository
  changes.

### 3.2 Rebase merge

- **FR-010:** `rebase` shall be a valid merge method in the API, web form, CLI,
  and gate-rule `allowed_methods` list.
- **FR-011:** A rebase merge shall replay every commit in
  `merge-base..head` onto the current base tip, preserving author name, author
  email, author time, and message, with the server as committer, and shall
  append a `Starforge-Trail` trailer to each replayed commit when absent.
- **FR-012:** A rebase merge shall refuse a non-linear history (any merge
  commit in the range) and any conflict, naming the conflicting paths.
- **FR-013:** The base branch shall move with the existing compare-and-swap;
  a rebase that conflicts after a base move shall retry once and then answer
  `409`.

### 3.3 Session checkpoints, rewind, resume

- **FR-020:** The CLI shall create a checkpoint as a git commit whose tree is
  the working tree (tracked plus untracked non-ignored files), stored at
  `refs/starforge/checkpoints/<session-ulid>/<n>`, with metadata in
  `sessions/<ulid>/checkpoints.json`.
- **FR-021:** The `post-commit` hook shall create a checkpoint for every
  session linked by the commit's `Starforge-Session` trailers; the
  `session-end` hook shall create a final checkpoint.
- **FR-022:** The server shall accept checkpoint refs only from users with
  `write` on the repository and only when the session is visible to repo
  readers (non-public repository, or published session on a public
  repository).
- **FR-023:** The server shall store checkpoint metadata in
  `session_checkpoints` and expose list/get routes under
  `/api/v1/repos/{owner}/{repo}/sessions/{ulid}/checkpoints`.
- **FR-024:** `starforge rewind <ulid> --checkpoint <n>` shall fetch the
  checkpoint ref when absent, refuse a dirty worktree unless `--force`, and
  restore the worktree and index to the checkpoint tree.
- **FR-025:** `starforge resume <ulid> --checkpoint <n>` shall rewind and write
  `.starforge/resume.md` with the session title, agent, checkpoint label, and
  the last 20 events, then print the suggested agent command.
- **FR-026:** The session page shall list checkpoints with links to the
  checkpoint commit and the diff against its parent.

## 4. Decisions and rulings

1. **Cross-repo objects are imported into the target repository.** This keeps
   every existing read, diff, gate, and merge path unchanged. The source is
   provenance, not a second object store.
2. **`change_sources` is a side table.** The `changes` row and its many
   SELECT lists stay untouched; a change without a source row is same-repo.
3. **Cross-repo changes use `kind = 'branch'`.** They are branch changes with
   a source; no new kind value is needed.
4. **Leak rule:** a public source may go anywhere. Otherwise the target must
   not be more visible than the source. Source admin permission does not
   bypass the rule.
5. **Rebase uses plumbing, not a worktree.** Each commit is replayed with
   `git merge-tree --write-tree --merge-base=<original-parent>` and
   `git commit-tree`; the server never checks out a worktree.
6. **Rebase cap:** 1024 commits. A longer range is refused with `422` rather
   than doing unbounded work.
7. **Checkpoints are git refs plus DB metadata.** The ref carries the objects;
   the DB carries labels and ordering. The viewer links to existing commit and
   compare pages.
8. **Checkpoint privacy:** on a public repository, a checkpoint ref is
   accepted only for a published session. On a non-public repository, repo
   readers may fetch it. Unpublished public sessions keep checkpoints local.
9. **Rewind is destructive only with `--force`.** A dirty worktree is refused
   by default; `--force` first saves the current state in a local git stash
   so the previous state is recoverable.
10. **Resume does not execute an agent.** It restores the tree and writes a
    context file; the operator starts the agent.

## 5. Failure handling

| Failure | Behavior |
|---|---|
| Source repository unreadable or missing | `404`/`403`, no change row |
| Source branch missing or deleted | `422` naming the branch |
| Object fetch fails | `502`-class `Internal`/`Conflict`; no change row |
| Rebase conflict | `409` with conflicting paths and the commit that conflicted |
| Rebase merge commit in range | `422` "rebase requires a linear history" |
| Checkpoint ref missing at metadata upload | `409` "push the checkpoint ref first" |
| Checkpoint ref/commit mismatch | `409` |
| Rewind with dirty worktree | `422` unless `--force` |
| Checkpoint fetch fails | CLI error, worktree untouched |

## 6. Verification

- `cargo nextest run -p starforged --test merge_changes` (rebase cases).
- `cargo nextest run -p starforged --test cross_repo_changes` (new).
- `cargo nextest run -p starforged --test api_changes --test web_changes`.
- `cargo nextest run -p starforge-cli --test checkpoints` (new).
- `cargo nextest run -p starforged --test api_sessions --test web_session`.
- `cargo nextest run -p starforged-db` (migration tests).
- `cargo clippy --workspace --all-targets -- -D warnings`.
- `scripts/check.sh` (SQLite + Postgres subset).
