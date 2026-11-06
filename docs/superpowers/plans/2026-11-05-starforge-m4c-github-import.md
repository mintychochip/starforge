# Starforge M4c (GitHub metadata import) Implementation Plan

> **For agentic workers:** implement this plan task by task with subagent-driven development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Spec §8.6 GitHub metadata import. GitHub objects map to Starforge as follows:

| GitHub | Starforge |
|---|---|
| Issue | Trail without changes (open or closed) |
| Pull request | Trail with one `imported` change, open, closed, or merged. Its head comes from `refs/pull/<n>/head` into `refs/trails/<n>/changes/1/head` and `rev/1` |
| Issue and PR comment | Trail comment |
| Review comment | Review thread on revision 1 where the line exists; otherwise a Trail comment quoting path and line |
| Labels, assignees | Labels, assignees |
| Numbers | Preserved; new Trails continue after the highest imported number |
| Author | Local user matched by verified email; otherwise a placeholder showing the original GitHub handle |

**Architecture:**
- **`starforged-core`** gains `github.rs`:
  - a small GitHub REST v3 client on the existing `reqwest`, with the outbound SSRF rules, a fixed configurable base URL, `Link`-header pagination, and rate-limit handling;
  - an importer job that writes through `Core`/db fns, never through the public API.
- **`starforged-db`** gains `0027_github_import.sql`:
  - placeholder-author columns (`*_imported_author TEXT`) on Trails, Trail comments, reviews, and review comments;
  - a `github_imports` record per repository.
- **The importer runs as an `ImportGithub` job** on a repository that already holds the git history: an M4b import, a mirror, or pushed. It needs a GitHub token (sealed with M4b's credential box) and the `owner/repo` slug.
- **Web and API:** repository settings → "Import from GitHub", which shows progress and the result. `POST /api/v1/repos/{owner}/{repo}/import/github` with `{"repository": "octo/proj", "token": "…"}`, plus `GET` for status.

**Tech Stack:** as before; no new dependencies. Tests use a fake GitHub API (axum) with JSON fixtures and a `file://` git remote that holds `refs/pull/<n>/head`.

**Spec:** §8.6 (the GitHub mapping table), §6.2 (Change kind `imported`), §6.6 (per-repo Trail numbers shared by all Trails), §2 goal 5.

**Deferred (not built here):**
- GitLab and Forgejo import (non-goal);
- importing releases, milestones, projects, reactions, and attachments;
- incremental re-sync (an import runs once per repository).

## Global Constraints

- **No new dependencies.**
- **Outbound HTTP:**
  - only to `github.api_url` (config; default `https://api.github.com`; GitHub Enterprise allowed). The host is checked with the webhook SSRF rules, with the test-only loopback flag;
  - no redirects; a 30 s per-request timeout; responses capped at 10 MiB;
  - pagination follows only `Link: rel="next"` URLs on the same origin as `api_url`.
- **The token** is sealed at rest (M4b credential box) and deleted when the import finishes or fails. It is never logged or rendered.
- **Rate limits:**
  - on 403 or 429 with `X-RateLimit-Remaining: 0` or `Retry-After`, the job saves its cursor and re-enqueues itself at the reset time (capped at 1 h); this is not a failure;
  - other errors use the retry ladder;
  - after 5 failures the import is `failed`, with the scrubbed error.
- **Idempotent resumption:** the importer records progress (`cursor_kind`, `cursor_page`, last imported number) in `github_imports` and never duplicates an object on resume. Each object import is one transaction keyed by the GitHub number or comment id; the stored GitHub id columns are unique.
- **Preconditions:** the import runs only on a repository with no Trails yet, before any Trail is created. Starting it on a repository with Trails gives 422, because numbers must be preserved.
- **Rendering:** imported bodies are Markdown, rendered through the existing sanitizing pipeline. Placeholder authors render as the escaped original handle with an "imported" marker, never as a link to a local user.
- **No webhooks and no timeline noise:** import writes one `trail.imported` timeline row per Trail, and dispatches no webhooks for imported objects.
- **Audit:** `repo.github_import_started` and `repo.github_import_finished`, with counts.
- **Every commit:** fmt, clippy `-D warnings`, and workspace tests green on SQLite and `STARFORGE_TEST_PG=1`.

## Decisions this plan makes where the spec is silent

- **D1. Authors.**
  - The GitHub user's public email (from the API objects; no extra lookups) is matched against local VERIFIED emails. A match makes that user the author, commenter, or reviewer.
  - Otherwise the local author column is NULL and `*_imported_author` holds the GitHub login. Placeholders hold no account.
  - Assignees and labels: labels are created by name. Assignees only map to matched local users who can be assigned (repo members); others are dropped and listed in the import summary.
- **D2. Numbers.**
  - Issues and PRs share GitHub's number space, so the import inserts each Trail with its GitHub number.
  - After the import, `trail_sequences` is set to `max(number) + 1`.
  - Gaps from deleted issues stay as gaps.
- **D3. Pull requests.**
  - One `imported` change, k = 1, with base = the PR's base ref name and head = the `refs/pull/<n>/head` commit.
  - The head is fetched with `git fetch <git_url> +refs/pull/<n>/head:refs/trails/<n>/changes/1/head` plus the `rev/1` ref. `git_url` is derived from the GitHub repository's `clone_url` (HTTPS, with the token through M4b's injected config) or given explicitly.
  - Revision 1 records the head SHA, the base SHA (the PR's `base.sha`), and the merge base.
  - Change state: merged (`merged_at` set) → `merged`, with `merge_commit_sha` stored when present; closed → `closed`; else `open`. Trail state follows §6.2 (merged when its change merged).
  - A PR whose head ref is gone (an unfetchable head) becomes a Trail with the change marked `closed` and a note comment; the import does not fail.
- **D4. Review comments.**
  - A comment whose `path` and line (`line`/`side` for the new API, falling back to `original_line`) exist in revision 1's diff becomes a review thread on revision 1 (side `head` for `RIGHT`, `base` for `LEFT`), with replies as thread comments (`in_reply_to_id`).
  - Otherwise it becomes a Trail comment that starts with a quote block: `> <path>:<line>` and a link to the GitHub comment URL.
  - PR reviews with state `APPROVED`, `CHANGES_REQUESTED`, or `COMMENTED` become submitted reviews on revision 1 with the mapped verdict and body. Imported approvals count toward gates only through the existing rule (only write+ reviewers count), so placeholder approvals never count.
- **D5. Scope of one run.** Issues (state `all`, skipping PRs in the issues listing), pulls (state `all`), issue comments, review comments, and reviews, in ascending number order, so resumption is simple.

## File Structure

```
crates/starforged-db/migrations/{sqlite,postgres}/0027_github_import.sql
crates/starforged-db/src/github_imports.rs              new; plus imported-author columns in trails/changes fns
crates/starforged-core/src/{github.rs (new),jobs.rs,trails.rs,changes.rs}
crates/starforged/src/config.rs                         github.api_url
crates/starforged-api/src/github_import.rs              new
crates/starforged-web/src/pages/github_import.rs        new, templates/github_import.html
crates/starforged-web/templates/{trail.html,change.html,…}  placeholder author rendering
crates/starforged/tests/{github_import.rs,github_import_security.rs}, tests/common/fake_github.rs, tests/fixtures/github/*.json
README.md
```

---

### Task G1: GitHub client, schema, and placeholder authors

**Files:**
- Create:
  - the 0027 migrations;
  - `crates/starforged-db/src/github_imports.rs`;
  - `crates/starforged-core/src/github.rs` (client part);
  - `crates/starforged/tests/common/fake_github.rs`;
  - the JSON fixtures.
- Modify:
  - `crates/starforged-db/src/{trails.rs,changes.rs}`, which read and write the imported-author columns;
  - every template that renders an author (Trail, comment, review, thread comment, timeline, list rows), so a NULL author with an imported handle renders the placeholder.

**Interfaces:**
- `GithubClient::new(api_url, token, policy)`;
- `list_issues(page)`, `list_pulls(page)`, `list_issue_comments(page)`, `list_review_comments(page)`, `list_reviews(pr)`, each returning `Page<T>` with a `next` URL;
- the serde types with only the fields D1–D5 use.

- [ ] **Step 1: Write the failing tests.**
  - **Pagination** follows `Link` next and refuses cross-origin next links.
  - **Rate limit:** a 403 with remaining 0 maps to `RateLimited { reset_at }`.
  - **SSRF:** a private `api_url` is refused (test flag off).
  - **Response cap:** the size cap is enforced.
  - **Placeholders:** a Trail row with a placeholder author renders "octocat (imported)", escaped, on the list, the Trail page, and comments.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged-core github` and `cargo test -p starforged --test github_import`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same commands plus clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Add the GitHub client and imported authors`.

---

### Task G2: The importer

**Files:**
- Modify:
  - `crates/starforged-core/src/{github.rs,jobs.rs,trails.rs,changes.rs}`;
  - `crates/starforged-git/src/remote.rs` (fetching refspecs for pull heads);
  - `crates/starforged/tests/github_import.rs`.

**Interfaces:**
- `Core::start_github_import(user, owner, repo, slug, token)` (admin of the repository; refused when the repository has Trails);
- the job `ImportGithub{repo_id}`, which does D1–D5 with resumption.

- [ ] **Step 1: Write the failing tests** against the fake API plus a `file://` remote with `refs/pull/*/head`:
  - **Issues and pull requests:**
    - issues 1 and 3 become Trails without changes (one open, one closed);
    - PR 2 (merged) becomes Trail 2 with an imported change, revision 1, and the head refs present;
    - PR 4 (open), with a review comment on an existing line, gets a thread; one on a missing line becomes a quoted Trail comment;
    - reviews map to verdicts.
  - **Mapping:**
    - labels and matched assignees are applied;
    - a matched author by verified email becomes the user; others become placeholders;
    - the next new Trail gets number 5.
  - **Resilience:**
    - a rate-limit mid-run re-enqueues and resumes without duplicates;
    - an unfetchable PR head closes the change with a note;
    - starting on a repository with Trails gives 422.
  - **Cleanup:** the token row is cleared on finish.
  - **Side effects:** no webhooks are dispatched (a hook is configured in the test); the audit rows are written.
- [ ] **Step 2: Run them to verify failure.** Run `cargo test -p starforged --test github_import`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run tests.** Run the same command plus `--test api_trails --test web_trails` and clippy. Expected: PASS.
- [ ] **Step 5: Commit** (PG gate first): `Import GitHub issues and pull requests`.

---

### Task G3: Import UI, API, sweep, and docs

**Files:**
- Create:
  - `crates/starforged-api/src/github_import.rs`;
  - `crates/starforged-web/src/pages/github_import.rs` and its template;
  - `crates/starforged/tests/github_import_security.rs`.
- Modify: the route registration files and `README.md`.

- [ ] **Step 1: Write the failing tests.**
  - **Start and progress:** start from settings (admin, CSRF); progress shows counts; the summary lists dropped assignees.
  - **API:** start and status.
  - **Access:** the 404/403 matrix.
  - **Secrecy:** the token never appears in any response or page.
  - **XSS:** hostile issue titles, bodies, and comment text from the fixtures are sanitized (Markdown) or escaped (titles, handles), and placeholder handles are escaped.
- [ ] **Step 2: Run them to verify failure,** then **implement**, then run the tests 3 times; all green.
- [ ] **Step 3: README:** an "Import from GitHub" section (prerequisites, token scopes needed (read-only `repo`), the mapping table, placeholders, numbering, rate limits, the API).
- [ ] **Step 4: Commit** (PG gate first): `Add the GitHub import page, sweep, and docs`.
