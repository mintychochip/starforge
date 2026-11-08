# Starforge M0.5 Plan B (Repositories and Code Views) Implementation Plan

> **For agentic workers:** Implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let repository owners and maintainers manage repositories from the browser (settings, an initial README, renames that keep old links working, archiving, deletion with a 7-day restore window), let users delete their accounts, and add branches, tags, compare, and syntax highlighting to the code views.

**Architecture:** Every rule lives in `starforged-core` (`Core::{set_repo_description, set_default_branch, set_visibility, rename_repo, moved_repo, archive_repo, unarchive_repo, delete_repo, restore_repo, deleted_repos, purge_deleted_repos, delete_account, compare, branch_list, tag_list}`); `starforged-git` gains plumbing writes (`write::{set_head, initial_commit}`), ref listings, range logs, range diffs, and `git maintenance`. `starforged-web` shares one repository header (`views::RepoHead` + `templates/repo_head.html`) across every repository page, adds the settings, branches, tags, compare, and deleted-repositories pages, highlights files with syntect, and answers old repository names with 301 through a middleware that runs after a 404. The API gets the same redirect middleware and two new fields.

**Tech Stack:** Rust 1.99.1 (edition 2024), axum 0.8 (`middleware::from_fn_with_state`), askama 0.16, sqlx 0.9 (`Any`, SQLite and Postgres), gix 0.90 (reads), the `git` binary (writes, diffs, maintenance), syntect 5.3 with two-face 0.5 (bat's syntaxes and themes).

**Spec:** `docs/superpowers/specs/2026-11-03-starforge-forge-basics-design.md` (forge basics, milestone M0.5). This plan implements §4.6 (the Repositories and Delete account rows), §5 (repositories), §6 (code views), the repository and static rows of §10, the Plan B rows of §11 (`repos.archived_at`, `repos.deleted_at`, `repo_redirects`), the Plan B parts of §8.4, §12, and §13. Plan A (merged) built the jobs queue, mail, and accounts; Plan C builds `/admin`. The main spec `docs/superpowers/specs/2026-11-03-starforge-design.md` still applies where the forge-basics design is silent.

## Global Constraints

- **Toolchain:** Rust `1.99.1` pinned in `rust-toolchain.toml`; edition 2024; `unsafe_code = "forbid"` workspace-wide.
- **Runtime:** system `git` 2.38 or newer on `PATH`.
- **License:** every crate is `AGPL-3.0-or-later`.
- **Dependencies:** versions exactly as in the root `Cargo.toml` `[workspace.dependencies]` table; crates inherit them with `dep.workspace = true`; internal crates depend on each other by relative path. The only new third-party dependencies in this plan are, exactly (Task B9):
  `syntect = { version = "5.3.0", default-features = false, features = ["default-fancy"] }` and
  `two-face = { version = "0.5.2", default-features = false, features = ["syntect-default-fancy"] }`.
- **SQL portability:** every statement in `starforged-db` runs unchanged on SQLite and Postgres: placeholders `$1, $2, …` with each number first appearing in ascending order; integer columns `INTEGER` (SQLite) / `BIGINT` (Postgres) decoded as `i64`; booleans stored as `0`/`1`; timestamps in unix seconds (nullable times decode as `Option<i64>`); SQL strings are `'static` literals.
- **Migrations:** each task that changes the schema adds its own numbered pair `crates/starforged-db/migrations/{sqlite,postgres}/000N_<name>.sql`: 0005 repository redirects (B3), 0006 archiving (B4), 0007 deletion (B5). Never edit an existing migration file. Both files of a pair define identical tables, columns, constraints, and indexes.
- **Both engines are tested:** DB-touching tests use `starforged_db::testing::TestDb` (through `test_core()` or `TestServer`). Tasks that add SQL run `STARFORGE_TEST_PG=1 scripts/check.sh` (podman, Postgres 17) before committing; it must pass on SQLite and Postgres.
- **Error mapping (unchanged):** `starforged-db` returns `DbResult<T>`; `starforged-core` returns `CoreResult<T>`. HTTP layers map `NotFound`→404, `Forbidden`→403, `Unauthenticated`→401 (API, git) or a redirect to `/login` (web), `Invalid`→422 (API, web forms), `Conflict`→409 (API) / 422 (web forms).
- **Permissions (spec §5.2):** description and default branch need `maintain`; visibility, rename, archive, unarchive, and delete need `admin`; collaborators stay `admin`. `Core::require_repo` enforces them: below the minimum, signed-in users get `Forbidden`, and a repository they cannot read is `NotFound`.
- **No existence leaks:** a soft-deleted repository answers exactly like a missing one on pages, git, and the API, and leaves every listing. An old name redirects only when the viewer can read the target; otherwise it answers exactly like a missing repository.
- **Audit actions** (spec §5.6, §4.7), with `target` = `repo:<owner>/<name>` or `user:<handle>`: `repo.visibility` (detail `old -> new`), `repo.default_branch` (detail: the branch), `repo.rename` (detail: the old name), `repo.archive`, `repo.unarchive`, `repo.delete`, `repo.restore`, `repo.purge`, `account.delete`. An action that changes nothing is not audited.
- **Repository pages** share `starforged_web::views::RepoHead` and `templates/repo_head.html` (owner, name, badges, description, tabs). Settings pages share `templates/repo_settings_nav.html`.
- **Settings forms** follow post-redirect-get: success answers `303` to `/{owner}/{name}/settings` (under the repository's current name); refused input (`Invalid`, `Conflict`) re-renders the page with the message and status 422. Every form carries the session's `_csrf` token, checked with `auth::verify_csrf`.
- **git subprocesses** are built only through `starforged_git::command::git()` (or `command::run`); nothing goes through a shell; refs and object ids reach git as separate arguments after validation.
- **HTML:** askama auto-escaping everywhere (askama writes `<` as `&#60;`). `|safe` is allowed only on Markdown output from `starforged_web::markdown::render` and on highlighted lines from `starforged_web::highlight::highlight_lines` (syntect escapes source text, writing `<` as `&lt;`). Inline styles stay forbidden by the CSP; colors come from stylesheets.
- **Tests:** integration tests that start a server use `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`. `TestServer` runs no job workers: tests run queued jobs with `s.core.run_due_jobs().await`. Only `starforged serve` starts workers.
- **Every commit:** `cargo fmt --all` and `cargo clippy --workspace --all-targets -- -D warnings` pass, and `cargo test --workspace` is green.
- **Deferred to Plan C:** the `/admin` pages, including listing, restoring, and purging deleted repositories as a site admin. Plan B's `Core::restore_repo` already accepts site admins.
- **Decisions this plan makes where the spec is silent:**
  - The Commits tab works before the first push: `/{owner}/{repo}/commits` shows the default branch's history, or "No commits yet."
  - Renaming to the current name changes nothing; a case-only rename (`proj` → `Proj`) is allowed and adds no redirect, because lookups ignore case.
  - Redirects answer `301` with a relative `Location`, for `GET` and `HEAD` only. git's `info/refs` is also considered when it answers `401`, because anonymous git clients get 401 (not 404) for a repository they cannot see. `git clone` and `git push` through a relative 301 were verified with git 2.53.
  - The delete confirmation must equal `owner/name` exactly (surrounding spaces ignored). A conflict on a name held by a deleted repository says so.
  - A purge parks the directory at `<data_dir>/tmp/purge-<id>.git` before deleting rows, so every step can be repeated after a crash. `CoreConfig` gains `tmp_dir`.
  - After an owner deletes a repository they land on **Settings → Repositories** (where Restore is); a site admin deleting someone else's repository lands on the owner's page.
  - Account deletion records `account.delete` before the rows go (the entry survives with its actor cleared), and the handle becomes free again.
  - Highlighting uses two bat themes, GitHub for light and OneHalfDark for dark, chosen by `prefers-color-scheme`. The interface follows the system color scheme, so the spec's single dark theme would leave code unreadable in light mode.
  - The compare picker lists branches; tags and full commit ids work in the URL.
  - Branch rows show the tip's age ("3 days ago"), with the exact time as a tooltip.
  - The maintenance job is deduplicated per repository (`git_maintenance:<id>`) and does nothing for a repository that was deleted meanwhile.

## File Structure

```
Cargo.toml                                        + syntect, two-face in [workspace.dependencies] (B9)
crates/starforged-db/
  migrations/{sqlite,postgres}/0005_repo_redirects.sql   repo_redirects (B3)
  migrations/{sqlite,postgres}/0006_repo_archive.sql     repos.archived_at (B4)
  migrations/{sqlite,postgres}/0007_repo_deletion.sql    repos.deleted_at (B5)
  src/repos.rs           + set_description, set_default_branch, set_visibility (B1); insert drops a redirect,
                           rename (B3); archived_at, set_archived (B4); deleted_at, live-only lookups,
                           list_deleted_by_owner, deleted_before, set_deleted (B5)
  src/redirects.rs       redirect lookup (B3)
  src/users.rs           + count_active_admins_except, delete (B6)
crates/starforged-git/
  src/write.rs           set_head (B1), initial_commit (B2)
  src/read.rs            + range_log, merge_base (B7); branch_list, tag_list (B8)
  src/diff.rs            commit_diff and range_diff share one streaming runner (B7)
  src/maintenance.rs     run_auto (B10)
crates/starforged-core/
  src/repos.rs           settings (B1), README on create (B2), rename + moved_repo + split_repo_path (B3),
                         archive (B4), delete/restore/purge (B5)
  src/account.rs         + delete_account (B6)
  src/content.rs         + compare (B7); branch_list, tag_list (B8)
  src/jobs.rs            + Job::PurgeDeletedRepos (B5), Job::GitMaintenance (B10)
  src/lib.rs             CoreConfig.tmp_dir (B5); testing::seed_branches (B1)
crates/starforged-web/
  src/views.rs           RepoHead (B1); CommitRow, FileView, file_views (B7); format_age (B8)
  src/moved.rs           redirect middleware for renamed repositories (B3)
  src/highlight.rs       syntect line highlighting and highlight.css (B9)
  src/githttp.rs         archived repositories refuse pushes (B4); maintenance after pushes (B10)
  src/pages/repo_settings.rs   /{owner}/{repo}/settings and its actions (B1, B3, B4, B5)
  src/pages/compare.rs   /{owner}/{repo}/compare[/{base}...{head}] (B7)
  src/pages/refs.rs      /{owner}/{repo}/branches, /tags (B8)
  src/pages/{code,history,collaborators,repo_new,settings}.rs   header, README checkbox, account pages
  templates/repo_head.html  repo_settings_nav.html  repo_settings.html  diff_files.html  compare.html
            branches.html  tags.html  settings_repositories.html  settings_delete.html
  static/starforge.css   + archived banner, line anchors
crates/starforged-api/
  src/moved.rs           redirect middleware for API reads (B3)
  src/repos.rs           `readme` on create (B2), `archived` in repository JSON (B4)
crates/starforged/
  src/config.rs          SecurityConfig Debug hides the key (B1); tmp_dir() (B5)
  src/admin.rs           CoreConfig.tmp_dir (B5)
  tests/common/mod.rs    CreateRepo.readme (B2); git_dated (B8)
  tests/web_repo_settings.rs  web_readme.rs  web_repo_rename.rs  web_repo_archive.rs  web_repo_delete.rs
        web_account_delete.rs  web_compare.rs  web_refs.rs  web_highlight.rs  maintenance.rs
README.md                repositories, code views (B10)
```

---
### Task B1: Repository header, the Commits tab, and the settings page

**Files:**
- Create: `crates/starforged-git/src/write.rs`; Modify: `crates/starforged-git/src/lib.rs`
- Modify: `crates/starforged-db/src/repos.rs` (`set_description`, `set_default_branch`, `set_visibility`)
- Modify: `crates/starforged-core/src/repos.rs` (`checked_description`, settings methods, tests), `crates/starforged-core/src/lib.rs` (`testing::seed_branches`)
- Modify: `crates/starforged-web/src/views.rs` (`RepoHead`), `src/pages/code.rs`, `src/pages/history.rs`, `src/pages/collaborators.rs`, `src/pages/mod.rs`, `src/lib.rs`
- Create: `crates/starforged-web/src/pages/repo_settings.rs`, `templates/repo_head.html`, `templates/repo_settings_nav.html`, `templates/repo_settings.html`
- Modify: `crates/starforged-web/templates/{tree,blob,commits,commit,collaborators}.html`
- Modify: `crates/starforged/src/config.rs` (`SecurityConfig`'s `Debug` hides the key)
- Test: Create `crates/starforged/tests/web_repo_settings.rs`; Modify `crates/starforged/tests/web_code.rs`

**Interfaces:**
- Consumes: `Core::{require_repo, repo_for, branches, resolve, log, commit, diff, audit, repo_path}`, `starforged_git::command::run`, `starforged_db::repos::{by_id, …}`, `views::{nav, NavUser, encode_path, content_href, crumbs, format_time}`, `auth::{RequireUser, MaybeUser, verify_csrf}` (M0, Plan A).
- Produces:
  - `starforged_git::write::set_head(repo: &Path, branch: &str) -> Result<(), GitError>`. Task B2 adds `initial_commit` to this module.
  - `starforged_db::repos::{set_description(db, id: i64, description: &str), set_default_branch(db, id: i64, branch: &str), set_visibility(db, id: i64, visibility: &str)} -> DbResult<()>`.
  - `Core::set_repo_description(&self, actor: &User, owner: &str, name: &str, description: &str) -> CoreResult<Repo>`, `Core::set_default_branch(&self, actor: &User, owner: &str, name: &str, branch: &str) -> CoreResult<Repo>`, `Core::set_visibility(&self, actor: &User, owner: &str, name: &str, visibility: Visibility) -> CoreResult<Repo>`; private `Core::reload_repo(id) -> CoreResult<Repo>` and `checked_description(&str) -> CoreResult<String>` in `repos.rs`.
  - Core test helper `crate::testing::seed_branches(core: &Core, repo_id: i64, branches: &[&str])`: one commit per branch (each branch starts from the previous one), fetched into the bare repository (no hooks run).
  - `starforged_web::views::RepoHead { owner, name, description, visibility: &'static str, tab: &'static str, commits_href, can_maintain: bool, can_admin: bool }` and `RepoHead::new(access: &RepoAccess, tab: &'static str, ref_name: Option<&str>) -> RepoHead`. Task B4 adds `archived: bool`; Task B8 adds the Branches and Tags tabs to `repo_head.html`.
  - `crate::pages::code::default_ref(state: &AppState, access: &RepoAccess) -> Result<Option<String>, WebError>` (`pub(crate)`).
  - `crate::pages::repo_settings::finish(state: &AppState, session: &WebSession, owner: &str, repo: &str, result: CoreResult<Repo>) -> Result<Response, WebError>` (`pub(crate)`): 303 to `/{owner}/{name}/settings` of the returned repository, or the settings page again with status 422 for `Invalid`/`Conflict`. Tasks B3–B5 add their actions to this module and template.
  - Templates `repo_head.html` (needs a `head: RepoHead` field) and `repo_settings_nav.html` (needs `head` and `settings_page: &'static str`).
  - Routes: `GET/POST /{owner}/{repo}/settings`, `POST /{owner}/{repo}/settings/visibility`, `GET /{owner}/{repo}/commits`.

- [ ] **Step 1: Write the failing core tests**

Add the test helper to the `#[cfg(test)] pub(crate) mod testing` block in `crates/starforged-core/src/lib.rs`, after `user`:

```rust
    /// Commits one file per branch in a scratch working copy (each branch starts from the previous one) and
    /// fetches every branch into repository `repo_id`'s bare directory. Fetching runs no hooks.
    pub(crate) fn seed_branches(core: &Core, repo_id: i64, branches: &[&str]) {
        let work = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
                .args(args)
                .current_dir(work.path())
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["init", "-q", "-b", branches[0], "."]);
        for (i, branch) in branches.iter().enumerate() {
            if i > 0 {
                git(&["checkout", "-q", "-b", branch]);
            }
            std::fs::write(
                work.path().join(format!("{}.txt", branch.replace('/', "-"))),
                branch,
            )
            .unwrap();
            git(&["add", "-A"]);
            git(&["commit", "-q", "-m", &format!("on {branch}")]);
        }
        let bare = core.repo_path(repo_id);
        git(&[
            "--git-dir",
            bare.to_str().unwrap(),
            "fetch",
            "-q",
            work.path().to_str().unwrap(),
            "refs/heads/*:refs/heads/*",
        ]);
    }
```

In `crates/starforged-core/src/repos.rs`, change the test module's import to `use crate::testing::{seed_branches, test_core, user};` and add:

```rust
    #[tokio::test]
    async fn settings_follow_maintain_and_admin_permissions() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let mia = user(&core, "mia").await;
        let walt = user(&core, "walt").await;
        let bob = user(&core, "bob").await;
        core.create_repo(&alice, new("proj", Visibility::Private))
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "walt", Permission::Write)
            .await
            .unwrap();

        let repo = core
            .set_repo_description(&mia, "alice", "proj", "  A demo  ")
            .await
            .unwrap();
        assert_eq!(repo.description, "A demo");
        assert!(matches!(
            core.set_repo_description(&walt, "alice", "proj", "x").await,
            Err(CoreError::Forbidden)
        ));
        assert!(
            matches!(
                core.set_repo_description(&bob, "alice", "proj", "x").await,
                Err(CoreError::NotFound)
            ),
            "people who cannot read the repository learn nothing"
        );
        assert!(matches!(
            core.set_repo_description(&mia, "alice", "proj", &"x".repeat(351))
                .await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.set_visibility(&mia, "alice", "proj", Visibility::Public)
                .await,
            Err(CoreError::Forbidden)
        ));
        let repo = core
            .set_visibility(&alice, "alice", "proj", Visibility::Public)
            .await
            .unwrap();
        assert_eq!(repo.visibility, Visibility::Public);
        core.set_visibility(&alice, "alice", "proj", Visibility::Public)
            .await
            .unwrap();
        let audited: Vec<(String, String)> = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.action == "repo.visibility")
            .map(|e| (e.target, e.detail))
            .collect();
        assert_eq!(
            audited,
            vec![("repo:alice/proj".to_owned(), "private -> public".to_owned())],
            "a visibility that did not change is not audited"
        );
    }

    #[tokio::test]
    async fn the_default_branch_must_exist_and_moves_head() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let repo = core
            .create_repo(&alice, new("proj", Visibility::Public))
            .await
            .unwrap();
        assert!(matches!(
            core.set_default_branch(&alice, "alice", "proj", "dev").await,
            Err(CoreError::Invalid(_))
        ));
        seed_branches(&core, repo.id, &["main", "dev"]);
        let changed = core
            .set_default_branch(&alice, "alice", "proj", "dev")
            .await
            .unwrap();
        assert_eq!(changed.default_branch, "dev");
        assert_eq!(
            std::fs::read_to_string(core.repo_path(repo.id).join("HEAD")).unwrap(),
            "ref: refs/heads/dev\n"
        );
        core.set_default_branch(&alice, "alice", "proj", "dev")
            .await
            .unwrap();
        let audited: Vec<String> = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.action == "repo.default_branch")
            .map(|e| e.detail)
            .collect();
        assert_eq!(audited, vec!["dev".to_owned()]);
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p starforged-core repos::tests`
Expected: compile errors: no method `set_repo_description`, `set_default_branch`, `set_visibility` on `Core`.

- [ ] **Step 3: Add `starforged_git::write::set_head`**

Create `crates/starforged-git/src/write.rs`:

```rust
//! Changing hosted repositories with git plumbing.

use std::ffi::OsStr;
use std::path::Path;

use crate::command::{GitError, run};

/// Points the bare repository's `HEAD` at `refs/heads/<branch>`, so new clones check that branch out.
/// git refuses names that are not valid ref names.
pub async fn set_head(repo: &Path, branch: &str) -> Result<(), GitError> {
    let target = format!("refs/heads/{branch}");
    run([
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("symbolic-ref"),
        OsStr::new("HEAD"),
        OsStr::new(&target),
    ])
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn set_head_moves_the_symbolic_ref() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("r.git");
        crate::init::init_bare(&repo, "main", Path::new("/bin/false"))
            .await
            .unwrap();
        set_head(&repo, "feature/x").await.unwrap();
        assert_eq!(
            std::fs::read_to_string(repo.join("HEAD")).unwrap(),
            "ref: refs/heads/feature/x\n"
        );
        assert!(set_head(&repo, "bad..name").await.is_err());
        assert_eq!(
            std::fs::read_to_string(repo.join("HEAD")).unwrap(),
            "ref: refs/heads/feature/x\n"
        );
    }
}
```

In `crates/starforged-git/src/lib.rs`, add `pub mod write;` after `pub mod refpolicy;`.

- [ ] **Step 4: Add the database setters**

Append to `crates/starforged-db/src/repos.rs`:

```rust
pub async fn set_description(db: &Db, id: i64, description: &str) -> DbResult<()> {
    sqlx::query("UPDATE repos SET description = $1, updated_at = $2 WHERE id = $3")
        .bind(description)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_default_branch(db: &Db, id: i64, branch: &str) -> DbResult<()> {
    sqlx::query("UPDATE repos SET default_branch = $1, updated_at = $2 WHERE id = $3")
        .bind(branch)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_visibility(db: &Db, id: i64, visibility: &str) -> DbResult<()> {
    sqlx::query("UPDATE repos SET visibility = $1, updated_at = $2 WHERE id = $3")
        .bind(visibility)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
```

- [ ] **Step 5: Implement the settings methods in `starforged-core`**

In `crates/starforged-core/src/repos.rs`, add after `fn viewer`:

```rust
/// Longest repository description, in characters.
const MAX_DESCRIPTION_CHARS: usize = 350;

/// Trims a description and checks its length.
fn checked_description(input: &str) -> CoreResult<String> {
    let description = input.trim();
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(CoreError::Invalid(
            "descriptions are at most 350 characters".into(),
        ));
    }
    Ok(description.to_owned())
}
```

In `create_repo`, replace the inline description check (`let description = input.description.trim();` and the `if description.chars().count() > 350 { … }` block) with:

```rust
        let description = checked_description(&input.description)?;
```

and set `description: &description,` in the `NewRepo` literal.

Append a new `impl Core` block after the existing one (before `#[cfg(test)]`):

```rust
impl Core {
    /// Maintainers and up: replaces the description (forge-basics design §5.2).
    pub async fn set_repo_description(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        description: &str,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        let description = checked_description(description)?;
        if description != access.repo.description {
            db_repos::set_description(self.db(), access.repo.id, &description).await?;
        }
        self.reload_repo(access.repo.id).await
    }

    /// Maintainers and up: makes the existing branch `branch` the default and points the bare repository's
    /// `HEAD` at it, so new clones check it out.
    pub async fn set_default_branch(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        branch: &str,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        if access.repo.default_branch == branch {
            return Ok(access.repo);
        }
        if !self.branches(&access).await?.iter().any(|b| b == branch) {
            return Err(CoreError::Invalid(format!(
                "there is no branch named '{branch}'"
            )));
        }
        starforged_git::write::set_head(&self.repo_path(access.repo.id), branch).await?;
        db_repos::set_default_branch(self.db(), access.repo.id, branch).await?;
        self.audit(
            Some(actor.id),
            "repo.default_branch",
            &format!("repo:{}", access.repo.full_name()),
            branch,
        )
        .await?;
        self.reload_repo(access.repo.id).await
    }

    /// Admins: changes who can read the repository.
    pub async fn set_visibility(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        visibility: Visibility,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        let old = access.repo.visibility;
        if old == visibility {
            return Ok(access.repo);
        }
        db_repos::set_visibility(self.db(), access.repo.id, visibility.as_str()).await?;
        self.audit(
            Some(actor.id),
            "repo.visibility",
            &format!("repo:{}", access.repo.full_name()),
            &format!("{} -> {}", old.as_str(), visibility.as_str()),
        )
        .await?;
        self.reload_repo(access.repo.id).await
    }

    /// The repository as stored now.
    async fn reload_repo(&self, id: i64) -> CoreResult<Repo> {
        to_repo(
            db_repos::by_id(self.db(), id)
                .await?
                .ok_or(CoreError::NotFound)?,
        )
    }
}
```

- [ ] **Step 6: Run the core and git tests**

Run: `cargo test -p starforged-core repos::tests && cargo test -p starforged-git write::tests`
Expected: all pass.

- [ ] **Step 7: Write the failing web tests**

Create `crates/starforged/tests/web_repo_settings.rs`:

```rust
mod common;

use common::*;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maintainers_edit_general_settings_and_admins_change_visibility() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    s.user("walt").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "walt", Permission::Write)
        .await
        .unwrap();
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# Proj\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "dev"]).await;
    commit_files(&work, &[("dev.txt", b"dev\n")], "dev work").await;
    git_ok(&work, &["push", "-q", &url, "main", "dev"]).await;

    let anonymous = s
        .browser()
        .get(s.url("/alice/proj/settings"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 303);
    assert!(
        anonymous.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("/login?next=")
    );

    let (walt, _) = s.login("walt").await;
    assert!(
        !get_text(&walt, &s.url("/alice/proj"))
            .await
            .contains(r#"href="/alice/proj/settings""#),
        "writers do not see the Settings tab"
    );
    assert_eq!(
        walt.get(s.url("/alice/proj/settings"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    let (mia, mia_csrf) = s.login("mia").await;
    assert!(
        get_text(&mia, &s.url("/alice/proj"))
            .await
            .contains(r#"href="/alice/proj/settings""#)
    );
    let settings = get_text(&mia, &s.url("/alice/proj/settings")).await;
    assert!(settings.contains(r#"name="description""#), "{settings}");
    assert!(settings.contains(r#"<option value="dev">dev</option>"#), "{settings}");
    assert!(
        !settings.contains("/settings/visibility"),
        "maintainers do not see admin settings"
    );
    assert!(
        !settings.contains("/settings/collaborators"),
        "nor the collaborators page"
    );

    let saved = mia
        .post(s.url("/alice/proj/settings"))
        .form(&[
            ("_csrf", mia_csrf.as_str()),
            ("description", "A demo"),
            ("default_branch", "dev"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 303);
    assert_eq!(saved.headers()["location"], "/alice/proj/settings");
    let home = get_text(&mia, &s.url("/alice/proj")).await;
    assert!(home.contains("A demo"), "{home}");
    assert!(home.contains("dev.txt"), "the home page shows the new default branch");
    assert!(
        get_text(&mia, &s.url("/alice/proj/commits"))
            .await
            .contains("dev work"),
        "the Commits tab follows the default branch"
    );
    assert_eq!(
        std::fs::read_to_string(s.core.repo_path(repo.id).join("HEAD")).unwrap(),
        "ref: refs/heads/dev\n"
    );
    git_ok(tmp.path(), &["clone", "-q", &url, "clone"]).await;
    assert_eq!(
        git_ok(&tmp.path().join("clone"), &["rev-parse", "--abbrev-ref", "HEAD"])
            .await
            .trim(),
        "dev",
        "new clones check out the default branch"
    );

    let unknown = mia
        .post(s.url("/alice/proj/settings"))
        .form(&[
            ("_csrf", mia_csrf.as_str()),
            ("description", "A demo"),
            ("default_branch", "nope"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 422);
    assert!(unknown.text().await.unwrap().contains("no branch named"));
    let forbidden = mia
        .post(s.url("/alice/proj/settings/visibility"))
        .form(&[("_csrf", mia_csrf.as_str()), ("visibility", "public")])
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), 403);

    let (owner, csrf) = s.login("alice").await;
    let admin_view = get_text(&owner, &s.url("/alice/proj/settings")).await;
    assert!(admin_view.contains("/alice/proj/settings/visibility"));
    assert!(admin_view.contains(r#"href="/alice/proj/settings/collaborators""#));
    let public = owner
        .post(s.url("/alice/proj/settings/visibility"))
        .form(&[("_csrf", csrf.as_str()), ("visibility", "public")])
        .send()
        .await
        .unwrap();
    assert_eq!(public.status(), 303);
    assert_eq!(
        s.browser()
            .get(s.url("/alice/proj"))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "anyone can read a public repository"
    );
    let actions: Vec<String> = starforged_db::audit::recent(s.core.db(), 20)
        .await
        .unwrap()
        .into_iter()
        .map(|e| e.action)
        .collect();
    assert!(actions.contains(&"repo.visibility".to_owned()), "{actions:?}");
    assert!(actions.contains(&"repo.default_branch".to_owned()), "{actions:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_commits_tab_works_before_the_first_push() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "empty", Visibility::Public).await;
    let client = s.browser();
    let home = get_text(&client, &s.url("/alice/empty")).await;
    assert!(home.contains(r#"href="/alice/empty/commits""#), "{home}");
    let commits = get_text(&client, &s.url("/alice/empty/commits")).await;
    assert!(commits.contains("No commits yet."), "{commits}");
}
```

In `crates/starforged/tests/web_code.rs`, `private_and_empty_repositories`, replace the two `Collaborators` assertions:

```rust
    assert!(
        !empty.contains(r#"href="/alice/empty/settings""#),
        "only maintainers and admins see the Settings tab"
    );
    let (owner, _) = s.login("alice").await;
    assert!(
        get_text(&owner, &s.url("/alice/hidden"))
            .await
            .contains(r#"href="/alice/hidden/settings""#)
    );
```

- [ ] **Step 8: Run them to see them fail**

Run: `cargo test -p starforged --test web_repo_settings --test web_code`
Expected: FAIL: `/alice/proj/settings` and `/alice/empty/commits` answer 404, and the home page has no Settings tab.

- [ ] **Step 9: Add `RepoHead` to `views.rs`**

In `crates/starforged-web/src/views.rs`, change the imports at the top to:

```rust
use starforged_core::permission::Permission;
use starforged_core::repos::{Repo, RepoAccess};
use starforged_core::sessions::WebSession;
```

and add after `nav`:

```rust
/// The header of every repository page (`repo_head.html`): owner and name, badges, description, and tabs.
pub struct RepoHead {
    pub owner: String,
    pub name: String,
    pub description: String,
    pub visibility: &'static str,
    /// The highlighted tab: `code`, `commits`, or `settings`; any other value highlights none.
    pub tab: &'static str,
    /// The Commits tab: the history of the ref being viewed, or `/{owner}/{repo}/commits`.
    pub commits_href: String,
    /// Maintainers and admins see the Settings tab.
    pub can_maintain: bool,
    /// Admins also see the admin-only settings.
    pub can_admin: bool,
}

impl RepoHead {
    /// `ref_name` is the branch, tag, or commit the page shows, when it shows one.
    pub fn new(access: &RepoAccess, tab: &'static str, ref_name: Option<&str>) -> RepoHead {
        let repo = &access.repo;
        let commits_href = match ref_name {
            Some(name) => format!(
                "/{}/{}/commits/{}",
                repo.owner,
                repo.name,
                encode_path(name)
            ),
            None => format!("/{}/{}/commits", repo.owner, repo.name),
        };
        RepoHead {
            owner: repo.owner.clone(),
            name: repo.name.clone(),
            description: repo.description.clone(),
            visibility: repo.visibility.as_str(),
            tab,
            commits_href,
            can_maintain: access.permission >= Permission::Maintain,
            can_admin: access.permission >= Permission::Admin,
        }
    }
}
```

- [ ] **Step 10: Write the shared templates**

Create `crates/starforged-web/templates/repo_head.html`:

```html
<div class="repo-head">
<h1><a href="/{{ head.owner }}">{{ head.owner }}</a> / <a href="/{{ head.owner }}/{{ head.name }}">{{ head.name }}</a> <span class="badge">{{ head.visibility }}</span></h1>
{% if !head.description.is_empty() %}<p class="muted">{{ head.description }}</p>{% endif %}
<nav class="tabs" aria-label="Repository">
<a href="/{{ head.owner }}/{{ head.name }}"{% if head.tab == "code" %} aria-current="page"{% endif %}>Code</a>
<a href="{{ head.commits_href }}"{% if head.tab == "commits" %} aria-current="page"{% endif %}>Commits</a>
{% if head.can_maintain %}<a href="/{{ head.owner }}/{{ head.name }}/settings"{% if head.tab == "settings" %} aria-current="page"{% endif %}>Settings</a>{% endif %}
</nav>
</div>
```

Create `crates/starforged-web/templates/repo_settings_nav.html`:

```html
<nav class="tabs" aria-label="Repository settings">
<a href="/{{ head.owner }}/{{ head.name }}/settings"{% if settings_page == "general" %} aria-current="page"{% endif %}>General</a>
{% if head.can_admin %}<a href="/{{ head.owner }}/{{ head.name }}/settings/collaborators"{% if settings_page == "collaborators" %} aria-current="page"{% endif %}>Collaborators</a>{% endif %}
</nav>
```

Create `crates/starforged-web/templates/repo_settings.html`:

```html
{% extends "base.html" %}
{% block title %}Settings · {{ head.owner }}/{{ head.name }}{% endblock %}
{% block content %}
{% include "repo_head.html" %}
{% include "repo_settings_nav.html" %}
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<h2>General</h2>
<form method="post" action="/{{ head.owner }}/{{ head.name }}/settings" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Description <input name="description" maxlength="350" value="{{ description }}"></label>
  {% if branches.is_empty() %}
  <p class="muted">You can choose the default branch after the first push.</p>
  {% else %}
  <label>Default branch <select name="default_branch">{% for b in branches %}<option value="{{ b.name }}"{% if b.selected %} selected{% endif %}>{{ b.name }}</option>{% endfor %}</select></label>
  {% endif %}
  <button type="submit">Save</button>
</form>
{% if head.can_admin %}
<h2>Visibility</h2>
<form method="post" action="/{{ head.owner }}/{{ head.name }}/settings/visibility" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <fieldset>
    <legend>Who can read this repository</legend>
    {% for v in visibility_choices %}<label class="check"><input type="radio" name="visibility" value="{{ v.value }}"{% if v.checked %} checked{% endif %}> {{ v.label }}</label>
    {% endfor %}
  </fieldset>
  <button type="submit">Change visibility</button>
</form>
{% endif %}
{% endblock %}
```

Tasks B3, B4, and B5 add their sections after the Visibility form, before the `{% endif %}` that closes `{% if head.can_admin %}`.

Replace `crates/starforged-web/templates/tree.html` with:

```html
{% extends "base.html" %}
{% block title %}{{ head.owner }}/{{ head.name }} · Starforge{% endblock %}
{% block content %}
{% include "repo_head.html" %}
<p>Clone with <code>git clone {{ clone_url }}</code></p>
{% if empty %}
<p>This repository is empty. Push an existing repository to it:</p>
<pre>git remote add origin {{ clone_url }}
git push -u origin main</pre>
{% else %}
<p class="crumbs"><span class="badge">{{ ref_name }}</span>{% for c in crumbs %} / <a href="{{ c.href }}">{{ c.name }}</a>{% endfor %}</p>
<table class="list files"><tbody>
{% for e in entries %}
<tr><td class="{% if e.is_dir %}dir{% else %}file{% endif %}">{% if e.href.is_empty() %}{{ e.name }}{% else %}<a href="{{ e.href }}">{{ e.name }}</a>{% endif %}</td></tr>
{% endfor %}
</tbody></table>
{% if let Some(html) = readme_html %}<article class="readme">{{ html|safe }}</article>{% endif %}
{% endif %}
{% endblock %}
```

Replace `crates/starforged-web/templates/blob.html` with:

```html
{% extends "base.html" %}
{% block title %}{{ path }} · {{ head.owner }}/{{ head.name }}{% endblock %}
{% block content %}
{% include "repo_head.html" %}
<p class="crumbs"><span class="badge">{{ ref_name }}</span>{% for c in crumbs %} / <a href="{{ c.href }}">{{ c.name }}</a>{% endfor %} / {{ file_name }} · <a href="{{ raw_href }}">Raw</a> · {{ size }} bytes</p>
{% if let Some(n) = notice %}
<p class="muted">{{ n }}</p>
{% else %}
<table class="code"><tbody>
{% for line in lines %}<tr><td class="ln">{{ loop.index }}</td><td><pre>{{ line }}</pre></td></tr>
{% endfor %}
</tbody></table>
{% endif %}
{% endblock %}
```

Replace `crates/starforged-web/templates/commits.html` with:

```html
{% extends "base.html" %}
{% block title %}Commits · {{ head.owner }}/{{ head.name }}{% endblock %}
{% block content %}
{% include "repo_head.html" %}
{% if ref_name.is_empty() %}
<p class="muted">No commits yet.</p>
{% else %}
<h2>Commits on <span class="badge">{{ ref_name }}</span></h2>
<ol class="commits">
{% for c in commits %}
<li><a href="/{{ head.owner }}/{{ head.name }}/commit/{{ c.id }}"><code>{{ c.short_id }}</code></a> {{ c.summary }} <span class="muted">{{ c.author }} · {{ c.when }}</span></li>
{% endfor %}
</ol>
<p class="pager">{% if page > 1 %}<a href="?page={{ page - 1 }}">Newer</a> {% endif %}{% if has_next %}<a href="?page={{ page + 1 }}">Older</a>{% endif %}</p>
{% endif %}
{% endblock %}
```

In `crates/starforged-web/templates/commit.html`, replace the `<h1>…</h1>` line with `{% include "repo_head.html" %}`, the title block with `{% block title %}{{ summary }} · {{ head.owner }}/{{ head.name }}{% endblock %}`, and the parent link with `<a href="/{{ head.owner }}/{{ head.name }}/commit/{{ p }}">`. Everything from the `{% if truncated %}` line down stays.

Replace `crates/starforged-web/templates/collaborators.html` with:

```html
{% extends "base.html" %}
{% block title %}Collaborators · {{ head.owner }}/{{ head.name }}{% endblock %}
{% block content %}
{% include "repo_head.html" %}
{% include "repo_settings_nav.html" %}
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<h2>Collaborators</h2>
{% if collaborators.is_empty() %}
<p class="muted">No collaborators yet.</p>
{% else %}
<table class="list">
<thead><tr><th>User</th><th>Permission</th><th></th></tr></thead>
<tbody>
{% for c in collaborators %}
<tr><td><a href="/{{ c.handle }}">{{ c.handle }}</a></td><td>{{ c.permission }}</td>
<td><form method="post" action="/{{ head.owner }}/{{ head.name }}/settings/collaborators/{{ c.handle }}/remove" class="inline"><input type="hidden" name="_csrf" value="{{ csrf }}"><button type="submit">Remove</button></form></td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}
<h2>Add or change a collaborator</h2>
<form method="post" action="/{{ head.owner }}/{{ head.name }}/settings/collaborators" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Handle <input name="handle" required></label>
  <label>Permission <select name="permission">{% for p in permission_choices %}<option value="{{ p }}">{{ p }}</option>{% endfor %}</select></label>
  <button type="submit">Save</button>
</form>
{% endblock %}
```

- [ ] **Step 11: Use `RepoHead` in the code, history, and collaborators pages**

In `crates/starforged-web/src/pages/code.rs`:
1. Imports: drop `starforged_core::permission::Permission` and `encode_path`; import `RepoHead`:
   `use crate::views::{Crumb, NavUser, RepoHead, content_href, crumbs, nav};`
2. Replace the two page structs:

```rust
#[derive(Template, WebTemplate)]
#[template(path = "tree.html")]
pub struct TreePage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    clone_url: String,
    empty: bool,
    ref_name: String,
    crumbs: Vec<Crumb>,
    entries: Vec<EntryRow>,
    readme_html: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "blob.html")]
pub struct BlobPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    ref_name: String,
    path: String,
    file_name: String,
    crumbs: Vec<Crumb>,
    raw_href: String,
    size: usize,
    lines: Vec<String>,
    notice: Option<&'static str>,
}

/// The default branch when it exists, else the first branch by name; `None` for an empty repository.
pub(crate) async fn default_ref(
    state: &AppState,
    access: &RepoAccess,
) -> Result<Option<String>, WebError> {
    let branches = state.core.branches(access).await?;
    Ok(if branches.contains(&access.repo.default_branch) {
        Some(access.repo.default_branch.clone())
    } else {
        branches.into_iter().next()
    })
}
```

3. In `repo_home`, replace everything from `let branches = …` through the `let Some(default) = default else { … };` statement with:

```rust
    let Some(default) = default_ref(&state, &access).await? else {
        return Ok(tree_page(
            &state,
            session.as_ref(),
            &access,
            None,
            "",
            Vec::new(),
            None,
        )
        .into_response());
    };
```

4. In `blob`, the `BlobPage` literal starts:

```rust
    Ok(BlobPage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "code", Some(&resolved.ref_name)),
        ref_name: resolved.ref_name.clone(),
```

and drops `owner` and `name` (the rest is unchanged).

5. Replace `fn tree_page` with:

```rust
fn tree_page(
    state: &AppState,
    session: Option<&WebSession>,
    access: &RepoAccess,
    ref_name: Option<&str>,
    dir: &str,
    entries: Vec<EntryRow>,
    readme_html: Option<String>,
) -> TreePage {
    let repo = &access.repo;
    let current = ref_name.unwrap_or_default();
    TreePage {
        nav_user: nav(session),
        head: RepoHead::new(access, "code", ref_name),
        clone_url: format!(
            "{}/{}/{}.git",
            state.settings.base_url, repo.owner, repo.name
        ),
        empty: ref_name.is_none(),
        ref_name: current.to_owned(),
        crumbs: crumbs(&repo.owner, &repo.name, current, dir),
        entries,
        readme_html,
    }
}
```

Replace `crates/starforged-web/src/pages/history.rs` from the top through the end of `pub async fn commits` with:

```rust
use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use starforged_core::repos::RepoAccess;
use starforged_core::sessions::WebSession;
use starforged_git::diff::{FileStatus, LineKind};

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::pages::code::default_ref;
use crate::views::{NavUser, RepoHead, format_time, nav};

pub const PER_PAGE: usize = 50;

#[derive(Deserialize)]
pub struct PageQuery {
    page: Option<usize>,
}

pub struct CommitRow {
    id: String,
    short_id: String,
    summary: String,
    author: String,
    when: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "commits.html")]
pub struct CommitsPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    /// Empty when the repository has no commits yet.
    ref_name: String,
    commits: Vec<CommitRow>,
    page: usize,
    has_next: bool,
}

pub struct LineView {
    class: &'static str,
    old: String,
    new: String,
    text: String,
}

pub struct HunkView {
    header: String,
    lines: Vec<LineView>,
}

pub struct FileView {
    status: &'static str,
    path: String,
    binary: bool,
    hunks: Vec<HunkView>,
}

#[derive(Template, WebTemplate)]
#[template(path = "commit.html")]
pub struct CommitPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    id: String,
    summary: String,
    body: String,
    author: String,
    when: String,
    parents: Vec<String>,
    files: Vec<FileView>,
    truncated: bool,
}

pub async fn commits(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
    Query(query): Query<PageQuery>,
) -> Result<CommitsPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let resolved = state.core.resolve(&access, &rest).await?;
    if !resolved.path.is_empty() {
        return Err(WebError::NotFound);
    }
    commits_page(
        &state,
        session.as_ref(),
        &access,
        Some((resolved.ref_name, resolved.commit_id)),
        query.page,
    )
    .await
}

/// `/{owner}/{repo}/commits`: the default branch's history; an empty repository shows "No commits yet."
pub async fn default_commits(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<PageQuery>,
) -> Result<CommitsPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let target = match default_ref(&state, &access).await? {
        Some(name) => {
            let resolved = state.core.resolve(&access, &name).await?;
            Some((resolved.ref_name, resolved.commit_id))
        }
        None => None,
    };
    commits_page(&state, session.as_ref(), &access, target, query.page).await
}

/// One page of the history of `target` (ref name, commit id); `None` lists nothing.
async fn commits_page(
    state: &AppState,
    session: Option<&WebSession>,
    access: &RepoAccess,
    target: Option<(String, String)>,
    page: Option<usize>,
) -> Result<CommitsPage, WebError> {
    let page = page.unwrap_or(1).max(1);
    let (ref_name, mut commits) = match target {
        Some((ref_name, commit_id)) => {
            let commits = state
                .core
                .log(
                    access,
                    &commit_id,
                    (page - 1).saturating_mul(PER_PAGE),
                    PER_PAGE + 1,
                )
                .await?;
            (ref_name, commits)
        }
        None => (String::new(), Vec::new()),
    };
    let has_next = commits.len() > PER_PAGE;
    commits.truncate(PER_PAGE);
    let head = RepoHead::new(
        access,
        "commits",
        Some(ref_name.as_str()).filter(|r| !r.is_empty()),
    );
    Ok(CommitsPage {
        nav_user: nav(session),
        head,
        ref_name,
        commits: commits
            .into_iter()
            .map(|c| CommitRow {
                short_id: c.short_id().to_owned(),
                author: c.author_name.clone(),
                when: format_time(c.author_time),
                summary: c.summary,
                id: c.id,
            })
            .collect(),
        page,
        has_next,
    })
}
```

In `pub async fn commit`, build the header right after `let access = …;`:

```rust
    let head = RepoHead::new(&access, "commits", None);
```

and in the `CommitPage` literal replace `owner: access.repo.owner, name: access.repo.name,` with `head,`.

In `crates/starforged-web/src/pages/collaborators.rs`:
1. Import `RepoHead`: `use crate::views::{NavUser, RepoHead};`
2. In `CollaboratorsPage`, replace the `owner: String, name: String,` fields with:

```rust
    head: RepoHead,
    settings_page: &'static str,
```

3. In `page`, the literal becomes:

```rust
    Ok(CollaboratorsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "collaborators",
        collaborators,
        permission_choices: Permission::ALL
            .into_iter()
            .map(Permission::as_str)
            .collect(),
        error,
    })
```

- [ ] **Step 12: Add the settings page**

Create `crates/starforged-web/src/pages/repo_settings.rs`:

```rust
//! The repository settings page (forge-basics design §5.2): general settings for maintainers; visibility and
//! the actions after it for admins.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::Repo;
use starforged_core::sessions::WebSession;
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};

pub struct BranchOption {
    name: String,
    selected: bool,
}

pub struct VisibilityChoice {
    value: &'static str,
    label: &'static str,
    checked: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_settings.html")]
pub struct RepoSettingsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    description: String,
    branches: Vec<BranchOption>,
    visibility_choices: Vec<VisibilityChoice>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct GeneralForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    description: String,
    /// Absent while the repository has no branches.
    #[serde(default)]
    default_branch: String,
}

#[derive(Deserialize)]
pub struct VisibilityForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    visibility: String,
}

pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<RepoSettingsPage, WebError> {
    page(&state, &session, &owner, &repo, None).await
}

pub async fn save_general(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<GeneralForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let user = &session.user;
    let result = match state
        .core
        .set_repo_description(user, &owner, &repo, &form.description)
        .await
    {
        Ok(updated) if form.default_branch.is_empty() => Ok(updated),
        Ok(_) => {
            state
                .core
                .set_default_branch(user, &owner, &repo, &form.default_branch)
                .await
        }
        Err(err) => Err(err),
    };
    finish(&state, &session, &owner, &repo, result).await
}

pub async fn change_visibility(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<VisibilityForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let visibility = Visibility::parse(&form.visibility)
        .ok_or_else(|| WebError::BadRequest("unknown visibility".into()))?;
    let result = state
        .core
        .set_visibility(&session.user, &owner, &repo, visibility)
        .await;
    finish(&state, &session, &owner, &repo, result).await
}

/// After a settings action: back to the settings page under the repository's current name, or this page
/// again with the message when the input was refused.
pub(crate) async fn finish(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    result: CoreResult<Repo>,
) -> Result<Response, WebError> {
    match result {
        Ok(updated) => Ok(Redirect::to(&format!(
            "/{}/{}/settings",
            updated.owner, updated.name
        ))
        .into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(state, session, owner, repo, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

async fn page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
) -> Result<RepoSettingsPage, WebError> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Maintain)
        .await?;
    let branches = state
        .core
        .branches(&access)
        .await?
        .into_iter()
        .map(|name| BranchOption {
            selected: name == access.repo.default_branch,
            name,
        })
        .collect();
    let current = access.repo.visibility;
    let visibility_choices = [
        (Visibility::Private, "Private"),
        (
            Visibility::Internal,
            "Internal (every signed-in user can read)",
        ),
        (Visibility::Public, "Public"),
    ]
    .into_iter()
    .map(|(visibility, label)| VisibilityChoice {
        value: visibility.as_str(),
        label,
        checked: visibility == current,
    })
    .collect();
    Ok(RepoSettingsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "general",
        description: access.repo.description.clone(),
        branches,
        visibility_choices,
        error,
    })
}
```

In `crates/starforged-web/src/pages/mod.rs`, add `pub mod repo_settings;` after `pub mod repo_new;`.

In `crates/starforged-web/src/lib.rs` `page_routes()`, add before the `/{owner}/{repo}/settings/collaborators` route:

```rust
        .route(
            "/{owner}/{repo}/settings",
            get(pages::repo_settings::show).post(pages::repo_settings::save_general),
        )
        .route(
            "/{owner}/{repo}/settings/visibility",
            post(pages::repo_settings::change_visibility),
        )
```

and after the `/{owner}/{repo}/blob/{*rest}`… routes, before `/{owner}/{repo}/commits/{*rest}`:

```rust
        .route(
            "/{owner}/{repo}/commits",
            get(pages::history::default_commits),
        )
```

- [ ] **Step 13: Hide the secret key in `SecurityConfig`'s `Debug` output**

In `crates/starforged/src/config.rs`, remove `Debug` from `SecurityConfig`'s derive list (`#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]`) and add after the struct:

```rust
impl std::fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("secret_key", &"<redacted>")
            .finish()
    }
}
```

Add to the config tests:

```rust
    #[test]
    fn debug_output_hides_the_secret_key() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains(&"ab".repeat(32)), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
```

- [ ] **Step 14: Run the tests**

Run: `cargo test -p starforged --test web_repo_settings --test web_code --test web_history --test web_collaborators && cargo test -p starforged config::tests`
Expected: all pass.

- [ ] **Step 15: Full check on both databases, commit**

```bash
STARFORGE_TEST_PG=1 scripts/check.sh
git add -A crates
git commit -m "feat: repository settings page, shared repository header, and the Commits tab before the first push"
```

Expected: fmt, clippy, and every test green on SQLite and Postgres.

---
### Task B2: Initialize new repositories with a README

**Files:**
- Modify: `crates/starforged-git/src/write.rs` (`Identity`, `initial_commit`, private `plumbing`)
- Modify: `crates/starforged-core/src/repos.rs` (`CreateRepo.readme`, `create_repo`, `initialize`, `commit_identity`, tests)
- Modify: `crates/starforged-web/src/pages/repo_new.rs`, `crates/starforged-web/templates/repo_new.html`
- Modify: `crates/starforged-api/src/repos.rs` (`readme` in the create body)
- Modify: `crates/starforged/tests/common/mod.rs` (`TestServer::repo` passes `readme: false`)
- Test: Create `crates/starforged/tests/web_readme.rs`

**Interfaces:**
- Consumes: `starforged_git::write` (B1), `starforged_git::{init::init_bare, read::{log, blob_bytes, branches, resolve}}`, `checked_description`, `Core::reload_repo` (B1), `starforged_db::now`, `url::Url`.
- Produces:
  - `starforged_git::write::Identity<'a> { name: &'a str, email: &'a str, time: i64 }` (`Clone`, `Copy`) and `starforged_git::write::initial_commit(repo: &Path, branch: &str, files: &[(&str, &[u8])], author: Identity<'_>, message: &str) -> Result<String, GitError>`: writes the first commit of `branch` with `files` at the root of the tree; fails without touching refs when `branch` exists; returns the commit id.
  - `starforged_core::repos::CreateRepo { name, description, visibility, readme: bool }`. Every constructor sets `readme`.
  - `Core::commit_identity(&self, user: &User) -> (String, String)` (`pub(crate)`): the display name (or handle), and the verified email or `<handle>@users.noreply.<host of base_url>`.
  - API: `POST /api/v1/user/repos` accepts `"readme": true`.

- [ ] **Step 1: Write the failing git and core tests**

Add to the tests in `crates/starforged-git/src/write.rs`:

```rust
    #[tokio::test]
    async fn initial_commit_writes_the_first_commit_once() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("r.git");
        crate::init::init_bare(&repo, "main", Path::new("/bin/false"))
            .await
            .unwrap();
        let author = Identity {
            name: "Alice Doe",
            email: "alice@example.com",
            time: 1_700_000_000,
        };
        let id = initial_commit(
            &repo,
            "main",
            &[("README.md", b"# proj\n")],
            author,
            "Initial commit",
        )
        .await
        .unwrap();
        let log = crate::read::log(&repo, &id, 0, 10).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            (
                log[0].summary.as_str(),
                log[0].author_name.as_str(),
                log[0].author_email.as_str(),
                log[0].author_time
            ),
            ("Initial commit", "Alice Doe", "alice@example.com", 1_700_000_000)
        );
        assert_eq!(
            crate::read::blob_bytes(&repo, &id, "README.md")
                .unwrap()
                .unwrap(),
            b"# proj\n"
        );
        assert_eq!(crate::read::branches(&repo).unwrap(), vec!["main"]);
        let again = initial_commit(
            &repo,
            "main",
            &[("README.md", b"other\n")],
            author,
            "Again",
        )
        .await;
        assert!(again.is_err(), "an existing branch is never overwritten");
        assert_eq!(
            crate::read::resolve(&repo, "main").unwrap().unwrap().commit_id,
            id
        );
    }
```

In `crates/starforged-core/src/repos.rs`'s tests, give the `new` helper and the `CreateRepo` literal in `create_repo_initializes_a_bare_repository` the field `readme: false`, add `use crate::accounts::CreateUser;` to the test imports, and add:

```rust
    #[tokio::test]
    async fn a_readme_commit_uses_the_owners_identity() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        core.create_repo(
            &alice,
            CreateRepo {
                name: "proj".into(),
                description: "A demo".into(),
                visibility: Visibility::Public,
                readme: true,
            },
        )
        .await
        .unwrap();
        let access = core.repo_for(Some(&alice), "alice", "proj").await.unwrap();
        let main = core.resolve(&access, "main").await.unwrap();
        let log = core.log(&access, &main.commit_id, 0, 10).await.unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            (log[0].author_name.as_str(), log[0].author_email.as_str()),
            ("alice", "alice@users.noreply.forge.test")
        );
        let readme = core
            .blob(&access, &main.commit_id, "README.md")
            .await
            .unwrap();
        assert_eq!(readme.bytes.unwrap(), b"# proj\n\nA demo\n");

        for (handle, display_name, verified, expected) in [
            ("bo", "Bo Diaz", true, ("Bo Diaz", "bo@example.com")),
            ("cy", "", false, ("cy", "cy@users.noreply.forge.test")),
        ] {
            let owner = core
                .create_user(CreateUser {
                    handle: handle.into(),
                    display_name: display_name.into(),
                    email: Some(format!("{handle}@example.com")),
                    email_verified: verified,
                    ..Default::default()
                })
                .await
                .unwrap();
            core.create_repo(
                &owner,
                CreateRepo {
                    name: "notes".into(),
                    description: String::new(),
                    visibility: Visibility::Private,
                    readme: true,
                },
            )
            .await
            .unwrap();
            let access = core.repo_for(Some(&owner), handle, "notes").await.unwrap();
            let main = core.resolve(&access, "main").await.unwrap();
            let log = core.log(&access, &main.commit_id, 0, 1).await.unwrap();
            assert_eq!(
                (log[0].author_name.as_str(), log[0].author_email.as_str()),
                expected,
                "{handle}: only a verified address is used"
            );
            assert_eq!(
                core.blob(&access, &main.commit_id, "README.md")
                    .await
                    .unwrap()
                    .bytes
                    .unwrap(),
                b"# notes\n"
            );
        }
    }
```

- [ ] **Step 2: Run them to see them fail**

Run: `cargo test -p starforged-git write::tests && cargo test -p starforged-core repos::tests`
Expected: compile errors: no `Identity` or `initial_commit` in `write`, and no field `readme` on `CreateRepo`.

- [ ] **Step 3: Implement `initial_commit`**

In `crates/starforged-git/src/write.rs`, change the imports to:

```rust
use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;

use crate::command::{GitError, git, run};
```

and add after `set_head`:

```rust
/// Who a commit written by the server is by. `time` is unix seconds.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    pub name: &'a str,
    pub email: &'a str,
    pub time: i64,
}

/// Writes the first commit of `branch`: `files` (a name without `/`, and the content) at the root of the
/// tree, with `author` as author and committer. Fails without changing any ref when `branch` already exists.
/// Returns the commit id.
pub async fn initial_commit(
    repo: &Path,
    branch: &str,
    files: &[(&str, &[u8])],
    author: Identity<'_>,
    message: &str,
) -> Result<String, GitError> {
    let mut tree = String::new();
    for (name, content) in files {
        let blob = plumbing(repo, &["hash-object", "-w", "--stdin"], Some(content), &[]).await?;
        tree.push_str(&format!("100644 blob {blob}\t{name}\n"));
    }
    let tree_id = plumbing(repo, &["mktree"], Some(tree.as_bytes()), &[]).await?;
    let date = format!("@{} +0000", author.time);
    let env = [
        ("GIT_AUTHOR_NAME", author.name),
        ("GIT_AUTHOR_EMAIL", author.email),
        ("GIT_AUTHOR_DATE", date.as_str()),
        ("GIT_COMMITTER_NAME", author.name),
        ("GIT_COMMITTER_EMAIL", author.email),
        ("GIT_COMMITTER_DATE", date.as_str()),
    ];
    let commit = plumbing(repo, &["commit-tree", &tree_id, "-m", message], None, &env).await?;
    // The empty old value makes `update-ref` refuse to overwrite an existing branch.
    let target = format!("refs/heads/{branch}");
    plumbing(repo, &["update-ref", &target, &commit, ""], None, &[]).await?;
    Ok(commit)
}

/// Runs `git --git-dir <repo> <args>` with optional stdin and extra environment; returns trimmed stdout.
async fn plumbing(
    repo: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    env: &[(&str, &str)],
) -> Result<String, GitError> {
    let mut command = git();
    command
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn()?;
    if let Some(input) = stdin
        && let Some(mut pipe) = child.stdin.take()
    {
        pipe.write_all(input).await?;
        // `pipe` drops here, closing git's stdin.
    }
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(GitError::Failed {
            command: args.first().copied().unwrap_or_default().to_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
```

- [ ] **Step 4: Create the README in `create_repo`**

In `crates/starforged-core/src/repos.rs`:
1. Add imports: `use std::path::Path;`, `use starforged_db::now;`, and `use starforged_git::write::Identity;`.
2. Add to `CreateRepo`:

```rust
    /// Commit a `README.md` (the name as a heading, then the description) as the first commit of `main`.
    pub readme: bool,
```

3. Replace `create_repo` with:

```rust
    /// Creates a repository owned by `actor` (organizations arrive in M3) and its bare git directory, with a
    /// README commit when `input.readme` is set (forge-basics design §5.1).
    pub async fn create_repo(&self, actor: &User, input: CreateRepo) -> CoreResult<Repo> {
        let name = validate::repo_name(&input.name)?;
        let description = checked_description(&input.description)?;
        let new = NewRepo {
            owner_id: actor.id,
            name: &name,
            description: &description,
            visibility: input.visibility.as_str(),
            default_branch: "main",
        };
        let id = db_repos::insert(self.db(), &new).await.map_err(|e| {
            if e.is_unique_violation() {
                CoreError::Conflict(format!("{}/{name} already exists", actor.handle))
            } else {
                e.into()
            }
        })?;
        let path = self.repo_path(id);
        if let Err(err) = self
            .initialize(actor, &path, &name, &description, input.readme)
            .await
        {
            db_repos::delete(self.db(), id).await?;
            let _ = tokio::fs::remove_dir_all(&path).await;
            return Err(err);
        }
        let repo = self.reload_repo(id).await?;
        self.audit(
            Some(actor.id),
            "repo.create",
            &format!("repo:{}", repo.full_name()),
            repo.visibility.as_str(),
        )
        .await?;
        Ok(repo)
    }

    /// Creates the bare repository and, when asked, its first commit with a README.
    async fn initialize(
        &self,
        actor: &User,
        path: &Path,
        name: &str,
        description: &str,
        readme: bool,
    ) -> CoreResult<()> {
        starforged_git::init::init_bare(path, "main", &self.config().hook_exe).await?;
        if readme {
            let (author, email) = self.commit_identity(actor);
            let text = if description.is_empty() {
                format!("# {name}\n")
            } else {
                format!("# {name}\n\n{description}\n")
            };
            starforged_git::write::initial_commit(
                path,
                "main",
                &[("README.md", text.as_bytes())],
                Identity {
                    name: &author,
                    email: &email,
                    time: now(),
                },
                "Initial commit",
            )
            .await?;
        }
        Ok(())
    }

    /// The name and email on commits the server writes for `user`: the display name (or the handle), and the
    /// verified email or `<handle>@users.noreply.<host of base_url>`.
    pub(crate) fn commit_identity(&self, user: &User) -> (String, String) {
        let name = if user.display_name.is_empty() {
            user.handle.clone()
        } else {
            user.display_name.clone()
        };
        let email = match &user.email {
            Some(email) if user.email_verified => email.clone(),
            _ => {
                let host = url::Url::parse(&self.config().base_url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .unwrap_or_else(|| "localhost".to_owned());
                format!("{}@users.noreply.{host}", user.handle)
            }
        };
        (name, email)
    }
```

- [ ] **Step 5: Run the git and core tests**

Run: `cargo test -p starforged-git write::tests && cargo test -p starforged-core repos::tests`
Expected: all pass.

- [ ] **Step 6: Write the failing web and API test**

Create `crates/starforged/tests/web_readme.rs`:

```rust
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_repositories_can_start_with_a_readme() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    let form = get_text(&client, &s.url("/new")).await;
    assert!(form.contains(r#"name="readme""#), "{form}");
    let created = client
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "proj"),
            ("description", "A demo"),
            ("visibility", "public"),
            ("readme", "on"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 303);
    let home = get_text(&client, &s.url("/alice/proj")).await;
    assert!(home.contains("<h1>proj</h1>"), "{home}");
    assert!(home.contains("<p>A demo</p>"), "{home}");

    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let made: Value = s
        .browser()
        .post(s.url("/api/v1/user/repos"))
        .bearer_auth(&token)
        .json(&json!({"name": "api-made", "readme": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(made["full_name"], "alice/api-made");
    let tmp = tempfile::tempdir().unwrap();
    git_ok(
        tmp.path(),
        &["clone", "-q", &s.git_url("alice", "api-made", Some(&token)), "copy"],
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("copy/README.md")).unwrap(),
        "# api-made\n"
    );
    let log = git_ok(&tmp.path().join("copy"), &["log", "--format=%an <%ae>|%s"]).await;
    assert_eq!(
        log.trim(),
        "alice <alice@users.noreply.127.0.0.1>|Initial commit"
    );
}
```

Run: `cargo test -p starforged --test web_readme`
Expected: compile error in `tests/common/mod.rs` (`CreateRepo` lacks `readme`); after Step 7's harness fix, FAIL because the form has no `readme` checkbox.

- [ ] **Step 7: Add the checkbox, the API field, and the harness field**

In `crates/starforged/tests/common/mod.rs`, `TestServer::repo` passes `readme: false` in its `CreateRepo` literal.

In `crates/starforged-web/src/pages/repo_new.rs`:
1. Add to `NewRepoForm`:

```rust
    /// The "Initialize with a README" checkbox: present only when ticked.
    #[serde(default)]
    readme: Option<String>,
```

2. Add `readme: bool,` to `RepoNewPage` after `description`.
3. Replace `page`, `form`, and `submit` with:

```rust
fn page(
    session: &WebSession,
    name: String,
    description: String,
    readme: bool,
    error: Option<String>,
) -> RepoNewPage {
    RepoNewPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        owner: session.user.handle.clone(),
        name,
        description,
        readme,
        error,
    }
}

pub async fn form(RequireUser(session): RequireUser) -> RepoNewPage {
    page(&session, String::new(), String::new(), false, None)
}

pub async fn submit(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<NewRepoForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let visibility = Visibility::parse(&form.visibility)
        .ok_or_else(|| WebError::BadRequest("unknown visibility".into()))?;
    let readme = form.readme.is_some();
    let input = CreateRepo {
        name: form.name.clone(),
        description: form.description.clone(),
        visibility,
        readme,
    };
    match state.core.create_repo(&session.user, input).await {
        Ok(repo) => Ok(Redirect::to(&format!("/{}/{}", repo.owner, repo.name)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(&session, form.name, form.description, readme, Some(message));
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}
```

In `crates/starforged-web/templates/repo_new.html`, add between `</fieldset>` and the submit button:

```html
  <label class="check"><input type="checkbox" name="readme" value="on"{% if readme %} checked{% endif %}> Initialize with a README</label>
```

In `crates/starforged-api/src/repos.rs`, add to `CreateRepoBody`:

```rust
    /// Commit a README as the first commit.
    #[serde(default)]
    readme: bool,
```

and pass `readme: body.readme,` in the `CreateRepo` literal in `create`.

- [ ] **Step 8: Run the tests**

Run: `cargo test -p starforged --test web_readme --test web_settings --test api`
Expected: all pass.

- [ ] **Step 9: Full check, commit**

```bash
scripts/check.sh
git add -A crates
git commit -m "feat: initialize new repositories with a README"
```

Expected: fmt, clippy, and every test green. (No SQL changed in this task, so SQLite alone suffices.)

---
### Task B3: Rename, with redirects from old names

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0005_repo_redirects.sql`, `crates/starforged-db/migrations/postgres/0005_repo_redirects.sql`
- Create: `crates/starforged-db/src/redirects.rs`; Modify: `crates/starforged-db/src/lib.rs` (`pub mod redirects;`), `crates/starforged-db/src/repos.rs` (`insert` drops a redirect; `rename`)
- Modify: `crates/starforged-core/src/repos.rs` (`rename_repo`, `moved_repo`, `split_repo_path`, tests)
- Create: `crates/starforged-web/src/moved.rs`; Modify: `crates/starforged-web/src/lib.rs` (middleware, route), `src/pages/repo_settings.rs` (`rename`), `templates/repo_settings.html`
- Create: `crates/starforged-api/src/moved.rs`; Modify: `crates/starforged-api/src/lib.rs`, `crates/starforged-api/src/auth.rs` (`bearer_token`)
- Test: Create `crates/starforged/tests/web_repo_rename.rs`

**Interfaces:**
- Consumes: `Core::{require_repo, permission_on, reload_repo, audit, web_session, authenticate_token}`, `validate::repo_name`, `githttp::basic_password`, `auth::SESSION_COOKIE`, `pages::repo_settings::finish` (B1).
- Produces:
  - Table `repo_redirects (owner_id, lower_name) → repo_id`; rows cascade with the repository and with the owner.
  - `starforged_db::redirects::target(db, owner_handle: &str, lower_name: &str) -> DbResult<Option<i64>>` (both arguments lowercase).
  - `starforged_db::repos::rename(db, id: i64, new_name: &str) -> DbResult<()>`: one transaction; the old name becomes a redirect (unless only the case changed); a redirect that held the new name is dropped; a taken name is a unique violation. `repos::insert` now also drops a redirect that held the new repository's name.
  - `Core::rename_repo(&self, actor: &User, owner: &str, name: &str, new_name: &str) -> CoreResult<Repo>` (admin; the same name is a no-op).
  - `Core::moved_repo(&self, user: Option<&User>, owner: &str, name: &str) -> CoreResult<Option<Repo>>`: the target of an old name when no repository has that name and `user` can read the target.
  - `starforged_core::repos::split_repo_path(path: &str) -> Option<(&str, &str, &str)>`: `/{owner}/{segment}{rest}`.
  - `starforged_web::moved::redirect_renamed` and `starforged_api::moved::redirect_renamed` middlewares (`from_fn_with_state`).
  - `starforged_api::auth::bearer_token(headers: &HeaderMap) -> Option<&str>` (`pub(crate)`).
  - Route `POST /{owner}/{repo}/settings/rename` (form field `new_name`).

- [ ] **Step 1: Write the migrations**

`crates/starforged-db/migrations/sqlite/0005_repo_redirects.sql`:

```sql
-- Starforge M0.5: old repository names redirect to the renamed repository (forge-basics design §5.3).
-- Keep in lockstep with ../postgres/0005_repo_redirects.sql.

CREATE TABLE repo_redirects (
    owner_id INTEGER NOT NULL REFERENCES owners (id) ON DELETE CASCADE,
    lower_name TEXT NOT NULL,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (owner_id, lower_name)
);
CREATE INDEX repo_redirects_repo ON repo_redirects (repo_id);
```

`crates/starforged-db/migrations/postgres/0005_repo_redirects.sql`:

```sql
-- Starforge M0.5: old repository names redirect to the renamed repository (forge-basics design §5.3).
-- Keep in lockstep with ../sqlite/0005_repo_redirects.sql.

CREATE TABLE repo_redirects (
    owner_id BIGINT NOT NULL REFERENCES owners (id) ON DELETE CASCADE,
    lower_name TEXT NOT NULL,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (owner_id, lower_name)
);
CREATE INDEX repo_redirects_repo ON repo_redirects (repo_id);
```

- [ ] **Step 2: Write the failing database test**

Create `crates/starforged-db/src/redirects.rs`:

```rust
//! `repo_redirects`: old repository names and the repository each now points at (forge-basics design §5.3).
//! `repos::rename` writes them; `repos::insert` and `repos::rename` drop the one holding a name they take.

use crate::{Db, DbResult};

/// The repository that `owner_handle/lower_name` redirects to; both arguments must be lowercase.
pub async fn target(db: &Db, owner_handle: &str, lower_name: &str) -> DbResult<Option<i64>> {
    let id: Option<i64> = sqlx::query_scalar(
        "SELECT d.repo_id FROM repo_redirects d JOIN owners o ON o.id = d.owner_id \
         WHERE o.handle = $1 AND d.lower_name = $2",
    )
    .bind(owner_handle)
    .bind(lower_name)
    .fetch_optional(db.pool())
    .await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::{self, NewRepo};
    use crate::testing::TestDb;
    use crate::users::{self, NewUser};

    fn repo(owner_id: i64, name: &str) -> NewRepo<'_> {
        NewRepo {
            owner_id,
            name,
            description: "",
            visibility: "public",
            default_branch: "main",
        }
    }

    #[tokio::test]
    async fn renames_leave_redirects_that_new_names_take_over() {
        let t = TestDb::new().await;
        let alice = users::insert(
            &t.db,
            &NewUser {
                handle: "alice",
                display_name: "",
                email: None,
                email_verified: false,
                password_hash: None,
                is_admin: false,
            },
        )
        .await
        .unwrap();
        let id = repos::insert(&t.db, &repo(alice, "one")).await.unwrap();
        repos::rename(&t.db, id, "two").await.unwrap();
        repos::rename(&t.db, id, "Three").await.unwrap();
        assert_eq!(target(&t.db, "alice", "one").await.unwrap(), Some(id));
        assert_eq!(target(&t.db, "alice", "two").await.unwrap(), Some(id));
        assert_eq!(target(&t.db, "alice", "three").await.unwrap(), None);

        repos::rename(&t.db, id, "three").await.unwrap();
        assert_eq!(
            target(&t.db, "alice", "three").await.unwrap(),
            None,
            "a case-only rename adds no redirect"
        );
        repos::insert(&t.db, &repo(alice, "One")).await.unwrap();
        assert_eq!(
            target(&t.db, "alice", "one").await.unwrap(),
            None,
            "a new repository takes its name over"
        );
        repos::rename(&t.db, id, "two").await.unwrap();
        assert_eq!(
            target(&t.db, "alice", "two").await.unwrap(),
            None,
            "renaming back onto an old name takes it over"
        );
        assert_eq!(target(&t.db, "alice", "three").await.unwrap(), Some(id));
        let taken = repos::rename(&t.db, id, "ONE").await.unwrap_err();
        assert!(taken.is_unique_violation());
        assert_eq!(repos::by_id(&t.db, id).await.unwrap().unwrap().name, "two");
        repos::delete(&t.db, id).await.unwrap();
        assert_eq!(
            target(&t.db, "alice", "three").await.unwrap(),
            None,
            "redirects go with their repository"
        );
    }
}
```

Add `pub mod redirects;` to `crates/starforged-db/src/lib.rs` after `pub mod jobs;`.

Run: `cargo test -p starforged-db redirects`
Expected: compile error: no function `rename` in `repos`.

- [ ] **Step 3: Implement `rename`; make `insert` take a name over**

In `crates/starforged-db/src/repos.rs`, replace `insert` with:

```rust
/// Inserts the repository. A redirect that held its name stops (forge-basics design §5.3).
pub async fn insert(db: &Db, repo: &NewRepo<'_>) -> DbResult<i64> {
    let ts = now();
    let lower_name = repo.name.to_ascii_lowercase();
    let mut tx = db.pool().begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO repos (owner_id, name, lower_name, description, visibility, default_branch, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
    )
    .bind(repo.owner_id)
    .bind(repo.name)
    .bind(lower_name.as_str())
    .bind(repo.description)
    .bind(repo.visibility)
    .bind(repo.default_branch)
    .bind(ts)
    .bind(ts)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM repo_redirects WHERE owner_id = $1 AND lower_name = $2")
        .bind(repo.owner_id)
        .bind(lower_name.as_str())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(id)
}
```

and append:

```rust
/// Renames repository `id` in one transaction. The old name then redirects to it (unless only the case
/// changed), and a redirect that held the new name is dropped. A taken name is a unique violation and changes
/// nothing.
pub async fn rename(db: &Db, id: i64, new_name: &str) -> DbResult<()> {
    let ts = now();
    let new_lower = new_name.to_ascii_lowercase();
    let mut tx = db.pool().begin().await?;
    let (owner_id, old_lower): (i64, String) =
        sqlx::query_as("SELECT owner_id, lower_name FROM repos WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("UPDATE repos SET name = $1, lower_name = $2, updated_at = $3 WHERE id = $4")
        .bind(new_name)
        .bind(new_lower.as_str())
        .bind(ts)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM repo_redirects WHERE owner_id = $1 AND lower_name = $2")
        .bind(owner_id)
        .bind(new_lower.as_str())
        .execute(&mut *tx)
        .await?;
    if old_lower != new_lower {
        sqlx::query(
            "INSERT INTO repo_redirects (owner_id, lower_name, repo_id, created_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (owner_id, lower_name) DO UPDATE SET repo_id = excluded.repo_id, created_at = excluded.created_at",
        )
        .bind(owner_id)
        .bind(old_lower.as_str())
        .bind(id)
        .bind(ts)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
```

Run: `cargo test -p starforged-db redirects`
Expected: PASS.

- [ ] **Step 4: Write the failing core tests**

Add to the tests in `crates/starforged-core/src/repos.rs`:

```rust
    #[test]
    fn request_paths_split_into_owner_repository_and_rest() {
        assert_eq!(split_repo_path("/alice/proj"), Some(("alice", "proj", "")));
        assert_eq!(
            split_repo_path("/alice/proj.git/info/refs"),
            Some(("alice", "proj.git", "/info/refs"))
        );
        assert_eq!(
            split_repo_path("/alice/proj/tree/main/src"),
            Some(("alice", "proj", "/tree/main/src"))
        );
        for no in ["/alice", "/alice/", "//proj", "alice/proj", ""] {
            assert_eq!(split_repo_path(no), None, "{no:?}");
        }
    }

    #[tokio::test]
    async fn renames_need_admin_and_old_names_lead_to_readers_only() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let mia = user(&core, "mia").await;
        let bob = user(&core, "bob").await;
        core.create_repo(&alice, new("proj", Visibility::Private))
            .await
            .unwrap();
        core.create_repo(&alice, new("other", Visibility::Private))
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
            .await
            .unwrap();
        assert!(matches!(
            core.rename_repo(&mia, "alice", "proj", "x").await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.rename_repo(&alice, "alice", "proj", "x.git").await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.rename_repo(&alice, "alice", "proj", "OTHER").await,
            Err(CoreError::Conflict(_))
        ));
        let same = core
            .rename_repo(&alice, "alice", "proj", "proj")
            .await
            .unwrap();
        assert_eq!(same.name, "proj");

        let renamed = core
            .rename_repo(&alice, "alice", "proj", "Renamed")
            .await
            .unwrap();
        assert_eq!(renamed.full_name(), "alice/Renamed");
        assert!(matches!(
            core.repo_for(Some(&alice), "alice", "proj").await,
            Err(CoreError::NotFound)
        ));
        let moved = core.moved_repo(Some(&alice), "alice", "PROJ").await.unwrap();
        assert_eq!(moved.map(|r| r.id), Some(renamed.id));
        assert!(
            core.moved_repo(Some(&mia), "alice", "proj").await.unwrap().is_some(),
            "collaborators follow the rename"
        );
        assert!(
            core.moved_repo(Some(&bob), "alice", "proj").await.unwrap().is_none(),
            "the private target stays hidden"
        );
        assert!(core.moved_repo(None, "alice", "proj").await.unwrap().is_none());
        assert!(
            core.moved_repo(Some(&alice), "alice", "Renamed")
                .await
                .unwrap()
                .is_none(),
            "a live name is not a redirect"
        );
        let entry = starforged_db::audit::recent(core.db(), 1)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(
            (entry.action.as_str(), entry.target.as_str(), entry.detail.as_str()),
            ("repo.rename", "repo:alice/Renamed", "proj")
        );
    }
```

Run: `cargo test -p starforged-core repos::tests`
Expected: compile errors: no `split_repo_path`, `rename_repo`, or `moved_repo`.

- [ ] **Step 5: Implement rename and redirect lookup in core**

In `crates/starforged-core/src/repos.rs`, import the redirects table: `use starforged_db::redirects;`. Add the free function after `checked_description`:

```rust
/// Splits a request path `/{owner}/{segment}{rest}` into the owner, the repository segment (which may end in
/// `.git`), and the rest (empty, or starting with `/`). `None` without two non-empty segments.
pub fn split_repo_path(path: &str) -> Option<(&str, &str, &str)> {
    let path = path.strip_prefix('/')?;
    let (owner, after) = path.split_once('/')?;
    let (segment, rest) = match after.find('/') {
        Some(at) => after.split_at(at),
        None => (after, ""),
    };
    if owner.is_empty() || segment.is_empty() {
        return None;
    }
    Some((owner, segment, rest))
}
```

Add to the `impl Core` block that holds the settings methods:

```rust
    /// Admins: renames the repository. The old name keeps working through a redirect (forge-basics design §5.3).
    pub async fn rename_repo(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        new_name: &str,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        let new_name = validate::repo_name(new_name)?;
        let old = access.repo;
        if new_name == old.name {
            return Ok(old);
        }
        db_repos::rename(self.db(), old.id, &new_name)
            .await
            .map_err(|e| {
                if e.is_unique_violation() {
                    CoreError::Conflict(format!("{}/{new_name} already exists", old.owner))
                } else {
                    e.into()
                }
            })?;
        let repo = self.reload_repo(old.id).await?;
        self.audit(
            Some(actor.id),
            "repo.rename",
            &format!("repo:{}", repo.full_name()),
            &old.name,
        )
        .await?;
        Ok(repo)
    }

    /// The repository that `owner/name` was renamed to, when `user` can read it. `None` when a repository has
    /// that name, no redirect exists, or the viewer cannot read the target, so an old name of a private
    /// repository answers like a missing one.
    pub async fn moved_repo(
        &self,
        user: Option<&User>,
        owner: &str,
        name: &str,
    ) -> CoreResult<Option<Repo>> {
        if db_repos::by_owner_and_name(self.db(), owner, name)
            .await?
            .is_some()
        {
            return Ok(None);
        }
        let Some(id) = redirects::target(
            self.db(),
            &owner.to_ascii_lowercase(),
            &name.to_ascii_lowercase(),
        )
        .await?
        else {
            return Ok(None);
        };
        let Some(row) = db_repos::by_id(self.db(), id).await? else {
            return Ok(None);
        };
        let repo = to_repo(row)?;
        Ok(self.permission_on(&repo, user).await?.map(|_| repo))
    }
```

Run: `cargo test -p starforged-core repos::tests`
Expected: PASS.

- [ ] **Step 6: Write the failing integration tests**

Create `crates/starforged/tests/web_repo_rename.rs`:

```rust
mod common;

use common::*;
use serde_json::Value;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn old_names_redirect_pages_git_and_the_api() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    s.repo(&alice, "taken", Visibility::Public).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("src/main.rs", "fn main() {}\n")]).await;
    git_ok(
        &work,
        &["push", "-q", &s.git_url("alice", "proj", Some(&token)), "main"],
    )
    .await;

    let (owner, csrf) = s.login("alice").await;
    let conflict = owner
        .post(s.url("/alice/proj/settings/rename"))
        .form(&[("_csrf", csrf.as_str()), ("new_name", "taken")])
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), 422);
    assert!(conflict.text().await.unwrap().contains("already exists"));
    let renamed = owner
        .post(s.url("/alice/proj/settings/rename"))
        .form(&[("_csrf", csrf.as_str()), ("new_name", "renamed")])
        .send()
        .await
        .unwrap();
    assert_eq!(renamed.status(), 303);
    assert_eq!(renamed.headers()["location"], "/alice/renamed/settings");

    let client = s.browser();
    for (old, new) in [
        ("/alice/proj", "/alice/renamed"),
        ("/alice/proj/tree/main/src?x=1", "/alice/renamed/tree/main/src?x=1"),
        ("/alice/PROJ/blob/main/src/main.rs", "/alice/renamed/blob/main/src/main.rs"),
    ] {
        let response = client.get(s.url(old)).send().await.unwrap();
        assert_eq!(response.status(), 301, "{old}");
        assert_eq!(response.headers()["location"], new, "{old}");
    }
    assert_eq!(
        client
            .get(s.url("/alice/renamed/tree/main/src"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let api = client
        .get(s.url("/api/v1/repos/alice/proj"))
        .send()
        .await
        .unwrap();
    assert_eq!(api.status(), 301);
    assert_eq!(api.headers()["location"], "/api/v1/repos/alice/renamed");
    let followed: Value = reqwest::get(s.url("/api/v1/repos/alice/proj"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(followed["full_name"], "alice/renamed");

    git_ok(
        tmp.path(),
        &["clone", "-q", &s.git_url("alice", "proj", None), "anonymous"],
    )
    .await;
    assert!(tmp.path().join("anonymous/src/main.rs").is_file());
    commit_files(&work, &[("more.txt", b"more\n")], "pushed through the old name").await;
    git_ok(
        &work,
        &["push", "-q", &s.git_url("alice", "proj", Some(&token)), "main"],
    )
    .await;
    assert!(
        get_text(&client, &s.url("/alice/renamed/commits/main"))
            .await
            .contains("pushed through the old name")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_need_read_access_and_yield_to_new_repositories() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("bob").await;
    s.repo(&alice, "secret", Visibility::Private).await;
    s.core
        .rename_repo(&alice, "alice", "secret", "hidden")
        .await
        .unwrap();

    let anonymous = s.browser();
    assert_eq!(
        anonymous
            .get(s.url("/alice/secret"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        anonymous
            .get(s.url("/alice/secret.git/info/refs?service=git-upload-pack"))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "anonymous git clients are asked to sign in, as for any hidden repository"
    );
    let (bob, _) = s.login("bob").await;
    assert_eq!(
        bob.get(s.url("/alice/secret")).send().await.unwrap().status(),
        404
    );
    let (owner, _) = s.login("alice").await;
    let moved = owner.get(s.url("/alice/secret")).send().await.unwrap();
    assert_eq!(moved.status(), 301);
    assert_eq!(moved.headers()["location"], "/alice/hidden");

    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let tmp = tempfile::tempdir().unwrap();
    git_ok(
        tmp.path(),
        &["clone", "-q", &s.git_url("alice", "secret", Some(&token)), "copy"],
    )
    .await;

    s.core
        .rename_repo(&alice, "alice", "hidden", "final")
        .await
        .unwrap();
    let hop = owner.get(s.url("/alice/secret")).send().await.unwrap();
    assert_eq!(
        hop.headers()["location"],
        "/alice/final",
        "a chain of renames resolves in one hop"
    );

    s.repo(&alice, "secret", Visibility::Public).await;
    assert_eq!(
        anonymous
            .get(s.url("/alice/secret"))
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "the new repository answers, not a redirect"
    );
}
```

Run: `cargo test -p starforged --test web_repo_rename`
Expected: FAIL: `/alice/proj/settings/rename` answers 405 (no such route), and old names answer 404.

- [ ] **Step 7: Add the web middleware and the rename form**

Create `crates/starforged-web/src/moved.rs`:

```rust
//! Old repository names answer 301 with the new name (forge-basics design §5.3).

use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use starforged_core::accounts::User;
use starforged_core::repos::split_repo_path;

use crate::AppState;
use crate::auth::SESSION_COOKIE;
use crate::githttp::basic_password;

/// After a `GET` or `HEAD` under `/{owner}/{repo}` answers 404, or git's `info/refs` answers 401 (what
/// anonymous git clients get for a repository they cannot see), answers 301 to the same path and query under
/// the repository's new name when it was renamed and the viewer can read it. Everything else passes through.
pub async fn redirect_renamed(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    let uri = request.uri().clone();
    let session = CookieJar::from_headers(request.headers())
        .get(SESSION_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    let token = basic_password(request.headers());
    let response = next.run(request).await;
    let status = response.status();
    let refused = status == StatusCode::NOT_FOUND
        || (status == StatusCode::UNAUTHORIZED && uri.path().ends_with("/info/refs"));
    if !refused {
        return response;
    }
    let Some((owner, segment, rest)) = split_repo_path(uri.path()) else {
        return response;
    };
    let (name, suffix) = match segment.strip_suffix(".git") {
        Some(name) => (name, ".git"),
        None => (segment, ""),
    };
    let viewer = viewer(&state, session.as_deref(), token.as_deref()).await;
    let target = match state.core.moved_repo(viewer.as_ref(), owner, name).await {
        Ok(Some(repo)) => repo,
        Ok(None) => return response,
        Err(err) => {
            tracing::warn!(error = %err, "looking up a renamed repository");
            return response;
        }
    };
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let location = format!("/{}/{}{suffix}{rest}{query}", target.owner, target.name);
    match HeaderValue::from_str(&location) {
        Ok(value) => (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, value)]).into_response(),
        Err(_) => response,
    }
}

/// The signed-in user (session cookie), else the user of an HTTP Basic token (what git sends).
async fn viewer(state: &AppState, session: Option<&str>, token: Option<&str>) -> Option<User> {
    if let Some(cookie) = session
        && let Ok(Some(session)) = state.core.web_session(cookie).await
    {
        return Some(session.user);
    }
    match token {
        Some(secret) => state
            .core
            .authenticate_token(secret)
            .await
            .ok()
            .map(|auth| auth.user),
        None => None,
    }
}
```

In `crates/starforged-web/src/lib.rs`: add `mod moved;` after `pub mod markdown;`, and in `router` add the middleware before the security headers:

```rust
    Router::new()
        .merge(page_routes())
        .merge(git_routes())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            moved::redirect_renamed,
        ))
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
```

and the route, after `/{owner}/{repo}/settings/visibility`:

```rust
        .route(
            "/{owner}/{repo}/settings/rename",
            post(pages::repo_settings::rename),
        )
```

In `crates/starforged-web/src/pages/repo_settings.rs`, add:

```rust
#[derive(Deserialize)]
pub struct RenameForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    new_name: String,
}

pub async fn rename(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<RenameForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = state
        .core
        .rename_repo(&session.user, &owner, &repo, &form.new_name)
        .await;
    finish(&state, &session, &owner, &repo, result).await
}
```

In `crates/starforged-web/templates/repo_settings.html`, add after the Visibility `</form>` (inside `{% if head.can_admin %}`):

```html
<h2>Rename</h2>
<form method="post" action="/{{ head.owner }}/{{ head.name }}/settings/rename" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>New name <input name="new_name" required maxlength="100" value="{{ head.name }}"></label>
  <p class="muted">Links, clones, and API calls that use the old name are redirected to the new one.</p>
  <button type="submit">Rename</button>
</form>
```

- [ ] **Step 8: Add the API middleware**

In `crates/starforged-api/src/auth.rs`, add:

```rust
/// The token in `Authorization: Bearer …` (or `token …`); `None` without the header or with another scheme.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("token "))
        .map(str::trim)
}
```

with `use axum::http::HeaderMap;`, and make `ApiAuth::from_request_parts` use it:

```rust
        if !parts.headers.contains_key(header::AUTHORIZATION) {
            return Ok(ApiAuth(None));
        }
        let token = bearer_token(&parts.headers).ok_or(ApiError::Unauthenticated)?;
        Ok(ApiAuth(Some(state.core.authenticate_token(token).await?)))
```

Create `crates/starforged-api/src/moved.rs`:

```rust
//! Old repository names answer 301 for API reads (forge-basics design §5.3).

use axum::extract::{OriginalUri, Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use starforged_core::repos::split_repo_path;

use crate::ApiState;
use crate::auth::bearer_token;

/// After a `GET` or `HEAD` of `/repos/{owner}/{repo}…` answers 404, answers 301 to the same path and query
/// under the repository's new name when it was renamed and the caller can read it.
pub async fn redirect_renamed(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    let uri = request.uri().clone();
    // The path as the client sent it, before `nest("/api/v1", …)` removed the prefix.
    let original = request
        .extensions()
        .get::<OriginalUri>()
        .map(|o| o.0.clone())
        .unwrap_or_else(|| uri.clone());
    let token = bearer_token(request.headers()).map(str::to_owned);
    let response = next.run(request).await;
    if response.status() != StatusCode::NOT_FOUND {
        return response;
    }
    let Some(repo_path) = uri.path().strip_prefix("/repos") else {
        return response;
    };
    let Some((owner, name, rest)) = split_repo_path(repo_path) else {
        return response;
    };
    let viewer = match token {
        Some(secret) => state
            .core
            .authenticate_token(&secret)
            .await
            .ok()
            .map(|auth| auth.user),
        None => None,
    };
    let target = match state.core.moved_repo(viewer.as_ref(), owner, name).await {
        Ok(Some(repo)) => repo,
        Ok(None) => return response,
        Err(err) => {
            tracing::warn!(error = %err, "looking up a renamed repository");
            return response;
        }
    };
    let prefix = original.path().strip_suffix(uri.path()).unwrap_or("");
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let location = format!(
        "{prefix}/repos/{}/{}{rest}{query}",
        target.owner, target.name
    );
    match HeaderValue::from_str(&location) {
        Ok(value) => (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, value)]).into_response(),
        Err(_) => response,
    }
}
```

In `crates/starforged-api/src/lib.rs`, add `mod moved;` and build the router with the state in a variable:

```rust
pub fn router(core: Core, base_url: String) -> Router {
    let state = ApiState {
        core,
        base_url: Arc::from(base_url),
    };
    Router::new()
        .route("/user", get(user::show))
        .route("/user/repos", post(repos::create))
        .route("/repos/{owner}/{repo}", get(repos::show))
        .route(
            "/repos/{owner}/{repo}/collaborators",
            get(repos::list_collaborators),
        )
        .route(
            "/repos/{owner}/{repo}/collaborators/{handle}",
            put(repos::set_collaborator).delete(repos::remove_collaborator),
        )
        .fallback(|| async { ApiError::NotFound })
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            moved::redirect_renamed,
        ))
        .with_state(state)
}
```

- [ ] **Step 9: Run the tests**

Run: `cargo test -p starforged --test web_repo_rename --test api --test smart_http --test web_code`
Expected: all pass. The rename test clones and pushes through the old URL: git follows the 301 on `info/refs` (`http.followRedirects=initial`) and prints "warning: redirecting to …".

- [ ] **Step 10: Full check on both databases, commit**

```bash
STARFORGE_TEST_PG=1 scripts/check.sh
git add -A crates
git commit -m "feat: rename repositories; old names redirect pages, git, and API reads"
```

Expected: fmt, clippy, and every test green on SQLite and Postgres.

---
### Task B4: Archive and unarchive

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0006_repo_archive.sql`, `crates/starforged-db/migrations/postgres/0006_repo_archive.sql`
- Modify: `crates/starforged-db/src/repos.rs` (`archived_at` in `RepoRow` and `select_repo!`; `set_archived`)
- Modify: `crates/starforged-core/src/repos.rs` (`Repo.archived_at`, `archive_repo`, `unarchive_repo`, tests)
- Modify: `crates/starforged-web/src/githttp.rs` (archived repositories refuse pushes), `src/views.rs` (`RepoHead.archived`), `templates/repo_head.html`, `src/pages/repo_settings.rs`, `templates/repo_settings.html`, `src/lib.rs` (routes)
- Modify: `crates/starforged-api/src/repos.rs` (`archived` in `RepoJson`)
- Test: Create `crates/starforged/tests/web_repo_archive.rs`

**Interfaces:**
- Consumes: `Core::{require_repo, reload_repo, audit}`, `starforged_db::now`, `pages::repo_settings::finish` (B1), `auth::CsrfForm`.
- Produces:
  - Column `repos.archived_at` (nullable unix time); `RepoRow.archived_at: Option<i64>`; `starforged_db::repos::set_archived(db, id: i64, archived_at: Option<i64>) -> DbResult<()>`.
  - `starforged_core::repos::Repo.archived_at: Option<i64>`.
  - `Core::archive_repo(&self, actor: &User, owner: &str, name: &str) -> CoreResult<Repo>` and `Core::unarchive_repo(…) -> CoreResult<Repo>` (admin; a no-op when nothing changes).
  - `RepoHead.archived: bool`; the header shows an `archived` badge and a read-only notice.
  - `GitHttpError::Archived`: `403` with the plain-text body `This repository is archived; pushes are disabled.\n` on both receive-pack endpoints.
  - API repository JSON field `archived: bool`.
  - Routes `POST /{owner}/{repo}/settings/archive` and `POST /{owner}/{repo}/settings/unarchive`.

- [ ] **Step 1: Write the migrations**

`crates/starforged-db/migrations/sqlite/0006_repo_archive.sql`:

```sql
-- Starforge M0.5: archived repositories stay readable and refuse pushes (forge-basics design §5.4).
-- Keep in lockstep with ../postgres/0006_repo_archive.sql.

ALTER TABLE repos ADD COLUMN archived_at INTEGER;
```

`crates/starforged-db/migrations/postgres/0006_repo_archive.sql`:

```sql
-- Starforge M0.5: archived repositories stay readable and refuse pushes (forge-basics design §5.4).
-- Keep in lockstep with ../sqlite/0006_repo_archive.sql.

ALTER TABLE repos ADD COLUMN archived_at BIGINT;
```

- [ ] **Step 2: Write the failing core test**

Add to the tests in `crates/starforged-core/src/repos.rs`:

```rust
    #[tokio::test]
    async fn archiving_needs_admin_and_is_audited_once() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let mia = user(&core, "mia").await;
        core.create_repo(&alice, new("proj", Visibility::Public))
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
            .await
            .unwrap();
        assert!(matches!(
            core.archive_repo(&mia, "alice", "proj").await,
            Err(CoreError::Forbidden)
        ));
        let archived = core.archive_repo(&alice, "alice", "proj").await.unwrap();
        assert!(archived.archived_at.is_some());
        core.archive_repo(&alice, "alice", "proj").await.unwrap();
        assert!(
            core.repo_for(None, "alice", "proj")
                .await
                .unwrap()
                .repo
                .archived_at
                .is_some(),
            "archived repositories stay readable"
        );
        let restored = core.unarchive_repo(&alice, "alice", "proj").await.unwrap();
        assert_eq!(restored.archived_at, None);
        let actions: Vec<String> = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .filter(|a| a.ends_with("archive"))
            .collect();
        assert_eq!(actions, vec!["repo.unarchive", "repo.archive"]);
    }
```

Run: `cargo test -p starforged-core repos::tests`
Expected: compile errors: no field `archived_at` on `Repo`, no `archive_repo`.

- [ ] **Step 3: Store and read `archived_at`**

In `crates/starforged-db/src/repos.rs`:
1. Add `pub archived_at: Option<i64>,` to `RepoRow` after `default_branch`.
2. In `select_repo!`, select it after `r.default_branch`:

```rust
macro_rules! select_repo {
    ($tail:literal) => {
        concat!(
            "SELECT r.id, r.owner_id, o.handle AS owner_handle, r.name, r.description, r.visibility, ",
            "r.default_branch, r.archived_at, r.created_at, r.updated_at FROM repos r JOIN owners o ON o.id = r.owner_id ",
            $tail
        )
    };
}
```

3. In `from_row`, add `archived_at: row.try_get("archived_at")?,`.
4. Append:

```rust
/// Archives the repository (`Some(time)`) or lifts the archive (`None`).
pub async fn set_archived(db: &Db, id: i64, archived_at: Option<i64>) -> DbResult<()> {
    sqlx::query("UPDATE repos SET archived_at = $1, updated_at = $2 WHERE id = $3")
        .bind(archived_at)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
```

In `crates/starforged-core/src/repos.rs`:
1. Add to `Repo` after `default_branch`:

```rust
    /// When the repository was archived; an archived repository refuses pushes (forge-basics design §5.4).
    pub archived_at: Option<i64>,
```

2. In `to_repo`, add `archived_at: row.archived_at,`.
3. Add to the settings `impl Core` block:

```rust
    /// Admins: archives the repository; it stays readable and refuses pushes until it is unarchived.
    pub async fn archive_repo(&self, actor: &User, owner: &str, name: &str) -> CoreResult<Repo> {
        self.set_archived(actor, owner, name, true).await
    }

    /// Admins: lifts the archive.
    pub async fn unarchive_repo(&self, actor: &User, owner: &str, name: &str) -> CoreResult<Repo> {
        self.set_archived(actor, owner, name, false).await
    }

    async fn set_archived(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        archived: bool,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        if access.repo.archived_at.is_some() == archived {
            return Ok(access.repo);
        }
        db_repos::set_archived(self.db(), access.repo.id, archived.then(now)).await?;
        let action = if archived {
            "repo.archive"
        } else {
            "repo.unarchive"
        };
        self.audit(
            Some(actor.id),
            action,
            &format!("repo:{}", access.repo.full_name()),
            "",
        )
        .await?;
        self.reload_repo(access.repo.id).await
    }
```

Run: `cargo test -p starforged-core repos::tests`
Expected: PASS.

- [ ] **Step 4: Write the failing integration test**

Create `crates/starforged/tests/web_repo_archive.rs`:

```rust
mod common;

use common::*;
use serde_json::Value;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archived_repositories_refuse_pushes_until_unarchived() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
        .await
        .unwrap();
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let url = s.git_url("alice", "proj", Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;

    let (mia, mia_csrf) = s.login("mia").await;
    let refused = mia
        .post(s.url("/alice/proj/settings/archive"))
        .form(&[("_csrf", mia_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403, "archiving needs admin");

    let (owner, csrf) = s.login("alice").await;
    let archived = owner
        .post(s.url("/alice/proj/settings/archive"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(archived.status(), 303);
    let home = get_text(&s.browser(), &s.url("/alice/proj")).await;
    assert!(home.contains("This repository is archived"), "{home}");
    assert!(home.contains(r#"<span class="badge">archived</span>"#), "{home}");

    commit_files(&work, &[("b.txt", b"b\n")], "after archiving").await;
    let push = git(&work, &["push", &url, "main"]).await;
    assert!(!push.status.success());
    let stderr = String::from_utf8_lossy(&push.stderr);
    assert!(
        stderr.contains("remote: This repository is archived; pushes are disabled."),
        "{stderr}"
    );
    let refs = s
        .browser()
        .get(s.url("/alice/proj.git/info/refs?service=git-receive-pack"))
        .basic_auth("git", Some(&token))
        .send()
        .await
        .unwrap();
    assert_eq!(refs.status(), 403);
    assert_eq!(
        refs.text().await.unwrap(),
        "This repository is archived; pushes are disabled.\n"
    );
    git_ok(
        tmp.path(),
        &["clone", "-q", &s.git_url("alice", "proj", None), "copy"],
    )
    .await;
    let json: Value = s
        .browser()
        .get(s.url("/api/v1/repos/alice/proj"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(json["archived"], true);
    let settings = get_text(&owner, &s.url("/alice/proj/settings")).await;
    assert!(settings.contains("/alice/proj/settings/unarchive"), "settings stay editable");

    let unarchived = owner
        .post(s.url("/alice/proj/settings/unarchive"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(unarchived.status(), 303);
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    assert!(
        !get_text(&s.browser(), &s.url("/alice/proj"))
            .await
            .contains("This repository is archived")
    );
}
```

Run: `cargo test -p starforged --test web_repo_archive`
Expected: FAIL: `/alice/proj/settings/archive` answers 405.

- [ ] **Step 5: Refuse pushes, show the banner, add the settings actions and API field**

In `crates/starforged-web/src/githttp.rs`:
1. Add the variant `Archived,` to `GitHttpError` (after `Forbidden`), and its response in `into_response`:

```rust
            GitHttpError::Archived => (
                StatusCode::FORBIDDEN,
                "This repository is archived; pushes are disabled.\n",
            )
                .into_response(),
```

2. In `authorize`, replace `Ok(access) => Ok(access),` in the final `match` with:

```rust
        Ok(access) if service == Service::ReceivePack && access.repo.archived_at.is_some() => {
            Err(GitHttpError::Archived)
        }
        Ok(access) => Ok(access),
```

In `crates/starforged-web/src/views.rs`, add to `RepoHead` after `visibility`:

```rust
    /// The repository is archived: read-only, pushes refused.
    pub archived: bool,
```

and set `archived: repo.archived_at.is_some(),` in `RepoHead::new`.

In `crates/starforged-web/templates/repo_head.html`, replace the `<h1>` line with these two lines:

```html
<h1><a href="/{{ head.owner }}">{{ head.owner }}</a> / <a href="/{{ head.owner }}/{{ head.name }}">{{ head.name }}</a> <span class="badge">{{ head.visibility }}</span>{% if head.archived %} <span class="badge">archived</span>{% endif %}</h1>
{% if head.archived %}<p class="notice">This repository is archived. It is read-only: pushes are refused.</p>{% endif %}
```

In `crates/starforged-web/src/pages/repo_settings.rs`, import `CsrfForm` (`use crate::auth::{CsrfForm, RequireUser, verify_csrf};`) and add:

```rust
pub async fn archive(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = state.core.archive_repo(&session.user, &owner, &repo).await;
    finish(&state, &session, &owner, &repo, result).await
}

pub async fn unarchive(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = state.core.unarchive_repo(&session.user, &owner, &repo).await;
    finish(&state, &session, &owner, &repo, result).await
}
```

In `crates/starforged-web/templates/repo_settings.html`, add after the Rename form (inside `{% if head.can_admin %}`):

```html
<h2>Archive</h2>
{% if head.archived %}
<form method="post" action="/{{ head.owner }}/{{ head.name }}/settings/unarchive" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <p>This repository is archived: it is read-only and refuses pushes.</p>
  <button type="submit">Unarchive this repository</button>
</form>
{% else %}
<form method="post" action="/{{ head.owner }}/{{ head.name }}/settings/archive" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <p>Archiving makes the repository read-only: pushes are refused until it is unarchived. Settings stay editable.</p>
  <button type="submit">Archive this repository</button>
</form>
{% endif %}
```

In `crates/starforged-web/src/lib.rs`, add after the rename route:

```rust
        .route(
            "/{owner}/{repo}/settings/archive",
            post(pages::repo_settings::archive),
        )
        .route(
            "/{owner}/{repo}/settings/unarchive",
            post(pages::repo_settings::unarchive),
        )
```

In `crates/starforged-api/src/repos.rs`, add `archived: bool,` to `RepoJson` after `default_branch`, and `archived: repo.archived_at.is_some(),` in `repo_json`.

- [ ] **Step 6: Run the tests**

Run: `cargo test -p starforged --test web_repo_archive --test smart_http --test api`
Expected: all pass.

- [ ] **Step 7: Full check on both databases, commit**

```bash
STARFORGE_TEST_PG=1 scripts/check.sh
git add -A crates
git commit -m "feat: archive repositories; archived repositories refuse pushes"
```

Expected: fmt, clippy, and every test green on SQLite and Postgres.

---
### Task B5: Delete, restore, and purge repositories

**Files:**
- Create: `crates/starforged-db/migrations/sqlite/0007_repo_deletion.sql`, `crates/starforged-db/migrations/postgres/0007_repo_deletion.sql`
- Modify: `crates/starforged-db/src/repos.rs` (`deleted_at`; live-only lookups and listings; `list_deleted_by_owner`, `deleted_before`, `set_deleted`, `deleted_name_exists`)
- Modify: `crates/starforged-core/src/lib.rs` (`CoreConfig.tmp_dir`), `src/repos.rs` (deletion, restore, purge, name conflicts, `moved_repo` skips deleted targets, tests), `src/jobs.rs` (`Job::PurgeDeletedRepos`, tests)
- Modify: `crates/starforged/src/config.rs` (`Config::tmp_dir`), `crates/starforged/src/admin.rs` (`tmp_dir` in `CoreConfig`)
- Modify: `crates/starforged-web/src/pages/repo_settings.rs` (`delete`), `templates/repo_settings.html`, `src/pages/settings.rs` (Repositories page, restore), `templates/settings_nav.html`, `src/lib.rs` (routes)
- Create: `crates/starforged-web/templates/settings_repositories.html`
- Test: Create `crates/starforged/tests/web_repo_delete.rs`

**Interfaces:**
- Consumes: `Core::{require_repo, reload_repo, audit, repo_path, enqueue, run_due_jobs}`, `starforged_db::now`, `pages::repo_settings::finish` (B1), `Job` and its recurrence (Plan A).
- Produces:
  - Column `repos.deleted_at` (nullable unix time), indexed. `RepoRow.deleted_at: Option<i64>`.
  - `starforged_db::repos::{by_owner_and_name, list_by_owner, list_collaborating}` return only repositories that are not deleted; `by_id` returns any. New: `list_deleted_by_owner(db, owner_id) -> DbResult<Vec<RepoRow>>` (newest deletion first), `deleted_before(db, cutoff: i64) -> DbResult<Vec<RepoRow>>`, `set_deleted(db, id, deleted_at: Option<i64>) -> DbResult<()>`, `deleted_name_exists(db, owner_id, name: &str) -> DbResult<bool>`.
  - `CoreConfig.tmp_dir: PathBuf` (`<data_dir>/tmp`); `starforged::config::Config::tmp_dir() -> PathBuf`.
  - `starforged_core::repos::{RESTORE_SECS: i64 = 7 days, DeletedRepo { id, name, deleted_at, purge_after }}`; `Repo.deleted_at: Option<i64>`.
  - `Core::delete_repo(&self, actor: &User, owner: &str, name: &str, confirm: &str) -> CoreResult<Repo>` (admin; `confirm` must equal `owner/name`), `Core::deleted_repos(&self, user: &User) -> CoreResult<Vec<DeletedRepo>>`, `Core::restore_repo(&self, actor: &User, repo_id: i64) -> CoreResult<Repo>` (owner or site admin, within the window), `Core::purge_deleted_repos(&self) -> CoreResult<usize>`, and `pub(crate) Core::purge_repo(&self, repo: &Repo, actor_id: Option<i64>) -> CoreResult<()>` (Task B6 uses it).
  - `Job::PurgeDeletedRepos` (daily, kind `purge_deleted_repos`); `start_workers` queues it.
  - Routes: `POST /{owner}/{repo}/settings/delete` (field `confirm`), `GET /settings/repositories`, `POST /settings/repositories/{id}/restore`.

- [ ] **Step 1: Write the migrations**

`crates/starforged-db/migrations/sqlite/0007_repo_deletion.sql`:

```sql
-- Starforge M0.5: deleted repositories keep their name and can be restored for 7 days (forge-basics design §5.5).
-- Keep in lockstep with ../postgres/0007_repo_deletion.sql.

ALTER TABLE repos ADD COLUMN deleted_at INTEGER;
CREATE INDEX repos_deleted ON repos (deleted_at);
```

`crates/starforged-db/migrations/postgres/0007_repo_deletion.sql`:

```sql
-- Starforge M0.5: deleted repositories keep their name and can be restored for 7 days (forge-basics design §5.5).
-- Keep in lockstep with ../sqlite/0007_repo_deletion.sql.

ALTER TABLE repos ADD COLUMN deleted_at BIGINT;
CREATE INDEX repos_deleted ON repos (deleted_at);
```

- [ ] **Step 2: Write the failing core tests**

In `crates/starforged-core/src/repos.rs`'s tests, add `use crate::jobs::Job;` and:

```rust
    #[tokio::test]
    async fn deleted_repositories_vanish_keep_their_name_and_can_be_restored() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        let repo = core
            .create_repo(&alice, new("proj", Visibility::Public))
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Admin)
            .await
            .unwrap();
        assert!(matches!(
            core.delete_repo(&alice, "alice", "proj", "alice/other").await,
            Err(CoreError::Invalid(_))
        ));
        let deleted = core
            .delete_repo(&bob, "alice", "proj", " alice/proj ")
            .await
            .unwrap();
        assert!(deleted.deleted_at.is_some(), "an admin collaborator may delete");
        for viewer in [Some(&alice), Some(&bob), None] {
            assert!(matches!(
                core.repo_for(viewer, "alice", "proj").await,
                Err(CoreError::NotFound)
            ));
        }
        assert!(core.repos_of(Some(&alice), "alice").await.unwrap().is_empty());
        assert!(core.dashboard_repos(&bob).await.unwrap().is_empty());
        assert!(core.repo_path(repo.id).exists(), "the data stays until the purge");
        let taken = core.create_repo(&alice, new("PROJ", Visibility::Public)).await;
        assert!(
            matches!(&taken, Err(CoreError::Conflict(m)) if m.contains("deleted")),
            "{taken:?}"
        );

        let listed: Vec<String> = core
            .deleted_repos(&alice)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(listed, vec!["proj"]);
        assert!(
            core.deleted_repos(&bob).await.unwrap().is_empty(),
            "the list shows the user's own repositories"
        );
        assert!(
            matches!(core.restore_repo(&bob, repo.id).await, Err(CoreError::NotFound)),
            "only the owner or a site admin restores"
        );
        let restored = core.restore_repo(&alice, repo.id).await.unwrap();
        assert_eq!(restored.deleted_at, None);
        assert_eq!(
            core.repo_for(Some(&bob), "alice", "proj")
                .await
                .unwrap()
                .permission,
            Permission::Admin,
            "collaborators come back with the repository"
        );
        let actions: Vec<String> = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert!(actions.contains(&"repo.delete".to_owned()));
        assert!(actions.contains(&"repo.restore".to_owned()));
    }

    #[tokio::test]
    async fn the_daily_purge_removes_week_old_deletions() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let old = core
            .create_repo(&alice, new("old", Visibility::Public))
            .await
            .unwrap();
        let recent = core
            .create_repo(&alice, new("recent", Visibility::Public))
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "old", "alice/old")
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "recent", "alice/recent")
            .await
            .unwrap();
        sqlx::query("UPDATE repos SET deleted_at = $1 WHERE id = $2")
            .bind(now() - 8 * 86_400)
            .bind(old.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        assert!(
            matches!(core.restore_repo(&alice, old.id).await, Err(CoreError::NotFound)),
            "past the restore window"
        );
        let listed: Vec<String> = core
            .deleted_repos(&alice)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(listed, vec!["recent"]);

        core.enqueue(&Job::PurgeDeletedRepos).await.unwrap();
        core.run_due_jobs().await.unwrap();
        assert!(
            starforged_db::repos::by_id(core.db(), old.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!core.repo_path(old.id).exists());
        assert!(
            !core
                .config()
                .tmp_dir
                .join(format!("purge-{}.git", old.id))
                .exists()
        );
        assert!(
            starforged_db::repos::by_id(core.db(), recent.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(core.repo_path(recent.id).exists());
        let purged = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.action == "repo.purge")
            .unwrap();
        assert_eq!((purged.target.as_str(), purged.actor_id), ("repo:alice/old", None));
        core.create_repo(&alice, new("old", Visibility::Public))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_purge_interrupted_after_parking_the_directory_finishes() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let repo = core
            .create_repo(&alice, new("proj", Visibility::Public))
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "proj", "alice/proj")
            .await
            .unwrap();
        sqlx::query("UPDATE repos SET deleted_at = $1 WHERE id = $2")
            .bind(now() - 8 * 86_400)
            .bind(repo.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        let parked = core.config().tmp_dir.join(format!("purge-{}.git", repo.id));
        std::fs::create_dir_all(&core.config().tmp_dir).unwrap();
        std::fs::rename(core.repo_path(repo.id), &parked).unwrap();
        assert_eq!(core.purge_deleted_repos().await.unwrap(), 1);
        assert!(!parked.exists());
        assert!(
            starforged_db::repos::by_id(core.db(), repo.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn old_names_of_deleted_repositories_lead_nowhere() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        core.create_repo(&alice, new("proj", Visibility::Public))
            .await
            .unwrap();
        core.rename_repo(&alice, "alice", "proj", "renamed")
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "renamed", "alice/renamed")
            .await
            .unwrap();
        assert!(core.moved_repo(Some(&alice), "alice", "proj").await.unwrap().is_none());
    }
```

In `crates/starforged-core/src/jobs.rs` tests:
1. `payloads_are_tagged_with_the_kind` iterates `[Job::HourlyCleanup, Job::DailyPrune, Job::PurgeDeletedRepos]`.
2. `workers_run_due_jobs_in_the_background` waits for `done == 3` and its panic message says "the three recurring jobs".

Run: `cargo test -p starforged-core`
Expected: compile errors: no `delete_repo`, `deleted_repos`, `restore_repo`, `purge_deleted_repos`, `Job::PurgeDeletedRepos`, `CoreConfig.tmp_dir`.

- [ ] **Step 3: Store `deleted_at`; keep deleted repositories out of lookups and listings**

In `crates/starforged-db/src/repos.rs`:
1. Add `pub deleted_at: Option<i64>,` to `RepoRow` after `archived_at`, select it in `select_repo!` (`"r.default_branch, r.archived_at, r.deleted_at, r.created_at, r.updated_at FROM repos r JOIN owners o ON o.id = r.owner_id "`), and read it in `from_row` (`deleted_at: row.try_get("deleted_at")?,`).
2. Change the three lookups to skip deleted repositories, and document `by_id`:

```rust
/// Case-insensitive lookup by owner handle and repository name, among repositories that are not deleted.
pub async fn by_owner_and_name(
    db: &Db,
    owner_handle: &str,
    name: &str,
) -> DbResult<Option<RepoRow>> {
    let row = sqlx::query(select_repo!(
        "WHERE o.handle = $1 AND r.lower_name = $2 AND r.deleted_at IS NULL"
    ))
    .bind(owner_handle.to_ascii_lowercase())
    .bind(name.to_ascii_lowercase())
    .fetch_optional(db.pool())
    .await?;
    row.as_ref().map(from_row).transpose()
}

/// Any repository with this id, deleted or not.
pub async fn by_id(db: &Db, id: i64) -> DbResult<Option<RepoRow>> {
    let row = sqlx::query(select_repo!("WHERE r.id = $1"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(from_row).transpose()
}

/// The owner's repositories that are not deleted, by name.
pub async fn list_by_owner(db: &Db, owner_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "WHERE r.owner_id = $1 AND r.deleted_at IS NULL ORDER BY r.lower_name"
    ))
    .bind(owner_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Repositories that are not deleted where `user_id` is a collaborator, by owner then name.
pub async fn list_collaborating(db: &Db, user_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "JOIN collaborators c ON c.repo_id = r.id WHERE c.user_id = $1 AND r.deleted_at IS NULL \
         ORDER BY o.handle, r.lower_name"
    ))
    .bind(user_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}
```

3. Append:

```rust
/// The owner's deleted repositories, the most recently deleted first.
pub async fn list_deleted_by_owner(db: &Db, owner_id: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "WHERE r.owner_id = $1 AND r.deleted_at IS NOT NULL ORDER BY r.deleted_at DESC"
    ))
    .bind(owner_id)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Repositories deleted at or before `cutoff`, the oldest deletion first.
pub async fn deleted_before(db: &Db, cutoff: i64) -> DbResult<Vec<RepoRow>> {
    let rows = sqlx::query(select_repo!(
        "WHERE r.deleted_at IS NOT NULL AND r.deleted_at <= $1 ORDER BY r.deleted_at"
    ))
    .bind(cutoff)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(from_row).collect()
}

/// Deletes the repository softly (`Some(time)`) or restores it (`None`).
pub async fn set_deleted(db: &Db, id: i64, deleted_at: Option<i64>) -> DbResult<()> {
    sqlx::query("UPDATE repos SET deleted_at = $1, updated_at = $2 WHERE id = $3")
        .bind(deleted_at)
        .bind(now())
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

/// Whether a deleted repository of `owner_id` holds `name` (case-insensitive).
pub async fn deleted_name_exists(db: &Db, owner_id: i64, name: &str) -> DbResult<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM repos WHERE owner_id = $1 AND lower_name = $2 AND deleted_at IS NOT NULL",
    )
    .bind(owner_id)
    .bind(name.to_ascii_lowercase())
    .fetch_one(db.pool())
    .await?;
    Ok(count > 0)
}
```

- [ ] **Step 4: Add `tmp_dir` to the configuration**

In `crates/starforged-core/src/lib.rs`, add to `CoreConfig` after `repos_dir`:

```rust
    /// Scratch space on the same filesystem as `repos_dir` (`<data_dir>/tmp`); purged repositories pass
    /// through it.
    pub tmp_dir: PathBuf,
```

and `tmp_dir: dir.path().join("tmp"),` in `testing::test_core_with`.

In `crates/starforged/src/config.rs`, add after `repos_dir`:

```rust
    pub fn tmp_dir(&self) -> PathBuf {
        self.storage.data_dir.join("tmp")
    }
```

In `crates/starforged/src/admin.rs`, `open_core` passes `tmp_dir: config.tmp_dir(),` after `repos_dir`.

- [ ] **Step 5: Implement deletion, restore, and purge in core**

In `crates/starforged-core/src/repos.rs`:
1. Add to `Repo` after `archived_at`:

```rust
    /// When the repository was deleted; a deleted repository answers like a missing one until it is restored
    /// or purged (forge-basics design §5.5).
    pub deleted_at: Option<i64>,
```

and `deleted_at: row.deleted_at,` in `to_repo`.
2. Add after `MAX_DESCRIPTION_CHARS`:

```rust
/// How long a deleted repository can be restored; the daily job purges it afterwards.
pub const RESTORE_SECS: i64 = 7 * 86_400;

/// A deleted repository that its owner can still restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedRepo {
    pub id: i64,
    pub name: String,
    pub deleted_at: i64,
    /// After this time the daily job removes it for good.
    pub purge_after: i64,
}
```

3. In `create_repo`, replace the `let id = db_repos::insert(…).await.map_err(…)?;` statement with:

```rust
        let id = match db_repos::insert(self.db(), &new).await {
            Ok(id) => id,
            Err(e) if e.is_unique_violation() => {
                return Err(self.name_taken(actor.id, &actor.handle, &name).await);
            }
            Err(e) => return Err(e.into()),
        };
```

4. In `rename_repo`, replace the `db_repos::rename(…).await.map_err(…)?;` statement with:

```rust
        if let Err(e) = db_repos::rename(self.db(), old.id, &new_name).await {
            return Err(if e.is_unique_violation() {
                self.name_taken(old.owner_id, &old.owner, &new_name).await
            } else {
                e.into()
            });
        }
```

5. In `moved_repo`, after `let repo = to_repo(row)?;`, add:

```rust
        if repo.deleted_at.is_some() {
            return Ok(None);
        }
```

6. Add to the settings `impl Core` block:

```rust
    /// The error for a name already used in `owner`'s namespace. A deleted repository keeps its name until it
    /// is purged, and the message says so.
    async fn name_taken(&self, owner_id: i64, owner: &str, name: &str) -> CoreError {
        match db_repos::deleted_name_exists(self.db(), owner_id, name).await {
            Ok(true) => CoreError::Conflict(format!(
                "{owner}/{name} already exists as a deleted repository; restore it, or use the name after it is removed for good"
            )),
            Ok(false) => CoreError::Conflict(format!("{owner}/{name} already exists")),
            Err(err) => err.into(),
        }
    }

    /// Admins: deletes the repository once `confirm` is `owner/name`. It answers 404 everywhere at once, keeps
    /// its name, and can be restored for [`RESTORE_SECS`] (forge-basics design §5.5).
    pub async fn delete_repo(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        confirm: &str,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        let full_name = access.repo.full_name();
        if confirm.trim() != full_name {
            return Err(CoreError::Invalid(format!("Type {full_name} to confirm.")));
        }
        db_repos::set_deleted(self.db(), access.repo.id, Some(now())).await?;
        self.audit(Some(actor.id), "repo.delete", &format!("repo:{full_name}"), "")
            .await?;
        self.reload_repo(access.repo.id).await
    }

    /// The user's own deleted repositories that can still be restored, the most recently deleted first.
    pub async fn deleted_repos(&self, user: &User) -> CoreResult<Vec<DeletedRepo>> {
        let cutoff = now() - RESTORE_SECS;
        let mut deleted = Vec::new();
        for row in db_repos::list_deleted_by_owner(self.db(), user.id).await? {
            if let Some(deleted_at) = row.deleted_at
                && deleted_at > cutoff
            {
                deleted.push(DeletedRepo {
                    id: row.id,
                    name: row.name,
                    deleted_at,
                    purge_after: deleted_at + RESTORE_SECS,
                });
            }
        }
        Ok(deleted)
    }

    /// Restores a deleted repository within [`RESTORE_SECS`]; its owner or a site admin may. Anyone else, and a
    /// repository that is not deleted or is past the window, gets `NotFound`.
    pub async fn restore_repo(&self, actor: &User, repo_id: i64) -> CoreResult<Repo> {
        let repo = to_repo(
            db_repos::by_id(self.db(), repo_id)
                .await?
                .ok_or(CoreError::NotFound)?,
        )?;
        let allowed = actor.active && (actor.id == repo.owner_id || actor.is_admin);
        let restorable = repo
            .deleted_at
            .is_some_and(|at| at > now() - RESTORE_SECS);
        if !allowed || !restorable {
            return Err(CoreError::NotFound);
        }
        db_repos::set_deleted(self.db(), repo.id, None).await?;
        self.audit(
            Some(actor.id),
            "repo.restore",
            &format!("repo:{}", repo.full_name()),
            "",
        )
        .await?;
        self.reload_repo(repo.id).await
    }

    /// The daily job: purges repositories deleted more than [`RESTORE_SECS`] ago; returns how many.
    pub async fn purge_deleted_repos(&self) -> CoreResult<usize> {
        let rows = db_repos::deleted_before(self.db(), now() - RESTORE_SECS).await?;
        let count = rows.len();
        for row in rows {
            self.purge_repo(&to_repo(row)?, None).await?;
        }
        Ok(count)
    }

    /// Removes a deleted repository for good: the directory moves to `<tmp_dir>/purge-<id>.git`, the rows go
    /// (collaborators and redirects cascade), then the directory is removed. Every step is safe to repeat
    /// after a crash.
    pub(crate) async fn purge_repo(&self, repo: &Repo, actor_id: Option<i64>) -> CoreResult<()> {
        let path = self.repo_path(repo.id);
        let tmp = &self.config().tmp_dir;
        let parked = tmp.join(format!("purge-{}.git", repo.id));
        let failed = |step: &str, err: std::io::Error| {
            CoreError::Internal(format!("purging {}: {step}: {err}", repo.full_name()))
        };
        if tokio::fs::try_exists(&path)
            .await
            .map_err(|e| failed("checking the directory", e))?
        {
            tokio::fs::create_dir_all(tmp)
                .await
                .map_err(|e| failed("creating the tmp directory", e))?;
            if tokio::fs::try_exists(&parked)
                .await
                .map_err(|e| failed("checking the tmp directory", e))?
            {
                tokio::fs::remove_dir_all(&parked)
                    .await
                    .map_err(|e| failed("clearing an earlier attempt", e))?;
            }
            tokio::fs::rename(&path, &parked)
                .await
                .map_err(|e| failed("parking the directory", e))?;
        }
        db_repos::delete(self.db(), repo.id).await?;
        match tokio::fs::remove_dir_all(&parked).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(failed("removing the directory", err)),
        }
        self.audit(
            actor_id,
            "repo.purge",
            &format!("repo:{}", repo.full_name()),
            "",
        )
        .await
    }
```

In `crates/starforged-core/src/jobs.rs`:
1. Add the variant after `DailyPrune`:

```rust
    /// Daily: purges repositories deleted more than 7 days ago (forge-basics design §5.5).
    PurgeDeletedRepos,
```

2. `kind`: `Job::PurgeDeletedRepos => "purge_deleted_repos",`; `recurrence`: `Job::PurgeDeletedRepos => Some(DAY),`.
3. `execute`: `Job::PurgeDeletedRepos => self.purge_deleted_repos().await.map(|_| ()),`.
4. `start_workers` queues `[Job::HourlyCleanup, Job::DailyPrune, Job::PurgeDeletedRepos]`.

Run: `cargo test -p starforged-core`
Expected: PASS.

- [ ] **Step 6: Write the failing integration tests**

Create `crates/starforged/tests/web_repo_delete.rs`:

```rust
mod common;

use common::*;
use starforged_core::accounts::CreateUser;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_hides_the_repository_everywhere_until_its_owner_restores_it() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    git_ok(
        &work,
        &["push", "-q", &s.git_url("alice", "proj", Some(&token)), "main"],
    )
    .await;

    let (owner, csrf) = s.login("alice").await;
    let wrong = owner
        .post(s.url("/alice/proj/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 422);
    assert!(wrong.text().await.unwrap().contains("Type alice/proj to confirm."));
    let deleted = owner
        .post(s.url("/alice/proj/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "alice/proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 303);
    assert_eq!(deleted.headers()["location"], "/settings/repositories");

    for path in ["/alice/proj", "/alice/proj/tree/main", "/alice/proj/settings"] {
        assert_eq!(
            owner.get(s.url(path)).send().await.unwrap().status(),
            404,
            "{path}"
        );
    }
    assert!(
        !get_text(&owner, &s.url("/"))
            .await
            .contains(r#"href="/alice/proj""#),
        "gone from the dashboard"
    );
    assert_eq!(
        s.browser()
            .get(s.url("/api/v1/repos/alice/proj"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let clone = git(
        tmp.path(),
        &["clone", "-q", &s.git_url("alice", "proj", Some(&token)), "gone"],
    )
    .await;
    assert!(!clone.status.success(), "git answers like a missing repository");
    let reused = owner
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "proj"),
            ("visibility", "public"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(reused.status(), 422);
    assert!(reused.text().await.unwrap().contains("deleted repository"));

    let listing = get_text(&owner, &s.url("/settings/repositories")).await;
    assert!(listing.contains("alice/proj"), "{listing}");
    let restored = owner
        .post(s.url(&format!("/settings/repositories/{}/restore", repo.id)))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(restored.status(), 303);
    assert_eq!(restored.headers()["location"], "/alice/proj");
    assert!(get_text(&owner, &s.url("/alice/proj")).await.contains("a.txt"));
    git_ok(
        tmp.path(),
        &["clone", "-q", &s.git_url("alice", "proj", Some(&token)), "back"],
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_admins_delete_and_only_owners_and_site_admins_restore() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    s.repo(&alice, "other", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
        .await
        .unwrap();

    let (mia, mia_csrf) = s.login("mia").await;
    let refused = mia
        .post(s.url("/alice/proj/settings/delete"))
        .form(&[("_csrf", mia_csrf.as_str()), ("confirm", "alice/proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
    s.core
        .delete_repo(&alice, "alice", "proj", "alice/proj")
        .await
        .unwrap();
    let restore = mia
        .post(s.url(&format!("/settings/repositories/{}/restore", repo.id)))
        .form(&[("_csrf", mia_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(restore.status(), 404);

    let (root, root_csrf) = s.login("root").await;
    let by_admin = root
        .post(s.url("/alice/other/settings/delete"))
        .form(&[("_csrf", root_csrf.as_str()), ("confirm", "alice/other")])
        .send()
        .await
        .unwrap();
    assert_eq!(by_admin.status(), 303);
    assert_eq!(
        by_admin.headers()["location"],
        "/alice",
        "a site admin lands on the owner's page"
    );
}
```

Run: `cargo test -p starforged --test web_repo_delete`
Expected: FAIL: `/alice/proj/settings/delete` answers 405.

- [ ] **Step 7: Add the delete form and the Repositories settings page**

In `crates/starforged-web/src/pages/repo_settings.rs`, add:

```rust
#[derive(Deserialize)]
pub struct DeleteForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    confirm: String,
}

/// After deleting, owners land on Settings → Repositories (where Restore is); site admins deleting someone
/// else's repository land on the owner's page.
pub async fn delete(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .delete_repo(&session.user, &owner, &repo, &form.confirm)
        .await
    {
        Ok(deleted) => {
            let next = if deleted.owner_id == session.user.id {
                "/settings/repositories".to_owned()
            } else {
                format!("/{}", deleted.owner)
            };
            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => finish(&state, &session, &owner, &repo, Err(err)).await,
    }
}
```

In `crates/starforged-web/templates/repo_settings.html`, add after the Archive section (inside `{% if head.can_admin %}`):

```html
<h2>Delete</h2>
<form method="post" action="/{{ head.owner }}/{{ head.name }}/settings/delete" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <p>The repository disappears at once and is removed for good after 7 days. Until then its owner can restore it from <strong>Settings → Repositories</strong>.</p>
  <label>Type <code>{{ head.owner }}/{{ head.name }}</code> to confirm <input name="confirm" required autocomplete="off"></label>
  <button type="submit">Delete this repository</button>
</form>
```

In `crates/starforged-web/src/pages/settings.rs`, add:

```rust
pub struct DeletedRow {
    id: i64,
    name: String,
    deleted: String,
    purge_after: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "settings_repositories.html")]
pub struct RepositoriesPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    handle: String,
    deleted: Vec<DeletedRow>,
}

/// `/settings/repositories`: the user's deleted repositories that can still be restored.
pub async fn repositories(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<RepositoriesPage, WebError> {
    let deleted = state
        .core
        .deleted_repos(&session.user)
        .await?
        .into_iter()
        .map(|d| DeletedRow {
            id: d.id,
            name: d.name,
            deleted: format_time(d.deleted_at),
            purge_after: format_time(d.purge_after),
        })
        .collect();
    Ok(RepositoriesPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "repositories",
        handle: session.user.handle.clone(),
        deleted,
    })
}

pub async fn restore_repository(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let repo = state.core.restore_repo(&session.user, id).await?;
    Ok(Redirect::to(&format!("/{}/{}", repo.owner, repo.name)).into_response())
}
```

Create `crates/starforged-web/templates/settings_repositories.html`:

```html
{% extends "base.html" %}
{% block title %}Repositories · Settings · Starforge{% endblock %}
{% block content %}
{% include "settings_nav.html" %}
<h1>Deleted repositories</h1>
{% if deleted.is_empty() %}
<p class="muted">You have no deleted repositories. A repository you delete can be restored here for 7 days.</p>
{% else %}
<table class="list">
<thead><tr><th>Repository</th><th>Deleted</th><th>Removed for good after</th><th></th></tr></thead>
<tbody>
{% for r in deleted %}
<tr><td>{{ handle }}/{{ r.name }}</td><td>{{ r.deleted }}</td><td>{{ r.purge_after }}</td>
<td><form method="post" action="/settings/repositories/{{ r.id }}/restore" class="inline"><input type="hidden" name="_csrf" value="{{ csrf }}"><button type="submit">Restore</button></form></td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}
{% endblock %}
```

In `crates/starforged-web/templates/settings_nav.html`, add after the Tokens link:

```html
  <a href="/settings/repositories"{% if settings_tab == "repositories" %} aria-current="page"{% endif %}>Repositories</a>
```

In `crates/starforged-web/src/lib.rs`, add after the `/settings/tokens/{id}/revoke` route:

```rust
        .route("/settings/repositories", get(pages::settings::repositories))
        .route(
            "/settings/repositories/{id}/restore",
            post(pages::settings::restore_repository),
        )
```

and after the `/settings/unarchive` route:

```rust
        .route(
            "/{owner}/{repo}/settings/delete",
            post(pages::repo_settings::delete),
        )
```

- [ ] **Step 8: Run the tests**

Run: `cargo test -p starforged --test web_repo_delete --test web_repo_rename --test web_settings --test web_collaborators`
Expected: all pass.

- [ ] **Step 9: Full check on both databases, commit**

```bash
STARFORGE_TEST_PG=1 scripts/check.sh
git add -A crates
git commit -m "feat: delete repositories with a 7-day restore window and a daily purge"
```

Expected: fmt, clippy, and every test green on SQLite and Postgres.

---
### Task B6: Delete your account

**Files:**
- Modify: `crates/starforged-db/src/users.rs` (`count_active_admins_except`, `delete`)
- Modify: `crates/starforged-core/src/repos.rs` (`purge_deleted_repos_of`), `crates/starforged-core/src/account.rs` (`delete_account`, test)
- Modify: `crates/starforged-web/src/pages/settings.rs` (delete-account page), `templates/settings_nav.html`, `src/lib.rs` (route)
- Create: `crates/starforged-web/templates/settings_delete.html`
- Test: Create `crates/starforged/tests/web_account_delete.rs`

**Interfaces:**
- Consumes: `Core::{purge_repo (B5), audit, create_repo, delete_repo, create_token, collaborators}`, `starforged_db::repos::{list_by_owner, list_deleted_by_owner}` (B5), `pages::message::MessagePage` (Plan A), `auth::{removal, SESSION_COOKIE}`.
- Produces:
  - `starforged_db::users::count_active_admins_except(db, id: i64) -> DbResult<i64>` and `starforged_db::users::delete(db, id: i64) -> DbResult<()>` (deletes the owner row; the user row, sessions, tokens, email links, collaborator grants, redirects, and any repository rows cascade; invites and audit entries keep their rows with the user cleared).
  - `pub(crate) Core::purge_deleted_repos_of(&self, owner_id: i64, actor_id: Option<i64>) -> CoreResult<()>`.
  - `Core::delete_account(&self, user: &User, confirm: &str) -> CoreResult<()>`: `confirm` is the handle (any case, spaces ignored); refused (`Invalid`) while the user owns repositories that are not deleted or is the only active site admin.
  - Routes `GET/POST /settings/delete` (field `confirm`); settings navigation tab "Delete account". Plan C's last-admin guards reuse `count_active_admins_except`.

- [ ] **Step 1: Write the failing core test**

Add to the tests in `crates/starforged-core/src/account.rs` (create the `#[cfg(test)] mod tests` block with `use super::*;` and `use crate::testing::{test_core, user};` if it has none):

```rust
    #[tokio::test]
    async fn accounts_go_only_without_repositories_and_never_the_last_admin() {
        use crate::accounts::CreateUser;
        use crate::permission::{Permission, Visibility};
        use crate::repos::CreateRepo;
        use crate::tokens::Scope;

        let (core, _f) = test_core().await;
        let root = core
            .create_user(CreateUser {
                handle: "root".into(),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        let repo = |name: &str| CreateRepo {
            name: name.into(),
            description: String::new(),
            visibility: Visibility::Public,
            readme: false,
        };
        let kept = core.create_repo(&alice, repo("kept")).await.unwrap();
        let gone = core.create_repo(&alice, repo("gone")).await.unwrap();
        core.create_repo(&bob, repo("theirs")).await.unwrap();
        core.set_collaborator(&bob, "bob", "theirs", "alice", Permission::Write)
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "gone", "alice/gone")
            .await
            .unwrap();
        core.create_token(&alice, "laptop", &[Scope::RepoRead], 30)
            .await
            .unwrap();

        assert!(matches!(
            core.delete_account(&alice, "bob").await,
            Err(CoreError::Invalid(_))
        ));
        let refused = core.delete_account(&alice, "alice").await;
        assert!(
            matches!(&refused, Err(CoreError::Invalid(m)) if m.contains("kept")),
            "{refused:?}"
        );
        let last_admin = core.delete_account(&root, "root").await;
        assert!(
            matches!(&last_admin, Err(CoreError::Invalid(m)) if m.contains("only site administrator")),
            "{last_admin:?}"
        );

        core.delete_repo(&alice, "alice", "kept", "alice/kept")
            .await
            .unwrap();
        core.delete_account(&alice, " ALICE ").await.unwrap();
        assert!(core.user_by_handle("alice").await.unwrap().is_none());
        for id in [kept.id, gone.id] {
            assert!(
                starforged_db::repos::by_id(core.db(), id)
                    .await
                    .unwrap()
                    .is_none(),
                "deleted repositories are purged at once"
            );
            assert!(!core.repo_path(id).exists());
        }
        assert!(
            core.collaborators(&bob, "bob", "theirs")
                .await
                .unwrap()
                .is_empty(),
            "collaborator grants go with the account"
        );
        let tokens: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM access_tokens")
            .fetch_one(core.db().pool())
            .await
            .unwrap();
        assert_eq!(tokens, 0);
        let entry = starforged_db::audit::recent(core.db(), 1)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(
            (entry.action.as_str(), entry.target.as_str(), entry.actor_id),
            ("account.delete", "user:alice", None),
            "the entry survives with its actor cleared"
        );
        user(&core, "alice").await;
    }
```

Run: `cargo test -p starforged-core account::tests`
Expected: compile error: no method `delete_account`.

- [ ] **Step 2: Implement account deletion**

Append to `crates/starforged-db/src/users.rs` (before its tests):

```rust
/// Active site admins other than `id`.
pub async fn count_active_admins_except(db: &Db, id: i64) -> DbResult<i64> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND state = 'active' AND id <> $1",
    )
    .bind(id)
    .fetch_one(db.pool())
    .await?;
    Ok(count)
}

/// Deletes the account's owner row. The user row, web sessions, access tokens, email links, collaborator
/// grants, repository redirects, and any repository rows cascade; invites and audit entries keep their rows
/// with the user cleared.
pub async fn delete(db: &Db, id: i64) -> DbResult<()> {
    sqlx::query("DELETE FROM owners WHERE id = $1")
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}
```

In `crates/starforged-core/src/repos.rs`, add to the settings `impl Core` block:

```rust
    /// Purges every deleted repository of `owner_id` now, whatever its age (account deletion).
    pub(crate) async fn purge_deleted_repos_of(
        &self,
        owner_id: i64,
        actor_id: Option<i64>,
    ) -> CoreResult<()> {
        for row in db_repos::list_deleted_by_owner(self.db(), owner_id).await? {
            self.purge_repo(&to_repo(row)?, actor_id).await?;
        }
        Ok(())
    }
```

In `crates/starforged-core/src/account.rs`, add `use starforged_db::repos as db_repos;` and append to the `impl Core` block:

```rust
    /// Deletes the account once the user typed their handle (forge-basics design §4.6). Refused while the user
    /// owns repositories that are not deleted, or is the only active site admin. Their deleted repositories are
    /// purged at once; sessions, tokens, and collaborator grants go with the account; audit entries stay with
    /// the actor cleared.
    pub async fn delete_account(&self, user: &User, confirm: &str) -> CoreResult<()> {
        if confirm.trim().to_ascii_lowercase() != user.handle {
            return Err(CoreError::Invalid(format!(
                "Type your handle, {}, to confirm.",
                user.handle
            )));
        }
        let owned: Vec<String> = db_repos::list_by_owner(self.db(), user.id)
            .await?
            .into_iter()
            .map(|r| r.name)
            .collect();
        if !owned.is_empty() {
            return Err(CoreError::Invalid(format!(
                "Delete your repositories first: {}.",
                owned.join(", ")
            )));
        }
        if user.is_admin && users::count_active_admins_except(self.db(), user.id).await? == 0 {
            return Err(CoreError::Invalid(
                "You are the only site administrator; make another user an administrator first.".into(),
            ));
        }
        self.purge_deleted_repos_of(user.id, Some(user.id)).await?;
        // Recorded before the account goes: the foreign key then clears the actor and keeps the entry.
        self.audit(
            Some(user.id),
            "account.delete",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        users::delete(self.db(), user.id).await?;
        Ok(())
    }
```

Run: `cargo test -p starforged-core account::tests`
Expected: PASS.

- [ ] **Step 3: Write the failing web test**

Create `crates/starforged/tests/web_account_delete.rs`:

```rust
mod common;

use common::*;
use starforged_core::permission::Visibility;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_delete_their_account_after_typing_their_handle() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let (client, csrf) = s.login("alice").await;
    let page = get_text(&client, &s.url("/settings/delete")).await;
    assert!(page.contains(r#"action="/settings/delete""#), "{page}");

    let blocked = client
        .post(s.url("/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "alice")])
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 422);
    assert!(
        blocked
            .text()
            .await
            .unwrap()
            .contains("Delete your repositories first: proj.")
    );
    s.core
        .delete_repo(&alice, "alice", "proj", "alice/proj")
        .await
        .unwrap();
    let wrong = client
        .post(s.url("/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "nope")])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 422);

    let deleted = client
        .post(s.url("/settings/delete"))
        .form(&[("_csrf", csrf.as_str()), ("confirm", "alice")])
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 200);
    assert!(
        deleted
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("sf_session=")),
        "the session cookie is cleared"
    );
    assert!(deleted.text().await.unwrap().contains("Account deleted"));
    assert_eq!(
        client
            .get(s.url("/settings/profile"))
            .send()
            .await
            .unwrap()
            .status(),
        303,
        "signed out"
    );
    let (_, again) = s.try_login("alice", PASSWORD).await;
    assert_ne!(again.status(), 303, "the account cannot sign in");
    assert_eq!(
        s.browser().get(s.url("/alice")).send().await.unwrap().status(),
        404
    );
}
```

Run: `cargo test -p starforged --test web_account_delete`
Expected: FAIL: `/settings/delete` answers 404.

- [ ] **Step 4: Add the page**

In `crates/starforged-web/src/pages/settings.rs`, add `use crate::pages::message::MessagePage;` and:

```rust
#[derive(Template, WebTemplate)]
#[template(path = "settings_delete.html")]
pub struct DeleteAccountPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    handle: String,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct DeleteAccountForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    confirm: String,
}

fn delete_account_page(session: &WebSession, error: Option<String>) -> DeleteAccountPage {
    DeleteAccountPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "delete",
        handle: session.user.handle.clone(),
        error,
    }
}

pub async fn delete_account_form(RequireUser(session): RequireUser) -> DeleteAccountPage {
    delete_account_page(&session, None)
}

pub async fn delete_account(
    State(state): State<AppState>,
    jar: CookieJar,
    RequireUser(session): RequireUser,
    Form(form): Form<DeleteAccountForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .delete_account(&session.user, &form.confirm)
        .await
    {
        Ok(()) => {
            let page = MessagePage::new(
                None,
                "Account deleted",
                "Your account and everything it owned are gone.",
            )
            .with_link("/", "Home");
            Ok((jar.remove(removal(SESSION_COOKIE)), page).into_response())
        }
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            delete_account_page(&session, Some(message)),
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}
```

Create `crates/starforged-web/templates/settings_delete.html`:

```html
{% extends "base.html" %}
{% block title %}Delete account · Settings · Starforge{% endblock %}
{% block content %}
{% include "settings_nav.html" %}
<h1>Delete your account</h1>
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<p>Deleting your account signs you out everywhere, revokes your tokens and collaborator access, and removes your deleted repositories for good. It cannot be undone. Delete your repositories first.</p>
<form method="post" action="/settings/delete" class="stack">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
  <label>Type your handle, <code>{{ handle }}</code>, to confirm <input name="confirm" required autocomplete="off"></label>
  <button type="submit">Delete my account</button>
</form>
{% endblock %}
```

In `crates/starforged-web/templates/settings_nav.html`, add after the Repositories link:

```html
  <a href="/settings/delete"{% if settings_tab == "delete" %} aria-current="page"{% endif %}>Delete account</a>
```

In `crates/starforged-web/src/lib.rs`, add after the `/settings/repositories/{id}/restore` route:

```rust
        .route(
            "/settings/delete",
            get(pages::settings::delete_account_form).post(pages::settings::delete_account),
        )
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p starforged --test web_account_delete --test web_account`
Expected: all pass.

- [ ] **Step 6: Full check on both databases, commit**

```bash
STARFORGE_TEST_PG=1 scripts/check.sh
git add -A crates
git commit -m "feat: users delete their own accounts"
```

Expected: fmt, clippy, and every test green on SQLite and Postgres.

---
### Task B7: Compare two refs

**Files:**
- Modify: `crates/starforged-git/src/read.rs` (`range_log`, `merge_base`, tests), `crates/starforged-git/src/diff.rs` (`range_diff`; `commit_diff` and `range_diff` share `run_patch`)
- Modify: `crates/starforged-core/src/content.rs` (`MAX_COMPARE_COMMITS`, `Comparison`, `Core::compare`)
- Modify: `crates/starforged-web/src/views.rs` (`CommitRow`, `LineView`, `HunkView`, `FileView`, `file_views`, moved from `pages/history.rs`), `src/pages/history.rs`, `templates/commit.html`, `src/pages/mod.rs`, `src/lib.rs`
- Create: `crates/starforged-web/src/pages/compare.rs`, `templates/compare.html`, `templates/diff_files.html`
- Test: Create `crates/starforged/tests/web_compare.rs`

**Interfaces:**
- Consumes: `Core::{repo_for, resolve, branches, repo_path}`, `content::{MAX_DIFF_LINES, MAX_DIFF_BYTES, blocking}`, `pages::code::default_ref` (B1), `RepoHead` (B1), `views::encode_path`.
- Produces:
  - `starforged_git::read::range_log(repo: &Path, base_id: &str, head_id: &str, limit: usize) -> Result<(Vec<CommitInfo>, usize), GitError>`: commits reachable from `head_id` but not `base_id`, newest first, at most `limit`, plus the total.
  - `starforged_git::read::merge_base(repo: &Path, a: &str, b: &str) -> Result<Option<String>, GitError>`.
  - `starforged_git::diff::range_diff(repo: &Path, base_id: &str, head_id: &str, max_lines: usize, max_bytes: usize) -> Result<CommitDiff, GitError>`: `git diff <base> <head>`, object ids only, the same limits and streaming as `commit_diff`.
  - `starforged_core::content::{MAX_COMPARE_COMMITS: usize = 250, Comparison { base: Resolved, head: Resolved, merge_base: Option<String>, commits: Vec<CommitInfo>, total_commits: usize, diff: CommitDiff }}` and `Core::compare(&self, access: &RepoAccess, base: &str, head: &str) -> CoreResult<Comparison>`.
  - `starforged_web::views::{CommitRow, LineView, HunkView, FileView}` (public fields), `impl From<CommitInfo> for CommitRow`, `views::file_views(files: Vec<FileDiff>) -> Vec<FileView>`.
  - Template partial `diff_files.html` (needs `files: Vec<FileView>` and `truncated: bool`).
  - Routes `GET /{owner}/{repo}/compare` (picker; `?base=…&head=…` answers 303 to the comparison) and `GET /{owner}/{repo}/compare/{*spec}` (`{base}...{head}`).

- [ ] **Step 1: Write the failing git tests**

Add to the tests in `crates/starforged-git/src/read.rs`:

```rust
    #[test]
    fn range_logs_list_what_head_adds_to_base() {
        let f = fixture();
        let p = f.path();
        let main = resolve(p, "main").unwrap().unwrap().commit_id;
        let feature = resolve(p, "feature/x").unwrap().unwrap().commit_id;
        let v1 = resolve(p, "v1").unwrap().unwrap().commit_id;
        let (commits, total) = range_log(p, &main, &feature, 10).unwrap();
        assert_eq!(total, 1);
        assert_eq!(commits[0].summary, "feature");
        assert_eq!(range_log(p, &main, &feature, 0).unwrap(), (Vec::new(), 1));
        assert_eq!(range_log(p, &feature, &main, 10).unwrap(), (Vec::new(), 0));
        let (two, total) = range_log(p, &v1, &feature, 10).unwrap();
        assert_eq!(total, 2);
        let summaries: Vec<&str> = two.iter().map(|c| c.summary.as_str()).collect();
        assert_eq!(summaries, vec!["feature", "second"], "newest first");
        assert_eq!(merge_base(p, &main, &feature).unwrap(), Some(main.clone()));
        assert_eq!(merge_base(p, &v1, &feature).unwrap(), Some(v1));
    }
```

In `crates/starforged-git/src/diff.rs`, extend `commit_diff_runs_git_and_refuses_non_ids` before its end:

```rust
        let range = range_diff(&repo, &root, &head, 100, 4 * 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(range.files[0].status, FileStatus::Modified);
        assert_eq!(range.files[0].hunks[0].lines.last().unwrap().text, "two");
        assert!(
            range_diff(&repo, "--cached", &head, 100, 4 * 1024 * 1024)
                .await
                .is_err()
        );
```

Run: `cargo test -p starforged-git`
Expected: compile errors: no `range_log`, `merge_base`, or `range_diff`.

- [ ] **Step 2: Implement them**

Append to `crates/starforged-git/src/read.rs` (before the tests):

```rust
/// Commits reachable from `head_id` but not from `base_id`, newest first (by commit time): at most `limit`
/// of them, and how many there are in all.
pub fn range_log(
    repo: &Path,
    base_id: &str,
    head_id: &str,
    limit: usize,
) -> Result<(Vec<CommitInfo>, usize), GitError> {
    let r = open(repo)?;
    let base = r.rev_parse_single(base_id).map_err(gix_err)?.detach();
    let head = r.rev_parse_single(head_id).map_err(gix_err)?.detach();
    let walk = r
        .rev_walk([head])
        .with_hidden([base])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(
            Default::default(),
        ))
        .all()
        .map_err(gix_err)?;
    let mut commits = Vec::new();
    let mut total = 0;
    for info in walk {
        let info = info.map_err(gix_err)?;
        total += 1;
        if commits.len() < limit {
            commits.push(commit_info(&info.object().map_err(gix_err)?)?);
        }
    }
    Ok((commits, total))
}

/// The best common ancestor of two commits; `None` when their histories are unrelated.
pub fn merge_base(repo: &Path, a: &str, b: &str) -> Result<Option<String>, GitError> {
    let r = open(repo)?;
    let a = r.rev_parse_single(a).map_err(gix_err)?.detach();
    let b = r.rev_parse_single(b).map_err(gix_err)?.detach();
    Ok(r.merge_base(a, b).map_err(gix_err)?.map(|id| id.to_string()))
}
```

In `crates/starforged-git/src/diff.rs`, replace `commit_diff` with these three functions and `run_patch`; the body of `run_patch` is the old body of `commit_diff` from `let mut child = …` on, with the git arguments and the command name taken from its parameters:

```rust
/// Diff of `commit_id` against its first parent (or the empty tree for a root commit).
/// Reads at most `max_bytes` of `git show` output; larger diffs are cut after
/// their last complete line and reported as `truncated`.
pub async fn commit_diff(
    repo: &Path,
    commit_id: &str,
    max_lines: usize,
    max_bytes: usize,
) -> Result<CommitDiff, GitError> {
    check_object_id("show", commit_id)?;
    run_patch(
        repo,
        "show",
        &[
            OsStr::new("show"),
            OsStr::new("--format="),
            OsStr::new("--patch"),
            OsStr::new("--find-renames"),
            OsStr::new("--diff-merges=first-parent"),
            OsStr::new("--no-color"),
            OsStr::new("--no-ext-diff"),
            OsStr::new("--no-textconv"),
            OsStr::new(commit_id),
        ],
        max_lines,
        max_bytes,
    )
    .await
}

/// Diff from `base_id` to `head_id` (compare passes the merge base as `base_id`), with the limits of
/// [`commit_diff`].
pub async fn range_diff(
    repo: &Path,
    base_id: &str,
    head_id: &str,
    max_lines: usize,
    max_bytes: usize,
) -> Result<CommitDiff, GitError> {
    check_object_id("diff", base_id)?;
    check_object_id("diff", head_id)?;
    run_patch(
        repo,
        "diff",
        &[
            OsStr::new("diff"),
            OsStr::new("--find-renames"),
            OsStr::new("--no-color"),
            OsStr::new("--no-ext-diff"),
            OsStr::new("--no-textconv"),
            OsStr::new(base_id),
            OsStr::new(head_id),
        ],
        max_lines,
        max_bytes,
    )
    .await
}

/// Only object ids reach git, so no argument can be read as an option.
fn check_object_id(command: &str, id: &str) -> Result<(), GitError> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(GitError::Failed {
            command: command.into(),
            stderr: format!("not an object id: {id}"),
        });
    }
    Ok(())
}

/// Runs `git -c core.quotePath=false --git-dir <repo> <args>` and parses its patch output, reading at most
/// `max_bytes` (then cut after the last complete line and marked `truncated`).
async fn run_patch(
    repo: &Path,
    command: &str,
    args: &[&OsStr],
    max_lines: usize,
    max_bytes: usize,
) -> Result<CommitDiff, GitError> {
    let mut child = git()
        .args([
            OsStr::new("-c"),
            OsStr::new("core.quotePath=false"),
            OsStr::new("--git-dir"),
            repo.as_os_str(),
        ])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(|| GitError::Failed {
        command: command.into(),
        stderr: format!("git {command} produced no stdout"),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| GitError::Failed {
        command: command.into(),
        stderr: format!("git {command} produced no stderr"),
    })?;
    let stderr_text = tokio::spawn(drain_bounded(stderr));
    let mut kept = Vec::new();
    let mut byte_truncated = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let n = stdout.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        kept.extend_from_slice(&chunk[..n]);
        if kept.len() > max_bytes {
            byte_truncated = true;
            break;
        }
    }
    if byte_truncated {
        let _ = child.kill().await;
        let _ = child.wait().await;
        let _ = stderr_text.await;
        kept.truncate(max_bytes);
        // Keep only complete lines; `\n` never appears inside a multi-byte
        // UTF-8 sequence, so this also keeps a character boundary.
        let end = kept.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        kept.truncate(end);
        let mut diff = parse(&String::from_utf8_lossy(&kept), max_lines);
        diff.truncated = true;
        return Ok(diff);
    }
    let status = child.wait().await?;
    let stderr = stderr_text.await.unwrap_or_default();
    if !status.success() {
        return Err(GitError::Failed {
            command: command.into(),
            stderr: String::from_utf8_lossy(&stderr).trim().to_owned(),
        });
    }
    Ok(parse(&String::from_utf8_lossy(&kept), max_lines))
}
```

Run: `cargo test -p starforged-git`
Expected: PASS (the existing diff tests keep passing unchanged).

- [ ] **Step 3: Add `Core::compare`**

In `crates/starforged-core/src/content.rs`, import `starforged_git::read::{self, CommitInfo, Resolved, TreeEntry}` (unchanged) and append:

```rust
/// Most commits a comparison lists; the rest are counted.
pub const MAX_COMPARE_COMMITS: usize = 250;

/// What `head` adds to `base` (forge-basics design §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    pub base: Resolved,
    pub head: Resolved,
    /// `None` when the refs share no history; `commits` and `diff` are then empty.
    pub merge_base: Option<String>,
    /// Newest first; at most [`MAX_COMPARE_COMMITS`].
    pub commits: Vec<CommitInfo>,
    /// Every commit reachable from `head` but not from `base`, listed or not.
    pub total_commits: usize,
    /// From the merge base to `head`, within [`MAX_DIFF_LINES`] and [`MAX_DIFF_BYTES`].
    pub diff: CommitDiff,
}

impl Core {
    /// Compares two refs (branch, tag, or full commit id) of one repository. Both are resolved to object ids
    /// before git runs; a name that is not exactly a ref is `NotFound`.
    pub async fn compare(
        &self,
        access: &RepoAccess,
        base: &str,
        head: &str,
    ) -> CoreResult<Comparison> {
        let base = self.resolve_exact(access, base).await?;
        let head = self.resolve_exact(access, head).await?;
        let repo = self.repo_path(access.repo.id);
        let (probe, a, b) = (repo.clone(), base.commit_id.clone(), head.commit_id.clone());
        let Some(merge_base) = blocking(move || read::merge_base(&probe, &a, &b)).await? else {
            return Ok(Comparison {
                base,
                head,
                merge_base: None,
                commits: Vec::new(),
                total_commits: 0,
                diff: CommitDiff {
                    files: Vec::new(),
                    truncated: false,
                },
            });
        };
        let (probe, a, b) = (repo.clone(), base.commit_id.clone(), head.commit_id.clone());
        let (commits, total_commits) =
            blocking(move || read::range_log(&probe, &a, &b, MAX_COMPARE_COMMITS)).await?;
        let diff = starforged_git::diff::range_diff(
            &repo,
            &merge_base,
            &head.commit_id,
            MAX_DIFF_LINES,
            MAX_DIFF_BYTES,
        )
        .await?;
        Ok(Comparison {
            base,
            head,
            merge_base: Some(merge_base),
            commits,
            total_commits,
            diff,
        })
    }

    /// A branch, tag, or commit id with nothing after it.
    async fn resolve_exact(&self, access: &RepoAccess, name: &str) -> CoreResult<Resolved> {
        let resolved = self.resolve(access, name).await?;
        if resolved.path.is_empty() {
            Ok(resolved)
        } else {
            Err(CoreError::NotFound)
        }
    }
}
```

- [ ] **Step 4: Write the failing integration tests**

Create `crates/starforged/tests/web_compare.rs`:

```rust
mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comparing_refs_lists_new_commits_and_the_diff_from_the_merge_base() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    commit_files(&work, &[("b.txt", b"bee\n")], "add bee").await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    commit_files(&work, &[("c.txt", b"main only\n")], "main moves on").await;
    git_ok(&work, &["checkout", "-q", "--orphan", "unrelated"]).await;
    git_ok(&work, &["rm", "-rq", "."]).await;
    commit_files(&work, &[("z.txt", b"z\n")], "unrelated root").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/x", "unrelated"]).await;
    let client = s.browser();

    let page = get_text(&client, &s.url("/alice/proj/compare/main...feature/x")).await;
    let newer = page.find("add bee").expect("the newest commit is listed");
    let older = page.find("add two").expect("the older commit is listed");
    assert!(newer < older, "newest first");
    assert!(page.contains("2 commits"), "{page}");
    assert!(!page.contains("main moves on"), "commits only on the base are not listed");
    assert!(page.contains(r#"<span class="badge">added</span> b.txt"#), "{page}");
    assert!(
        page.contains(r#"<tr class="add"><td class="ln"></td><td class="ln">2</td><td><pre>two</pre></td></tr>"#),
        "{page}"
    );
    assert!(!page.contains("c.txt"), "the diff starts at the merge base");

    let same = get_text(&client, &s.url("/alice/proj/compare/main...main")).await;
    assert!(same.contains("main has no commits that main lacks."), "{same}");
    let unrelated = get_text(&client, &s.url("/alice/proj/compare/main...unrelated")).await;
    assert!(unrelated.contains("share no history"), "{unrelated}");

    let picked = client
        .get(s.url("/alice/proj/compare?base=main&head=feature/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(picked.status(), 303);
    assert_eq!(picked.headers()["location"], "/alice/proj/compare/main...feature/x");
    let picker = get_text(&client, &s.url("/alice/proj/compare")).await;
    assert!(
        picker.contains(r#"<option value="feature/x" selected>feature/x</option>"#),
        "the head defaults to another branch: {picker}"
    );
    assert!(picker.contains(r#"<option value="main" selected>main</option>"#), "{picker}");

    for missing in [
        "/alice/proj/compare/main...nope",
        "/alice/proj/compare/main",
        "/alice/proj/compare/main...feature/x/a.txt",
    ] {
        assert_eq!(
            client.get(s.url(missing)).send().await.unwrap().status(),
            404,
            "{missing}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn long_comparisons_list_250_commits_and_count_the_rest() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "long"]).await;
    for i in 0..253 {
        git_ok(
            &work,
            &["commit", "-q", "--allow-empty", "-m", &format!("step {i}")],
        )
        .await;
    }
    git_ok(&work, &["push", "-q", &url, "main", "long"]).await;
    let page = get_text(&s.browser(), &s.url("/alice/proj/compare/main...long")).await;
    assert!(page.contains("253 commits"), "{page}");
    assert!(page.contains("and 3 more commits"), "{page}");
    assert_eq!(page.matches("<li>").count(), 250);
}
```

Run: `cargo test -p starforged --test web_compare`
Expected: FAIL: the compare routes answer 404.

- [ ] **Step 5: Share commit rows and diff views**

In `crates/starforged-web/src/views.rs`, add the imports `use starforged_git::diff::{FileDiff, FileStatus, LineKind};` and `use starforged_git::read::CommitInfo;`, and append before the tests:

```rust
/// One commit in a list (`commits.html`, `compare.html`).
pub struct CommitRow {
    pub id: String,
    pub short_id: String,
    pub summary: String,
    pub author: String,
    pub when: String,
}

impl From<CommitInfo> for CommitRow {
    fn from(commit: CommitInfo) -> CommitRow {
        let short_id = commit.short_id().to_owned();
        CommitRow {
            id: commit.id,
            short_id,
            summary: commit.summary,
            author: commit.author_name,
            when: format_time(commit.author_time),
        }
    }
}

pub struct LineView {
    pub class: &'static str,
    pub old: String,
    pub new: String,
    pub text: String,
}

pub struct HunkView {
    pub header: String,
    pub lines: Vec<LineView>,
}

pub struct FileView {
    pub status: &'static str,
    pub path: String,
    pub binary: bool,
    pub hunks: Vec<HunkView>,
}

/// Diff files as `diff_files.html` renders them.
pub fn file_views(files: Vec<FileDiff>) -> Vec<FileView> {
    files
        .into_iter()
        .map(|file| FileView {
            status: match file.status {
                FileStatus::Added => "added",
                FileStatus::Deleted => "deleted",
                FileStatus::Modified => "modified",
                FileStatus::Renamed => "renamed",
            },
            path: match (file.status, &file.old_path) {
                (FileStatus::Renamed, Some(old)) => format!("{old} → {}", file.display_path()),
                _ => file.display_path().to_owned(),
            },
            binary: file.binary,
            hunks: file
                .hunks
                .into_iter()
                .map(|hunk| HunkView {
                    header: hunk.header,
                    lines: hunk
                        .lines
                        .into_iter()
                        .map(|line| LineView {
                            class: match line.kind {
                                LineKind::Context => "ctx",
                                LineKind::Added => "add",
                                LineKind::Removed => "del",
                                LineKind::NoNewline => "nonl",
                            },
                            old: line.old_line.map(|n| n.to_string()).unwrap_or_default(),
                            new: line.new_line.map(|n| n.to_string()).unwrap_or_default(),
                            text: line.text,
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect()
}
```

In `crates/starforged-web/src/pages/history.rs`:
1. Delete the local `CommitRow`, `LineView`, `HunkView`, and `FileView` structs and the `starforged_git::diff::{FileStatus, LineKind}` import, and import the shared ones (`commit` still uses `format_time`): `use crate::views::{CommitRow, FileView, NavUser, RepoHead, file_views, format_time, nav};`.
2. In `commits_page`, build the rows with `commits: commits.into_iter().map(CommitRow::from).collect(),`.
3. In `commit`, replace the whole `let files = diff.files.into_iter().map(…).collect();` statement with `let files = file_views(diff.files);`.

Create `crates/starforged-web/templates/diff_files.html` with the diff part of `commit.html`:

```html
{% if truncated %}<p class="notice">This diff is large; only the first lines are shown.</p>{% endif %}
{% for f in files %}
<section class="file">
<h3><span class="badge">{{ f.status }}</span> {{ f.path }}</h3>
{% if f.binary %}
<p class="muted">Binary file</p>
{% else %}
<table class="diff"><tbody>
{% for h in f.hunks %}
<tr class="hunk"><td colspan="3">{{ h.header }}</td></tr>
{% for l in h.lines %}<tr class="{{ l.class }}"><td class="ln">{{ l.old }}</td><td class="ln">{{ l.new }}</td><td><pre>{{ l.text }}</pre></td></tr>
{% endfor %}
{% endfor %}
</tbody></table>
{% endif %}
</section>
{% endfor %}
```

In `crates/starforged-web/templates/commit.html`, replace everything from the `{% if truncated %}` line through the closing `{% endfor %}` of the files loop with `{% include "diff_files.html" %}`.

Run: `cargo test -p starforged --test web_history`
Expected: PASS (the commit page renders exactly as before).

- [ ] **Step 6: Add the compare pages**

Create `crates/starforged-web/src/pages/compare.rs`:

```rust
//! Comparing two refs (forge-basics design §6): the commits `head` adds to `base`, and the diff from their
//! merge base to `head`.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use starforged_core::repos::RepoAccess;

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::pages::code::default_ref;
use crate::views::{CommitRow, FileView, NavUser, RepoHead, encode_path, file_views, nav};

#[derive(Deserialize)]
pub struct PickQuery {
    base: Option<String>,
    head: Option<String>,
}

pub struct RefOption {
    name: String,
    selected: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "compare.html")]
pub struct ComparePage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    base_options: Vec<RefOption>,
    head_options: Vec<RefOption>,
    /// False on the picker page, which shows only the form.
    compared: bool,
    base_ref: String,
    head_ref: String,
    /// The refs share history.
    related: bool,
    commits: Vec<CommitRow>,
    total: usize,
    /// Commits beyond the listed ones.
    more: usize,
    files: Vec<FileView>,
    truncated: bool,
}

/// `/{owner}/{repo}/compare`: two branch pickers. With `?base=…&head=…` it answers 303 to the comparison.
pub async fn pick(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<PickQuery>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let base = query.base.filter(|b| !b.is_empty());
    let head = query.head.filter(|h| !h.is_empty());
    if let (Some(base), Some(head)) = (&base, &head) {
        return Ok(Redirect::to(&compare_href(&access, base, head)).into_response());
    }
    let branches = state.core.branches(&access).await?;
    let base = match base {
        Some(base) => base,
        None => default_ref(&state, &access).await?.unwrap_or_default(),
    };
    let head = head
        .or_else(|| branches.iter().find(|b| **b != base).cloned())
        .unwrap_or_else(|| base.clone());
    Ok(ComparePage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "compare", None),
        base_options: options(&branches, &base),
        head_options: options(&branches, &head),
        compared: false,
        base_ref: base,
        head_ref: head,
        related: false,
        commits: Vec::new(),
        total: 0,
        more: 0,
        files: Vec::new(),
        truncated: false,
    }
    .into_response())
}

/// `/{owner}/{repo}/compare/{base}...{head}`. A valid ref never contains `...`, so the first one splits.
pub async fn compare(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, spec)): Path<(String, String, String)>,
) -> Result<ComparePage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let (base, head) = spec.split_once("...").ok_or(WebError::NotFound)?;
    let comparison = state.core.compare(&access, base, head).await?;
    let branches = state.core.branches(&access).await?;
    let total = comparison.total_commits;
    let more = total - comparison.commits.len();
    Ok(ComparePage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "compare", None),
        base_options: options(&branches, &comparison.base.ref_name),
        head_options: options(&branches, &comparison.head.ref_name),
        compared: true,
        base_ref: comparison.base.ref_name,
        head_ref: comparison.head.ref_name,
        related: comparison.merge_base.is_some(),
        commits: comparison.commits.into_iter().map(CommitRow::from).collect(),
        total,
        more,
        files: file_views(comparison.diff.files),
        truncated: comparison.diff.truncated,
    })
}

fn compare_href(access: &RepoAccess, base: &str, head: &str) -> String {
    format!(
        "/{}/{}/compare/{}...{}",
        access.repo.owner,
        access.repo.name,
        encode_path(base),
        encode_path(head)
    )
}

/// The branches as options with `selected` chosen. A name that is not a branch (a tag or a commit id) comes
/// first, so the form still shows what is compared.
fn options(branches: &[String], selected: &str) -> Vec<RefOption> {
    let mut options: Vec<RefOption> = branches
        .iter()
        .map(|name| RefOption {
            selected: name == selected,
            name: name.clone(),
        })
        .collect();
    if !selected.is_empty() && !branches.iter().any(|b| b == selected) {
        options.insert(
            0,
            RefOption {
                name: selected.to_owned(),
                selected: true,
            },
        );
    }
    options
}
```

Create `crates/starforged-web/templates/compare.html`:

```html
{% extends "base.html" %}
{% block title %}Compare · {{ head.owner }}/{{ head.name }}{% endblock %}
{% block content %}
{% include "repo_head.html" %}
<form method="get" action="/{{ head.owner }}/{{ head.name }}/compare" class="inline">
  <label>Base <select name="base">{% for o in base_options %}<option value="{{ o.name }}"{% if o.selected %} selected{% endif %}>{{ o.name }}</option>{% endfor %}</select></label>
  <label>Compare <select name="head">{% for o in head_options %}<option value="{{ o.name }}"{% if o.selected %} selected{% endif %}>{{ o.name }}</option>{% endfor %}</select></label>
  <button type="submit">Compare</button>
</form>
{% if compared %}
{% if !related %}
<p class="notice">{{ base_ref }} and {{ head_ref }} share no history, so there is nothing to compare.</p>
{% else if commits.is_empty() %}
<p class="muted">{{ head_ref }} has no commits that {{ base_ref }} lacks.</p>
{% else %}
<h2>{{ total }} commit{% if total != 1 %}s{% endif %}</h2>
<ol class="commits">
{% for c in commits %}
<li><a href="/{{ head.owner }}/{{ head.name }}/commit/{{ c.id }}"><code>{{ c.short_id }}</code></a> {{ c.summary }} <span class="muted">{{ c.author }} · {{ c.when }}</span></li>
{% endfor %}
</ol>
{% if more > 0 %}<p class="muted">and {{ more }} more commit{% if more != 1 %}s{% endif %}</p>{% endif %}
{% include "diff_files.html" %}
{% endif %}
{% endif %}
{% endblock %}
```

In `crates/starforged-web/src/pages/mod.rs`, add `pub mod compare;` after `pub mod collaborators;`.

In `crates/starforged-web/src/lib.rs`, add after the `/{owner}/{repo}/commit/{id}` route:

```rust
        .route("/{owner}/{repo}/compare", get(pages::compare::pick))
        .route(
            "/{owner}/{repo}/compare/{*spec}",
            get(pages::compare::compare),
        )
```

- [ ] **Step 7: Run the tests**

Run: `cargo test -p starforged --test web_compare --test web_history`
Expected: all pass.

- [ ] **Step 8: Full check, commit**

```bash
scripts/check.sh
git add -A crates
git commit -m "feat: compare two refs: new commits and the diff from the merge base"
```

Expected: fmt, clippy, and every test green. (No SQL changed in this task.)

---
### Task B8: Branches and tags pages

**Files:**
- Modify: `crates/starforged-git/src/read.rs` (`BranchInfo`, `TagInfo`, `branch_list`, `tag_list`, tests)
- Modify: `crates/starforged-core/src/content.rs` (`Core::branch_list`, `Core::tag_list`)
- Modify: `crates/starforged-web/src/views.rs` (`format_age`, test), `templates/repo_head.html` (Branches and Tags tabs), `src/pages/mod.rs`, `src/lib.rs`
- Create: `crates/starforged-web/src/pages/refs.rs`, `templates/branches.html`, `templates/tags.html`
- Modify: `crates/starforged/tests/common/mod.rs` (`git_with_env`, `git_dated`)
- Test: Create `crates/starforged/tests/web_refs.rs`

**Interfaces:**
- Consumes: `read::{open, gix_err, commit_info}`, `content::blocking`, `RepoHead` (B1), `views::{content_href, encode_path, format_time}`, the compare route (B7).
- Produces:
  - `starforged_git::read::BranchInfo { name: String, tip: CommitInfo, committed_at: i64 }` and `read::branch_list(repo: &Path) -> Result<Vec<BranchInfo>, GitError>` (newest tip first by committer time, then by name).
  - `starforged_git::read::TagInfo { name: String, commit_id: String, date: i64, annotation: Option<String> }` and `read::tag_list(repo: &Path) -> Result<Vec<TagInfo>, GitError>` (newest first: tagger date for annotated tags, commit date otherwise; then by name; `annotation` is the message's first line).
  - `Core::branch_list(&self, access: &RepoAccess) -> CoreResult<Vec<BranchInfo>>`, `Core::tag_list(&self, access: &RepoAccess) -> CoreResult<Vec<TagInfo>>`.
  - `starforged_web::views::format_age(now: i64, then: i64) -> String` ("just now", "5 minutes ago", "1 day ago", …).
  - Test harness: `git_with_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output` and `git_dated(dir: &Path, args: &[&str], unix_time: i64) -> String` (author and committer dates set; must succeed).
  - Routes `GET /{owner}/{repo}/branches`, `GET /{owner}/{repo}/tags`; `repo_head.html` tabs: Code · Commits · Branches · Tags · Settings.

- [ ] **Step 1: Write the failing git and view tests**

Add to the tests in `crates/starforged-git/src/read.rs`:

```rust
    #[test]
    fn branches_list_the_newest_tip_first() {
        let f = fixture();
        let branches = branch_list(f.path()).unwrap();
        let names: Vec<&str> = branches.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, vec!["feature/x", "main"]);
        assert_eq!(branches[0].tip.summary, "feature");
        assert_eq!(branches[0].committed_at, 1_704_240_000, "2024-01-03T00:00:00Z");
        assert_eq!(branches[1].tip.author_name, "T");
    }

    #[test]
    fn tags_are_dated_by_tagger_or_commit() {
        let f = fixture();
        let p = f.path();
        git(
            p,
            &["tag", "-a", "v2", "-m", "Second release\n\nWith notes"],
            Some("2024-02-01T00:00:00Z"),
        );
        let tags = tag_list(p).unwrap();
        let summary: Vec<(&str, i64, Option<&str>)> = tags
            .iter()
            .map(|t| (t.name.as_str(), t.date, t.annotation.as_deref()))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("v2", 1_706_745_600, Some("Second release")),
                ("v1", 1_704_067_200, None),
            ]
        );
        let main = resolve(p, "main").unwrap().unwrap().commit_id;
        assert_eq!(tags[0].commit_id, main, "an annotated tag leads to its commit");
    }
```

Add to the tests in `crates/starforged-web/src/views.rs`:

```rust
    #[test]
    fn ages_read_naturally() {
        let now = 1_700_000_000;
        let cases = [
            (now, "just now"),
            (now - 59, "just now"),
            (now - 60, "1 minute ago"),
            (now - 5 * 60, "5 minutes ago"),
            (now - 3_600, "1 hour ago"),
            (now - 2 * 86_400, "2 days ago"),
            (now - 45 * 86_400, "1 month ago"),
            (now - 800 * 86_400, "2 years ago"),
            (now + 30, "just now"),
        ];
        for (then, expected) in cases {
            assert_eq!(format_age(now, then), expected, "{then}");
        }
    }
```

Run: `cargo test -p starforged-git read::tests && cargo test -p starforged-web views::tests`
Expected: compile errors: no `branch_list`, `tag_list`, or `format_age`.

- [ ] **Step 2: Implement the listings and `format_age`**

Add to `crates/starforged-git/src/read.rs` after `Resolved`:

```rust
/// A branch and the commit at its tip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchInfo {
    pub name: String,
    pub tip: CommitInfo,
    /// Committer time of the tip, unix seconds.
    pub committed_at: i64,
}

/// A tag and the commit it leads to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagInfo {
    pub name: String,
    pub commit_id: String,
    /// The tagger's time for an annotated tag, the commit's otherwise; unix seconds.
    pub date: i64,
    /// The first line of an annotated tag's message.
    pub annotation: Option<String>,
}
```

and append (before the tests):

```rust
/// Local branches, the most recently committed tip first, then by name. Branches whose tip is not a
/// commit are skipped.
pub fn branch_list(repo: &Path) -> Result<Vec<BranchInfo>, GitError> {
    let r = open(repo)?;
    let platform = r.references().map_err(gix_err)?;
    let mut branches = Vec::new();
    for reference in platform.local_branches().map_err(gix_err)? {
        let mut reference = reference.map_err(gix_err)?;
        let name = reference.name().shorten().to_string();
        let Ok(commit) = reference.peel_to_commit() else {
            continue;
        };
        branches.push(BranchInfo {
            name,
            committed_at: commit.time().map_err(gix_err)?.seconds,
            tip: commit_info(&commit)?,
        });
    }
    branches.sort_by(|a, b| {
        b.committed_at
            .cmp(&a.committed_at)
            .then_with(|| a.name.cmp(&b.name))
    });
    Ok(branches)
}

/// Tags, newest first, then by name. Tags that do not lead to a commit are skipped.
pub fn tag_list(repo: &Path) -> Result<Vec<TagInfo>, GitError> {
    let r = open(repo)?;
    let platform = r.references().map_err(gix_err)?;
    let mut tags = Vec::new();
    for reference in platform.tags().map_err(gix_err)? {
        let mut reference = reference.map_err(gix_err)?;
        let name = reference.name().shorten().to_string();
        // The object the tag names directly: a tag object for annotated tags, the commit otherwise.
        let target = reference.id().detach();
        let Ok(commit) = reference.peel_to_commit() else {
            continue;
        };
        let commit_time = commit.time().map_err(gix_err)?.seconds;
        let object = r.find_object(target).map_err(gix_err)?;
        let (date, annotation) = if object.kind == gix::object::Kind::Tag {
            let tag = object.into_tag();
            let decoded = tag.decode().map_err(gix_err)?;
            let date = match decoded.tagger().map_err(gix_err)? {
                Some(tagger) => tagger.time().map_err(gix_err)?.seconds,
                None => commit_time,
            };
            let first_line = decoded
                .message
                .to_string()
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            (date, Some(first_line).filter(|line| !line.is_empty()))
        } else {
            (commit_time, None)
        };
        tags.push(TagInfo {
            name,
            commit_id: commit.id.to_string(),
            date,
            annotation,
        });
    }
    tags.sort_by(|a, b| b.date.cmp(&a.date).then_with(|| a.name.cmp(&b.name)));
    Ok(tags)
}
```

Add to `crates/starforged-web/src/views.rs` after `format_time`:

```rust
/// How long ago `then` was, seen at `now` (unix seconds): "just now", "5 minutes ago", "1 day ago", …
/// Times in the future read "just now".
pub fn format_age(now: i64, then: i64) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;
    let secs = (now - then).max(0);
    let (count, unit) = if secs < MINUTE {
        return "just now".to_owned();
    } else if secs < HOUR {
        (secs / MINUTE, "minute")
    } else if secs < DAY {
        (secs / HOUR, "hour")
    } else if secs < 30 * DAY {
        (secs / DAY, "day")
    } else if secs < 365 * DAY {
        (secs / (30 * DAY), "month")
    } else {
        (secs / (365 * DAY), "year")
    };
    let plural = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{plural} ago")
}
```

Run: `cargo test -p starforged-git read::tests && cargo test -p starforged-web views::tests`
Expected: PASS.

- [ ] **Step 3: Add the core wrappers**

In `crates/starforged-core/src/content.rs`, change the read import to `use starforged_git::read::{self, BranchInfo, CommitInfo, Resolved, TagInfo, TreeEntry};` and add to the first `impl Core` block:

```rust
    /// Branches with their tip commits, the newest tip first.
    pub async fn branch_list(&self, access: &RepoAccess) -> CoreResult<Vec<BranchInfo>> {
        let repo = self.repo_path(access.repo.id);
        blocking(move || read::branch_list(&repo)).await
    }

    /// Tags with their commits, the newest first.
    pub async fn tag_list(&self, access: &RepoAccess) -> CoreResult<Vec<TagInfo>> {
        let repo = self.repo_path(access.repo.id);
        blocking(move || read::tag_list(&repo)).await
    }
```

- [ ] **Step 4: Add the dated git helper to the test harness**

In `crates/starforged/tests/common/mod.rs`, replace `pub async fn git` with:

```rust
/// Runs `git` in `dir` on a blocking thread, isolated from the developer's configuration.
/// Defaults to protocol v2; pass `-c protocol.version=0` to override.
pub async fn git(dir: &Path, args: &[&str]) -> Output {
    git_with_env(dir, args, &[]).await
}

/// [`git`] with extra environment variables.
pub async fn git_with_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let dir = dir.to_path_buf();
    let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
    let env: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    tokio::task::spawn_blocking(move || {
        std::process::Command::new("git")
            .args([
                "-c",
                "credential.helper=",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
            ])
            .args(["-c", "init.defaultBranch=main", "-c", "protocol.version=2"])
            .args(&args)
            .current_dir(&dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .envs(env)
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

/// [`git_ok`] with the author and committer (and tagger) dates set to `unix_time`.
pub async fn git_dated(dir: &Path, args: &[&str], unix_time: i64) -> String {
    let date = format!("@{unix_time} +0000");
    let out = git_with_env(
        dir,
        args,
        &[
            ("GIT_AUTHOR_DATE", date.as_str()),
            ("GIT_COMMITTER_DATE", date.as_str()),
        ],
    )
    .await;
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
```

- [ ] **Step 5: Write the failing integration test**

Create `crates/starforged/tests/web_refs.rs`:

```rust
mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn branches_and_tags_pages() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    git_ok(tmp.path(), &["init", "-q", "work"]).await;
    let work = tmp.path().join("work");
    let day = 86_400;
    let t0 = 1_700_000_000;
    let commit = |file: &'static str, message: &'static str, when: i64| {
        let work = work.clone();
        async move {
            std::fs::write(work.join(file), message).unwrap();
            git_ok(&work, &["add", "-A"]).await;
            git_dated(&work, &["commit", "-q", "-m", message], when).await;
        }
    };
    commit("a.txt", "root", t0).await;
    git_ok(&work, &["branch", "old"]).await;
    git_ok(&work, &["tag", "v0.1"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature"]).await;
    commit("f.txt", "feature work", t0 + 2 * day).await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    commit("m.txt", "main work", t0 + day).await;
    git_dated(
        &work,
        &["tag", "-a", "v1.0", "-m", "First release\n\nNotes here"],
        t0 + 3 * day,
    )
    .await;
    git_ok(
        &work,
        &["push", "-q", &url, "main", "feature", "old", "v0.1", "v1.0"],
    )
    .await;

    let client = s.browser();
    let branches = get_text(&client, &s.url("/alice/proj/branches")).await;
    let main_at = branches
        .find(r#">main</a> <span class="badge">default</span>"#)
        .unwrap_or_else(|| panic!("{branches}"));
    let feature_at = branches.find(">feature</a>").unwrap();
    let old_at = branches.find(">old</a>").unwrap();
    assert!(
        main_at < feature_at && feature_at < old_at,
        "the default branch first, then the newest: {branches}"
    );
    assert!(branches.contains(r#"href="/alice/proj/compare/main...feature""#));
    assert!(!branches.contains("/alice/proj/compare/main...main"));
    assert!(branches.contains("feature work"));
    assert!(branches.contains(" ago"), "{branches}");

    let tags = get_text(&client, &s.url("/alice/proj/tags")).await;
    let v1 = tags.find(">v1.0</a>").unwrap_or_else(|| panic!("{tags}"));
    let v0 = tags.find(">v0.1</a>").unwrap();
    assert!(v1 < v0, "newest first: {tags}");
    assert!(tags.contains("First release"));
    assert!(!tags.contains("Notes here"), "only the first line");
    assert!(tags.contains(r#"href="/alice/proj/tree/v1.0""#));

    let home = get_text(&client, &s.url("/alice/proj")).await;
    assert!(home.contains(r#"href="/alice/proj/branches""#), "{home}");
    assert!(home.contains(r#"href="/alice/proj/tags""#), "{home}");
    let empty = s.repo(&alice, "empty", Visibility::Public).await;
    let none = get_text(&client, &s.url(&format!("/alice/{}/branches", empty.name))).await;
    assert!(none.contains("No branches yet."), "{none}");
}
```

Run: `cargo test -p starforged --test web_refs`
Expected: FAIL: `/alice/proj/branches` answers 404.

- [ ] **Step 6: Add the pages and the tabs**

Create `crates/starforged-web/src/pages/refs.rs`:

```rust
//! The branches and tags of a repository (forge-basics design §6).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, RepoHead, content_href, encode_path, format_age, format_time, nav};

pub struct BranchRow {
    name: String,
    tree_href: String,
    is_default: bool,
    summary: String,
    author: String,
    age: String,
    when: String,
    /// Empty for the default branch, or when the default branch does not exist.
    compare_href: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "branches.html")]
pub struct BranchesPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    branches: Vec<BranchRow>,
}

pub struct TagRow {
    name: String,
    tree_href: String,
    commit_id: String,
    short_id: String,
    annotation: String,
    when: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "tags.html")]
pub struct TagsPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    tags: Vec<TagRow>,
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// `/{owner}/{repo}/branches`: the default branch first, then the newest tips.
pub async fn branches(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<BranchesPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let mut list = state.core.branch_list(&access).await?;
    let repo = &access.repo;
    let default = repo.default_branch.as_str();
    if let Some(at) = list.iter().position(|b| b.name == default) {
        let first = list.remove(at);
        list.insert(0, first);
    }
    let has_default = list.first().is_some_and(|b| b.name == default);
    let now = unix_now();
    let branches = list
        .into_iter()
        .map(|b| BranchRow {
            tree_href: content_href(&repo.owner, &repo.name, "tree", &b.name, ""),
            is_default: b.name == default,
            compare_href: if has_default && b.name != default {
                format!(
                    "/{}/{}/compare/{}...{}",
                    repo.owner,
                    repo.name,
                    encode_path(default),
                    encode_path(&b.name)
                )
            } else {
                String::new()
            },
            summary: b.tip.summary,
            author: b.tip.author_name,
            age: format_age(now, b.committed_at),
            when: format_time(b.committed_at),
            name: b.name,
        })
        .collect();
    Ok(BranchesPage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "branches", None),
        branches,
    })
}

/// `/{owner}/{repo}/tags`: the newest first.
pub async fn tags(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<TagsPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let repo = &access.repo;
    let tags = state
        .core
        .tag_list(&access)
        .await?
        .into_iter()
        .map(|t| TagRow {
            tree_href: content_href(&repo.owner, &repo.name, "tree", &t.name, ""),
            short_id: t.commit_id[..t.commit_id.len().min(10)].to_owned(),
            commit_id: t.commit_id,
            annotation: t.annotation.unwrap_or_default(),
            when: format_time(t.date),
            name: t.name,
        })
        .collect();
    Ok(TagsPage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "tags", None),
        tags,
    })
}
```

Create `crates/starforged-web/templates/branches.html`:

```html
{% extends "base.html" %}
{% block title %}Branches · {{ head.owner }}/{{ head.name }}{% endblock %}
{% block content %}
{% include "repo_head.html" %}
{% if branches.is_empty() %}
<p class="muted">No branches yet.</p>
{% else %}
<table class="list"><tbody>
{% for b in branches %}
<tr><td><a href="{{ b.tree_href }}">{{ b.name }}</a>{% if b.is_default %} <span class="badge">default</span>{% endif %}</td>
<td>{{ b.summary }} <span class="muted">{{ b.author }} · <span title="{{ b.when }}">{{ b.age }}</span></span></td>
<td>{% if !b.compare_href.is_empty() %}<a href="{{ b.compare_href }}">Compare</a>{% endif %}</td></tr>
{% endfor %}
</tbody></table>
{% endif %}
{% endblock %}
```

Create `crates/starforged-web/templates/tags.html`:

```html
{% extends "base.html" %}
{% block title %}Tags · {{ head.owner }}/{{ head.name }}{% endblock %}
{% block content %}
{% include "repo_head.html" %}
{% if tags.is_empty() %}
<p class="muted">No tags yet.</p>
{% else %}
<table class="list"><tbody>
{% for t in tags %}
<tr><td><a href="{{ t.tree_href }}">{{ t.name }}</a></td>
<td><a href="/{{ head.owner }}/{{ head.name }}/commit/{{ t.commit_id }}"><code>{{ t.short_id }}</code></a></td>
<td>{{ t.annotation }}</td>
<td class="muted">{{ t.when }}</td></tr>
{% endfor %}
</tbody></table>
{% endif %}
{% endblock %}
```

In `crates/starforged-web/templates/repo_head.html`, add after the Commits tab:

```html
<a href="/{{ head.owner }}/{{ head.name }}/branches"{% if head.tab == "branches" %} aria-current="page"{% endif %}>Branches</a>
<a href="/{{ head.owner }}/{{ head.name }}/tags"{% if head.tab == "tags" %} aria-current="page"{% endif %}>Tags</a>
```

and update the `tab` doc comment on `RepoHead` in `views.rs` to list `code`, `commits`, `branches`, `tags`, or `settings`.

In `crates/starforged-web/src/pages/mod.rs`, add `pub mod refs;` after `pub mod password;`.

In `crates/starforged-web/src/lib.rs`, add after the `/{owner}/{repo}/compare/{*spec}` route:

```rust
        .route("/{owner}/{repo}/branches", get(pages::refs::branches))
        .route("/{owner}/{repo}/tags", get(pages::refs::tags))
```

- [ ] **Step 7: Run the tests**

Run: `cargo test -p starforged --test web_refs --test web_code`
Expected: all pass.

- [ ] **Step 8: Full check, commit**

```bash
scripts/check.sh
git add -A crates
git commit -m "feat: branches and tags pages"
```

Expected: fmt, clippy, and every test green. (No SQL changed in this task.)

---
### Task B9: Syntax highlighting in the file view

**Files:**
- Modify: root `Cargo.toml` (`syntect`, `two-face` in `[workspace.dependencies]`), `crates/starforged-web/Cargo.toml`
- Create: `crates/starforged-web/src/highlight.rs`; Modify: `crates/starforged-web/src/lib.rs` (`pub mod highlight;`, `/static/highlight.css`)
- Modify: `crates/starforged-web/src/pages/code.rs` (`blob` highlights on the blocking pool), `templates/blob.html` (line anchors), `templates/base.html` (stylesheet link), `static/starforge.css` (anchored line)
- Test: Create `crates/starforged/tests/web_highlight.rs`; Modify `crates/starforged/tests/web_code.rs` (the plain `<pre>` assertion)

**Interfaces:**
- Consumes: `BlobPage`, `RepoHead` (B1), `starforged_git::read::{classify, Blob}`.
- Produces:
  - `starforged_web::highlight::{MAX_HIGHLIGHT_BYTES: usize = 512 KiB, MAX_HIGHLIGHT_LINE_CHARS: usize = 5_000, STYLESHEET: LazyLock<String>, highlight_lines(file_name: &str, text: &str) -> Option<Vec<String>>}`: one HTML fragment per line, every span closed on its line; `None` means show the file as plain text.
  - `BlobPage.highlighted: bool`; `blob.html` rows `<tr id="L{n}">` with `<a href="#L{n}">` line numbers.
  - Route `GET /static/highlight.css` (generated once, at startup).

- [ ] **Step 1: Add the dependencies**

In the root `Cargo.toml` `[workspace.dependencies]`, add in alphabetical order:

```toml
syntect = { version = "5.3.0", default-features = false, features = ["default-fancy"] }
two-face = { version = "0.5.2", default-features = false, features = ["syntect-default-fancy"] }
```

In `crates/starforged-web/Cargo.toml` `[dependencies]`, add `syntect.workspace = true` and `two-face.workspace = true`.

- [ ] **Step 2: Write the failing unit tests**

Create `crates/starforged-web/src/highlight.rs` with the tests first:

```rust
//! Syntax highlighting for the file view (forge-basics design §6): syntect with bat's syntaxes and themes
//! (two-face), CSS classes prefixed `hl-`, and one self-contained HTML fragment per line, so line anchors work.

#[cfg(test)]
mod tests {
    use super::*;

    fn balanced(line: &str) -> bool {
        line.matches("<span").count() == line.matches("</span>").count()
    }

    #[test]
    fn source_text_is_escaped_and_every_line_stands_alone() {
        let source = "/* a block\n   comment <b> */\nfn main() {\n    let s = \"<script>alert(1)</script>\";\n}\n";
        let lines = highlight_lines("main.rs", source).unwrap();
        assert_eq!(lines.len(), 5);
        assert!(lines.iter().all(|l| balanced(l)), "{lines:#?}");
        assert!(
            lines[1].contains("hl-comment"),
            "a block comment keeps its classes on its second line: {}",
            lines[1]
        );
        assert!(
            lines[2].contains(r#"<span class="hl-storage hl-type hl-function hl-rust">fn</span>"#),
            "{}",
            lines[2]
        );
        assert!(
            lines[3].contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "{}",
            lines[3]
        );
        assert!(
            lines.iter().all(|l| !l.contains("<script") && !l.contains("<b>")),
            "{lines:#?}"
        );
        assert!(lines.iter().all(|l| !l.contains('\n')));
    }

    #[test]
    fn languages_come_from_the_name_then_the_first_line() {
        let shell = highlight_lines("deploy", "#!/bin/bash\necho hi\n").unwrap();
        assert!(shell[1].contains("hl-shell"), "{}", shell[1]);
        let toml = highlight_lines("Cargo.toml", "[package]\n").unwrap();
        assert!(toml[0].contains("hl-toml"), "{}", toml[0]);
        let plain = highlight_lines("notes", "just words\n").unwrap();
        assert!(plain[0].contains("hl-text hl-plain"), "{}", plain[0]);
        assert_eq!(highlight_lines("empty.rs", "").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn large_files_and_long_lines_are_not_highlighted() {
        assert!(highlight_lines("a.rs", &"x".repeat(MAX_HIGHLIGHT_LINE_CHARS)).is_some());
        assert!(highlight_lines("a.rs", &"x".repeat(MAX_HIGHLIGHT_LINE_CHARS + 1)).is_none());
        let big = "short line\n".repeat(MAX_HIGHLIGHT_BYTES / 11 + 1);
        assert!(big.len() > MAX_HIGHLIGHT_BYTES);
        assert!(highlight_lines("a.txt", &big).is_none());
    }

    #[test]
    fn the_stylesheet_has_light_and_dark_colors() {
        assert!(STYLESHEET.contains(".hl-comment"));
        assert!(STYLESHEET.contains("@media (prefers-color-scheme: dark)"));
    }
}
```

Add `pub mod highlight;` to `crates/starforged-web/src/lib.rs` after `pub mod githttp;`.

Run: `cargo test -p starforged-web highlight`
Expected: compile errors: `highlight_lines`, `STYLESHEET`, and the constants are missing.

- [ ] **Step 3: Implement the highlighter**

Insert above the tests in `crates/starforged-web/src/highlight.rs`:

```rust
use std::sync::LazyLock;

use syntect::html::{ClassStyle, css_for_theme_with_class_style, line_tokens_to_classed_spans};
use syntect::parsing::{ParseState, Scope, ScopeStack, SyntaxReference, SyntaxSet};
use syntect::util::LinesWithEndings;
use two_face::theme::EmbeddedThemeName;

/// Larger files are shown as plain text.
pub const MAX_HIGHLIGHT_BYTES: usize = 512 * 1024;
/// A file with a longer line is shown as plain text.
pub const MAX_HIGHLIGHT_LINE_CHARS: usize = 5_000;

const STYLE: ClassStyle = ClassStyle::SpacedPrefixed { prefix: "hl-" };

static SYNTAXES: LazyLock<SyntaxSet> = LazyLock::new(two_face::syntax::extra_newlines);

/// `/static/highlight.css`: bat's GitHub theme, and OneHalfDark under `prefers-color-scheme: dark`, matching
/// the interface, which follows the system color scheme.
pub static STYLESHEET: LazyLock<String> = LazyLock::new(|| {
    let themes = two_face::theme::extra();
    let light = css_for_theme_with_class_style(themes.get(EmbeddedThemeName::Github), STYLE)
        .expect("the GitHub theme converts to CSS");
    let dark = css_for_theme_with_class_style(themes.get(EmbeddedThemeName::OneHalfDark), STYLE)
        .expect("the OneHalfDark theme converts to CSS");
    format!("{light}\n@media (prefers-color-scheme: dark) {{\n{dark}\n}}\n")
});

/// The syntax for `file_name` (a full name such as `Makefile`, then its extension), then for the first line
/// (a shebang), else plain text.
fn syntax_for(file_name: &str, first_line: &str) -> &'static SyntaxReference {
    let syntaxes: &'static SyntaxSet = &SYNTAXES;
    let extension = file_name
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or_default();
    syntaxes
        .find_syntax_by_extension(file_name)
        .or_else(|| syntaxes.find_syntax_by_extension(extension))
        .or_else(|| syntaxes.find_syntax_by_first_line(first_line))
        .unwrap_or_else(|| syntaxes.find_syntax_plain_text())
}

/// Each line of `text` as HTML whose spans all close on that line: the scopes still open from earlier lines
/// are reopened first and closed at the end. syntect escapes the text. `None` when the file is over
/// [`MAX_HIGHLIGHT_BYTES`], has a line over [`MAX_HIGHLIGHT_LINE_CHARS`] characters, or cannot be parsed;
/// show it as plain text then. Slow for large files: call it on the blocking thread pool.
pub fn highlight_lines(file_name: &str, text: &str) -> Option<Vec<String>> {
    if text.len() > MAX_HIGHLIGHT_BYTES
        || text
            .lines()
            .any(|line| line.chars().count() > MAX_HIGHLIGHT_LINE_CHARS)
    {
        return None;
    }
    let syntaxes: &SyntaxSet = &SYNTAXES;
    let syntax = syntax_for(file_name, text.lines().next().unwrap_or_default());
    let mut state = ParseState::new(syntax);
    let mut stack = ScopeStack::new();
    let mut lines = Vec::new();
    for line in LinesWithEndings::from(text) {
        let ops = state.parse_line(line, syntaxes).ok()?;
        let mut html = String::new();
        for scope in stack.as_slice() {
            open_span(&mut html, *scope);
        }
        let (body, _) = line_tokens_to_classed_spans(line, &ops, STYLE, &mut stack).ok()?;
        html.push_str(&body.replace(['\n', '\r'], ""));
        for _ in 0..stack.len() {
            html.push_str("</span>");
        }
        lines.push(html);
    }
    Some(lines)
}

/// `<span class="hl-a hl-b">` for scope `a.b`, as syntect writes it.
fn open_span(html: &mut String, scope: Scope) {
    html.push_str("<span class=\"");
    for (i, atom) in scope.build_string().split('.').enumerate() {
        if i > 0 {
            html.push(' ');
        }
        html.push_str("hl-");
        html.push_str(atom);
    }
    html.push_str("\">");
}
```

Run: `cargo test -p starforged-web highlight`
Expected: PASS.

- [ ] **Step 4: Write the failing integration test**

Create `crates/starforged/tests/web_highlight.rs`:

```rust
mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_are_highlighted_with_line_anchors_and_escaped() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let long = format!("{}\n", "x".repeat(5_001));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[
            (
                "src/main.rs",
                "fn main() {\n    let s = \"<script>alert(1)</script>\";\n}\n",
            ),
            ("long.rs", long.as_str()),
        ],
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let client = s.browser();

    let page = get_text(&client, &s.url("/alice/proj/blob/main/src/main.rs")).await;
    assert!(
        page.contains(r##"<tr id="L1"><td class="ln"><a href="#L1">1</a></td>"##),
        "{page}"
    );
    assert!(
        page.contains(r#"<span class="hl-storage hl-type hl-function hl-rust">fn</span>"#),
        "{page}"
    );
    assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{page}");
    assert!(!page.contains("<script>alert"), "{page}");

    let plain = get_text(&client, &s.url("/alice/proj/blob/main/long.rs")).await;
    assert!(
        !plain.contains("hl-source"),
        "a line over 5,000 characters turns highlighting off"
    );
    assert!(plain.contains(&"x".repeat(5_001)));

    let css = client.get(s.url("/static/highlight.css")).send().await.unwrap();
    assert_eq!(css.headers()["content-type"], "text/css; charset=utf-8");
    assert!(css.text().await.unwrap().contains(".hl-comment"));
}
```

In `crates/starforged/tests/web_code.rs`, `browsing_trees_files_raw_and_readme`, replace `assert!(file.contains("<pre>fn main() {}</pre>"), "{file}");` with:

```rust
    assert!(
        file.contains(r#"<span class="hl-storage hl-type hl-function hl-rust">fn</span>"#),
        "{file}"
    );
```

Run: `cargo test -p starforged --test web_highlight`
Expected: FAIL: the page has no line anchors or `hl-` classes, and `/static/highlight.css` answers 404.

- [ ] **Step 5: Highlight in the file view**

In `crates/starforged-web/src/pages/code.rs`:
1. Import the module: `use crate::highlight;`.
2. Add `highlighted: bool,` to `BlobPage` after `lines`.
3. In `blob`, compute `dir` and `file_name` before the content, and render the lines on the blocking pool. Replace everything from `let size = …;` to the end of the function with:

```rust
    let size = usize::try_from(file.size).unwrap_or(usize::MAX);
    let (dir, file_name) = resolved
        .path
        .rsplit_once('/')
        .unwrap_or(("", resolved.path.as_str()));
    let (lines, highlighted, notice) = match file.bytes {
        None => (Vec::new(), false, Some("This file is too large to display.")),
        Some(bytes) => match classify(bytes) {
            Blob::Text(text) => {
                let (lines, highlighted) = render_lines(file_name.to_owned(), text).await?;
                (lines, highlighted, None)
            }
            Blob::Binary => (Vec::new(), false, Some("Binary file not shown.")),
        },
    };
    let repo = &access.repo;
    Ok(BlobPage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "code", Some(&resolved.ref_name)),
        ref_name: resolved.ref_name.clone(),
        crumbs: crumbs(&repo.owner, &repo.name, &resolved.ref_name, dir),
        file_name: file_name.to_owned(),
        raw_href: content_href(
            &repo.owner,
            &repo.name,
            "raw",
            &resolved.ref_name,
            &resolved.path,
        ),
        path: resolved.path.clone(),
        size,
        lines,
        highlighted,
        notice,
    })
}

/// The file's lines as highlighted HTML (`true`), or as plain text when highlighting does not apply
/// (`false`). Runs on the blocking pool: highlighting a large file takes a while.
async fn render_lines(file_name: String, text: String) -> Result<(Vec<String>, bool), WebError> {
    tokio::task::spawn_blocking(move || match highlight::highlight_lines(&file_name, &text) {
        Some(lines) => (lines, true),
        None => (text.lines().map(str::to_owned).collect(), false),
    })
    .await
    .map_err(|e| WebError::Internal(e.to_string()))
}
```

In `crates/starforged-web/templates/blob.html`, replace the table with:

```html
<table class="code"><tbody>
{% for line in lines %}<tr id="L{{ loop.index }}"><td class="ln"><a href="#L{{ loop.index }}">{{ loop.index }}</a></td><td><pre>{% if highlighted %}{{ line|safe }}{% else %}{{ line }}{% endif %}</pre></td></tr>
{% endfor %}
</tbody></table>
```

(`|safe` is allowed here because every highlighted line comes from `highlight::highlight_lines`, where syntect escapes the source text; plain lines stay auto-escaped.)

In `crates/starforged-web/templates/base.html`, add after the `starforge.css` link:

```html
<link rel="stylesheet" href="/static/highlight.css">
```

In `crates/starforged-web/static/starforge.css`:
1. Add `--target: #fff8c5;` to the light `:root` variables and `--target: #3d3200;` to the dark ones.
2. Append:

```css
table.code tr:target { background: var(--target); }
td.ln a { color: inherit; }
```

In `crates/starforged-web/src/lib.rs`:
1. Add the route after `/static/starforge.css`: `.route("/static/highlight.css", get(highlight_stylesheet))`.
2. Add the handler after `stylesheet`:

```rust
async fn highlight_stylesheet() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        highlight::STYLESHEET.as_str(),
    )
}
```

3. In `router`, generate the stylesheet at startup, before building the state:

```rust
    std::sync::LazyLock::force(&highlight::STYLESHEET);
```

- [ ] **Step 6: Run the tests**

Run: `cargo test -p starforged --test web_highlight --test web_code`
Expected: all pass.

- [ ] **Step 7: Full check, commit**

```bash
scripts/check.sh
git add -A Cargo.toml Cargo.lock crates
git commit -m "feat: syntax highlighting with line anchors in the file view"
```

Expected: fmt, clippy, and every test green. (No SQL changed in this task.)

---
### Task B10: `git maintenance` after pushes, and the README

**Files:**
- Create: `crates/starforged-git/src/maintenance.rs`; Modify: `crates/starforged-git/src/lib.rs`
- Modify: `crates/starforged-core/src/jobs.rs` (`Job::GitMaintenance`, per-repository deduplication, tests)
- Modify: `crates/starforged-web/src/githttp.rs` (queue maintenance after a successful receive-pack)
- Modify: `crates/starforged/Cargo.toml` (`sqlx` dev-dependency)
- Test: Create `crates/starforged/tests/maintenance.rs`
- Modify: `README.md`

**Interfaces:**
- Consumes: `Core::{enqueue, run_due_jobs, repo_path, create_repo, delete_repo}`, `starforged_db::repos::by_id` (B5 `deleted_at`), the receive-pack reaper task in `githttp::rpc`.
- Produces:
  - `starforged_git::maintenance::run_auto(repo: &Path) -> Result<(), GitError>` (`git maintenance run --auto`).
  - `Job::GitMaintenance { repo_id: i64 }` (kind `git_maintenance`, deduplication key `git_maintenance:<repo_id>`); it does nothing for a repository that is missing or deleted. `Job::dedupe_key(&self) -> Option<String>` (private) replaces `recurrence().map(|_| kind)` in `enqueue_at`.
  - After every receive-pack that exits successfully, the web layer queues `Job::GitMaintenance` for the repository.

- [ ] **Step 1: Write the failing tests**

Create `crates/starforged-git/src/maintenance.rs`:

```rust
//! Housekeeping for hosted repositories.

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[tokio::test]
    async fn runs_on_bare_repositories_and_fails_elsewhere() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("r.git");
        crate::init::init_bare(&repo, "main", Path::new("/bin/false"))
            .await
            .unwrap();
        super::run_auto(&repo).await.unwrap();
        assert!(super::run_auto(&tmp.path().join("missing.git")).await.is_err());
    }
}
```

and add `pub mod maintenance;` to `crates/starforged-git/src/lib.rs` after `pub mod init;`.

Add to the tests in `crates/starforged-core/src/jobs.rs` (with `use crate::permission::Visibility;` and `use crate::repos::CreateRepo;`):

```rust
    #[test]
    fn maintenance_payloads_carry_the_repository() {
        let json = serde_json::to_string(&Job::GitMaintenance { repo_id: 7 }).unwrap();
        assert_eq!(json, r#"{"kind":"git_maintenance","repo_id":7}"#);
    }

    #[tokio::test]
    async fn maintenance_runs_once_per_repository_and_skips_deleted_ones() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let repo = |name: &str| CreateRepo {
            name: name.into(),
            description: String::new(),
            visibility: Visibility::Public,
            readme: true,
        };
        let a = core.create_repo(&alice, repo("a")).await.unwrap();
        let b = core.create_repo(&alice, repo("b")).await.unwrap();
        for repo_id in [a.id, a.id, b.id] {
            core.enqueue(&Job::GitMaintenance { repo_id }).await.unwrap();
        }
        let pending: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE kind = 'git_maintenance'")
                .fetch_one(core.db().pool())
                .await
                .unwrap();
        assert_eq!(pending, 2, "one pending run per repository");
        core.delete_repo(&alice, "alice", "b", "alice/b").await.unwrap();
        assert_eq!(core.run_due_jobs().await.unwrap(), 2);
        let states: Vec<String> = sqlx::query_scalar(
            "SELECT state FROM jobs WHERE kind = 'git_maintenance' ORDER BY id",
        )
        .fetch_all(core.db().pool())
        .await
        .unwrap();
        assert_eq!(states, vec!["done", "done"]);
    }
```

Run: `cargo test -p starforged-git maintenance && cargo test -p starforged-core jobs::tests`
Expected: compile errors: no `run_auto`, no `Job::GitMaintenance`.

- [ ] **Step 2: Implement the job**

In `crates/starforged-git/src/maintenance.rs`, insert above the tests:

```rust
use std::ffi::OsStr;
use std::path::Path;

use crate::command::{GitError, run};

/// `git maintenance run --auto`: packs loose objects and refs when git's thresholds say it is worth it.
pub async fn run_auto(repo: &Path) -> Result<(), GitError> {
    run([
        OsStr::new("--git-dir"),
        repo.as_os_str(),
        OsStr::new("maintenance"),
        OsStr::new("run"),
        OsStr::new("--auto"),
    ])
    .await?;
    Ok(())
}
```

In `crates/starforged-core/src/jobs.rs`:
1. Add the variant after `SendEmail`:

```rust
    /// `git maintenance run --auto` for one repository, after a push to it (forge-basics design §8.4).
    GitMaintenance { repo_id: i64 },
```

2. `kind`: `Job::GitMaintenance { .. } => "git_maintenance",`; `recurrence`: `Job::GitMaintenance { .. } => None,`.
3. Add after `recurrence`:

```rust
    /// At most one job per key is pending: recurring jobs use their kind, maintenance one key per repository.
    fn dedupe_key(&self) -> Option<String> {
        match self {
            Job::GitMaintenance { repo_id } => Some(format!("git_maintenance:{repo_id}")),
            _ => self.recurrence().map(|_| self.kind().to_owned()),
        }
    }
```

4. In `enqueue_at`, replace `let dedupe_key = job.recurrence().map(|_| job.kind());` with `let dedupe_key = job.dedupe_key();` and pass `dedupe_key: dedupe_key.as_deref(),` in the `NewJob` literal.
5. `execute`: `Job::GitMaintenance { repo_id } => self.maintain_repo(*repo_id).await,`.
6. Add to the `impl Core` block after `blank_email`:

```rust
    /// `git maintenance` for a repository that still exists; it may have been deleted since the push.
    async fn maintain_repo(&self, repo_id: i64) -> CoreResult<()> {
        let live = starforged_db::repos::by_id(self.db(), repo_id)
            .await?
            .is_some_and(|row| row.deleted_at.is_none());
        if live {
            starforged_git::maintenance::run_auto(&self.repo_path(repo_id)).await?;
        }
        Ok(())
    }
```

Run: `cargo test -p starforged-git maintenance && cargo test -p starforged-core jobs::tests`
Expected: PASS.

- [ ] **Step 3: Write the failing integration test**

In `crates/starforged/Cargo.toml` `[dev-dependencies]`, add `sqlx.workspace = true`.

Create `crates/starforged/tests/maintenance.rs`:

```rust
mod common;

use std::time::Duration;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pushes_queue_git_maintenance() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "a\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;

    // The push response ends before the server reaps git, so the job appears shortly after.
    let key = format!("git_maintenance:{}", repo.id);
    let mut queued = 0_i64;
    for _ in 0..100 {
        queued = sqlx::query_scalar(
            "SELECT COUNT(*) FROM jobs WHERE dedupe_key = $1 AND state = 'queued'",
        )
        .bind(key.as_str())
        .fetch_one(s.core.db().pool())
        .await
        .unwrap();
        if queued == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(queued, 1, "the push queued maintenance");
    s.core.run_due_jobs().await.unwrap();
    let state: String = sqlx::query_scalar("SELECT state FROM jobs WHERE dedupe_key = $1")
        .bind(key.as_str())
        .fetch_one(s.core.db().pool())
        .await
        .unwrap();
    assert_eq!(state, "done");
}
```

Run: `cargo test -p starforged --test maintenance`
Expected: FAIL: "the push queued maintenance" (0 queued).

- [ ] **Step 4: Queue maintenance after successful pushes**

In `crates/starforged-web/src/githttp.rs`, import `use starforged_core::jobs::Job;` and replace the reaper task in `rpc` (from `let mut stderr = process.stderr;` through the end of its `tokio::spawn`) with:

```rust
    let mut stderr = process.stderr;
    let mut child = process.child;
    // A successful push queues `git maintenance` for the repository (one pending run per repository).
    let maintenance = (service == Service::ReceivePack).then(|| (state.core.clone(), access.repo.id));
    tokio::spawn(async move {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text).await;
        let status = child.wait().await;
        let failed = !matches!(&status, Ok(s) if s.success());
        if failed || !text.trim().is_empty() {
            tracing::warn!(stderr = %text.trim(), ?status, "git rpc finished");
        }
        if !failed
            && let Some((core, repo_id)) = maintenance
            && let Err(err) = core.enqueue(&Job::GitMaintenance { repo_id }).await
        {
            tracing::warn!(error = %err, repo_id, "queueing git maintenance failed");
        }
    });
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p starforged --test maintenance --test smart_http`
Expected: all pass.

- [ ] **Step 6: Document Plan B in `README.md`**

1. In "Accounts and email", replace the last sentence ("Signed-in users manage their display name, …") with:

```markdown
Signed-in users manage their display name, email address, password, sessions, and tokens under **Settings**, and
can delete their account there once they own no repositories.
```

2. Add this section after "Accounts and email":

```markdown
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
```

3. In "API", replace the first sentence with:

```markdown
`/api/v1` accepts `Authorization: Bearer <token>`: `GET /user`, `POST /user/repos` (with `"readme": true` for a
first commit), `GET /repos/{owner}/{repo}` (including `archived`), and
`GET`/`PUT`/`DELETE /repos/{owner}/{repo}/collaborators[/{handle}]`. Reads of a renamed repository answer `301`
with the new location.
```

- [ ] **Step 7: Full check on both databases, commit**

```bash
STARFORGE_TEST_PG=1 scripts/check.sh
git add -A crates README.md Cargo.lock
git commit -m "feat: run git maintenance after pushes; document repositories and code views"
```

Expected: fmt, clippy, and every test green on SQLite and Postgres.

---

## Spec coverage (Plan B)

| Forge-basics design | Task |
|---|---|
| §4.6 Repositories (deleted repositories, Restore) | B5 |
| §4.6 Delete account (typed handle; refused with repositories or as the only admin; purges deleted repositories; audit survives) | B6 |
| §4.7 audit of account deletion | B6 |
| §5.1 initial README (form and API; plumbing; identity) | B2 |
| §5.2 settings page, collaborators in its navigation, maintain/admin permissions, default branch moves `HEAD` | B1 (description, default branch, visibility), B3–B5 (admin actions) |
| §5.3 rename, redirects for pages, git `info/refs`, API reads; read access required; new names take over; one hop | B3 (deleted targets: B5) |
| §5.4 archive: receive-pack 403 with the message git shows; banner; settings editable; API `archived` | B4 |
| §5.5 delete with typed `owner/name`, 404 everywhere, name reserved, 7-day restore, daily purge via `data/tmp` | B5 |
| §5.6 audit of repository events | B1, B3, B4, B5 |
| §6 navigation Code · Commits · Branches · Tags · Settings | B1, B8 |
| §6 branches (default first, newest, summary/author/age, Compare) and tags (newest, short id, annotation) | B8 |
| §6 compare (picker, `{base}...{head}`, 250 commits and "and N more", merge-base diff with the commit limits, refs resolved first, 404 for unknown refs) | B7 |
| §6 highlighting (name then shebang, per-line HTML, `#L<n>`, escaping, 512 KiB / 5,000 characters, blocking pool, `/static/highlight.css` with `hl-`) | B9 |
| §8.4 daily purge; `git maintenance run --auto` after each push | B5, B10 |
| §10 repository routes, account settings routes for repositories and deletion, API changes, `/static/highlight.css` | B1–B9 |
| §11 `repos.archived_at`, `repos.deleted_at`, `repo_redirects` | B4, B5, B3 |
| §12 no existence leaks (deleted repositories, redirects), escaping of highlighted source, CSRF on every form | B3, B5, B9, all |
| §13 tests: settings permissions, rename redirects and `git clone` of an old URL, private targets, archived pushes, delete/restore/purge, highlighting and anchors | B1–B10 |
| Deferred item from Plan A: `SecurityConfig`'s `Debug` output hides the secret key | B1 |
| §7 site administration | Plan C |
