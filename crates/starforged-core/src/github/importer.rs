//! The GitHub metadata importer (M4c G2, spec §8.6, plan D1–D5).
//!
//! [`Core::start_github_import`] records a sealed token and queues the
//! [`crate::jobs::Job::ImportGithub`] job; the job
//! ([`Core::run_github_import`]) walks GitHub in ascending number order
//! (D5: issues, skipping PRs in that listing, then pulls, each with its
//! issue comments, reviews, and review comments) and writes through the db
//! fns directly, never through the public API:
//!
//! - an issue becomes a Trail without changes; a pull request becomes a
//!   Trail with one `imported` change (k = 1, head fetched from
//!   `refs/pull/<n>/head` into the trail refs, revision 1 holding the head
//!   SHA, the PR base SHA, and the merge base) (D3);
//! - numbers are the GitHub numbers; `trail_sequences` is advanced past the
//!   highest imported number by the insert itself (D2);
//! - authors match a local user by verified email, else become
//!   placeholders carrying the GitHub login (D1); labels are created by
//!   name, assignees only map to matched repo members (others are dropped
//!   and listed in the import summary);
//! - review comments whose path and line exist in revision 1's diff become
//!   review threads (replies thread under their parent); the rest become
//!   quoted Trail comments (D4); reviews map to verdicts (`PENDING` is
//!   skipped);
//! - one `trail.imported` timeline row per Trail, and no webhook is
//!   dispatched for any imported object.
//!
//! Resumption (plan Global Constraints): every object import is keyed by
//! its unique `github_id` column, so re-running a page never duplicates a
//! row. The cursor (`cursor_kind`/`cursor_page`/`cursor_number`) is saved
//! before each page fetch and after each object; a rate limit saves it,
//! marks the import `rate_limited`, and re-enqueues the job at the reset
//! time (capped at 1 h). Other errors count toward the 5-failure cap
//! (`github_imports.failures` mirrors the job retry ladder); at the cap the
//! import is `failed`, the scrubbed error is stored, and the sealed token
//! is deleted — as it is on completion.

use std::collections::HashSet;

use starforged_db::changes as db_changes;
use starforged_db::github_imports as db_imports;
use starforged_db::now;
use starforged_db::trails as db_trails;
use starforged_db::users as db_users;
use starforged_git::diff as git_diff;
use starforged_git::read as git_read;
use starforged_git::remote::{self, RemoteCreds};
use starforged_git::write as git_write;

use super::{GhIssue, GhLabel, GhPull, GhUser, GithubClient, GithubError};
use crate::permission::Permission;
use crate::{Core, CoreError, CoreResult};

/// How long one pull-head fetch may take (mirrors the M4b import bound).
const PULL_HEAD_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// A rate-limited re-enqueue is never further than this out (plan).
const RATE_LIMIT_CAP_SECS: i64 = 3_600;
/// Failures after which the import is `failed` and the token is deleted.
const MAX_FAILURES: i64 = 5;

/// How a run ended: a rate limit (control flow, not a failure) or a fatal
/// error that follows the failure cap.
enum Fail {
    RateLimited { reset_at: i64 },
    Fatal(String),
}

impl From<GithubError> for Fail {
    fn from(e: GithubError) -> Fail {
        match e {
            GithubError::RateLimited { reset_at } => Fail::RateLimited { reset_at },
            other => Fail::Fatal(other.to_string()),
        }
    }
}

/// The resumption cursor, kept in hand alongside the `github_imports` row
/// so a rate limit at any depth can persist exactly where the run stopped.
#[derive(Debug, Clone)]
struct Cursor {
    kind: String,
    page: i64,
    number: Option<i64>,
    dropped: Vec<String>,
}

/// The per-import context every pagination helper shares: the repository,
/// the import record, the GitHub coordinates, the client, and (once
/// resolved) the pull-head remote. Passed by reference so the call chains
/// stay short.
struct ImportCtx<'a> {
    repo_id: i64,
    row: &'a db_imports::GithubImportRow,
    gh_owner: &'a str,
    gh_repo: &'a str,
    client: &'a GithubClient,
    pinned: Option<&'a starforged_git::remote::PinnedRemote>,
    creds: Option<&'a RemoteCreds>,
}

/// One GitHub issue or pull request as `import_trail` sees it (its API
/// objects share the needed fields differently, so the caller bundles them).
struct TrailSubject<'a> {
    number: i64,
    title: &'a str,
    intent: &'a str,
    state: &'a str,
    is_pull: bool,
    user: &'a Option<GhUser>,
    github_id: i64,
    labels: &'a [GhLabel],
    assignees: &'a [GhUser],
}

impl Core {
    /// Starts a GitHub metadata import on `owner/repo` from the GitHub
    /// repository `slug` (`"octo/proj"`).
    ///
    /// Repository admin only (`Forbidden` below that, `NotFound` when the
    /// repository cannot be read); refused with `Invalid` (422) when the
    /// repository is archived or already has Trails — numbers must be
    /// preserved, so an import only ever runs on an empty repository. The
    /// token is sealed with the credential box and deleted when the import
    /// finishes or fails; it is never logged or rendered.
    pub async fn start_github_import(
        &self,
        user: &crate::accounts::User,
        owner: &str,
        repo: &str,
        slug: &str,
        token: &str,
    ) -> CoreResult<db_imports::GithubImportRow> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid(
                "archived repositories cannot import".into(),
            ));
        }
        let (gh_owner, gh_repo) = slug
            .split_once('/')
            .map(|(o, r)| (o.trim(), r.trim()))
            .filter(|(o, r)| !o.is_empty() && !r.is_empty() && !r.contains('/'))
            .ok_or_else(|| CoreError::Invalid("github repository must be 'owner/repo'".into()))?;
        let token = token.trim();
        if token.is_empty() {
            return Err(CoreError::Invalid("a github token is required".into()));
        }
        let filter = db_trails::TrailFilter {
            limit: 1,
            ..Default::default()
        };
        if !db_trails::trails_of_repo(self.db(), access.repo.id, &filter)
            .await?
            .is_empty()
        {
            return Err(CoreError::Invalid(
                "repository already has trails; github import requires an empty repository".into(),
            ));
        }
        let row =
            db_imports::get_or_create(self.db(), access.repo.id, &format!("{gh_owner}/{gh_repo}"))
                .await?;
        let sealed = self.config().credential_box.seal(token.as_bytes());
        db_imports::set_token_sealed(self.db(), row.id, Some(&sealed)).await?;
        db_imports::set_state(self.db(), row.id, "pending").await?;
        db_imports::set_error(self.db(), row.id, None, 0).await?;
        if row.started_at.is_none() {
            db_imports::set_started(self.db(), row.id, now()).await?;
        }
        self.audit(
            Some(user.id),
            "repo.github_import_started",
            &format!("repo:{owner}/{repo}"),
            slug,
        )
        .await?;
        self.enqueue(&crate::jobs::Job::ImportGithub {
            repo_id: access.repo.id,
        })
        .await?;
        db_imports::import_of_repo(self.db(), access.repo.id)
            .await?
            .ok_or_else(|| CoreError::Internal("github import vanished".into()))
    }

    /// Runs (or resumes) the import of one repository. Returns `Ok` when the
    /// import completes, rate-limit re-enqueues itself, or fails after the
    /// 5-failure cap; a fatal error below the cap returns `Err` so the job
    /// retry ladder re-enqueues it (the cursor makes the retry a resume).
    pub async fn run_github_import(&self, repo_id: i64) -> CoreResult<()> {
        let Some(row) = db_imports::import_of_repo(self.db(), repo_id).await? else {
            return Ok(());
        };
        if row.state == "completed" || row.state == "failed" {
            return Ok(());
        }
        let Some(sealed) = row.token_sealed.clone() else {
            return Ok(());
        };
        let token = self
            .config()
            .credential_box
            .open(&sealed)
            .map_err(|_| CoreError::Internal("github token unreadable".into()))?;
        let token = String::from_utf8(token)
            .map_err(|_| CoreError::Internal("github token unreadable".into()))?;
        let (gh_owner, gh_repo) = row
            .source
            .split_once('/')
            .map(|(o, r)| (o.to_owned(), r.to_owned()))
            .ok_or_else(|| CoreError::Internal("github import source is malformed".into()))?;
        db_imports::set_state(self.db(), row.id, "running").await?;
        let allow_loopback = self.config().allow_file_urls || self.config().allow_loopback_webhooks;
        let client = match GithubClient::new(&self.config().github_api_url, &token, allow_loopback)
        {
            Ok(client) => client,
            Err(e) => {
                return self.fail_import(repo_id, &row, e.to_string()).await;
            }
        };
        let mut cursor = Cursor {
            kind: row.cursor_kind.clone(),
            page: row.cursor_page.max(1),
            number: row.cursor_number,
            dropped: row
                .dropped_assignees
                .split(';')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
        };
        let startup_ctx = ImportCtx {
            repo_id,
            row: &row,
            gh_owner: &gh_owner,
            gh_repo: &gh_repo,
            client: &client,
            pinned: None,
            creds: None,
        };
        let outcome = self.import_all(&startup_ctx, &token, &mut cursor).await;
        match outcome {
            Ok(()) => {
                db_imports::set_state(self.db(), row.id, "completed").await?;
                db_imports::set_finished(self.db(), row.id, now()).await?;
                db_imports::clear_token(self.db(), row.id).await?;
                let done = db_imports::import_of_repo(self.db(), repo_id)
                    .await?
                    .ok_or_else(|| CoreError::Internal("github import vanished".into()))?;
                self.audit(
                    None,
                    "repo.github_import_finished",
                    &format!("repo:{}", done.source),
                    &counts_detail(&done),
                )
                .await?;
                Ok(())
            }
            Err(Fail::RateLimited { reset_at }) => {
                db_imports::set_state(self.db(), row.id, "rate_limited").await?;
                self.save_cursor(&row, &cursor).await?;
                let run_at = reset_at.clamp(now(), now() + RATE_LIMIT_CAP_SECS);
                self.enqueue_at(&crate::jobs::Job::ImportGithub { repo_id }, run_at)
                    .await?;
                Ok(())
            }
            Err(Fail::Fatal(message)) => self.fail_import(repo_id, &row, message).await,
        }
    }

    /// Records one fatal failure: increments the failure count, and at the
    /// cap marks the import `failed`, stores the scrubbed error, and deletes
    /// the sealed token. Below the cap the error propagates so the job
    /// retry ladder re-enqueues the run.
    async fn fail_import(
        &self,
        repo_id: i64,
        row: &db_imports::GithubImportRow,
        message: String,
    ) -> CoreResult<()> {
        let failures = row.failures + 1;
        db_imports::set_error(self.db(), row.id, Some(&message), failures).await?;
        if failures >= MAX_FAILURES {
            db_imports::set_state(self.db(), row.id, "failed").await?;
            db_imports::set_finished(self.db(), row.id, now()).await?;
            db_imports::clear_token(self.db(), row.id).await?;
            self.audit(
                None,
                "repo.github_import_finished",
                &format!("repo:{}", row.source),
                &format!("state=failed error={message}"),
            )
            .await?;
            Ok(())
        } else {
            let _ = repo_id;
            Err(CoreError::Internal(message))
        }
    }

    async fn save_cursor(
        &self,
        row: &db_imports::GithubImportRow,
        cursor: &Cursor,
    ) -> CoreResult<()> {
        db_imports::set_cursor(self.db(), row.id, &cursor.kind, cursor.page, cursor.number).await?;
        db_imports::set_dropped_assignees(self.db(), row.id, &cursor.dropped.join(";")).await?;
        Ok(())
    }

    /// The whole run: repository metadata (clone_url), issues, then pulls.
    /// `import_ctx` carries the repository, import record, GitHub
    /// coordinates, and client (without the pull-head remote yet); this
    /// resolves the remote and rebuilds the context with it.
    async fn import_all(
        &self,
        import_ctx: &ImportCtx<'_>,
        token: &str,
        cursor: &mut Cursor,
    ) -> Result<(), Fail> {
        let repository = import_ctx
            .client
            .get_repository(import_ctx.gh_owner, import_ctx.gh_repo)
            .await?;
        let pinned = self
            .check_remote_url(&repository.clone_url)
            .map_err(|e| Fail::Fatal(e.to_string()))?;
        let creds = match pinned.scheme {
            starforged_git::remote::RemoteScheme::Https => RemoteCreds::Basic {
                username: "x-access-token".to_owned(),
                password: token.to_owned(),
            },
            _ => RemoteCreds::None,
        };
        let ctx = ImportCtx {
            repo_id: import_ctx.repo_id,
            row: import_ctx.row,
            gh_owner: import_ctx.gh_owner,
            gh_repo: import_ctx.gh_repo,
            client: import_ctx.client,
            pinned: Some(&pinned),
            creds: Some(&creds),
        };
        let start_issues = cursor.kind.is_empty() || cursor.kind == "issues";
        if start_issues {
            self.import_issues(&ctx, cursor).await?;
            cursor.kind = "pulls".to_owned();
            cursor.page = 1;
            cursor.number = None;
        }
        self.import_pulls(&ctx, cursor).await?;
        Ok(())
    }

    async fn import_issues(&self, ctx: &ImportCtx<'_>, cursor: &mut Cursor) -> Result<(), Fail> {
        cursor.kind = "issues".to_owned();
        let mut page = cursor.page.max(1);
        loop {
            cursor.page = page;
            self.save_cursor(ctx.row, cursor)
                .await
                .map_err(|e| Fail::Fatal(e.to_string()))?;
            let page_res = ctx
                .client
                .list_issues(ctx.gh_owner, ctx.gh_repo, page as u32)
                .await?;
            for issue in &page_res.items {
                if issue.pull_request.is_some() {
                    continue;
                }
                self.import_issue(ctx, issue, cursor).await?;
                cursor.number = Some(issue.number);
            }
            if page_res.next.is_none() {
                break;
            }
            page += 1;
        }
        Ok(())
    }

    async fn import_issue(
        &self,
        ctx: &ImportCtx<'_>,
        issue: &GhIssue,
        cursor: &mut Cursor,
    ) -> Result<(), Fail> {
        let trail = self
            .import_trail(
                ctx,
                &TrailSubject {
                    number: issue.number,
                    title: &issue.title,
                    intent: issue.body.as_deref().unwrap_or(""),
                    state: trail_state(issue.state.as_str(), false),
                    is_pull: false,
                    user: &issue.user,
                    github_id: issue.id,
                    labels: &issue.labels,
                    assignees: &issue.assignees,
                },
                cursor,
            )
            .await?;
        self.import_issue_comments(ctx, issue.number, trail.id, cursor)
            .await?;
        Ok(())
    }

    async fn import_pulls(&self, ctx: &ImportCtx<'_>, cursor: &mut Cursor) -> Result<(), Fail> {
        cursor.kind = "pulls".to_owned();
        let mut page = cursor.page.max(1);
        loop {
            cursor.page = page;
            self.save_cursor(ctx.row, cursor)
                .await
                .map_err(|e| Fail::Fatal(e.to_string()))?;
            let page_res = ctx
                .client
                .list_pulls(ctx.gh_owner, ctx.gh_repo, page as u32)
                .await?;
            for pull in &page_res.items {
                self.import_pull(ctx, pull, cursor).await?;
                cursor.number = Some(pull.number);
            }
            if page_res.next.is_none() {
                break;
            }
            page += 1;
        }
        Ok(())
    }

    async fn import_pull(
        &self,
        ctx: &ImportCtx<'_>,
        pull: &GhPull,
        cursor: &mut Cursor,
    ) -> Result<(), Fail> {
        let merged = pull.merged_at.is_some();
        let trail = self
            .import_trail(
                ctx,
                &TrailSubject {
                    number: pull.number,
                    title: &pull.title,
                    intent: pull.body.as_deref().unwrap_or(""),
                    state: trail_state(pull.state.as_str(), merged),
                    is_pull: true,
                    user: &pull.user,
                    github_id: pull.id,
                    labels: &pull.labels,
                    assignees: &pull.assignees,
                },
                cursor,
            )
            .await?;
        // The imported change (k = 1), if not already there from a prior run.
        let change = match db_changes::change_by_trail_number(self.db(), trail.id, 1).await {
            Ok(Some(change)) => change,
            Ok(None) => {
                let (author_id, _) = self.resolve_author(&pull.user).await;
                db_changes::insert_imported_change(
                    self.db(),
                    trail.id,
                    Some(&pull.head.name),
                    &pull.base.name,
                    author_id,
                    now(),
                )
                .await
                .map_err(|e| Fail::Fatal(e.to_string()))?
            }
            Err(e) => return Err(Fail::Fatal(e.to_string())),
        };
        let revision = match db_changes::revision_by_number(self.db(), change.id, 1).await {
            Ok(Some(revision)) => Some(revision),
            Ok(None) => {
                self.import_revision(ctx, pull, trail.number, change.id, &trail, cursor)
                    .await?
            }
            Err(e) => return Err(Fail::Fatal(e.to_string())),
        };
        // The change state follows the pull state (D3), also on resume —
        // but an unfetchable head already closed it in
        // `note_unfetchable_head`, and that stands.
        if revision.is_some() && merged {
            match &pull.merge_commit_sha {
                Some(sha) => {
                    db_changes::set_merged(self.db(), change.id, "merge", sha, now())
                        .await
                        .map_err(|e| Fail::Fatal(e.to_string()))?;
                }
                None => {
                    db_changes::set_change_state(self.db(), change.id, "merged", now())
                        .await
                        .map_err(|e| Fail::Fatal(e.to_string()))?;
                }
            }
        } else if revision.is_some() && pull.state == "closed" {
            db_changes::set_change_state(self.db(), change.id, "closed", now())
                .await
                .map_err(|e| Fail::Fatal(e.to_string()))?;
        }
        self.import_issue_comments(ctx, pull.number, trail.id, cursor)
            .await?;
        if let Some(revision) = revision {
            self.import_reviews(ctx, pull.number, change.id, revision.id, cursor)
                .await?;
            self.import_review_comments(ctx, pull.number, change.id, revision.id, &trail, cursor)
                .await?;
        }
        Ok(())
    }

    /// Fetches the pull head and records revision 1. An unfetchable head
    /// (D3) closes the change with a note comment and yields no revision;
    /// the import itself does not fail.
    async fn import_revision(
        &self,
        ctx: &ImportCtx<'_>,
        pull: &GhPull,
        trail_number: i64,
        change_id: i64,
        trail: &db_trails::TrailRow,
        cursor: &mut Cursor,
    ) -> Result<Option<db_changes::RevisionRow>, Fail> {
        let repo_dir = self.repo_path(ctx.repo_id);
        let head_ref = format!("refs/pull/{}/head", pull.number);
        let pinned = ctx
            .pinned
            .ok_or_else(|| Fail::Fatal("import context has no pull-head remote".into()))?;
        let creds = ctx
            .creds
            .ok_or_else(|| Fail::Fatal("import context has no pull-head credentials".into()))?;
        let head_sha = match remote::ls_remote_ref(
            &repo_dir,
            pinned,
            creds,
            &head_ref,
            PULL_HEAD_FETCH_TIMEOUT,
        )
        .await
        .map_err(|e| Fail::Fatal(remote::scrub(&e.to_string(), &pinned.url)))?
        {
            Some(sha) => sha,
            None => {
                self.note_unfetchable_head(ctx, pull, trail, change_id)
                    .await?;
                return Ok(None);
            }
        };
        if remote::fetch_pull_head(
            &repo_dir,
            pinned,
            creds,
            pull.number,
            PULL_HEAD_FETCH_TIMEOUT,
        )
        .await
        .is_err()
        {
            self.note_unfetchable_head(ctx, pull, trail, change_id)
                .await?;
            return Ok(None);
        }
        let (author_id, _) = self.resolve_author(&pull.user).await;
        let revision = db_changes::insert_revision(
            self.db(),
            change_id,
            &head_sha,
            &pull.base.sha,
            author_id,
            now(),
        )
        .await
        .map_err(|e| Fail::Fatal(e.to_string()))?;
        db_changes::set_current_revision(self.db(), change_id, revision.id, now())
            .await
            .map_err(|e| Fail::Fatal(e.to_string()))?;
        let merge_base = git_read::merge_base(&repo_dir, &pull.base.sha, &head_sha)
            .ok()
            .flatten();
        db_changes::set_revision_snapshot(
            self.db(),
            revision.id,
            merge_base.as_deref(),
            "unknown",
            "",
        )
        .await
        .map_err(|e| Fail::Fatal(e.to_string()))?;
        for name in [
            format!("refs/trails/{trail_number}/changes/1/head"),
            format!("refs/trails/{trail_number}/changes/1/rev/1"),
        ] {
            git_write::set_ref(&repo_dir, &name, &head_sha)
                .await
                .map_err(|e| Fail::Fatal(e.to_string()))?;
        }
        let _ = cursor;
        Ok(Some(revision))
    }

    /// D3 unfetchable head: the change closes and a note comment records
    /// it. The note carries a synthetic negative `github_id` (`-pull.id`)
    /// so the unique index keeps it to one row per pull across resumes.
    async fn note_unfetchable_head(
        &self,
        ctx: &ImportCtx<'_>,
        pull: &GhPull,
        trail: &db_trails::TrailRow,
        change_id: i64,
    ) -> Result<(), Fail> {
        db_changes::set_change_state(self.db(), change_id, "closed", now())
            .await
            .map_err(|e| Fail::Fatal(e.to_string()))?;
        let note_id = -pull.id;
        if db_trails::comment_by_github_id(self.db(), note_id)
            .await
            .map_err(|e| Fail::Fatal(e.to_string()))?
            .is_none()
        {
            let (author_id, imported_author) = self.resolve_author(&pull.user).await;
            db_trails::insert_imported_comment(
                self.db(),
                trail.id,
                author_id,
                imported_author.as_deref(),
                note_id,
                &format!(
                    "Imported pull request head (refs/pull/{}/head) is no longer fetchable; \
                     the change is closed without a revision.",
                    pull.number
                ),
                now(),
            )
            .await
            .map_err(|e| Fail::Fatal(e.to_string()))?;
            db_imports::add_counts(self.db(), ctx.row.id, 0, 0, 1, 0, 0)
                .await
                .map_err(|e| Fail::Fatal(e.to_string()))?;
        }
        Ok(())
    }

    /// Inserts (or reuses) the Trail for one GitHub issue or pull request,
    /// applying labels and assignees, writing the single `trail.imported`
    /// timeline row, and counting the object. Reuse on resume counts
    /// nothing and writes no second timeline row.
    async fn import_trail(
        &self,
        ctx: &ImportCtx<'_>,
        subject: &TrailSubject<'_>,
        cursor: &mut Cursor,
    ) -> Result<db_trails::TrailRow, Fail> {
        let map_err = |e: starforged_db::DbError| Fail::Fatal(e.to_string());
        if let Some(existing) = db_trails::trail_by_github_id(self.db(), subject.github_id)
            .await
            .map_err(map_err)?
        {
            return Ok(existing);
        }
        let (author_id, imported_author) = self.resolve_author(subject.user).await;
        let trail = db_trails::insert_imported_trail(
            self.db(),
            ctx.repo_id,
            subject.number,
            subject.title,
            subject.intent,
            subject.state,
            author_id,
            imported_author.as_deref(),
            subject.github_id,
            now(),
        )
        .await
        .map_err(map_err)?;
        db_trails::insert_timeline(
            self.db(),
            ctx.repo_id,
            Some(trail.id),
            "trail.imported",
            None,
            &serde_json::json!({"number": subject.number, "github_id": subject.github_id})
                .to_string(),
            now(),
        )
        .await
        .map_err(map_err)?;
        for label in subject.labels {
            if let Ok(name) = crate::trails::normalize_label(&label.name) {
                db_trails::add_label(self.db(), trail.id, &name)
                    .await
                    .map_err(map_err)?;
            }
        }
        for assignee in subject.assignees {
            match self.resolve_author(&Some(assignee.clone())).await {
                (Some(user_id), _)
                    if self
                        .is_repo_member(ctx.repo_id, user_id)
                        .await
                        .map_err(|e| Fail::Fatal(e.to_string()))? =>
                {
                    db_trails::add_assignee(self.db(), trail.id, user_id)
                        .await
                        .map_err(map_err)?;
                }
                _ => {
                    if !cursor.dropped.contains(&assignee.login) {
                        cursor.dropped.push(assignee.login.clone());
                    }
                }
            }
        }
        db_imports::add_counts(
            self.db(),
            ctx.row.id,
            i64::from(!subject.is_pull),
            i64::from(subject.is_pull),
            0,
            0,
            0,
        )
        .await
        .map_err(map_err)?;
        Ok(trail)
    }

    async fn import_issue_comments(
        &self,
        ctx: &ImportCtx<'_>,
        number: i64,
        trail_id: i64,
        cursor: &mut Cursor,
    ) -> Result<(), Fail> {
        let map_err = |e: starforged_db::DbError| Fail::Fatal(e.to_string());
        let mut page = 1u32;
        loop {
            let page_res = ctx
                .client
                .list_issue_comments(ctx.gh_owner, ctx.gh_repo, number, page)
                .await?;
            for comment in &page_res.items {
                if db_trails::comment_by_github_id(self.db(), comment.id)
                    .await
                    .map_err(map_err)?
                    .is_some()
                {
                    continue;
                }
                let (author_id, imported_author) = self.resolve_author(&comment.user).await;
                db_trails::insert_imported_comment(
                    self.db(),
                    trail_id,
                    author_id,
                    imported_author.as_deref(),
                    comment.id,
                    comment.body.as_deref().unwrap_or(""),
                    now(),
                )
                .await
                .map_err(map_err)?;
                db_imports::add_counts(self.db(), ctx.row.id, 0, 0, 1, 0, 0)
                    .await
                    .map_err(map_err)?;
            }
            let _ = cursor;
            if page_res.next.is_none() {
                break;
            }
            page += 1;
        }
        Ok(())
    }

    /// Reviews (D4) become `submitted` reviews on revision 1 with the
    /// mapped verdict; `PENDING` reviews are skipped.
    async fn import_reviews(
        &self,
        ctx: &ImportCtx<'_>,
        number: i64,
        change_id: i64,
        revision_id: i64,
        cursor: &mut Cursor,
    ) -> Result<(), Fail> {
        let map_err = |e: starforged_db::DbError| Fail::Fatal(e.to_string());
        let mut page = 1u32;
        loop {
            let page_res = ctx
                .client
                .list_reviews(ctx.gh_owner, ctx.gh_repo, number, page)
                .await?;
            for review in &page_res.items {
                let verdict = match review.state.as_str() {
                    "APPROVED" => "approve",
                    "CHANGES_REQUESTED" => "request_changes",
                    "COMMENTED" => "comment",
                    _ => continue,
                };
                if db_changes::review_by_github_id(self.db(), review.id)
                    .await
                    .map_err(map_err)?
                    .is_some()
                {
                    continue;
                }
                let (author_id, imported_author) = self.resolve_author(&review.user).await;
                db_changes::insert_imported_review(
                    self.db(),
                    change_id,
                    revision_id,
                    author_id,
                    imported_author.as_deref(),
                    review.id,
                    verdict,
                    review.body.as_deref().unwrap_or(""),
                    now(),
                )
                .await
                .map_err(map_err)?;
                db_imports::add_counts(self.db(), ctx.row.id, 0, 0, 0, 1, 0)
                    .await
                    .map_err(map_err)?;
            }
            let _ = cursor;
            if page_res.next.is_none() {
                break;
            }
            page += 1;
        }
        Ok(())
    }

    /// Review comments (D4): a comment whose path and line exist in
    /// revision 1's diff becomes a review thread (side `head` for `RIGHT`,
    /// `base` for `LEFT`); a reply (`in_reply_to_id`) appends to its
    /// parent's thread. Anything else becomes a quoted Trail comment.
    async fn import_review_comments(
        &self,
        ctx: &ImportCtx<'_>,
        number: i64,
        change_id: i64,
        revision_id: i64,
        trail: &db_trails::TrailRow,
        cursor: &mut Cursor,
    ) -> Result<(), Fail> {
        let map_err = |e: starforged_db::DbError| Fail::Fatal(e.to_string());
        let mut page = 1u32;
        let mut diff_lines: Option<HashSet<(String, i64, i64)>> = None;
        loop {
            let page_res = ctx
                .client
                .list_review_comments(ctx.gh_owner, ctx.gh_repo, number, page)
                .await?;
            for comment in &page_res.items {
                if db_changes::thread_comment_by_github_id(self.db(), comment.id)
                    .await
                    .map_err(map_err)?
                    .is_some()
                    || db_trails::comment_by_github_id(self.db(), comment.id)
                        .await
                        .map_err(map_err)?
                        .is_some()
                {
                    continue;
                }
                let line = comment.line.or(comment.original_line);
                let path = comment.path.clone().unwrap_or_default();
                let on_diff = match (&path, line) {
                    (p, Some(l)) if !p.is_empty() => {
                        if diff_lines.is_none() {
                            diff_lines =
                                Some(self.revision_diff_lines(ctx.repo_id, revision_id).await);
                        }
                        let side = if comment.side.as_deref() == Some("LEFT") {
                            0
                        } else {
                            1
                        };
                        diff_lines
                            .as_ref()
                            .is_some_and(|set| set.contains(&(p.clone(), side, l)))
                    }
                    _ => false,
                };
                let (author_id, imported_author) = self.resolve_author(&comment.user).await;
                let body = comment.body.as_deref().unwrap_or("");
                if on_diff {
                    let side = if comment.side.as_deref() == Some("LEFT") {
                        "base"
                    } else {
                        "head"
                    };
                    let line = line.unwrap_or(0);
                    // A reply threads under its parent when the parent is
                    // already imported; comments arrive in id order, so the
                    // parent precedes the reply.
                    let thread_id = match comment.in_reply_to_id {
                        Some(parent_id) => {
                            db_changes::thread_comment_by_github_id(self.db(), parent_id)
                                .await
                                .map_err(map_err)?
                                .map(|parent| parent.thread_id)
                        }
                        None => None,
                    };
                    let thread_id = match thread_id {
                        Some(thread_id) => thread_id,
                        None => {
                            db_changes::insert_thread(
                                self.db(),
                                change_id,
                                revision_id,
                                &path,
                                side,
                                line,
                                line,
                                now(),
                            )
                            .await
                            .map_err(map_err)?
                            .id
                        }
                    };
                    let review_id = match comment.pull_request_review_id {
                        Some(github_review_id) => {
                            db_changes::review_by_github_id(self.db(), github_review_id)
                                .await
                                .map_err(map_err)?
                                .map(|review| review.id)
                        }
                        None => None,
                    };
                    db_changes::insert_imported_thread_comment(
                        self.db(),
                        thread_id,
                        review_id,
                        author_id,
                        imported_author.as_deref(),
                        comment.id,
                        body,
                        now(),
                    )
                    .await
                    .map_err(map_err)?;
                } else {
                    let quoted = match (comment.path.as_deref(), line) {
                        (Some(p), Some(l)) => format!(
                            "> {p}:{l}\n> {}\n\n{body}",
                            comment.html_url.as_deref().unwrap_or("")
                        ),
                        _ => body.to_owned(),
                    };
                    db_trails::insert_imported_comment(
                        self.db(),
                        trail.id,
                        author_id,
                        imported_author.as_deref(),
                        comment.id,
                        &quoted,
                        now(),
                    )
                    .await
                    .map_err(map_err)?;
                }
                db_imports::add_counts(self.db(), ctx.row.id, 0, 0, 0, 0, 1)
                    .await
                    .map_err(map_err)?;
            }
            let _ = cursor;
            if page_res.next.is_none() {
                break;
            }
            page += 1;
        }
        Ok(())
    }

    /// The `(path, side, line)` set of revision 1's diff: side 1 is the new
    /// (`RIGHT`) side, side 0 the old (`LEFT`) side. Empty when the diff
    /// cannot be computed, which sends every review comment to the quoted
    /// Trail-comment path.
    async fn revision_diff_lines(
        &self,
        repo_id: i64,
        revision_id: i64,
    ) -> HashSet<(String, i64, i64)> {
        let mut lines = HashSet::new();
        let Ok(Some(revision)) = db_changes::revision_by_id(self.db(), revision_id).await else {
            return lines;
        };
        let repo_dir = self.repo_path(repo_id);
        let diff = match git_read::merge_base(&repo_dir, &revision.base_sha, &revision.head_sha)
            .ok()
            .flatten()
        {
            Some(merge_base) => {
                git_diff::range_diff(
                    &repo_dir,
                    &merge_base,
                    &revision.head_sha,
                    10_000,
                    10 * 1024 * 1024,
                )
                .await
            }
            None => {
                git_diff::commit_diff(&repo_dir, &revision.head_sha, 10_000, 10 * 1024 * 1024).await
            }
        };
        let Ok(diff) = diff else {
            return lines;
        };
        for file in &diff.files {
            let path = file.display_path().to_owned();
            for hunk in &file.hunks {
                for line in &hunk.lines {
                    if let Some(new_line) = line.new_line {
                        lines.insert((path.clone(), 1, i64::from(new_line)));
                    }
                    if let Some(old_line) = line.old_line {
                        lines.insert((path.clone(), 0, i64::from(old_line)));
                    }
                }
            }
        }
        lines
    }

    /// D1 author matching: a local user with the GitHub user's public
    /// email as their *verified* email; otherwise a placeholder carrying
    /// the GitHub login. A deleted GitHub account (`user: null`) is
    /// neither.
    async fn resolve_author(&self, user: &Option<GhUser>) -> (Option<i64>, Option<String>) {
        let Some(user) = user else {
            return (None, None);
        };
        if let Some(email) = user.email.as_deref() {
            let email = email.trim().to_ascii_lowercase();
            if let Ok(Some(row)) = db_users::by_email(self.db(), &email).await
                && row.email_verified
            {
                return (Some(row.id), None);
            }
        }
        (None, Some(user.login.clone()))
    }
}

/// The `trail.imported` audit detail: the import counts.
fn counts_detail(row: &db_imports::GithubImportRow) -> String {
    format!(
        "issues={} pulls={} comments={} reviews={} review_comments={} dropped_assignees={}",
        row.issues_count,
        row.pulls_count,
        row.comments_count,
        row.reviews_count,
        row.review_comments_count,
        row.dropped_assignees
    )
}

/// Trail state from a GitHub object state (D3/D2): merged PRs are `merged`,
/// closed objects `closed`, everything else `open`.
fn trail_state(github_state: &str, merged: bool) -> &'static str {
    if merged {
        "merged"
    } else if github_state == "closed" {
        "closed"
    } else {
        "open"
    }
}
