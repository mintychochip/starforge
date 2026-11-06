//! Server-side merge (spec §6.2, M2c H4): `merge`, `squash`, and
//! `fast_forward` onto the base branch with a compare-and-swap, plus the
//! Trail `merged` transition.
//!
//! The merge path never trusts a client report: it re-resolves the base tip
//! and head, re-evaluates gates at merge time, refuses archived repos,
//! closed/merged changes, failing gates, unknown or disallowed methods, and
//! conflicts. `update-ref` races retry once (re-resolve, rebuild, re-evaluate,
//! retry); a second mismatch is a `409` carrying the fresh state. Every
//! created commit carries a `Starforge-Trail: <owner>/<repo>#<n>` trailer; the
//! squash message composes the squashed subjects plus the distinct
//! `Starforge-Session` trailers in order of appearance.
//!
//! All git runs are argv-only through `starforged-git` (hermetic env, 60s
//! timeouts); blocking reads go through `spawn_blocking`. Every success
//! writes exactly one `change.merge` timeline row plus a `change.merge`
//! audit row, fans `ChangeMergeability` out to every OTHER open change on the
//! moved base, and flips the Trail to `merged` (with `trail.merged`
//! timeline + audit) when no open change remains.

use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use starforged_db::{changes as db_changes, checks as db_checks, now, trails as db_trails};
use starforged_git::refpolicy::pattern_matches;
use starforged_git::{merge, read, write};

use crate::accounts::User;
use crate::jobs::Job;
use crate::permission::Permission;
use crate::{Core, CoreError, CoreResult};

/// Merge methods the server understands.
pub const MERGE_METHODS: [&str; 3] = ["merge", "squash", "fast_forward"];

/// The merge form body (`{"method": "merge"|"squash"|"fast_forward"}`),
/// shared by the API route and the web form.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct MergeRequest {
    pub method: String,
}

/// A completed merge: the base branch now points at `sha`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeOutcome {
    pub sha: String,
    pub method: String,
}

/// Test seam: runs on a blocking thread immediately before each `update-ref`
/// CAS attempt. `None` in production; integration tests set it to move the
/// base ref between gate evaluation and the compare-and-swap, deterministically
/// exercising the retry and the double-mismatch `409`.
#[derive(Clone)]
pub struct PreCasHook(Arc<dyn Fn() + Send + Sync>);

impl std::fmt::Debug for PreCasHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreCasHook(..)")
    }
}

impl PreCasHook {
    /// Wraps a synchronous hook (it runs on a blocking thread, so blocking
    /// git commands are fine).
    pub fn new(hook: impl Fn() + Send + Sync + 'static) -> PreCasHook {
        PreCasHook(Arc::new(hook))
    }
}

/// Cap on the `merge_base..head` walk for squash subjects; longer histories
/// still merge, carrying the newest `MAX_SQUASH_COMMITS` commits' subjects.
/// (Session-evidence caps are a gate concern, not a message concern.)
const MAX_SQUASH_COMMITS: usize = 1024;

/// How many conflict paths a 409 message names before summarizing the rest.
const MAX_REPORT_PATHS: usize = 10;

fn all_methods() -> Vec<String> {
    MERGE_METHODS.iter().map(ToString::to_string).collect()
}

/// Parses one rule's `allowed_methods` JSON array. `NULL`/empty/unparseable —
/// or naming no known method — means all three (matching the settings-form
/// default); unknown names are dropped, never honored.
fn parse_allowed(raw: &str) -> Vec<String> {
    let parsed: Vec<String> = serde_json::from_str(raw).unwrap_or_default();
    let known: Vec<String> = parsed
        .into_iter()
        .filter(|m| MERGE_METHODS.contains(&m.as_str()))
        .collect();
    if known.is_empty() {
        all_methods()
    } else {
        known
    }
}

fn conflict_summary(paths: &[String]) -> String {
    if paths.len() <= MAX_REPORT_PATHS {
        paths.join(", ")
    } else {
        format!(
            "{}, …and {} more",
            paths[..MAX_REPORT_PATHS].join(", "),
            paths.len() - MAX_REPORT_PATHS
        )
    }
}

/// Pure squash selection over newest-first `range_log` output: keeps the
/// newest `max` commits, lists their subjects oldest-first, dedupes their
/// `Starforge-Session` trailers in order of appearance, and counts how many
/// older commits fell outside the cap (`total` is the true range size, which
/// `range_log` reports even when it truncates the list). `max` is a
/// parameter — not the constant — so tests can exercise truncation with a
/// lowered cap instead of pushing a thousand commits.
fn select_squash_parts(
    commits: &[starforged_git::read::CommitInfo],
    total: usize,
    max: usize,
) -> (Vec<String>, Vec<String>, usize) {
    let take = commits.len().min(max);
    let mut subjects = Vec::new();
    let mut sessions = Vec::new();
    let mut seen = HashSet::new();
    for commit in commits[..take].iter().rev() {
        if let Some(subject) = commit.message.lines().next().map(str::trim)
            && !subject.is_empty()
        {
            subjects.push(subject.to_owned());
        }
        for trailer in crate::gates::session_trailers(&commit.message) {
            if seen.insert(trailer.clone()) {
                sessions.push(trailer);
            }
        }
    }
    (subjects, sessions, total.saturating_sub(take))
}

/// Renders the squash commit message: title, squashed subjects oldest-first,
/// an omission marker when the range exceeded the cap (so the history gap is
/// visible, like [`conflict_summary`]), the distinct session trailers, then
/// the `Change:` line and the `Starforge-Trail:` trailer.
#[allow(clippy::too_many_arguments)]
fn compose_squash_message(
    trail_title: &str,
    trail_n: i64,
    k: i64,
    stamp: &str,
    subjects: &[String],
    sessions: &[String],
    omitted: usize,
) -> String {
    let mut message = format!("{trail_title} (#{trail_n})\n\n");
    if !subjects.is_empty() {
        message.push_str(&subjects.join("\n"));
        message.push('\n');
    }
    if omitted > 0 {
        let noun = if omitted == 1 { "commit" } else { "commits" };
        message.push_str(&format!("…and {omitted} earlier {noun} omitted\n"));
    }
    if !subjects.is_empty() || omitted > 0 {
        message.push('\n');
    }
    for session in sessions {
        message.push_str(&format!("Starforge-Session: {session}\n"));
    }
    message.push_str(&format!(
        "Change: {stamp}/{k}\n\nStarforge-Trail: {stamp}\n"
    ));
    message
}

impl Core {
    /// Sets (or clears) the merge CAS test seam. `None` in production.
    pub fn set_merge_cas_hook(&self, hook: Option<PreCasHook>) {
        if let Ok(mut guard) = self.inner.merge_cas_hook.lock() {
            *guard = hook;
        }
    }

    fn pre_cas_hook(&self) -> Option<PreCasHook> {
        self.inner
            .merge_cas_hook
            .lock()
            .ok()
            .and_then(|g| g.clone())
    }

    async fn fire_pre_cas_hook(&self) -> CoreResult<()> {
        if let Some(hook) = self.pre_cas_hook() {
            tokio::task::spawn_blocking(move || (hook.0)())
                .await
                .map_err(|e| CoreError::Internal(format!("merge CAS hook failed: {e}")))?;
        }
        Ok(())
    }

    /// The methods the matching gate rules allow for this change's base
    /// branch (intersection across matching rules; no matching rule means all
    /// three). Fail-closed: disjoint rules allow nothing. `viewer` needs read
    /// visibility (`NotFound` otherwise, like [`Core::get_change`]).
    pub async fn allowed_merge_methods(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
    ) -> CoreResult<Vec<String>> {
        let access = self.repo_for(viewer, owner, repo).await?;
        let trail = db_trails::trail_by_number(self.db(), access.repo.id, trail_n)
            .await?
            .ok_or(CoreError::NotFound)?;
        let change = db_changes::change_by_trail_number(self.db(), trail.id, k)
            .await?
            .ok_or(CoreError::NotFound)?;
        self.compute_allowed_methods(access.repo.id, &change.base_branch)
            .await
    }

    async fn compute_allowed_methods(
        &self,
        repo_id: i64,
        base_branch: &str,
    ) -> CoreResult<Vec<String>> {
        let rules = db_checks::gate_rules_for(self.db(), repo_id).await?;
        let mut allowed: Option<Vec<String>> = None;
        for rule in rules
            .iter()
            .filter(|r| pattern_matches(r.pattern.as_deref(), base_branch))
        {
            let methods = parse_allowed(&rule.allowed_methods);
            allowed = Some(match allowed {
                None => methods,
                Some(acc) => acc.into_iter().filter(|m| methods.contains(m)).collect(),
            });
        }
        Ok(allowed.unwrap_or_else(all_methods))
    }

    /// Live base tip and merge base for (`base_branch`, `head`): `(tip,
    /// merge_base)`, with `None` tips for a missing base and `None` merge
    /// bases for unrelated histories. One blocking call (gix reads).
    async fn resolve_merge_endpoints(
        &self,
        repo_id: i64,
        base_branch: &str,
        head: &str,
    ) -> CoreResult<(Option<String>, Option<String>)> {
        let repo = self.repo_path(repo_id);
        let base = base_branch.to_owned();
        let head = head.to_owned();
        tokio::task::spawn_blocking(move || {
            let branches = read::branch_list(&repo)?;
            let tip = branches
                .into_iter()
                .find(|b| b.name == base)
                .map(|b| b.tip.id);
            let merge_base = match &tip {
                Some(tip) => read::merge_base(&repo, &head, tip)?,
                None => None,
            };
            Ok::<_, starforged_git::GitError>((tip, merge_base))
        })
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))?
        .map_err(CoreError::from)
    }

    /// True when `head` contains `base` (`merge-base --is-ancestor`, bounded
    /// by the merge path's 60 s budget; expiry kills the child and refuses).
    /// Checked before the first CAS attempt and again on retry: a
    /// fast-forward that stops being one must refuse, never rewind the base.
    async fn is_fast_forwardable(&self, repo_id: i64, base: &str, head: &str) -> CoreResult<bool> {
        let repo = self.repo_path(repo_id);
        merge::is_ancestor(&repo, base, head)
            .await
            .map_err(CoreError::from)
    }

    /// Subjects (oldest-first), distinct `Starforge-Session` trailers (in
    /// order of appearance), and the count of older commits beyond
    /// [`MAX_SQUASH_COMMITS`] for the `merge_base..head` range.
    async fn squash_parts(
        &self,
        repo_id: i64,
        merge_base: &str,
        head: &str,
    ) -> CoreResult<(Vec<String>, Vec<String>, usize)> {
        let repo = self.repo_path(repo_id);
        let (from, to) = (merge_base.to_owned(), head.to_owned());
        let (commits, total) = tokio::task::spawn_blocking(move || {
            read::range_log(&repo, &from, &to, MAX_SQUASH_COMMITS)
        })
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))?
        .map_err(CoreError::from)?;
        Ok(select_squash_parts(&commits, total, MAX_SQUASH_COMMITS))
    }

    /// Builds (but does not point any ref at) the merge commit for `method`
    /// on top of `base`: `merge` merges `head` via the merge-tree result,
    /// `squash` commits the head tree with the composed message. Refuses
    /// conflicts and unrelated histories with `Conflict`.
    #[allow(clippy::too_many_arguments)]
    async fn build_merge_commit(
        &self,
        repo_id: i64,
        method: &str,
        trail_title: &str,
        trail_n: i64,
        k: i64,
        owner: &str,
        repo: &str,
        base_branch: &str,
        base: &str,
        head: &str,
        merge_base: Option<&str>,
    ) -> CoreResult<String> {
        let Some(merge_base) = merge_base else {
            return Err(CoreError::Conflict(format!(
                "cannot merge: base branch '{base_branch}' and the change head share no history"
            )));
        };
        let repo_path = self.repo_path(repo_id);
        let stamp = format!("{owner}/{repo}#{trail_n}");
        let change_line = format!("Change: {stamp}/{k}");
        let trail_trailer = format!("Starforge-Trail: {stamp}");
        let identity = write::Identity {
            name: "Starforge",
            email: "forge@local",
            time: now(),
        };
        match method {
            "merge" => {
                let probe = merge::merge_tree(&repo_path, base, head)
                    .await
                    .map_err(CoreError::from)?;
                if !probe.clean {
                    return Err(CoreError::Conflict(format!(
                        "merge conflicts in: {} (base_sha: {base}, head_sha: {head})",
                        conflict_summary(&probe.paths)
                    )));
                }
                let tree = probe.tree.ok_or_else(|| {
                    CoreError::Internal("merge-tree reported clean with no tree".into())
                })?;
                let message =
                    format!("{trail_title} (#{trail_n})\n\n{change_line}\n\n{trail_trailer}\n");
                write::commit_tree(&repo_path, &tree, &[base, head], &message, identity)
                    .await
                    .map_err(CoreError::from)
            }
            "squash" => {
                // Squash takes the head tree wholesale (conflict-free by
                // construction); the message carries the squashed history.
                let probe = merge::merge_tree(&repo_path, base, head)
                    .await
                    .map_err(CoreError::from)?;
                if !probe.clean {
                    return Err(CoreError::Conflict(format!(
                        "merge conflicts in: {} (base_sha: {base}, head_sha: {head})",
                        conflict_summary(&probe.paths)
                    )));
                }
                let tree = write::rev_parse_tree(&repo_path, head)
                    .await
                    .map_err(CoreError::from)?;
                let (subjects, sessions, omitted) =
                    self.squash_parts(repo_id, merge_base, head).await?;
                let message = compose_squash_message(
                    trail_title,
                    trail_n,
                    k,
                    &stamp,
                    &subjects,
                    &sessions,
                    omitted,
                );
                write::commit_tree(&repo_path, &tree, &[base], &message, identity)
                    .await
                    .map_err(CoreError::from)
            }
            _ => Err(CoreError::Internal(format!(
                "unsupported merge method '{method}'"
            ))),
        }
    }

    /// Server-side merge (binding): re-resolves the base tip and head,
    /// re-evaluates gates AT MERGE TIME (never trusts a client report),
    /// refuses archived repos, closed/merged changes, failing gates, unknown
    /// or disallowed methods, and conflicts. The base moves exactly once via
    /// `update-ref` CAS with a single retry; then the change flips to
    /// `merged`, other open changes on the moved base recompute, and the
    /// Trail flips to `merged` when no open change remains.
    pub async fn merge_change(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        method: &str,
    ) -> CoreResult<MergeOutcome> {
        if !MERGE_METHODS.contains(&method) {
            return Err(CoreError::Invalid(format!(
                "unknown merge method '{method}' (expected one of merge, squash, fast_forward)"
            )));
        }
        // Write+ on a non-archived repo: merging mutates the base branch, the
        // same threshold as a direct branch push.
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Write)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        let trail = db_trails::trail_by_number(self.db(), access.repo.id, trail_n)
            .await?
            .ok_or(CoreError::NotFound)?;
        let change = db_changes::change_by_trail_number(self.db(), trail.id, k)
            .await?
            .ok_or(CoreError::NotFound)?;
        if change.state != "open" {
            return Err(CoreError::Invalid(format!(
                "change is {} (only open changes merge)",
                change.state
            )));
        }
        let current_id = change
            .current_revision_id
            .ok_or_else(|| CoreError::Invalid("change has no revisions yet".into()))?;
        let revision = db_changes::revision_by_id(self.db(), current_id)
            .await?
            .ok_or_else(|| CoreError::Internal("change has no current revision".into()))?;
        let head = revision.head_sha.clone();
        let base_branch = change.base_branch.clone();
        let base_ref = format!("refs/heads/{base_branch}");
        if base_branch.contains('\0') || base_branch.contains('\n') {
            return Err(CoreError::Invalid(format!(
                "invalid base branch {base_branch:?}"
            )));
        }

        // Fresh endpoints + fresh gates: a stale client report authorizes
        // nothing.
        let (base_tip, merge_base) = self
            .resolve_merge_endpoints(access.repo.id, &base_branch, &head)
            .await?;
        let Some(base_tip) = base_tip else {
            return Err(CoreError::Conflict(format!(
                "base branch '{base_branch}' is missing"
            )));
        };
        let report = self
            .evaluate_gates(Some(user), owner, repo, trail_n, k)
            .await?;
        if !report.passed {
            let mut reasons: Vec<String> = report
                .results
                .iter()
                .filter(|r| !r.passed)
                .map(|r| r.reason.clone())
                .collect();
            if reasons.is_empty() {
                reasons.push("merge gates failing".to_owned());
            }
            return Err(CoreError::Invalid(format!(
                "merge gates failing: {}",
                reasons.join("; ")
            )));
        }
        let allowed = self
            .compute_allowed_methods(access.repo.id, &base_branch)
            .await?;
        if !allowed.iter().any(|m| m == method) {
            let list = if allowed.is_empty() {
                "none".to_owned()
            } else {
                allowed.join(", ")
            };
            return Err(CoreError::Invalid(format!(
                "merge method '{method}' is not allowed by the matching gate rules (allowed: {list})"
            )));
        }

        if method == "fast_forward"
            && !self
                .is_fast_forwardable(access.repo.id, &base_tip, &head)
                .await?
        {
            return Err(CoreError::Invalid(format!(
                "cannot fast-forward: base branch '{base_branch}' is not an ancestor of the change head"
            )));
        }

        // Builds the merge commit below, twice (first attempt and retry):
        // spelled out instead of behind a closure, because the two borrows
        // need independent lifetimes. Fast-forwards move the ref at the head
        // with no new commit (a base ancestor of the head merges trivially
        // clean, so no probe runs). Unrelated histories fail the ancestor
        // check above; merge/squash refuse them inside the builder.
        let mut new_sha = if method == "fast_forward" {
            head.clone()
        } else {
            self.build_merge_commit(
                access.repo.id,
                method,
                &trail.title,
                trail.number,
                change.number,
                owner,
                repo,
                &base_branch,
                &base_tip,
                &head,
                merge_base.as_deref(),
            )
            .await?
        };
        let mut base_old = base_tip;

        self.fire_pre_cas_hook().await?;
        let moved = write::update_ref_cas(
            &self.repo_path(access.repo.id),
            &base_ref,
            &new_sha,
            &base_old,
        )
        .await
        .map_err(CoreError::from)?;
        if !moved {
            // One retry: re-resolve, rebuild, re-evaluate, retry. Only the
            // `update-ref` races — never the whole gate evaluation loop.
            let (tip, merge_base) = self
                .resolve_merge_endpoints(access.repo.id, &base_branch, &head)
                .await?;
            let Some(tip) = tip else {
                return Err(CoreError::Conflict(format!(
                    "base branch '{base_branch}' is missing"
                )));
            };
            // A rule edit landing between the two CAS attempts that disallows
            // the in-flight method refuses here, before the second CAS moves
            // the ref. Same `Invalid` shape as the first allowed-methods
            // check above.
            let allowed = self
                .compute_allowed_methods(access.repo.id, &base_branch)
                .await?;
            if !allowed.iter().any(|m| m == method) {
                let list = if allowed.is_empty() {
                    "none".to_owned()
                } else {
                    allowed.join(", ")
                };
                return Err(CoreError::Invalid(format!(
                    "merge method '{method}' is not allowed by the matching gate rules (allowed: {list})"
                )));
            }
            // A fast-forward that stopped being one must refuse, never rewind
            // the base: pointing the ref at the head now would discard the
            // racer's commits. Checked before the rebuild, so nothing writes.
            if method == "fast_forward"
                && !self
                    .is_fast_forwardable(access.repo.id, &tip, &head)
                    .await?
            {
                return Err(CoreError::Conflict(format!(
                    "base branch '{base_branch}' moved during merge and is no longer an ancestor of the change head"
                )));
            }
            new_sha = if method == "fast_forward" {
                head.clone()
            } else {
                self.build_merge_commit(
                    access.repo.id,
                    method,
                    &trail.title,
                    trail.number,
                    change.number,
                    owner,
                    repo,
                    &base_branch,
                    &tip,
                    &head,
                    merge_base.as_deref(),
                )
                .await?
            };
            let report = self
                .evaluate_gates(Some(user), owner, repo, trail_n, k)
                .await?;
            if !report.passed {
                let mut reasons: Vec<String> = report
                    .results
                    .iter()
                    .filter(|r| !r.passed)
                    .map(|r| r.reason.clone())
                    .collect();
                if reasons.is_empty() {
                    reasons.push("merge gates failing".to_owned());
                }
                return Err(CoreError::Invalid(format!(
                    "merge gates failing: {}",
                    reasons.join("; ")
                )));
            }
            base_old = tip;
            self.fire_pre_cas_hook().await?;
            let moved = write::update_ref_cas(
                &self.repo_path(access.repo.id),
                &base_ref,
                &new_sha,
                &base_old,
            )
            .await
            .map_err(CoreError::from)?;
            if !moved {
                return Err(self.cas_conflict(access.repo.id, &base_branch, &head).await);
            }
        }

        self.finish_merge(
            user,
            owner,
            repo,
            &trail,
            &change,
            method,
            &new_sha,
            &base_branch,
        )
        .await?;
        Ok(MergeOutcome {
            sha: new_sha,
            method: method.to_owned(),
        })
    }

    /// Fresh `409` state after the second CAS mismatch: re-resolves the base
    /// once more and probes mergeability, so the report names the current
    /// tip rather than either stale one.
    async fn cas_conflict(&self, repo_id: i64, base_branch: &str, head: &str) -> CoreError {
        let repo_path = self.repo_path(repo_id);
        let (tip, _) = self
            .resolve_merge_endpoints(repo_id, base_branch, head)
            .await
            .unwrap_or((None, None));
        match tip {
            None => CoreError::Conflict(format!(
                "base branch '{base_branch}' moved during merge and is now missing (head_sha: {head})"
            )),
            Some(tip) => {
                let probe = merge::merge_tree(&repo_path, &tip, head).await;
                let mergeability = match probe {
                    Ok(outcome) if outcome.clean => "clean".to_owned(),
                    Ok(outcome) => format!("conflict: {}", conflict_summary(&outcome.paths)),
                    Err(_) => "unknown".to_owned(),
                };
                CoreError::Conflict(format!(
                    "base branch '{base_branch}' moved during merge (base_sha: {tip}, head_sha: {head}, mergeability: {mergeability})"
                ))
            }
        }
    }

    /// Post-CAS bookkeeping: the change flips to `merged`, the change's trail
    /// head ref follows the merge commit, one `change.merge` timeline row +
    /// audit row land, every OTHER open change on the moved base recomputes,
    /// and the Trail flips to `merged` when no open change remains.
    #[allow(clippy::too_many_arguments)]
    async fn finish_merge(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail: &starforged_db::trails::TrailRow,
        change: &db_changes::ChangeRow,
        method: &str,
        new_sha: &str,
        base_branch: &str,
    ) -> CoreResult<()> {
        // The change's trail head ref follows the merge commit (best-effort:
        // the CAS already moved the base, so a ref failure only warns).
        if let Err(err) = write::set_ref(
            &self.repo_path(trail.repo_id),
            &format!(
                "refs/trails/{}/changes/{}/head",
                trail.number, change.number
            ),
            new_sha,
        )
        .await
        {
            tracing::warn!(trail = trail.number, change = change.number, error = %err, "merge: trail head ref write failed");
        }
        let at = now();
        db_changes::set_merged(self.db(), change.id, method, new_sha, at).await?;
        let payload = serde_json::json!({
            "change": change.number,
            "method": method,
            "commit": new_sha,
        });
        self.change_timeline(
            trail.repo_id,
            trail.id,
            "change.merge",
            Some(user.id),
            payload,
        )
        .await?;
        self.audit(
            Some(user.id),
            "change.merge",
            &format!("change:{owner}/{repo}#{}/{}", trail.number, change.number),
            &serde_json::json!({"method": method, "commit": new_sha}).to_string(),
        )
        .await?;
        // Recompute triggers: every OTHER open change targeting the moved
        // base. The merged change itself never recomputes (it is no longer
        // open, and the id guard holds even if that ever changes).
        for id in
            db_changes::open_change_ids_with_base(self.db(), trail.repo_id, base_branch).await?
        {
            if id == change.id {
                continue;
            }
            self.enqueue(&Job::ChangeMergeability { change_id: id })
                .await?;
        }
        // The Trail merges when no open change remains. A closed trail stays
        // closed: only an open trail transitions. Exactly one event fires:
        // `merged` when this merge flipped the trail, else `updated` with a
        // `change_merged` cause.
        let siblings = db_changes::changes_of_trail(self.db(), trail.id).await?;
        let flipped = trail.state == "open" && !siblings.iter().any(|c| c.state == "open");
        if flipped {
            db_trails::set_merged(self.db(), trail.id, now()).await?;
            self.change_timeline(
                trail.repo_id,
                trail.id,
                "trail.merged",
                Some(user.id),
                serde_json::json!({"number": trail.number}),
            )
            .await?;
            self.audit(
                Some(user.id),
                "trail.merged",
                &format!("trail:{owner}/{repo}#{}", trail.number),
                "",
            )
            .await?;
        }
        let revision = match change.current_revision_id {
            Some(id) => db_changes::revision_by_id(self.db(), id)
                .await?
                .map(|row| row.number)
                .unwrap_or(0),
            None => 0,
        };
        let (action, cause) = if flipped {
            (Some("merged"), None)
        } else {
            (Some("updated"), Some("change_merged"))
        };
        self.dispatch_trail_event(
            trail.repo_id,
            Some(user.handle.clone()),
            action,
            cause,
            trail.number,
            Some(serde_json::json!({"k": change.number, "revision": revision})),
        )
        .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starforged_git::read::CommitInfo;

    fn commit(id: &str, message: &str) -> CommitInfo {
        CommitInfo {
            id: id.to_owned(),
            summary: message.lines().next().unwrap_or("").to_owned(),
            message: message.to_owned(),
            author_name: "test".to_owned(),
            author_email: "test@example.test".to_owned(),
            author_time: 1_700_000_000,
            parents: Vec::new(),
        }
    }

    /// Newest-first input, like `range_log` returns: keeps the newest `max`,
    /// subjects oldest-first, trailers deduped in order of appearance.
    #[test]
    fn squash_selection_orders_and_dedupes() {
        let commits = vec![
            commit("3", "three\n\nStarforge-Session: B\n"),
            commit("2", "two\n\nStarforge-Session: A\n"),
            commit("1", "one\n\nStarforge-Session: A\n"),
        ];
        let (subjects, sessions, omitted) = select_squash_parts(&commits, 3, 1024);
        assert_eq!(subjects, vec!["one", "two", "three"]);
        assert_eq!(sessions, vec!["A", "B"]);
        assert_eq!(omitted, 0);
    }

    /// A lowered cap truncates the oldest commits and counts them, so the
    /// history gap stays visible without pushing a thousand commits.
    #[test]
    fn squash_selection_truncates_oldest_with_count() {
        let commits = vec![
            commit("5", "five"),
            commit("4", "four"),
            commit("3", "three"),
            commit("2", "two"),
            commit("1", "one"),
        ];
        let (subjects, _, omitted) = select_squash_parts(&commits, 5, 3);
        assert_eq!(subjects, vec!["three", "four", "five"]);
        assert_eq!(omitted, 2);
    }

    #[test]
    fn squash_message_marks_truncation() {
        let message = compose_squash_message(
            "feature work",
            1,
            1,
            "alice/proj#1",
            &["three".to_owned(), "four".to_owned(), "five".to_owned()],
            &[],
            2,
        );
        assert_eq!(
            message,
            "feature work (#1)\n\nthree\nfour\nfive\n…and 2 earlier commits omitted\n\nChange: alice/proj#1/1\n\nStarforge-Trail: alice/proj#1\n"
        );
    }

    #[test]
    fn squash_message_singular_marker_and_no_marker() {
        let singular = compose_squash_message("t", 9, 2, "o/r#9", &["s".to_owned()], &[], 1);
        assert!(
            singular.contains("…and 1 earlier commit omitted\n"),
            "{singular}"
        );
        let full =
            compose_squash_message("t", 9, 2, "o/r#9", &["s".to_owned()], &["U".to_owned()], 0);
        assert!(!full.contains("omitted"), "{full}");
        assert_eq!(
            full,
            "t (#9)\n\ns\n\nStarforge-Session: U\nChange: o/r#9/2\n\nStarforge-Trail: o/r#9\n"
        );
    }
}
