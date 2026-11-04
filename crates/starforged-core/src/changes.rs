//! Change ingestion from `refs/for` pushes, branch-head moves, and the
//! mergeability worker (spec §8.2–§8.4, M2b G3).
//!
//! The post-push scan in `starforged-web` calls [`Core::record_agit_push`]
//! for every accepted `refs/for` tip and [`Core::record_branch_move`] for
//! every moved branch; [`Core::recompute_mergeability`] (via
//! `Job::ChangeMergeability`) resolves clean/conflict. `Core` owns every
//! database write and timeline row here; git ref writes go through
//! `starforged-git` and a failed ref write only warns — the mergeability job
//! replays the trail refs on every run, so they are self-healing.
//!
//! Timeline rows: `change.open` (new change, with base/topic), `change.revision`
//! (every new revision), and `change.mergeability` (only when the status
//! changes). Trail refs live at
//! `refs/trails/<n>/changes/<k>/{head,rev/<r>}` (server-written, hidden from
//! fetches by `uploadpack.hideRefs` and from push negotiation by
//! `receive.hideRefs`); the consumed `refs/for/*` pseudo-ref is deleted by
//! the scan after a successful ingest.

use starforged_db::{changes as db_changes, now, repos as db_repos, trails as db_trails};
use starforged_git::{merge, read, refpolicy, write};

use crate::jobs::Job;
use crate::{Core, CoreError, CoreResult};

/// Addressing for one accepted `refs/for` line, from the pre-receive sidecar
/// (`base`/`topic` already validated there) or the scan's optionless fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestSidecar {
    pub base: String,
    pub topic: String,
    pub trail: Option<i64>,
    pub title: Option<String>,
}

/// Cap on the serialized `conflict_paths` payload (count is capped in
/// `starforged-git`; this bounds the byte size).
pub const MAX_CONFLICT_PAYLOAD_BYTES: usize = 4 * 1024;

impl Core {
    /// Agit push: resolves the trail (`trail` pins an open trail in this repo,
    /// otherwise the open change's trail is reused or a new trail is created),
    /// finds or creates the open agit change for `(repo, user, base, topic)`,
    /// and appends a revision — unless the head SHA is unchanged, in which
    /// case nothing is written and `None` is returned.
    ///
    /// On a new revision: writes `refs/trails/<n>/changes/<k>/{head,rev/<r>}`
    /// (failures only warn; the mergeability job replays them), sets the
    /// current revision, appends `change.open`/`change.revision` timeline
    /// rows, and enqueues `ChangeMergeability`. Returns the `(k, r)` numbers.
    pub async fn record_agit_push(
        &self,
        repo_id: i64,
        user_id: i64,
        sc: &IngestSidecar,
        head_sha: &str,
        base_tip: &str,
    ) -> CoreResult<Option<(i64, i64)>> {
        if !refpolicy::is_oid(head_sha) || !refpolicy::is_oid(base_tip) {
            return Err(CoreError::Invalid("push tip is not an object id".into()));
        }
        if sc.base.is_empty() || sc.topic.is_empty() {
            return Err(CoreError::Invalid(
                "refs/for target needs a base and topic".into(),
            ));
        }
        let live = db_repos::by_id(self.db(), repo_id)
            .await?
            .is_some_and(|row| row.deleted_at.is_none());
        if !live {
            return Ok(None);
        }
        let (trail, fresh) = self
            .resolve_ingest_trail(repo_id, user_id, sc, head_sha)
            .await?;
        let trail_id = trail.id;
        let trail_number = trail.number;

        // Scope the lookup by the resolved trail id — never by the
        // user-facing trail number (`sc.trail`): ids and numbers diverge
        // across repos, and scoping by number would miss the change and open
        // a duplicate (or match another repo's trail, which the repo join
        // would then wrongly exclude).
        let existing = db_changes::open_agit_change(
            self.db(),
            repo_id,
            user_id,
            &sc.base,
            &sc.topic,
            sc.trail.map(|_| trail_id),
        )
        .await?;
        let (change, revision) = match existing {
            Some(change) => {
                debug_assert_eq!(change.trail_id, trail_id);
                if let Some(current_id) = change.current_revision_id
                    && let Some(current) = db_changes::revision_by_id(self.db(), current_id).await?
                    && current.head_sha == head_sha
                {
                    // Idempotent re-push: no row, no timeline.
                    return Ok(None);
                }
                // reserve → refs → row: a visible revision always has refs.
                let revision = self
                    .append_revision(
                        repo_id,
                        trail_number,
                        &change,
                        head_sha,
                        base_tip,
                        Some(user_id),
                    )
                    .await?;
                (change, revision)
            }
            None if fresh => {
                // A fresh trail's first change is k == 1 with first revision
                // r == 1 (nothing else can allocate either): publish the refs
                // before the rows, so readers polling rows can never observe
                // this revision ref-less, and the change → current-revision
                // path stays free of git work.
                if let Err(err) = self
                    .ensure_trail_refs(repo_id, trail_number, 1, 1, head_sha)
                    .await
                {
                    tracing::warn!(repo_id, error = %err, "trail ref write failed before the rows; the mergeability job replays it");
                }
                let (row, revision) = match db_changes::insert_agit_change_with_revision(
                    self.db(),
                    trail_id,
                    &sc.base,
                    &sc.topic,
                    user_id,
                    head_sha,
                    base_tip,
                    Some(user_id),
                    now(),
                )
                .await
                {
                    Ok(t) => t,
                    Err(e) if e.is_unique_violation() => {
                        return Err(CoreError::Conflict(
                            "could not allocate a change number; please retry".into(),
                        ));
                    }
                    Err(e) => return Err(e.into()),
                };
                if (row.number, revision.number) != (1, 1) {
                    // Impossible on a fresh trail unless rows were written
                    // behind the sequence's back; re-point instead of stranding.
                    if let Err(err) = self
                        .ensure_trail_refs(
                            repo_id,
                            trail_number,
                            row.number,
                            revision.number,
                            head_sha,
                        )
                        .await
                    {
                        tracing::warn!(repo_id, change = row.number, error = %err, "trail ref write failed; the mergeability job replays it");
                    }
                }
                self.change_timeline(
                    repo_id,
                    trail_id,
                    "change.open",
                    Some(user_id),
                    serde_json::json!({
                        "change": row.number,
                        "kind": "agit",
                        "base": sc.base,
                        "topic": sc.topic,
                    }),
                )
                .await?;
                (row, revision)
            }
            None => {
                // Pinned trail: k is only known post-insert, so refs follow
                // the rows (baseline order); no test reads refs here.
                let row = self
                    .create_agit_change(repo_id, user_id, trail_id, sc)
                    .await?;
                let revision = self
                    .insert_revision_and_point(row.id, head_sha, base_tip, Some(user_id))
                    .await?;
                if let Err(err) = self
                    .ensure_trail_refs(repo_id, trail_number, row.number, revision.number, head_sha)
                    .await
                {
                    tracing::warn!(repo_id, change = row.number, error = %err, "trail ref write failed; the mergeability job replays it");
                }
                (row, revision)
            }
        };
        self.change_timeline(
            repo_id,
            trail_id,
            "change.revision",
            Some(user_id),
            serde_json::json!({
                "change": change.number,
                "revision": revision.number,
                "head": head_sha,
                "base": base_tip,
            }),
        )
        .await?;
        self.enqueue(&Job::ChangeMergeability {
            change_id: change.id,
        })
        .await?;
        Ok(Some((change.number, revision.number)))
    }

    /// Branch push: for every open branch change whose head branch is
    /// `branch`, appends a revision when the tip moved (no revision when the
    /// head SHA is unchanged, and never on a delete). Base-branch moves append
    /// no revisions but recompute mergeability for every open change targeting
    /// that base.
    pub async fn record_branch_move(
        &self,
        repo_id: i64,
        branch: &str,
        old: Option<&str>,
        new: &str,
    ) -> CoreResult<()> {
        if branch.is_empty() {
            return Err(CoreError::Invalid("branch name must not be empty".into()));
        }
        if old.is_some_and(|old| old == new) {
            return Ok(());
        }
        let live = db_repos::by_id(self.db(), repo_id)
            .await?
            .is_some_and(|row| row.deleted_at.is_none());
        if !live {
            return Ok(());
        }
        // Base moves recompute mergeability for every open change targeting
        // that base — including deletes, which otherwise leave a stale
        // verdict behind (the worker reports a missing base as conflict).
        for id in db_changes::open_change_ids_with_base(self.db(), repo_id, branch).await? {
            self.enqueue(&Job::ChangeMergeability { change_id: id })
                .await?;
        }
        if !refpolicy::is_oid(new) {
            // Deletes carry the zero oid: no revision records a deletion.
            return Ok(());
        }
        for change in db_changes::open_branch_changes(self.db(), repo_id, branch).await? {
            let current_head = match change.current_revision_id {
                Some(id) => db_changes::revision_by_id(self.db(), id)
                    .await?
                    .map(|row| row.head_sha),
                None => None,
            };
            if current_head.as_deref() == Some(new) {
                continue;
            }
            let base_tip = self.branch_tip(repo_id, &change.base_branch).await?;
            let base_sha = base_tip.as_deref().unwrap_or(new);
            let Some(trail) = db_trails::trail_by_id(self.db(), change.trail_id).await? else {
                return Err(CoreError::Internal("change has no trail".into()));
            };
            let revision = self
                .append_revision(repo_id, trail.number, &change, new, base_sha, None)
                .await?;
            self.change_timeline(
                repo_id,
                trail.id,
                "change.revision",
                None,
                serde_json::json!({
                    "change": change.number,
                    "revision": revision.number,
                    "head": new,
                    "base": base_sha,
                }),
            )
            .await?;
            self.enqueue(&Job::ChangeMergeability {
                change_id: change.id,
            })
            .await?;
        }
        Ok(())
    }

    /// Worker: recomputes one change's mergeability against its base tip. No
    /// merge base (unrelated histories) is `conflict` flagged `unrelated`; a
    /// missing base ref is `conflict` flagged `base_missing`; otherwise
    /// `git merge-tree --write-tree <base_tip> <head>` decides, exit `0` is
    /// clean and anything else reports the conflicting paths.
    ///
    /// The verdict lands on the `changes` row and, once, as a snapshot on the
    /// current revision row (later recomputes never rewrite it); a
    /// `change.mergeability` timeline row is written only when the status
    /// changes. Trail refs are replayed best-effort. A deleted change, a
    /// missing revision, or a deleted repository is a successful no-op.
    pub async fn recompute_mergeability(&self, change_id: i64) -> CoreResult<()> {
        let Some(change) = db_changes::change_by_id(self.db(), change_id).await? else {
            return Ok(());
        };
        let Some(trail) = db_trails::trail_by_id(self.db(), change.trail_id).await? else {
            return Ok(());
        };
        let live = db_repos::by_id(self.db(), trail.repo_id)
            .await?
            .is_some_and(|row| row.deleted_at.is_none());
        if !live {
            return Ok(());
        }
        let Some(revision_id) = change.current_revision_id else {
            return Ok(());
        };
        let Some(revision) = db_changes::revision_by_id(self.db(), revision_id).await? else {
            return Ok(());
        };
        let repo = self.repo_path(trail.repo_id);
        let base_branch = change.base_branch.clone();
        let head_sha = revision.head_sha.clone();
        let (base_tip, merge_base) = tokio::task::spawn_blocking(move || {
            let branches = read::branch_list(&repo)?;
            let tip = branches
                .into_iter()
                .find(|branch| branch.name == base_branch)
                .map(|branch| branch.tip.id);
            let merge_base = match &tip {
                Some(tip) => read::merge_base(&repo, &head_sha, tip)?,
                None => None,
            };
            Ok::<_, CoreError>((tip, merge_base))
        })
        .await
        .map_err(|err| CoreError::Internal(err.to_string()))??;

        let (status, paths, extra) = match (&base_tip, &merge_base) {
            (None, _) => (
                "conflict",
                Vec::new(),
                serde_json::json!({"base_missing": true}),
            ),
            (Some(_), None) => (
                "conflict",
                Vec::new(),
                serde_json::json!({"unrelated": true}),
            ),
            (Some(tip), Some(_)) => {
                let outcome =
                    merge::merge_tree(&self.repo_path(trail.repo_id), tip, &revision.head_sha)
                        .await
                        .map_err(CoreError::from)?;
                let status = if outcome.clean { "clean" } else { "conflict" };
                (status, outcome.paths, serde_json::json!({}))
            }
        };
        let payload = conflict_payload(&paths);
        db_changes::set_mergeability(self.db(), change.id, status, &payload).await?;
        if revision.mergeability == "unknown" {
            db_changes::set_revision_snapshot(
                self.db(),
                revision.id,
                merge_base.as_deref(),
                status,
                &payload,
            )
            .await?;
        }
        if change.mergeability != status {
            let mut event = serde_json::json!({
                "change": change.number,
                "from": change.mergeability,
                "to": status,
                "paths": paths,
            });
            if let Some(extra) = extra.as_object() {
                event
                    .as_object_mut()
                    .expect("event is an object")
                    .extend(extra.clone());
            }
            self.change_timeline(trail.repo_id, trail.id, "change.mergeability", None, event)
                .await?;
        }
        if let Err(err) = self
            .ensure_trail_refs(
                trail.repo_id,
                trail.number,
                change.number,
                revision.number,
                &revision.head_sha,
            )
            .await
        {
            tracing::warn!(change = change.number, error = %err, "mergeability job: trail ref replay failed");
        }
        Ok(())
    }

    /// Resolves the trail for an agit push: a pinned `-o trail=` must name an
    /// open trail in this repo (missing or closed falls back to a new trail
    /// with a timeline note); otherwise the open change's trail is reused, or
    /// a new trail titled from `-o title=` or the tip subject is created. The
    /// flag reports a trail created by this call: its first change is `k == 1`
    /// and its first revision `r == 1`, so refs can precede the rows.
    async fn resolve_ingest_trail(
        &self,
        repo_id: i64,
        user_id: i64,
        sc: &IngestSidecar,
        head_sha: &str,
    ) -> CoreResult<(db_trails::TrailRow, bool)> {
        if let Some(number) = sc.trail {
            let reason = match db_trails::trail_by_number(self.db(), repo_id, number).await? {
                Some(trail) if trail.state == "open" => return Ok((trail, false)),
                Some(_) => "closed",
                None => "missing",
            };
            let title = self.ingest_title(repo_id, sc, head_sha).await;
            return Ok((
                self.create_ingest_trail(repo_id, user_id, title, Some((number, reason)))
                    .await?,
                true,
            ));
        }
        if let Some(change) =
            db_changes::open_agit_change(self.db(), repo_id, user_id, &sc.base, &sc.topic, None)
                .await?
            && let Some(trail) = db_trails::trail_by_id(self.db(), change.trail_id).await?
        {
            return Ok((trail, false));
        }
        let title = self.ingest_title(repo_id, sc, head_sha).await;
        Ok((
            self.create_ingest_trail(repo_id, user_id, title, None)
                .await?,
            true,
        ))
    }

    /// Creates the trail for an agit push (empty intent) with its `trail.open`
    /// row, noting the requested trail when falling back from a bad pin.
    async fn create_ingest_trail(
        &self,
        repo_id: i64,
        user_id: i64,
        title: String,
        fallback: Option<(i64, &str)>,
    ) -> CoreResult<db_trails::TrailRow> {
        let trail = match db_trails::insert_trail(
            self.db(),
            &db_trails::NewTrail {
                repo_id,
                title: &title,
                intent: "",
                author_id: user_id,
            },
            now(),
        )
        .await
        {
            Ok(trail) => trail,
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Conflict(
                    "could not allocate a trail number; please retry".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        let mut event = serde_json::json!({"number": trail.number});
        if let Some((requested, reason)) = fallback {
            event["requested_trail"] = requested.into();
            event["trail_fallback"] = reason.into();
        }
        self.change_timeline(repo_id, trail.id, "trail.open", Some(user_id), event)
            .await?;
        Ok(trail)
    }

    /// New-trail title: an explicit `-o title=` wins, then the pushed commit's
    /// subject line, then the topic. Always a single trimmed line within the
    /// trail title limit.
    async fn ingest_title(&self, repo_id: i64, sc: &IngestSidecar, head_sha: &str) -> String {
        if let Some(title) = sc.title.as_deref().map(str::trim)
            && !title.is_empty()
        {
            return truncate_title(title);
        }
        let repo = self.repo_path(repo_id);
        let sha = head_sha.to_owned();
        let subject = tokio::task::spawn_blocking(move || {
            read::commit(&repo, &sha)
                .ok()
                .flatten()
                .map(|info| info.message)
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        let subject = subject.lines().next().unwrap_or("").trim();
        if subject.is_empty() {
            truncate_title(sc.topic.trim())
        } else {
            truncate_title(subject)
        }
    }

    /// Tip of `branch`, or `None` when the branch does not exist.
    async fn branch_tip(&self, repo_id: i64, branch: &str) -> CoreResult<Option<String>> {
        let repo = self.repo_path(repo_id);
        let name = branch.to_owned();
        tokio::task::spawn_blocking(move || {
            Ok::<_, CoreError>(
                read::branch_list(&repo)?
                    .into_iter()
                    .find(|branch| branch.name == name)
                    .map(|branch| branch.tip.id),
            )
        })
        .await
        .map_err(|err| CoreError::Internal(err.to_string()))?
    }

    /// Appends a revision and points the trail refs at it: reserves the number
    /// first, writes `head`/`rev/<r>`, and only then inserts the row and sets
    /// it current. Readers poll rows (never refs), so a visible revision
    /// always has its refs — a row that outruns its refs breaks the
    /// push→change→revision mapping the scan promises. A ref-write failure
    /// only warns (the mergeability job replays refs); a number collision
    /// behind the sequence is a `Conflict`, never retried in a loop.
    async fn append_revision(
        &self,
        repo_id: i64,
        trail_number: i64,
        change: &db_changes::ChangeRow,
        head_sha: &str,
        base_sha: &str,
        pusher: Option<i64>,
    ) -> CoreResult<db_changes::RevisionRow> {
        let number = match db_changes::reserve_revision_number(self.db(), change.id).await {
            Ok(number) => number,
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Conflict(
                    "could not allocate a revision number; please retry".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        if let Err(err) = self
            .ensure_trail_refs(repo_id, trail_number, change.number, number, head_sha)
            .await
        {
            tracing::warn!(repo_id, change = change.number, error = %err, "trail ref write failed; the revision row is not yet visible");
        }
        let revision = match db_changes::insert_revision_numbered(
            self.db(),
            change.id,
            number,
            head_sha,
            base_sha,
            pusher,
            now(),
        )
        .await
        {
            Ok(revision) => revision,
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Conflict(
                    "could not allocate a revision number; please retry".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        db_changes::set_current_revision(self.db(), change.id, revision.id, now()).await?;
        Ok(revision)
    }

    /// Inserts the agit change row with its `change.open` timeline row.
    async fn create_agit_change(
        &self,
        repo_id: i64,
        user_id: i64,
        trail_id: i64,
        sc: &IngestSidecar,
    ) -> CoreResult<db_changes::ChangeRow> {
        let row = match db_changes::insert_change(
            self.db(),
            trail_id,
            "agit",
            Some(&sc.topic),
            &sc.base,
            user_id,
            now(),
        )
        .await
        {
            Ok(row) => row,
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Conflict(
                    "could not allocate a change number; please retry".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        self.change_timeline(
            repo_id,
            trail_id,
            "change.open",
            Some(user_id),
            serde_json::json!({
                "change": row.number,
                "kind": "agit",
                "base": sc.base,
                "topic": sc.topic,
            }),
        )
        .await?;
        Ok(row)
    }

    /// Inserts a revision with the plain allocator and points the change at
    /// it. Use when the refs are handled by the caller (fresh-trail pre-write
    /// or pinned post-write); [`Core::append_revision`] otherwise.
    async fn insert_revision_and_point(
        &self,
        change_id: i64,
        head_sha: &str,
        base_sha: &str,
        pusher: Option<i64>,
    ) -> CoreResult<db_changes::RevisionRow> {
        let revision = match db_changes::insert_revision(
            self.db(),
            change_id,
            head_sha,
            base_sha,
            pusher,
            now(),
        )
        .await
        {
            Ok(revision) => revision,
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Conflict(
                    "could not allocate a revision number; please retry".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        db_changes::set_current_revision(self.db(), change_id, revision.id, now()).await?;
        Ok(revision)
    }

    /// Points `refs/trails/<n>/changes/<k>/{head,rev/<r>}` at `sha`.
    async fn ensure_trail_refs(
        &self,
        repo_id: i64,
        trail_number: i64,
        k: i64,
        r: i64,
        sha: &str,
    ) -> CoreResult<()> {
        let repo = self.repo_path(repo_id);
        write::set_ref(
            &repo,
            &format!("refs/trails/{trail_number}/changes/{k}/head"),
            sha,
        )
        .await?;
        write::set_ref(
            &repo,
            &format!("refs/trails/{trail_number}/changes/{k}/rev/{r}"),
            sha,
        )
        .await?;
        Ok(())
    }

    /// One timeline row on the change's trail.
    async fn change_timeline(
        &self,
        repo_id: i64,
        trail_id: i64,
        kind: &str,
        actor_id: Option<i64>,
        payload: serde_json::Value,
    ) -> CoreResult<()> {
        db_trails::insert_timeline(
            self.db(),
            repo_id,
            Some(trail_id),
            kind,
            actor_id,
            &payload.to_string(),
            now(),
        )
        .await?;
        Ok(())
    }
}

/// Single trimmed line within the trail title limit, never empty (falls back
/// to the topic, which pre-receive validated non-empty).
fn truncate_title(title: &str) -> String {
    const MAX_TITLE_CHARS: usize = 200;
    let trimmed = title.trim();
    let cut: String = trimmed.chars().take(MAX_TITLE_CHARS).collect();
    if cut.trim().is_empty() {
        "change".to_owned()
    } else {
        cut
    }
}

/// Serializes conflict paths as a JSON array, capped at
/// [`MAX_CONFLICT_PAYLOAD_BYTES`]; over-long lists shed trailing paths (the
/// merge-tree probe already caps the count).
fn conflict_payload(paths: &[String]) -> String {
    let mut kept: Vec<&str> = paths.iter().map(String::as_str).collect();
    loop {
        let payload = serde_json::to_string(&kept).unwrap_or_else(|_| "[]".to_owned());
        if payload.len() <= MAX_CONFLICT_PAYLOAD_BYTES || kept.is_empty() {
            return payload;
        }
        kept.pop();
    }
}
// ── G4: user-facing changes/reviews/threads service (M2b) ─────────────────────
//
// Reads resolve through `repo_for` (invisible repos and below-`Read` viewers
// answer `NotFound`, never leak); mutations check the action threshold and
// answer `Forbidden`. Every mutation writes exactly one timeline row on the
// change's trail (§6.2): `change.open` (new branch change, first revision
// included), `change.state`, `review.submitted`, `review.dismissed`,
// `thread.open` (the opening comment is covered by it), `thread.resolved`,
// `thread.comment`. A new branch change also enqueues `ChangeMergeability`.
// API and web handlers authenticate and delegate; no logic lives there.

use std::time::Duration;

use starforged_db::sessions as db_sessions;
use starforged_git::diff::{self, CommitDiff};

use crate::accounts::User;
use crate::content::MAX_DIFF_LINES;
use crate::permission::Permission;
use crate::repos::RepoAccess;

/// Cap on one revision diff's unified output (the compare page uses 4 MiB;
/// the change surface stays at 256 KiB total).
pub const MAX_CHANGE_DIFF_BYTES: usize = 256 * 1024;
/// Review bodies and thread comments are Markdown, capped at 64 KiB (chars,
/// mirroring the trail text cap).
pub const MAX_REVIEW_CHARS: usize = 64 * 1024;
/// Longest thread path (chars).
pub const MAX_THREAD_PATH_CHARS: usize = 1024;
/// Widest thread line span (`end - start`).
pub const MAX_THREAD_SPAN: i64 = 1000;
/// How long one revision diff may run; the caller sees `Internal` on expiry.
const DIFF_TIMEOUT: Duration = Duration::from_secs(60);

/// Flat read shape for a change.
#[derive(Debug, Clone)]
pub struct ChangeView {
    pub trail_number: i64,
    pub k: i64,
    pub kind: String,
    pub head_branch: Option<String>,
    pub base_branch: String,
    pub current_revision: i64,
    pub state: String,
    pub creator_handle: String,
    pub mergeability: String,
    pub conflict_paths: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Flat read shape for one immutable revision.
#[derive(Debug, Clone)]
pub struct RevisionView {
    pub r: i64,
    pub head_sha: String,
    pub base_sha: String,
    pub merge_base_sha: Option<String>,
    pub pusher_handle: Option<String>,
    pub created_at: i64,
    pub mergeability: String,
    pub conflict_paths: Vec<String>,
}

/// Flat read shape for a review.
#[derive(Debug, Clone)]
pub struct ReviewView {
    pub id: i64,
    pub revision: i64,
    pub author_handle: String,
    pub verdict: String,
    pub body: String,
    pub session_ulid: Option<String>,
    pub state: String,
    pub created_at: i64,
}

/// Flat read shape for a thread with its comments in insert order.
#[derive(Debug, Clone)]
pub struct ThreadView {
    pub id: i64,
    pub revision: i64,
    pub path: String,
    pub side: String,
    pub start_line: i64,
    pub end_line: i64,
    pub resolved: bool,
    pub outdated: bool,
    pub comments: Vec<ThreadCommentView>,
}

/// Flat read shape for one thread comment.
#[derive(Debug, Clone)]
pub struct ThreadCommentView {
    pub id: i64,
    pub review_id: Option<i64>,
    pub author_handle: String,
    pub body: String,
    pub created_at: i64,
}

/// Full read shape: the change, its revisions, the selected revision, whether
/// the selected diff is truncated, its discussion, and viewer capabilities.
#[derive(Debug, Clone)]
pub struct ChangeDetail {
    pub change: ChangeView,
    pub revisions: Vec<RevisionView>,
    pub selected: RevisionView,
    pub files_truncated: bool,
    pub reviews: Vec<ReviewView>,
    pub threads: Vec<ThreadView>,
    pub can_review: bool,
    pub can_triage: bool,
    pub can_close: bool,
}

/// Stored `conflict_paths` payloads are JSON arrays; corrupt rows read empty.
fn parse_paths(raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_default()
}

fn check_markdown(body: &str, what: &str) -> CoreResult<String> {
    if body.trim().is_empty() {
        return Err(CoreError::Invalid(format!("{what} must not be empty")));
    }
    if body.chars().count() > MAX_REVIEW_CHARS {
        return Err(CoreError::Invalid(format!("{what} is too long")));
    }
    Ok(body.to_owned())
}

fn check_limit(limit: Option<i64>) -> CoreResult<Option<usize>> {
    match limit {
        None => Ok(None),
        Some(l) if l >= 1 => Ok(Some(l as usize)),
        Some(_) => Err(CoreError::Invalid("limit must be positive".into())),
    }
}

impl Core {
    fn ensure_writable_g4(access: &RepoAccess) -> CoreResult<()> {
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        Ok(())
    }

    async fn change_view(&self, row: &db_changes::ChangeRow) -> CoreResult<ChangeView> {
        let trail = db_trails::trail_by_id(self.db(), row.trail_id)
            .await?
            .ok_or_else(|| CoreError::Internal("change has no trail".into()))?;
        let creator_handle = match row.creator_id {
            None => "deleted user".to_owned(),
            Some(id) => self
                .user_by_id(id)
                .await?
                .map(|u| u.handle)
                .unwrap_or_else(|| "deleted user".to_owned()),
        };
        let current_revision = match row.current_revision_id {
            None => 0,
            Some(id) => db_changes::revision_by_id(self.db(), id)
                .await?
                .map(|r| r.number)
                .unwrap_or(0),
        };
        Ok(ChangeView {
            trail_number: trail.number,
            k: row.number,
            kind: row.kind.clone(),
            head_branch: row.head_branch.clone(),
            base_branch: row.base_branch.clone(),
            current_revision,
            state: row.state.clone(),
            creator_handle,
            mergeability: row.mergeability.clone(),
            conflict_paths: parse_paths(&row.conflict_paths),
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn revision_view(&self, row: &db_changes::RevisionRow) -> CoreResult<RevisionView> {
        let pusher_handle = match row.pusher_id {
            None => None,
            Some(id) => self.user_by_id(id).await?.map(|u| u.handle),
        };
        Ok(RevisionView {
            r: row.number,
            head_sha: row.head_sha.clone(),
            base_sha: row.base_sha.clone(),
            merge_base_sha: row.merge_base_sha.clone(),
            pusher_handle,
            created_at: row.created_at,
            mergeability: row.mergeability.clone(),
            conflict_paths: parse_paths(&row.conflict_paths),
        })
    }

    async fn review_view(&self, row: &db_changes::ReviewRow) -> CoreResult<ReviewView> {
        let revision = db_changes::revision_by_id(self.db(), row.revision_id)
            .await?
            .ok_or_else(|| CoreError::Internal("review has no revision".into()))?;
        let author_handle = match row.author_id {
            None => "deleted user".to_owned(),
            Some(id) => self
                .user_by_id(id)
                .await?
                .map(|u| u.handle)
                .unwrap_or_else(|| "deleted user".to_owned()),
        };
        Ok(ReviewView {
            id: row.id,
            revision: revision.number,
            author_handle,
            verdict: row.verdict.clone(),
            body: row.body.clone(),
            session_ulid: row.session_ulid.clone(),
            state: row.state.clone(),
            created_at: row.created_at,
        })
    }

    async fn thread_comment_view(
        &self,
        row: &db_changes::ReviewCommentRow,
    ) -> CoreResult<ThreadCommentView> {
        let author_handle = match row.author_id {
            None => "deleted user".to_owned(),
            Some(id) => self
                .user_by_id(id)
                .await?
                .map(|u| u.handle)
                .unwrap_or_else(|| "deleted user".to_owned()),
        };
        Ok(ThreadCommentView {
            id: row.id,
            review_id: row.review_id,
            author_handle,
            body: row.body.clone(),
            created_at: row.created_at,
        })
    }

    /// The change plus its trail and repo access; missing rows are `NotFound`.
    async fn resolve_change(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        n: i64,
        k: i64,
    ) -> CoreResult<(RepoAccess, db_trails::TrailRow, db_changes::ChangeRow)> {
        let access = self.repo_for(viewer, owner, repo).await?;
        let trail = db_trails::trail_by_number(self.db(), access.repo.id, n)
            .await?
            .ok_or(CoreError::NotFound)?;
        let change = db_changes::change_by_trail_number(self.db(), trail.id, k)
            .await?
            .ok_or(CoreError::NotFound)?;
        Ok((access, trail, change))
    }

    /// `None` selects the current revision; unknown numbers are `NotFound`.
    async fn resolve_revision(
        &self,
        change: &db_changes::ChangeRow,
        r: Option<i64>,
    ) -> CoreResult<db_changes::RevisionRow> {
        match r {
            Some(r) => db_changes::revision_by_number(self.db(), change.id, r)
                .await?
                .ok_or(CoreError::NotFound),
            None => match change.current_revision_id {
                Some(id) => db_changes::revision_by_id(self.db(), id)
                    .await?
                    .ok_or(CoreError::NotFound),
                None => Err(CoreError::NotFound),
            },
        }
    }

    /// Tips of `branches` in one blocking call: `(found, missing)` by name.
    async fn branch_tips(
        &self,
        repo_id: i64,
        head: &str,
        base: &str,
    ) -> CoreResult<(String, String)> {
        let repo = self.repo_path(repo_id);
        let (head_name, base_name) = (head.to_owned(), base.to_owned());
        let branches = tokio::task::spawn_blocking(move || read::branch_list(&repo))
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))??;
        let tip = |name: &str| {
            branches
                .iter()
                .find(|b| b.name == name)
                .map(|b| b.tip.id.clone())
        };
        match (tip(&head_name), tip(&base_name)) {
            (Some(h), Some(b)) => Ok((h, b)),
            (None, _) => Err(CoreError::Invalid(format!(
                "unknown head branch '{head_name}'"
            ))),
            (_, None) => Err(CoreError::Invalid(format!(
                "unknown base branch '{base_name}'"
            ))),
        }
    }

    /// `None` passes; `Some` must name an existing, non-quarantined session
    /// row in this repo — anything else is `Invalid` (422, never 404: ULIDs
    /// stay undiscoverable).
    async fn check_session(
        &self,
        repo_id: i64,
        session: Option<&str>,
    ) -> CoreResult<Option<String>> {
        let Some(raw) = session else {
            return Ok(None);
        };
        let value = raw.trim();
        if value.parse::<ulid::Ulid>().is_err() {
            return Err(CoreError::Invalid(format!("unknown session '{value}'")));
        }
        let row = db_sessions::session_by_ulid(self.db(), repo_id, value)
            .await?
            .ok_or_else(|| CoreError::Invalid(format!("unknown session '{value}'")))?;
        if row.quarantine == "quarantined" {
            return Err(CoreError::Invalid("session is quarantined".into()));
        }
        Ok(Some(value.to_owned()))
    }

    /// Creates a `branch`-kind change tracking `head` against `base`.
    /// Triage+; both branches must exist and differ; one open change per
    /// head branch (a second would double-revise on every push). Writes the
    /// first revision (`r == 1`), points the trail refs at it (best-effort),
    /// audits `change.open`, and enqueues `ChangeMergeability`.
    pub async fn create_branch_change(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        head: &str,
        base: &str,
    ) -> CoreResult<ChangeView> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Triage)
            .await?;
        Self::ensure_writable_g4(&access)?;
        let trail = db_trails::trail_by_number(self.db(), access.repo.id, trail_n)
            .await?
            .ok_or(CoreError::NotFound)?;
        if trail.state != "open" {
            return Err(CoreError::Invalid("trail is closed".into()));
        }
        let head = head.trim();
        let base = base.trim();
        if head.is_empty() || base.is_empty() {
            return Err(CoreError::Invalid(
                "head and base branches must not be empty".into(),
            ));
        }
        if head == base {
            return Err(CoreError::Invalid(
                "head and base branches must differ".into(),
            ));
        }
        if !db_changes::open_branch_changes(self.db(), access.repo.id, head)
            .await?
            .is_empty()
        {
            return Err(CoreError::Invalid(format!(
                "a change already tracks branch '{head}'"
            )));
        }
        let (head_tip, base_tip) = self.branch_tips(access.repo.id, head, base).await?;
        let row = match db_changes::insert_change(
            self.db(),
            trail.id,
            "branch",
            Some(head),
            base,
            user.id,
            now(),
        )
        .await
        {
            Ok(row) => row,
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Conflict(
                    "could not allocate a change number; please retry".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        let revision = match db_changes::insert_revision(
            self.db(),
            row.id,
            &head_tip,
            &base_tip,
            Some(user.id),
            now(),
        )
        .await
        {
            Ok(revision) => revision,
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Conflict(
                    "could not allocate a revision number; please retry".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        db_changes::set_current_revision(self.db(), row.id, revision.id, now()).await?;
        if let Err(err) = self
            .ensure_trail_refs(
                access.repo.id,
                trail.number,
                row.number,
                revision.number,
                &head_tip,
            )
            .await
        {
            tracing::warn!(repo = access.repo.id, change = row.number, error = %err, "trail ref write failed; the mergeability job replays it");
        }
        self.change_timeline(
            access.repo.id,
            trail.id,
            "change.open",
            Some(user.id),
            serde_json::json!({
                "change": row.number,
                "kind": "branch",
                "base": base,
                "head": head,
            }),
        )
        .await?;
        self.enqueue(&Job::ChangeMergeability { change_id: row.id })
            .await?;
        self.change_view(
            &db_changes::change_by_id(self.db(), row.id)
                .await?
                .ok_or_else(|| CoreError::Internal("change vanished".into()))?,
        )
        .await
    }

    /// Changes of the trail in ascending `k` order.
    pub async fn list_changes(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        limit: Option<i64>,
    ) -> CoreResult<Vec<ChangeView>> {
        let access = self.repo_for(viewer, owner, repo).await?;
        let trail = db_trails::trail_by_number(self.db(), access.repo.id, trail_n)
            .await?
            .ok_or(CoreError::NotFound)?;
        let take = check_limit(limit)?;
        let mut out = Vec::new();
        for row in db_changes::changes_of_trail(self.db(), trail.id).await? {
            if take.is_some_and(|n| out.len() >= n) {
                break;
            }
            out.push(self.change_view(&row).await?);
        }
        Ok(out)
    }

    /// The full detail: change, revisions, selected revision, whether the
    /// selected diff is truncated, discussion, and viewer capabilities.
    pub async fn get_change(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        rev: Option<i64>,
    ) -> CoreResult<ChangeDetail> {
        let (access, _, change) = self.resolve_change(viewer, owner, repo, trail_n, k).await?;
        let selected_row = self.resolve_revision(&change, rev).await?;
        let mut revisions = Vec::new();
        for row in db_changes::revisions_of_change(self.db(), change.id).await? {
            revisions.push(self.revision_view(&row).await?);
        }
        let selected = self.revision_view(&selected_row).await?;
        let diff = self.diff_for(&access, &selected_row).await?;
        let mut reviews = Vec::new();
        for row in db_changes::reviews_of_change(self.db(), change.id).await? {
            reviews.push(self.review_view(&row).await?);
        }
        let threads = self.thread_views(&access, &change).await?;
        let triage = access.permission >= Permission::Triage;
        let can_close = match viewer {
            None => false,
            Some(u) => triage || change.creator_id == Some(u.id),
        };
        Ok(ChangeDetail {
            change: self.change_view(&change).await?,
            revisions,
            selected,
            files_truncated: diff.truncated,
            reviews,
            threads,
            can_review: viewer.is_some(),
            can_triage: triage,
            can_close,
        })
    }

    /// Unified diff from the revision's merge base to its head, within
    /// [`MAX_DIFF_LINES`] and [`MAX_CHANGE_DIFF_BYTES`]. Unrelated histories
    /// diff `base_sha..head_sha` directly. Runs on blocking threads (never a
    /// worktree) with a 60s timeout.
    pub async fn change_diff_files(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        rev: Option<i64>,
    ) -> CoreResult<CommitDiff> {
        let (access, _, change) = self.resolve_change(viewer, owner, repo, trail_n, k).await?;
        let revision = self.resolve_revision(&change, rev).await?;
        self.diff_for(&access, &revision).await
    }

    async fn diff_for(
        &self,
        access: &RepoAccess,
        revision: &db_changes::RevisionRow,
    ) -> CoreResult<CommitDiff> {
        let repo = self.repo_path(access.repo.id);
        let (head, base) = (revision.head_sha.clone(), revision.base_sha.clone());
        let probe = repo.clone();
        let base_probe = base.clone();
        let merge_base =
            tokio::task::spawn_blocking(move || read::merge_base(&probe, &head, &base_probe))
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))??;
        let from = merge_base.unwrap_or(base);
        let (head_id, from_id) = (revision.head_sha.clone(), from);
        tokio::time::timeout(
            DIFF_TIMEOUT,
            diff::range_diff(
                &repo,
                &from_id,
                &head_id,
                MAX_DIFF_LINES,
                MAX_CHANGE_DIFF_BYTES,
            ),
        )
        .await
        .map_err(|_| CoreError::Internal("diff timed out".into()))?
        .map_err(CoreError::from)
    }

    /// Submits a review on `r` (default: current). Any ≥ `Read` viewer may
    /// submit any verdict — gate counting (write+ only) is M2c's problem.
    /// Audits `review.submitted`.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_review(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        r: Option<i64>,
        verdict: &str,
        body: &str,
        session: Option<&str>,
    ) -> CoreResult<ReviewView> {
        let (access, trail, change) = self
            .resolve_change(Some(user), owner, repo, trail_n, k)
            .await?;
        Self::ensure_writable_g4(&access)?;
        let revision = self.resolve_revision(&change, r).await?;
        if !matches!(verdict, "approve" | "request_changes" | "comment") {
            return Err(CoreError::Invalid(format!("invalid verdict '{verdict}'")));
        }
        let body = check_markdown(body, "review body")?;
        let session = self.check_session(access.repo.id, session).await?;
        let row = db_changes::insert_review(
            self.db(),
            change.id,
            revision.id,
            user.id,
            verdict,
            &body,
            session.as_deref(),
            now(),
        )
        .await?;
        self.change_timeline(
            access.repo.id,
            trail.id,
            "review.submitted",
            Some(user.id),
            serde_json::json!({
                "change": change.number,
                "review": row.id,
                "revision": revision.number,
                "verdict": verdict,
            }),
        )
        .await?;
        self.review_view(&row).await
    }

    /// Reviews of the change in submission order.
    pub async fn list_reviews(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        limit: Option<i64>,
    ) -> CoreResult<Vec<ReviewView>> {
        let (_, _, change) = self.resolve_change(viewer, owner, repo, trail_n, k).await?;
        let take = check_limit(limit)?;
        let mut out = Vec::new();
        for row in db_changes::reviews_of_change(self.db(), change.id).await? {
            if take.is_some_and(|n| out.len() >= n) {
                break;
            }
            out.push(self.review_view(&row).await?);
        }
        Ok(out)
    }

    /// Dismisses a submitted review. Triage+; the author alone is `Forbidden`.
    /// Audits `review.dismissed`.
    pub async fn dismiss_review(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        review_id: i64,
    ) -> CoreResult<ReviewView> {
        let (access, trail, change) = self
            .resolve_change(Some(user), owner, repo, trail_n, k)
            .await?;
        Self::ensure_writable_g4(&access)?;
        if access.permission < Permission::Triage {
            return Err(CoreError::Forbidden);
        }
        let row = db_changes::reviews_of_change(self.db(), change.id)
            .await?
            .into_iter()
            .find(|r| r.id == review_id)
            .ok_or(CoreError::NotFound)?;
        if row.state != "dismissed" {
            db_changes::set_review_state(self.db(), row.id, "dismissed").await?;
            self.change_timeline(
                access.repo.id,
                trail.id,
                "review.dismissed",
                Some(user.id),
                serde_json::json!({ "change": change.number, "review": row.id }),
            )
            .await?;
        }
        let row = db_changes::reviews_of_change(self.db(), change.id)
            .await?
            .into_iter()
            .find(|r| r.id == review_id)
            .ok_or(CoreError::NotFound)?;
        self.review_view(&row).await
    }

    /// Opens a thread anchored at `r` (default: current) with `body` as its
    /// first comment. Any ≥ `Read` viewer. Audits one `thread.open` row.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_thread(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        r: Option<i64>,
        path: &str,
        side: &str,
        start: i64,
        end: i64,
        body: &str,
    ) -> CoreResult<ThreadView> {
        let (access, trail, change) = self
            .resolve_change(Some(user), owner, repo, trail_n, k)
            .await?;
        Self::ensure_writable_g4(&access)?;
        let revision = self.resolve_revision(&change, r).await?;
        let path = path.trim();
        if path.is_empty() || path.chars().count() > MAX_THREAD_PATH_CHARS {
            return Err(CoreError::Invalid("thread path is invalid".into()));
        }
        if !matches!(side, "base" | "head") {
            return Err(CoreError::Invalid(format!("invalid thread side '{side}'")));
        }
        if start < 1 || end < start || end - start > MAX_THREAD_SPAN {
            return Err(CoreError::Invalid("thread lines are invalid".into()));
        }
        let body = check_markdown(body, "thread body")?;
        let thread = db_changes::insert_thread(
            self.db(),
            change.id,
            revision.id,
            path,
            side,
            start,
            end,
            now(),
        )
        .await?;
        db_changes::insert_thread_comment(self.db(), thread.id, None, user.id, &body, now())
            .await?;
        self.change_timeline(
            access.repo.id,
            trail.id,
            "thread.open",
            Some(user.id),
            serde_json::json!({
                "change": change.number,
                "thread": thread.id,
                "revision": revision.number,
                "path": path,
                "side": side,
                "start_line": start,
                "end_line": end,
            }),
        )
        .await?;
        self.thread_view(&access, &change, &thread).await
    }

    /// Threads of the change in creation order, with outdated flags.
    pub async fn list_threads(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        limit: Option<i64>,
    ) -> CoreResult<Vec<ThreadView>> {
        let (access, _, change) = self.resolve_change(viewer, owner, repo, trail_n, k).await?;
        let take = check_limit(limit)?;
        let mut out = Vec::new();
        for row in db_changes::threads_of_change(self.db(), change.id).await? {
            if take.is_some_and(|n| out.len() >= n) {
                break;
            }
            out.push(self.thread_view(&access, &change, &row).await?);
        }
        Ok(out)
    }

    async fn thread_views(
        &self,
        access: &RepoAccess,
        change: &db_changes::ChangeRow,
    ) -> CoreResult<Vec<ThreadView>> {
        let mut out = Vec::new();
        for row in db_changes::threads_of_change(self.db(), change.id).await? {
            out.push(self.thread_view(access, change, &row).await?);
        }
        Ok(out)
    }

    async fn thread_view(
        &self,
        access: &RepoAccess,
        change: &db_changes::ChangeRow,
        thread: &db_changes::ThreadRow,
    ) -> CoreResult<ThreadView> {
        let anchor = db_changes::revision_by_id(self.db(), thread.anchor_revision_id)
            .await?
            .ok_or_else(|| CoreError::Internal("thread has no revision".into()))?;
        let mut comments = Vec::new();
        for row in db_changes::comments_of_thread(self.db(), thread.id).await? {
            comments.push(self.thread_comment_view(&row).await?);
        }
        let outdated = self
            .thread_outdated(access, change, thread, &anchor)
            .await?;
        Ok(ThreadView {
            id: thread.id,
            revision: anchor.number,
            path: thread.path.clone(),
            side: thread.side.clone(),
            start_line: thread.start_line,
            end_line: thread.end_line,
            resolved: thread.resolved != 0,
            outdated,
            comments,
        })
    }

    /// A thread is outdated iff its anchor is not the current revision AND
    /// its lines no longer exist there: the file is missing, `end_line`
    /// exceeds the file's line count, or the blob is binary. Computed from
    /// one `blob_bytes` call per distinct (side-SHA, path) — content equality
    /// is never checked.
    async fn thread_outdated(
        &self,
        access: &RepoAccess,
        change: &db_changes::ChangeRow,
        thread: &db_changes::ThreadRow,
        anchor: &db_changes::RevisionRow,
    ) -> CoreResult<bool> {
        let current_id = match change.current_revision_id {
            Some(id) => id,
            None => return Ok(false),
        };
        if anchor.id == current_id {
            return Ok(false);
        }
        let current = db_changes::revision_by_id(self.db(), current_id)
            .await?
            .ok_or_else(|| CoreError::Internal("change has no current revision".into()))?;
        let sha = if thread.side == "head" {
            current.head_sha.clone()
        } else {
            current
                .merge_base_sha
                .clone()
                .unwrap_or_else(|| current.base_sha.clone())
        };
        let repo = self.repo_path(access.repo.id);
        let (path, side_sha) = (thread.path.clone(), sha);
        let blob = tokio::task::spawn_blocking(move || read::blob_bytes(&repo, &side_sha, &path))
            .await
            .map_err(|e| CoreError::Internal(e.to_string()))??;
        let Some(bytes) = blob else {
            return Ok(true);
        };
        if bytes.iter().take(8000).any(|&b| b == 0) {
            return Ok(true);
        }
        let mut lines = bytes.iter().filter(|&&b| b == b'\n').count() as i64;
        if !bytes.is_empty() && *bytes.last().unwrap() != b'\n' {
            lines += 1;
        }
        Ok(thread.end_line > lines)
    }

    /// Resolves or reopens a thread. The thread author (first comment) or
    /// triage+. Audits `thread.resolved`.
    #[allow(clippy::too_many_arguments)]
    pub async fn resolve_thread(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        thread_id: i64,
        resolved: bool,
    ) -> CoreResult<ThreadView> {
        let (access, trail, change) = self
            .resolve_change(Some(user), owner, repo, trail_n, k)
            .await?;
        Self::ensure_writable_g4(&access)?;
        let thread = db_changes::threads_of_change(self.db(), change.id)
            .await?
            .into_iter()
            .find(|t| t.id == thread_id)
            .ok_or(CoreError::NotFound)?;
        let author = db_changes::comments_of_thread(self.db(), thread.id)
            .await?
            .into_iter()
            .next()
            .and_then(|c| c.author_id);
        if author != Some(user.id) && access.permission < Permission::Triage {
            return Err(CoreError::Forbidden);
        }
        if (thread.resolved != 0) != resolved {
            db_changes::set_thread_resolved(self.db(), thread.id, i64::from(resolved)).await?;
            self.change_timeline(
                access.repo.id,
                trail.id,
                "thread.resolved",
                Some(user.id),
                serde_json::json!({
                    "change": change.number,
                    "thread": thread.id,
                    "resolved": resolved,
                }),
            )
            .await?;
        }
        let thread = db_changes::threads_of_change(self.db(), change.id)
            .await?
            .into_iter()
            .find(|t| t.id == thread_id)
            .ok_or(CoreError::NotFound)?;
        self.thread_view(&access, &change, &thread).await
    }

    /// Appends a comment to a thread. Any ≥ `Read` viewer. `review_id`, when
    /// given, must name a review on the same change. Audits `thread.comment`.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_thread_comment(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        thread_id: i64,
        body: &str,
        review_id: Option<i64>,
    ) -> CoreResult<ThreadCommentView> {
        let (access, trail, change) = self
            .resolve_change(Some(user), owner, repo, trail_n, k)
            .await?;
        Self::ensure_writable_g4(&access)?;
        let thread = db_changes::threads_of_change(self.db(), change.id)
            .await?
            .into_iter()
            .find(|t| t.id == thread_id)
            .ok_or(CoreError::NotFound)?;
        if let Some(id) = review_id {
            let known = db_changes::reviews_of_change(self.db(), change.id)
                .await?
                .iter()
                .any(|r| r.id == id);
            if !known {
                return Err(CoreError::Invalid("unknown review".into()));
            }
        }
        let body = check_markdown(body, "comment body")?;
        let row = db_changes::insert_thread_comment(
            self.db(),
            thread.id,
            review_id,
            user.id,
            &body,
            now(),
        )
        .await?;
        self.change_timeline(
            access.repo.id,
            trail.id,
            "thread.comment",
            Some(user.id),
            serde_json::json!({
                "change": change.number,
                "thread": thread.id,
                "comment": row.id,
            }),
        )
        .await?;
        self.thread_comment_view(&row).await
    }

    /// Closes or reopens a change. Only `open`/`closed` — `merged` is owned
    /// by the merge path (M2c) and rejected everywhere here. Allowed for the
    /// creator (holding ≥ `Read`) or triage+. Audits `change.state`.
    pub async fn set_change_state(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        state: &str,
    ) -> CoreResult<ChangeView> {
        let (access, trail, change) = self
            .resolve_change(Some(user), owner, repo, trail_n, k)
            .await?;
        Self::ensure_writable_g4(&access)?;
        if state == "merged" {
            return Err(CoreError::Invalid(
                "the merge path owns the 'merged' transition".into(),
            ));
        }
        if !matches!(state, "open" | "closed") {
            return Err(CoreError::Invalid(format!(
                "invalid change state '{state}'"
            )));
        }
        let triage = access.permission >= Permission::Triage;
        if change.creator_id != Some(user.id) && !triage {
            return Err(CoreError::Forbidden);
        }
        if change.state != state {
            db_changes::set_change_state(self.db(), change.id, state, now()).await?;
            self.change_timeline(
                access.repo.id,
                trail.id,
                "change.state",
                Some(user.id),
                serde_json::json!({
                    "change": change.number,
                    "from": change.state,
                    "to": state,
                }),
            )
            .await?;
        }
        let row = db_changes::change_by_id(self.db(), change.id)
            .await?
            .ok_or_else(|| CoreError::Internal("change vanished".into()))?;
        self.change_view(&row).await
    }

    /// Replaces the `refs/for` access mode. Maintain+ via the existing
    /// repo-settings power.
    pub async fn set_refs_for_access(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        value: &str,
    ) -> CoreResult<String> {
        if !matches!(value, "anyone_with_read" | "members") {
            return Err(CoreError::Invalid(format!(
                "invalid refs_for_access '{value}'"
            )));
        }
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        db_repos::set_refs_for_access(self.db(), access.repo.id, value).await?;
        Ok(value.to_owned())
    }

    /// Revisions of one change in ascending order (for `GET …/revisions`).
    pub async fn list_revisions(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        limit: Option<i64>,
    ) -> CoreResult<Vec<RevisionView>> {
        let (_, _, change) = self.resolve_change(viewer, owner, repo, trail_n, k).await?;
        let take = check_limit(limit)?;
        let mut out = Vec::new();
        for row in db_changes::revisions_of_change(self.db(), change.id).await? {
            if take.is_some_and(|n| out.len() >= n) {
                break;
            }
            out.push(self.revision_view(&row).await?);
        }
        Ok(out)
    }
}

impl Core {
    /// The `…/diff` and revision-detail payload: file metadata with unified hunks
    /// (binary/capped files carry empty hunks, never raw bytes) plus a top-level
    /// truncation flag. Kept in core because only core may name `git` types —
    /// the API embeds the value verbatim.
    pub async fn change_diff_json(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        rev: Option<i64>,
    ) -> CoreResult<serde_json::Value> {
        Ok(diff_json(
            &self
                .change_diff_files(viewer, owner, repo, trail_n, k, rev)
                .await?,
        ))
    }
}

fn diff_json(diff: &CommitDiff) -> serde_json::Value {
    serde_json::json!({
        "files": diff.files.iter().map(file_json).collect::<Vec<_>>(),
        "truncated": diff.truncated,
    })
}

fn file_json(f: &starforged_git::diff::FileDiff) -> serde_json::Value {
    use starforged_git::diff::{FileStatus, LineKind};
    let status = match f.status {
        FileStatus::Added => "added",
        FileStatus::Deleted => "deleted",
        FileStatus::Modified => "modified",
        FileStatus::Renamed => "renamed",
    };
    let hunks = f
        .hunks
        .iter()
        .map(|h| {
            serde_json::json!({
                "header": h.header,
                "lines": h.lines.iter().map(|l| {
                    let kind = match l.kind {
                        LineKind::Context => "context",
                        LineKind::Added => "added",
                        LineKind::Removed => "removed",
                        LineKind::NoNewline => "no_newline",
                    };
                    serde_json::json!({
                        "kind": kind,
                        "old_line": l.old_line,
                        "new_line": l.new_line,
                        "text": l.text,
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "path": f.display_path(),
        "status": status,
        "binary": f.binary,
        "hunks": hunks,
    })
}
