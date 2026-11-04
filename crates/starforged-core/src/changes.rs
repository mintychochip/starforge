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

        let existing = db_changes::open_agit_change(
            self.db(),
            repo_id,
            user_id,
            &sc.base,
            &sc.topic,
            sc.trail,
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
        if !refpolicy::is_oid(new) {
            // Deletes carry the zero oid: no revision records a deletion.
            return Ok(());
        }
        let live = db_repos::by_id(self.db(), repo_id)
            .await?
            .is_some_and(|row| row.deleted_at.is_none());
        if !live {
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
        for id in db_changes::open_change_ids_with_base(self.db(), repo_id, branch).await? {
            self.enqueue(&Job::ChangeMergeability { change_id: id })
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
