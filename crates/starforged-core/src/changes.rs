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

use crate::gates::pattern_matches;
use crate::jobs::Job;
use crate::webhooks::HookEvent;
use crate::{Core, CoreError, CoreResult};
use starforged_db::{
    changes as db_changes, checks as db_checks, now, repos as db_repos, trails as db_trails,
};
use starforged_git::{merge, read, refpolicy, write};

/// One ref motion observed by the post-receive scan: the full refname and
/// the before/after oids. A zero oid marks a create (`old`) or a delete
/// (`new`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub name: String,
    pub old: String,
    pub new: String,
}

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
        let is_new = existing.is_none();
        let (change, revision) = match existing {
            Some(change) => {
                debug_assert_eq!(change.trail_id, trail_id);
                if let Some(latest) =
                    db_changes::latest_revision_of_change(self.db(), change.id).await?
                    && latest.head_sha == head_sha
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
                // Walk the commit range before the transaction so the cached
                // commits land atomically with the revision and its pointer:
                // a revision that is current always has its commits recorded,
                // or flag 0 after a git failure for the backfill.
                let commits = self
                    .walk_revision_commits(repo_id, base_tip, head_sha)
                    .await;
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
                    commits.as_deref(),
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
                self.dispatch_trail_event(
                    repo_id,
                    self.sender_of(user_id).await,
                    Some("updated"),
                    Some("change_opened"),
                    trail_number,
                    Some(serde_json::json!({"k": row.number, "revision": revision.number})),
                )
                .await;
                (row, revision)
            }
            None => {
                // Pinned trail: k is only known post-insert, so refs follow
                // the rows (baseline order); no test reads refs here.
                let row = self
                    .create_agit_change(repo_id, user_id, trail_id, sc)
                    .await?;
                let revision = self
                    .insert_revision_and_point(repo_id, row.id, head_sha, base_tip, Some(user_id))
                    .await?;
                if let Err(err) = self
                    .ensure_trail_refs(repo_id, trail_number, row.number, revision.number, head_sha)
                    .await
                {
                    tracing::warn!(repo_id, change = row.number, error = %err, "trail ref write failed; the mergeability job replays it");
                }
                self.dispatch_trail_event(
                    repo_id,
                    self.sender_of(user_id).await,
                    Some("updated"),
                    Some("change_opened"),
                    trail_number,
                    Some(serde_json::json!({"k": row.number, "revision": revision.number})),
                )
                .await;
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
        // A new change already fanned out `change_opened` above: only a
        // revision appended to an existing change fans out `revision_pushed`.
        if !is_new {
            self.dispatch_trail_event(
                repo_id,
                self.sender_of(user_id).await,
                Some("updated"),
                Some("revision_pushed"),
                trail_number,
                Some(serde_json::json!({"k": change.number, "revision": revision.number})),
            )
            .await;
        }
        Ok(Some((change.number, revision.number)))
    }
    /// Push fan-out (spec §10.4 D2): emits one `push` event per heads/tags
    /// update (create, update, delete). `refs/for/*` (reported as `trail`)
    /// and `refs/trails/*` (server-internal) never emit. Does not replace
    /// [`Core::record_branch_move`]'s work; githttp calls both. Never fails
    /// the caller: unknown repos and deleted repos skip silently, and
    /// dispatch itself never fails.
    pub async fn record_push(&self, repo_id: i64, pusher: Option<&User>, updates: &[RefUpdate]) {
        let live = db_repos::by_id(self.db(), repo_id)
            .await
            .is_ok_and(|row| row.is_some_and(|row| row.deleted_at.is_none()));
        if !live {
            return;
        }
        let sender = pusher.map(|user| user.handle.clone());
        for update in updates {
            if !update.name.starts_with("refs/heads/") && !update.name.starts_with("refs/tags/") {
                continue;
            }
            let zero_old = refpolicy::is_zero_oid(&update.old);
            let zero_new = refpolicy::is_zero_oid(&update.new);
            if zero_old && zero_new {
                continue;
            }
            self.dispatch_event(
                repo_id,
                HookEvent {
                    event: "push",
                    action: None,
                    cause: None,
                    sender: sender.clone(),
                    subject: serde_json::json!({
                        "ref": update.name,
                        "before": update.old,
                        "after": update.new,
                        "created": zero_old && !zero_new,
                        "deleted": !zero_old && zero_new,
                        "pusher": sender,
                    }),
                },
            )
            .await;
        }
    }

    /// Serialized branch-move ingest for one push (D1). Call with the repo's
    /// ingest lock held — the `_ingest` guard is proof of that. Every moved
    /// branch is ingested at its CURRENT tip, re-read under the lock: the
    /// push line's `new` may be stale when scans race, and the pointer must
    /// never land on an older head. Branches that no longer exist are
    /// skipped (a delete still runs when its `new` is the zero oid, so
    /// base-branch deletions recompute mergeability). Per-branch failures
    /// only warn: a push never fails because of the scan.
    pub async fn ingest_branch_moves(
        &self,
        _ingest: &tokio::sync::OwnedMutexGuard<()>,
        repo_id: i64,
        pusher_id: Option<i64>,
        moves: &[(String, Option<String>, String)],
    ) {
        for (name, old, new) in moves {
            let Some(branch) = name.strip_prefix("refs/heads/") else {
                continue;
            };
            let tip = match self.branch_tip(repo_id, branch).await {
                Ok(tip) => tip,
                Err(err) => {
                    tracing::warn!(repo_id, branch, error = %err, "push scan: branch tip read failed");
                    continue;
                }
            };
            let new = tip.as_deref().unwrap_or(new);
            if tip.is_none() && refpolicy::is_oid(new) {
                // The branch vanished mid-scan while the line claims an
                // update: recording the line's head would point at a ref
                // that no longer exists.
                continue;
            }
            if let Err(err) = self
                .record_branch_move(repo_id, branch, old.as_deref(), new, pusher_id)
                .await
            {
                tracing::warn!(repo_id, branch, error = %err, "push scan: branch move ingest failed");
            }
        }
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
        pusher_id: Option<i64>,
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
            // Compare against the LATEST row, never the current-revision
            // pointer: a row that landed without moving the pointer (or a
            // stale pointer in general) must not be recorded twice.
            let latest_head = db_changes::latest_revision_of_change(self.db(), change.id)
                .await?
                .map(|row| row.head_sha);
            if latest_head.as_deref() == Some(new) {
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
            self.dispatch_trail_event(
                repo_id,
                match pusher_id {
                    Some(id) => self.sender_of(id).await,
                    None => None,
                },
                Some("updated"),
                Some("revision_pushed"),
                trail.number,
                Some(serde_json::json!({"k": change.number, "revision": revision.number})),
            )
            .await;
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

    /// Appends a revision and points the trail refs at it: returns the
    /// latest row unchanged when it already carries `head_sha` (no row, no
    /// dismissals, no timeline, no webhook), otherwise reserves the number
    /// first, writes `head`/`rev/<r>`, and only then inserts the row, records
    /// its commits, and sets it current. A revision that is current always
    /// has its commits recorded, or flag 0 after a git failure for the
    /// backfill. Readers poll rows (never refs), so a visible revision always
    /// has its refs — a row that outruns its refs breaks the
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
        // Never append a head equal to the latest row's head: with a stale
        // current-revision pointer (or a racing scan) this call would
        // otherwise record the same head twice. The existing row is
        // returned with no dismissals, no timeline, and no webhook, so
        // every caller is covered.
        if let Some(latest) = db_changes::latest_revision_of_change(self.db(), change.id).await?
            && latest.head_sha == head_sha
        {
            return Ok(latest);
        }
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
        // Record the commits BEFORE moving the current-revision pointer: a
        // revision that is current always has its commits recorded, or flag 0
        // after a git failure for the backfill. Readers (Sessions tab,
        // timeline) polling the pointer depend on this order.
        self.record_revision_commits(repo_id, &revision).await;
        db_changes::set_current_revision(self.db(), change.id, revision.id, now()).await?;
        self.dismiss_stale_reviews(repo_id, trail_number, change, &revision)
            .await?;
        Ok(revision)
    }

    /// Maximum cached commits per revision (D2): the newest are kept.
    /// (The git wrapper reports truncation so over-long ranges warn.)
    pub(crate) const MAX_REVISION_COMMITS: usize = 250;

    /// Walks the revision's commit range (reachable from the head and not
    /// from `from`), newest first with the head at position 0. `None` when
    /// git fails (callers leave the flag at 0 for the backfill); over-long
    /// ranges warn and truncate to the newest [`Self::MAX_REVISION_COMMITS`].
    async fn walk_revision_commits(
        &self,
        repo_id: i64,
        from: &str,
        head: &str,
    ) -> Option<Vec<(String, String)>> {
        let repo = self.repo_path(repo_id);
        let (from, head) = (from.to_owned(), head.to_owned());
        let walked = tokio::task::spawn_blocking(move || {
            read::rev_list_capped(&repo, &from, &head, Self::MAX_REVISION_COMMITS)
        })
        .await;
        let (commits, truncated) = match walked {
            Ok(Ok(walked)) => walked,
            Ok(Err(err)) => {
                tracing::warn!(repo_id, error = %err, "revision commit walk failed; the backfill will retry");
                return None;
            }
            Err(err) => {
                tracing::warn!(repo_id, error = %err, "revision commit walk panicked; the backfill will retry");
                return None;
            }
        };
        if truncated {
            tracing::warn!(
                repo_id,
                kept = Self::MAX_REVISION_COMMITS,
                "revision exceeds the commit cache cap; keeping the newest"
            );
        }
        Some(
            commits
                .into_iter()
                .map(|rev| (rev.sha, rev.subject))
                .collect(),
        )
    }

    /// Caches the revision's commits (reachable from the head and not from
    /// the merge base — or the base SHA when no merge base is known) and
    /// marks it recorded. Git and store failures only warn and leave the
    /// flag at 0 for the backfill; never fails the caller.
    async fn record_revision_commits(&self, repo_id: i64, revision: &db_changes::RevisionRow) {
        let from = revision
            .merge_base_sha
            .clone()
            .unwrap_or_else(|| revision.base_sha.clone());
        let revision_id = revision.id;
        let Some(commits) = self
            .walk_revision_commits(repo_id, &from, &revision.head_sha)
            .await
        else {
            return;
        };
        if let Err(err) = db_changes::store_revision_commits(self.db(), revision_id, &commits).await
        {
            tracing::warn!(repo_id, revision = revision_id, error = %err, "revision commit store failed; the backfill will retry");
        }
    }

    /// Backfills one unrecorded revision (the hourly maintenance pass's work
    /// item): reuses the merge base once the mergeability worker resolved it.
    /// Missing rows and recorded revisions are successful no-ops; git and
    /// store failures only warn (the flag stays 0 for the next pass).
    pub(crate) async fn backfill_revision_commits(&self, revision_id: i64) -> CoreResult<()> {
        let Some(revision) = db_changes::revision_by_id(self.db(), revision_id).await? else {
            return Ok(());
        };
        if revision.commits_recorded != 0 {
            return Ok(());
        }
        let Some(change) = db_changes::change_by_id(self.db(), revision.change_id).await? else {
            return Ok(());
        };
        let Some(trail) = db_trails::trail_by_id(self.db(), change.trail_id).await? else {
            return Ok(());
        };
        self.record_revision_commits(trail.repo_id, &revision).await;
        Ok(())
    }

    /// The D2 `review` subject for a dismissal: the review's identity and
    /// content plus the state it moved to. Built from the stored row so
    /// explicit and automatic dismissals share one shape.
    async fn review_subject(
        &self,
        trail_number: i64,
        change: &db_changes::ChangeRow,
        review: &db_changes::ReviewRow,
    ) -> CoreResult<serde_json::Value> {
        let revision = db_changes::revision_by_id(self.db(), review.revision_id)
            .await?
            .map(|row| row.number)
            .unwrap_or(0);
        let author = match review.author_id {
            Some(id) => self
                .sender_of(id)
                .await
                .unwrap_or_else(|| "deleted user".to_owned()),
            None => "deleted user".to_owned(),
        };
        Ok(serde_json::json!({
            "id": review.id,
            "trail": trail_number,
            "change": change.number,
            "revision": revision,
            "verdict": review.verdict,
            "state": review.state,
            "author": author,
            "body": review.body,
        }))
    }

    /// `dismiss_on_push`: when every gate rule matching the change's base
    /// branch has the flag set, prior `approve` reviews tied to older
    /// revisions move to `state='dismissed'`. `request_changes` is never
    /// touched here — a blocking review survives a push until its author
    /// supersedes it or triage dismisses it explicitly. Rows (and their
    /// revision ids) survive for history; each dismissal writes a
    /// `review.dismissed` timeline row with `reason: "new revision"` next to
    /// the revision event, so the audit trail shows why the approval
    /// vanished. Runs in the revision-creation path, never lazily in gate
    /// evaluation.
    async fn dismiss_stale_reviews(
        &self,
        repo_id: i64,
        trail_number: i64,
        change: &db_changes::ChangeRow,
        revision: &db_changes::RevisionRow,
    ) -> CoreResult<()> {
        let rules = db_checks::gate_rules_for(self.db(), repo_id).await?;
        // Unanimous arming: dismiss only when EVERY matching rule carries the
        // flag. A mixed set is safe without dismissal — flag-ON rules count
        // current-revision approvals at evaluation time while flag-OFF rules
        // keep counting older ones — but dismissing on ANY would physically
        // erase the older approvals a flag-OFF rule still needs.
        let matching: Vec<_> = rules
            .iter()
            .filter(|r| pattern_matches(r.pattern.as_deref(), &change.base_branch))
            .collect();
        if matching.is_empty() || matching.iter().any(|r| r.dismiss_on_push == 0) {
            return Ok(());
        }
        for review in db_changes::reviews_of_change(self.db(), change.id).await? {
            if review.revision_id == revision.id
                || review.state != "submitted"
                || review.verdict != "approve"
            {
                continue;
            }
            db_changes::set_review_state(self.db(), review.id, "dismissed").await?;
            self.change_timeline(
                repo_id,
                change.trail_id,
                "review.dismissed",
                None,
                serde_json::json!({
                    "change": change.number,
                    "revision": revision.number,
                    "review": review.id,
                    "reason": "new revision",
                }),
            )
            .await?;
            let dismissed = db_changes::reviews_of_change(self.db(), change.id)
                .await?
                .into_iter()
                .find(|r| r.id == review.id)
                .ok_or(CoreError::Internal("review vanished after dismiss".into()))?;
            let subject = self
                .review_subject(trail_number, change, &dismissed)
                .await?;
            self.dispatch_event(
                repo_id,
                HookEvent {
                    event: "review",
                    action: Some("dismissed"),
                    cause: None,
                    sender: None,
                    subject,
                },
            )
            .await;
        }
        Ok(())
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

    /// Inserts a revision and points the change at it: the row lands first,
    /// its commits are recorded, and only then does the pointer move — a
    /// revision that is current always has its commits recorded, or flag 0
    /// after a git failure for the backfill. Use when the refs are handled
    /// by the caller (fresh-trail pre-write or pinned post-write);
    /// [`Core::append_revision`] otherwise.
    async fn insert_revision_and_point(
        &self,
        repo_id: i64,
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
        self.record_revision_commits(repo_id, &revision).await;
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
    pub(crate) async fn change_timeline(
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
pub(crate) fn conflict_payload(paths: &[String]) -> String {
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

/// One inline comment on a batched review: an anchor plus its body.
#[derive(Debug, Clone)]
pub struct NewInlineComment {
    pub path: String,
    pub side: String,
    pub start_line: i64,
    pub end_line: i64,
    pub body: String,
}
/// Most inline comments one review may carry.
pub const MAX_REVIEW_COMMENTS: usize = 100;

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
/// Flat read shape for one draft comment: the thread it will open on submit.
#[derive(Debug, Clone)]
pub struct PendingCommentView {
    pub id: i64,
    pub thread_id: i64,
    pub body: String,
    pub created_at: i64,
}

/// Flat read shape for the viewer's draft review on a change (D9).
#[derive(Debug, Clone)]
pub struct PendingReviewView {
    pub id: i64,
    pub revision: i64,
    pub comments: Vec<PendingCommentView>,
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

/// One file of a change diff (D8): the git file diff plus the viewer's
/// viewed flag, resolved against the file's blob at the displayed head.
/// A file counts as viewed while the stored `blob_sha` equals the blob at
/// the displayed head, so a later revision that changes the file resets it.
#[derive(Debug, Clone)]
pub struct DiffFileView {
    pub file: starforged_git::diff::FileDiff,
    pub viewed: bool,
    pub blob_sha: Option<String>,
}

/// A change diff (D8): the files with viewed flags plus the truncation flag.
#[derive(Debug, Clone)]
pub struct ChangeDiff {
    pub files: Vec<DiffFileView>,
    pub truncated: bool,
}

/// Stored `conflict_paths` payloads are JSON arrays; corrupt rows read empty.
fn parse_paths(raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_default()
}

/// Validates one thread anchor (path, side, line span) plus its body: the
/// checks `create_thread` enforces, shared with batched-review inline
/// comments so both paths accept exactly the same anchors. Returns the
/// trimmed path, the side, and the body.
fn check_thread_anchor(
    path: &str,
    side: &str,
    start: i64,
    end: i64,
    body: &str,
) -> CoreResult<(String, String, String)> {
    let path = path.trim();
    if path.is_empty() || path.chars().count() > MAX_THREAD_PATH_CHARS {
        return Err(CoreError::Invalid("thread path is invalid".into()));
    }
    if path.chars().any(char::is_control) {
        return Err(CoreError::Invalid("thread path is invalid".into()));
    }
    if !matches!(side, "base" | "head") {
        return Err(CoreError::Invalid(format!("invalid thread side '{side}'")));
    }
    if start < 1 || end < start || end - start > MAX_THREAD_SPAN {
        return Err(CoreError::Invalid("thread lines are invalid".into()));
    }
    let body = check_markdown(body, "thread body")?;
    Ok((path.to_owned(), side.to_owned(), body))
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
        // One transaction: the change, its first revision, its cached
        // commits, and the current pointer commit together, so readers never
        // see a change with no current revision — and a revision that is
        // current always has its commits recorded, or flag 0 after a git
        // failure for the backfill. The range is walked before the
        // transaction so no git work happens inside it.
        let commits = self
            .walk_revision_commits(access.repo.id, &base_tip, &head_tip)
            .await;
        let (row, revision) = match db_changes::insert_branch_change_with_revision(
            self.db(),
            trail.id,
            head,
            base,
            user.id,
            &head_tip,
            &base_tip,
            Some(user.id),
            now(),
            commits.as_deref(),
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
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("updated"),
            Some("change_opened"),
            trail.number,
            Some(serde_json::json!({"k": row.number, "revision": revision.number})),
        )
        .await;
        self.change_view(
            &db_changes::change_by_id(self.db(), row.id)
                .await?
                .ok_or_else(|| CoreError::Internal("change vanished".into()))?,
        )
        .await
    }

    /// Changes in the repo (any state) whose CURRENT revision's head is
    /// `sha`, visible to the viewer, ascending by (trail number, k). `sha`
    /// must be lowercase 40/64-hex → else `Invalid` (so non-oids never reach
    /// git or the query). Invisible repos and below-`Read` viewers answer
    /// `NotFound`, like the other change reads.
    pub async fn changes_with_head(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> CoreResult<Vec<ChangeView>> {
        if !refpolicy::is_oid(sha) {
            return Err(CoreError::Invalid(format!("invalid head sha '{sha}'")));
        }
        let access = self.repo_for(viewer, owner, repo).await?;
        let mut out = Vec::new();
        for row in db_changes::changes_with_current_head(self.db(), access.repo.id, sha).await? {
            out.push(self.change_view(&row).await?);
        }
        Ok(out)
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
        let diff = self
            .change_diff_files(viewer, owner, repo, trail_n, k, rev, None)
            .await?;
        let mut reviews = Vec::new();
        for row in db_changes::reviews_of_change(self.db(), change.id).await? {
            // D9: drafts never appear in the detail — not even to their
            // author, who reads them through `pending_review`.
            if row.state == "pending" {
                continue;
            }
            reviews.push(self.review_view(&row).await?);
        }
        let threads = self.thread_views(viewer, &access, &change).await?;
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

    /// Unified diff for one revision (D8): from the revision's merge base to
    /// its head (unrelated histories diff `base_sha..head_sha` directly).
    /// With `range = Some((from, to))` two distinct revisions, the tree diff
    /// between their head commits instead, labeled as such by callers (it
    /// includes base changes when the change was rebased). Unknown revisions
    /// are `NotFound`; `from == to` is `Invalid`. Files carry the viewer's
    /// viewed flags, keyed by each file's blob at the displayed head.
    /// Within [`MAX_DIFF_LINES`] and [`MAX_CHANGE_DIFF_BYTES`]; runs on
    /// blocking threads (never a worktree) with a 60s timeout.
    #[allow(clippy::too_many_arguments)]
    pub async fn change_diff_files(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        rev: Option<i64>,
        range: Option<(i64, i64)>,
    ) -> CoreResult<ChangeDiff> {
        let (access, _, change) = self.resolve_change(viewer, owner, repo, trail_n, k).await?;
        let (from_id, head_id, head_sha) = match range {
            Some((from, to)) => {
                if from == to {
                    return Err(CoreError::Invalid(
                        "identical revisions have no inter-revision diff".into(),
                    ));
                }
                let from_row = db_changes::revision_by_number(self.db(), change.id, from)
                    .await?
                    .ok_or(CoreError::NotFound)?;
                let to_row = db_changes::revision_by_number(self.db(), change.id, to)
                    .await?
                    .ok_or(CoreError::NotFound)?;
                (from_row.head_sha, to_row.head_sha.clone(), to_row.head_sha)
            }
            None => {
                let revision = self.resolve_revision(&change, rev).await?;
                let repo = self.repo_path(access.repo.id);
                let (head, base) = (revision.head_sha.clone(), revision.base_sha.clone());
                let probe = repo.clone();
                let base_probe = base.clone();
                let merge_base = tokio::task::spawn_blocking(move || {
                    read::merge_base(&probe, &head, &base_probe)
                })
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))??;
                let from = merge_base.unwrap_or(base);
                (from, revision.head_sha.clone(), revision.head_sha.clone())
            }
        };
        let repo = self.repo_path(access.repo.id);
        let (head_arg, from_arg) = (head_id, from_id);
        let commit_diff = tokio::time::timeout(
            DIFF_TIMEOUT,
            diff::range_diff(
                &repo,
                &from_arg,
                &head_arg,
                MAX_DIFF_LINES,
                MAX_CHANGE_DIFF_BYTES,
            ),
        )
        .await
        .map_err(|_| CoreError::Internal("diff timed out".into()))?
        .map_err(CoreError::from)?;
        self.attach_viewed(viewer, &access, &change, &head_sha, commit_diff)
            .await
    }

    /// Resolves each diff file's blob at `head_sha` and marks the viewer's
    /// stored views: viewed while the stored `blob_sha` equals the blob.
    /// Anonymous viewers and missing blobs are never viewed.
    async fn attach_viewed(
        &self,
        viewer: Option<&User>,
        access: &RepoAccess,
        change: &db_changes::ChangeRow,
        head_sha: &str,
        commit_diff: CommitDiff,
    ) -> CoreResult<ChangeDiff> {
        let marks: std::collections::HashMap<String, String> = match viewer {
            None => std::collections::HashMap::new(),
            Some(user) => db_changes::file_views_of_change(self.db(), change.id, user.id)
                .await?
                .into_iter()
                .map(|row| (row.path, row.blob_sha))
                .collect(),
        };
        let repo = self.repo_path(access.repo.id);
        let mut files = Vec::with_capacity(commit_diff.files.len());
        for file in commit_diff.files {
            let path = file.display_path().to_owned();
            let head = head_sha.to_owned();
            let candidate = path.clone();
            let probe = repo.clone();
            let blob =
                tokio::task::spawn_blocking(move || read::blob_ref(&probe, &head, &candidate))
                    .await
                    .map_err(|e| CoreError::Internal(e.to_string()))??;
            let blob_sha = blob.map(|b| b.id);
            let viewed = blob_sha
                .as_ref()
                .is_some_and(|sha| marks.get(&path).is_some_and(|mark| mark == sha));
            files.push(DiffFileView {
                file,
                viewed,
                blob_sha,
            });
        }
        Ok(ChangeDiff {
            files,
            truncated: commit_diff.truncated,
        })
    }

    /// Marks `path` viewed (`viewed = true`) or un-viewed (`false`) for the
    /// signed-in reader (D8). Readers only (non-readers get `NotFound`);
    /// archived repos refuse (`Invalid`). The mark stores the file's blob at
    /// the change's current head, so a later revision that changes the file
    /// resets it while one that leaves it alone keeps it viewed. Unknown
    /// files are `Invalid`. Viewed state writes no timeline rows and
    /// dispatches nothing.
    #[allow(clippy::too_many_arguments)]
    pub async fn set_file_viewed(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        path: &str,
        viewed: bool,
    ) -> CoreResult<()> {
        let (access, _, change) = self
            .resolve_change(Some(user), owner, repo, trail_n, k)
            .await?;
        Self::ensure_writable_g4(&access)?;
        let path = path.trim();
        if path.is_empty() {
            return Err(CoreError::Invalid("unknown file".into()));
        }
        if path.chars().count() > MAX_THREAD_PATH_CHARS {
            return Err(CoreError::Invalid("unknown file".into()));
        }
        // Folded F5 finding: only paths in the displayed (current-revision)
        // diff may be marked — any other in-tree path is `Invalid`, so no
        // orphan row is ever stored.
        let current = self
            .change_diff_files(Some(user), owner, repo, trail_n, k, None, None)
            .await?;
        if !current.files.iter().any(|f| f.file.display_path() == path) {
            return Err(CoreError::Invalid("unknown file".into()));
        }
        let revision = self.resolve_revision(&change, None).await?;
        let repo_path = self.repo_path(access.repo.id);
        let (head, candidate) = (revision.head_sha.clone(), path.to_owned());
        let blob =
            tokio::task::spawn_blocking(move || read::blob_ref(&repo_path, &head, &candidate))
                .await
                .map_err(|e| CoreError::Internal(e.to_string()))??;
        let Some(blob) = blob else {
            return Err(CoreError::Invalid("unknown file".into()));
        };
        if viewed {
            db_changes::upsert_file_view(self.db(), change.id, user.id, path, &blob.id, now())
                .await?;
        } else {
            db_changes::delete_file_view(self.db(), change.id, user.id, path).await?;
        }
        Ok(())
    }

    /// Submits a review on `r` (default: current) with `comments` inline
    /// comments. Any ≥ `Read` viewer may submit any verdict — gate counting
    /// (write+ only) is M2c's problem. Every input is validated before the
    /// first write — verdict, body, session, comment count
    /// (≤ [`MAX_REVIEW_COMMENTS`]), and each comment's anchor and body via
    /// the SAME validator `create_thread` uses — so an
    /// invalid comment (`Invalid("comments[<i>]: <reason>")`) writes nothing.
    /// Each comment opens a thread on the reviewed revision; its first
    /// comment carries `review_id` = the new review. Audits one
    /// `review.submitted` row plus one `thread.open` row per comment (the
    /// same rows the separate calls write today, written in this method).
    /// D9: when the actor holds a pending review, it converts in place
    /// instead — same verdict/body/session, the pending comments plus any
    /// comments sent in the call — still exactly one `review.submitted`
    /// row and one webhook. The `thread.open` rows the draft creation
    /// deferred fire now, once per newly public thread.
    ///
    /// The db layer has no transaction seam for these helpers, so "nothing is
    /// written" is guaranteed by validating everything first. A mid-sequence
    /// database failure can leave partial rows, exactly as every existing
    /// multi-row `Core` mutation can; no transactions are added here.
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
        comments: &[NewInlineComment],
    ) -> CoreResult<(ReviewView, Vec<ThreadView>)> {
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
        if comments.len() > MAX_REVIEW_COMMENTS {
            return Err(CoreError::Invalid(format!(
                "too many comments (max {MAX_REVIEW_COMMENTS})"
            )));
        }
        let mut checked = Vec::with_capacity(comments.len());
        for (i, comment) in comments.iter().enumerate() {
            match check_thread_anchor(
                &comment.path,
                &comment.side,
                comment.start_line,
                comment.end_line,
                &comment.body,
            ) {
                Ok((path, side, body)) => {
                    checked.push((path, side, comment.start_line, comment.end_line, body));
                }
                Err(CoreError::Invalid(reason)) => {
                    return Err(CoreError::Invalid(format!("comments[{i}]: {reason}")));
                }
                Err(other) => return Err(other),
            }
        }
        // D9: the actor's pending review, if any, converts in place — one
        // row write, so submit still audits exactly one `review.submitted`
        // row and dispatches one webhook however many drafts fed it. Without
        // a draft the call behaves exactly as before.
        let draft = db_changes::pending_review_of_author(self.db(), change.id, user.id).await?;
        let draft_id = draft.as_ref().map(|row| row.id);
        let row = match draft {
            Some(pending) => {
                db_changes::submit_pending_review(
                    self.db(),
                    pending.id,
                    revision.id,
                    verdict,
                    &body,
                    session.as_deref(),
                )
                .await?;
                db_changes::reviews_of_change(self.db(), change.id)
                    .await?
                    .into_iter()
                    .find(|r| r.id == pending.id)
                    .ok_or_else(|| CoreError::Internal("review vanished after submit".into()))?
            }
            None => {
                db_changes::insert_review(
                    self.db(),
                    change.id,
                    revision.id,
                    user.id,
                    verdict,
                    &body,
                    session.as_deref(),
                    now(),
                )
                .await?
            }
        };
        // D7: the reviewer's pending request on this Trail is fulfilled. No
        // timeline row and no dispatch; `review.submitted` records it.
        db_trails::remove_review_request(self.db(), trail.id, user.id).await?;
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
        self.dispatch_event(
            access.repo.id,
            HookEvent {
                event: "review",
                action: Some("submitted"),
                cause: None,
                sender: Some(user.handle.clone()),
                subject: serde_json::json!({
                    "id": row.id,
                    "trail": trail.number,
                    "change": change.number,
                    "revision": revision.number,
                    "verdict": verdict,
                    "state": row.state.clone(),
                    "author": user.handle.clone(),
                    "body": body.clone(),
                }),
            },
        )
        .await;
        let review = self.review_view(&row).await?;
        let viewer = Some(user);
        // The converted draft now reads `submitted`, so its comments are
        // visible to the response builder below.
        let reviews = self.reviews_by_id(change.id).await?;
        // Threads the draft already opened go public with this submit: the
        // `thread.open` rows their pending creation deferred fire now, once
        // each (a thread that already has one — e.g. a pending reply on a
        // public thread — is left alone).
        let mut threads = Vec::new();
        if let Some(id) = draft_id {
            let opened: std::collections::HashSet<i64> =
                db_trails::timeline_of_trail(self.db(), trail.id)
                    .await?
                    .iter()
                    .filter(|e| e.kind == "thread.open")
                    .filter_map(|e| serde_json::from_str::<serde_json::Value>(&e.payload).ok())
                    .filter_map(|p| p.get("thread").and_then(serde_json::Value::as_i64))
                    .collect();
            for thread in self.review_threads(change.id, id).await? {
                if !opened.contains(&thread.id) {
                    let anchor = db_changes::revision_by_id(self.db(), thread.anchor_revision_id)
                        .await?
                        .ok_or_else(|| CoreError::Internal("thread has no revision".into()))?;
                    self.change_timeline(
                        access.repo.id,
                        trail.id,
                        "thread.open",
                        Some(user.id),
                        serde_json::json!({
                            "change": change.number,
                            "thread": thread.id,
                            "revision": anchor.number,
                            "path": thread.path,
                            "side": thread.side,
                            "start_line": thread.start_line,
                            "end_line": thread.end_line,
                        }),
                    )
                    .await?;
                }
                threads.push(
                    self.thread_view(viewer, &access, &change, &thread, &reviews)
                        .await?
                        .ok_or_else(|| CoreError::Internal("own thread hidden".into()))?,
                );
            }
        }
        for (path, side, start_line, end_line, comment_body) in checked {
            let thread = db_changes::insert_thread(
                self.db(),
                change.id,
                revision.id,
                &path,
                &side,
                start_line,
                end_line,
                now(),
            )
            .await?;
            db_changes::insert_thread_comment(
                self.db(),
                thread.id,
                Some(row.id),
                user.id,
                &comment_body,
                now(),
            )
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
                    "start_line": start_line,
                    "end_line": end_line,
                }),
            )
            .await?;
            threads.push(
                self.thread_view(viewer, &access, &change, &thread, &reviews)
                    .await?
                    .ok_or_else(|| CoreError::Internal("own thread hidden".into()))?,
            );
        }
        Ok((review, threads))
    }

    /// The viewer's draft review on the change (D9), or `None` when they
    /// hold none. Anonymous viewers never hold one. Readers only;
    /// non-readers get `NotFound`, exactly like every other change read.
    pub async fn pending_review(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
    ) -> CoreResult<Option<PendingReviewView>> {
        let (_, _, change) = self.resolve_change(viewer, owner, repo, trail_n, k).await?;
        let Some(user) = viewer else {
            return Ok(None);
        };
        let Some(draft) =
            db_changes::pending_review_of_author(self.db(), change.id, user.id).await?
        else {
            return Ok(None);
        };
        let revision = db_changes::revision_by_id(self.db(), draft.revision_id)
            .await?
            .ok_or_else(|| CoreError::Internal("review has no revision".into()))?;
        let mut comments = Vec::new();
        for row in db_changes::comments_of_review(self.db(), draft.id).await? {
            comments.push(PendingCommentView {
                id: row.id,
                thread_id: row.thread_id,
                body: row.body.clone(),
                created_at: row.created_at,
            });
        }
        Ok(Some(PendingReviewView {
            id: draft.id,
            revision: revision.number,
            comments,
            created_at: draft.created_at,
        }))
    }

    /// Discards the actor's draft review (D9): its comments, plus the threads
    /// left without comments. Writes no timeline row and dispatches nothing.
    /// No draft is `NotFound`.
    pub async fn discard_pending_review(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
    ) -> CoreResult<()> {
        let (access, _, change) = self
            .resolve_change(Some(user), owner, repo, trail_n, k)
            .await?;
        Self::ensure_writable_g4(&access)?;
        let Some(draft) =
            db_changes::pending_review_of_author(self.db(), change.id, user.id).await?
        else {
            return Err(CoreError::NotFound);
        };
        for comment in db_changes::comments_of_review(self.db(), draft.id).await? {
            db_changes::delete_thread_comment(self.db(), comment.id).await?;
            if db_changes::comments_of_thread(self.db(), comment.thread_id)
                .await?
                .is_empty()
            {
                db_changes::delete_thread(self.db(), comment.thread_id).await?;
            }
        }
        db_changes::delete_review(self.db(), draft.id).await?;
        Ok(())
    }

    /// The actor's draft review, creating it on the current revision when
    /// missing. A concurrent create loses the insert race on the partial
    /// unique index and re-reads the winner, so one author still ends up
    /// with exactly one draft.
    async fn ensure_pending_review(
        &self,
        user: &User,
        change: &db_changes::ChangeRow,
    ) -> CoreResult<db_changes::ReviewRow> {
        if let Some(row) =
            db_changes::pending_review_of_author(self.db(), change.id, user.id).await?
        {
            return Ok(row);
        }
        let revision = self.resolve_revision(change, None).await?;
        match db_changes::insert_pending_review(self.db(), change.id, revision.id, user.id, now())
            .await
        {
            Ok(row) => Ok(row),
            Err(e) if e.is_unique_violation() => {
                db_changes::pending_review_of_author(self.db(), change.id, user.id)
                    .await?
                    .ok_or_else(|| {
                        CoreError::Internal("pending review vanished after conflict".into())
                    })
            }
            Err(other) => Err(other.into()),
        }
    }

    /// Threads holding at least one comment linked to the review, in
    /// creation order.
    async fn review_threads(
        &self,
        change_id: i64,
        review_id: i64,
    ) -> CoreResult<Vec<db_changes::ThreadRow>> {
        let mut out = Vec::new();
        for thread in db_changes::threads_of_change(self.db(), change_id).await? {
            let linked = db_changes::comments_of_thread(self.db(), thread.id)
                .await?
                .iter()
                .any(|c| c.review_id == Some(review_id));
            if linked {
                out.push(thread);
            }
        }
        Ok(out)
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
            // D9: pending drafts never appear in review listings — not even to
            // their author, who reads them through `pending_review`.
            if row.state == "pending" {
                continue;
            }
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
        // D9: drafts are submitted or discarded, never dismissed.
        if row.state == "pending" {
            return Err(CoreError::Invalid(
                "pending reviews cannot be dismissed; submit or discard them".into(),
            ));
        }
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
            let dismissed = db_changes::reviews_of_change(self.db(), change.id)
                .await?
                .into_iter()
                .find(|r| r.id == review_id)
                .ok_or(CoreError::Internal("review vanished after dismiss".into()))?;
            let subject = self
                .review_subject(trail.number, &change, &dismissed)
                .await?;
            self.dispatch_event(
                access.repo.id,
                HookEvent {
                    event: "review",
                    action: Some("dismissed"),
                    cause: None,
                    sender: Some(user.handle.clone()),
                    subject,
                },
            )
            .await;
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
    /// With `pending`, the first comment attaches to the actor's draft
    /// review (created on demand) instead of auditing a `thread.open` row:
    /// the thread stays visible only to its author until submit.
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
        pending: bool,
    ) -> CoreResult<ThreadView> {
        let (access, trail, change) = self
            .resolve_change(Some(user), owner, repo, trail_n, k)
            .await?;
        Self::ensure_writable_g4(&access)?;
        let revision = self.resolve_revision(&change, r).await?;
        let (path, side, body) = check_thread_anchor(path, side, start, end, body)?;
        let thread = db_changes::insert_thread(
            self.db(),
            change.id,
            revision.id,
            &path,
            &side,
            start,
            end,
            now(),
        )
        .await?;
        let comment =
            db_changes::insert_thread_comment(self.db(), thread.id, None, user.id, &body, now())
                .await?;
        if pending {
            let draft = self.ensure_pending_review(user, &change).await?;
            db_changes::set_comment_review(self.db(), comment.id, draft.id).await?;
        } else {
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
        }
        let reviews = self.reviews_by_id(change.id).await?;
        self.thread_view(Some(user), &access, &change, &thread, &reviews)
            .await?
            .ok_or_else(|| CoreError::Internal("own thread hidden".into()))
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
        let reviews = self.reviews_by_id(change.id).await?;
        let mut out = Vec::new();
        for row in db_changes::threads_of_change(self.db(), change.id).await? {
            if take.is_some_and(|n| out.len() >= n) {
                break;
            }
            if let Some(view) = self
                .thread_view(viewer, &access, &change, &row, &reviews)
                .await?
            {
                out.push(view);
            }
        }
        Ok(out)
    }

    /// Reviews of one change keyed by id, for draft-visibility checks.
    pub(crate) async fn reviews_by_id(
        &self,
        change_id: i64,
    ) -> CoreResult<std::collections::HashMap<i64, db_changes::ReviewRow>> {
        let mut map = std::collections::HashMap::new();
        for row in db_changes::reviews_of_change(self.db(), change_id).await? {
            map.insert(row.id, row);
        }
        Ok(map)
    }

    async fn thread_views(
        &self,
        viewer: Option<&User>,
        access: &RepoAccess,
        change: &db_changes::ChangeRow,
    ) -> CoreResult<Vec<ThreadView>> {
        let reviews = self.reviews_by_id(change.id).await?;
        let mut out = Vec::new();
        for row in db_changes::threads_of_change(self.db(), change.id).await? {
            if let Some(view) = self
                .thread_view(viewer, access, change, &row, &reviews)
                .await?
            {
                out.push(view);
            }
        }
        Ok(out)
    }

    /// One thread with its visible comments, or `None` when the viewer may
    /// see none of them. D9: pending comments — and threads whose only
    /// comments are pending — are visible only to their author.
    async fn thread_view(
        &self,
        viewer: Option<&User>,
        access: &RepoAccess,
        change: &db_changes::ChangeRow,
        thread: &db_changes::ThreadRow,
        reviews: &std::collections::HashMap<i64, db_changes::ReviewRow>,
    ) -> CoreResult<Option<ThreadView>> {
        let anchor = db_changes::revision_by_id(self.db(), thread.anchor_revision_id)
            .await?
            .ok_or_else(|| CoreError::Internal("thread has no revision".into()))?;
        let mut comments = Vec::new();
        for row in db_changes::comments_of_thread(self.db(), thread.id).await? {
            if Self::comment_visible(viewer, reviews, &row) {
                comments.push(self.thread_comment_view(&row).await?);
            }
        }
        if comments.is_empty() {
            return Ok(None);
        }
        let outdated = self
            .thread_outdated(access, change, thread, &anchor)
            .await?;
        Ok(Some(ThreadView {
            id: thread.id,
            revision: anchor.number,
            path: thread.path.clone(),
            side: thread.side.clone(),
            start_line: thread.start_line,
            end_line: thread.end_line,
            resolved: thread.resolved != 0,
            outdated,
            comments,
        }))
    }

    /// The draft review a comment is attached to, if any — the single place
    /// that names the D9 draft rule. Read paths (`comment_visible`) and gate
    /// counting share it.
    pub(crate) fn comment_draft<'a>(
        reviews: &'a std::collections::HashMap<i64, db_changes::ReviewRow>,
        comment: &db_changes::ReviewCommentRow,
    ) -> Option<&'a db_changes::ReviewRow> {
        comment
            .review_id
            .and_then(|id| reviews.get(&id))
            .filter(|row| row.state == "pending")
    }

    /// A comment is visible when it is not attached to a draft, or when the
    /// viewer authored that draft. Unlinked comments and comments on
    /// submitted or dismissed reviews are always visible.
    fn comment_visible(
        viewer: Option<&User>,
        reviews: &std::collections::HashMap<i64, db_changes::ReviewRow>,
        comment: &db_changes::ReviewCommentRow,
    ) -> bool {
        let Some(draft) = Self::comment_draft(reviews, comment) else {
            return true;
        };
        matches!((viewer, draft.author_id), (Some(user), Some(author)) if user.id == author)
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
        // D9: resolving a thread the caller cannot see is `NotFound`, never
        // a leak-shaped error.
        let reviews = self.reviews_by_id(change.id).await?;
        self.thread_view(Some(user), &access, &change, &thread, &reviews)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// Appends a comment to a thread. Any ≥ `Read` viewer. `review_id`, when
    /// given, must name a review on the same change. Audits `thread.comment`.
    /// With `pending`, the comment attaches to the actor's draft review
    /// (created on demand) and audits nothing. `pending` and `review_id`
    /// cannot be combined.
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
        pending: bool,
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
        let reviews = self.reviews_by_id(change.id).await?;
        // D9: commenting on a thread the caller cannot see is `NotFound`,
        // pending or plain alike — a 201 here would oracle foreign draft
        // threads, and a plain comment would publish the thread with no
        // prior `thread.open` row.
        let visible = self
            .thread_view(Some(user), &access, &change, &thread, &reviews)
            .await?
            .is_some();
        if !visible {
            return Err(CoreError::NotFound);
        }
        if pending && review_id.is_some() {
            return Err(CoreError::Invalid(
                "pending and review_id cannot be combined".into(),
            ));
        }
        if let Some(id) = review_id {
            // Unknown ids, reviews on other changes (absent from this
            // change's map), and foreign drafts all answer identically, so
            // probing `review_id`s cannot distinguish draft ids from noise.
            let linked = reviews
                .get(&id)
                .filter(|row| row.state != "pending" || row.author_id == Some(user.id));
            if linked.is_none() {
                return Err(CoreError::Invalid("unknown review".into()));
            }
        }
        let body = check_markdown(body, "comment body")?;
        let row = if pending {
            let draft = self.ensure_pending_review(user, &change).await?;
            db_changes::insert_thread_comment(
                self.db(),
                thread.id,
                Some(draft.id),
                user.id,
                &body,
                now(),
            )
            .await?
        } else {
            db_changes::insert_thread_comment(
                self.db(),
                thread.id,
                review_id,
                user.id,
                &body,
                now(),
            )
            .await?
        };
        if pending {
            return self.thread_comment_view(&row).await;
        }
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
            let revision = match change.current_revision_id {
                Some(id) => db_changes::revision_by_id(self.db(), id)
                    .await?
                    .map(|row| row.number)
                    .unwrap_or(0),
                None => 0,
            };
            self.dispatch_trail_event(
                access.repo.id,
                Some(user.handle.clone()),
                Some("updated"),
                Some(if state == "closed" {
                    "change_closed"
                } else {
                    "change_reopened"
                }),
                trail.number,
                Some(serde_json::json!({"k": change.number, "revision": revision})),
            )
            .await;
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
    /// (binary/capped files carry empty hunks, never raw bytes), the viewer's
    /// viewed flag per file (D8), plus a top-level truncation flag. Kept in
    /// core because only core may name `git` types — the API embeds the value
    /// verbatim. With `range = Some((from, to))` the tree diff between those
    /// revisions' heads.
    #[allow(clippy::too_many_arguments)]
    pub async fn change_diff_json(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        trail_n: i64,
        k: i64,
        rev: Option<i64>,
        range: Option<(i64, i64)>,
    ) -> CoreResult<serde_json::Value> {
        Ok(diff_json(
            &self
                .change_diff_files(viewer, owner, repo, trail_n, k, rev, range)
                .await?,
        ))
    }
}

fn diff_json(diff: &ChangeDiff) -> serde_json::Value {
    serde_json::json!({
        "files": diff.files.iter().map(file_json).collect::<Vec<_>>(),
        "truncated": diff.truncated,
    })
}

fn file_json(f: &DiffFileView) -> serde_json::Value {
    use starforged_git::diff::{FileStatus, LineKind};
    let status = match f.file.status {
        FileStatus::Added => "added",
        FileStatus::Deleted => "deleted",
        FileStatus::Modified => "modified",
        FileStatus::Renamed => "renamed",
    };
    let hunks = f
        .file
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
        "path": f.file.display_path(),
        "status": status,
        "binary": f.file.binary,
        "viewed": f.viewed,
        "hunks": hunks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_anchor_rejects_interior_control_characters() {
        for path in ["a\nb.rs", "a\rb.rs", "a\tb.rs", "a\u{7f}b.rs"] {
            let err = check_thread_anchor(path, "head", 1, 1, "body")
                .unwrap_err()
                .to_string();
            assert_eq!(err, "thread path is invalid", "{path:?}");
        }
    }

    #[test]
    fn thread_anchor_accepts_normal_paths() {
        for path in [
            "a.rs",
            "src/main.rs",
            "dir/sub.dir:file-name_test.rs",
            "ci/unit:linux-x86_64.txt",
        ] {
            let (kept, side, body) = check_thread_anchor(path, "head", 1, 2, "nit")
                .unwrap_or_else(|_| panic!("{path:?} must pass"));
            assert_eq!(kept, path);
            assert_eq!(side, "head");
            assert_eq!(body, "nit");
        }
    }

    /// D1: `append_revision` refuses to append a head equal to the latest
    /// row's head. It returns that row with no dismissals, no timeline, and
    /// no webhook, so every caller is covered.
    #[tokio::test]
    async fn append_revision_with_latest_head_is_a_noop() {
        use starforged_db::{now, repos, trails, users};

        use crate::testing::test_core;

        let (core, _fx) = test_core().await;
        let db = core.db();
        let alice = users::insert(
            db,
            &users::NewUser {
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
        let repo_id = repos::insert(
            db,
            &repos::NewRepo {
                owner_id: alice,
                name: "proj",
                description: "",
                visibility: "private",
                default_branch: "main",
            },
        )
        .await
        .unwrap();
        let trail = trails::insert_trail(
            db,
            &trails::NewTrail {
                repo_id,
                title: "t",
                intent: "why",
                author_id: alice,
            },
            now(),
        )
        .await
        .unwrap();
        let change = db_changes::insert_change(
            db,
            trail.id,
            "branch",
            Some("feature"),
            "main",
            alice,
            now(),
        )
        .await
        .unwrap();
        let head = "a".repeat(40);
        let base = "b".repeat(40);
        let first = db_changes::insert_revision(db, change.id, &head, &base, Some(alice), now())
            .await
            .unwrap();
        db_changes::set_current_revision(db, change.id, first.id, now())
            .await
            .unwrap();

        let got = core
            .append_revision(repo_id, trail.number, &change, &head, &base, None)
            .await
            .unwrap();
        assert_eq!(got.id, first.id, "the existing latest row is returned");
        let revs = db_changes::revisions_of_change(db, change.id)
            .await
            .unwrap();
        assert_eq!(revs.len(), 1, "no duplicate row is inserted");
        let timeline = trails::timeline_of_trail(db, trail.id).await.unwrap();
        assert!(
            timeline.is_empty(),
            "no timeline row is written: {timeline:?}"
        );
    }
}
