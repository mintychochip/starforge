//! Search index feeding (spec §10.5, plan M4a): building index documents
//! from database rows and blobs, and the full rebuild behind
//! `starforged index rebuild`.
//!
//! The index is never the source of truth, and indexing never blocks or
//! fails a mutation: incremental indexing runs through the job queue (plan
//! D5, task S2); this module owns the row-to-document translation shared by
//! the jobs and the rebuild, so the two can never drift apart.
//!
//! Session documents come from the same reader the session viewer uses
//! ([`Core::load_session_items`]), with redaction applied, so the index
//! never holds text the viewer would redact. Quarantined sessions ARE
//! indexed, with their quarantine state, so the uploader and repo admins can
//! find them; the query filter (plan D3) and the caller-side re-check hide
//! them from everyone else.

use starforge_format::EventKind;
use starforged_db::repos as db_repos;
use starforged_db::repos::RepoRow;
use starforged_db::sessions::{self as db_sessions, SessionRow};
use starforged_db::trails::{self as db_trails, TrailCommentRow, TrailFilter, TrailRow};
use starforged_index::{EventDoc, IndexStats, TrailDoc};

use crate::jobs::Job;
use crate::read::SessionPageItem;
use crate::{Core, CoreError, CoreResult};

/// How many rows one listing call pulls; rebuild loops until a listing
/// returns fewer, so no count is ever truncated.
const REBUILD_PAGE: i64 = 1000;

/// Maps the index crate's error to [`CoreError::Internal`] for callers that
/// cannot fail a mutation (startup, rebuild): the message keeps the cause.
fn index<T>(result: starforged_index::Result<T>) -> CoreResult<T> {
    result.map_err(|err| CoreError::Internal(format!("search index: {err}")))
}

/// The indexed visibility string for a repository row. Unknown values fail
/// closed to `private` so a stale schema can never widen visibility.
pub fn visibility_of(repo: &RepoRow) -> &'static str {
    match repo.visibility.as_str() {
        "public" => "public",
        "internal" => "internal",
        _ => "private",
    }
}

/// One Trail document (plan D2): `body` is the intent plus every comment
/// body, `ts` is `updated_at`.
pub fn trail_doc(
    trail: &TrailRow,
    visibility: &'static str,
    comments: &[TrailCommentRow],
) -> TrailDoc {
    let mut body = String::from(trail.intent.as_str());
    for comment in comments {
        if !body.is_empty() {
            body.push_str("\n\n");
        }
        body.push_str(&comment.body);
    }
    TrailDoc {
        trail_id: trail.id,
        repo_id: trail.repo_id,
        repo_visibility: visibility,
        title: trail.title.clone(),
        body,
        author_id: trail.author_id,
        state: trail.state.clone(),
        ts: trail.updated_at,
    }
}

/// One event document per event that has searchable content (plan D2): user
/// and assistant message text, tool names, and file paths. Reasoning,
/// tool results (inputs/outputs), and everything else produce no document.
pub fn event_docs(
    session: &SessionRow,
    visibility: &'static str,
    items: &[SessionPageItem],
    commits: &[String],
) -> Vec<EventDoc> {
    let models = models_of(session);
    let mut docs = Vec::new();
    for item in items {
        let SessionPageItem::Event(event) = item else {
            continue;
        };
        let Some(text) = searchable_text(&event.kind) else {
            continue;
        };
        docs.push(EventDoc {
            session_id: session.id,
            seq: i64::try_from(event.seq).unwrap_or(i64::MAX),
            repo_id: session.repo_id,
            repo_visibility: visibility,
            text,
            agent: session.agent_name.clone(),
            models: models.clone(),
            uploader_id: session.uploader_id,
            published: session.visibility == "published",
            quarantined: session.quarantine == "quarantined",
            commits: commits.to_vec(),
            ts: event_ts(&event.ts, session.started_at),
        });
    }
    docs
}

fn searchable_text(kind: &EventKind) -> Option<String> {
    match kind {
        EventKind::UserMessage(message) => Some(message.text.clone()),
        EventKind::AssistantMessage(message) => Some(message.text.clone()),
        EventKind::ToolCall(call) => Some(call.tool.name.clone()),
        EventKind::FileChange(change) => Some(change.path.clone()),
        _ => None,
    }
}

/// `SessionRow.models` is the JSON array of model ids (the format
/// [`crate::ingest`] stores); unparseable stored values index as no models.
fn models_of(session: &SessionRow) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(&session.models).unwrap_or_default()
}

/// An event's timestamp as unix seconds. An unparseable timestamp falls back
/// to the session's start rather than failing the rebuild.
fn event_ts(raw: &str, fallback: i64) -> i64 {
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .map(|parsed| parsed.unix_timestamp())
        .unwrap_or(fallback)
}

impl Core {
    /// Wipes the search index and rebuilds it from the database and blobs,
    /// returning the document counts. The caller holds the writer lock: from
    /// `starforged index rebuild` only while the server is stopped, from the
    /// `RebuildIndex` job while the server runs.
    ///
    /// Only `complete` sessions are indexed — the same sessions the
    /// incremental path (plan D5) indexes, so a rebuild produces exactly the
    /// index the jobs would have produced.
    pub async fn rebuild_search_index(&self) -> CoreResult<IndexStats> {
        let search_index = self.search_index();
        index(search_index.clear())?;
        let mut stats = IndexStats {
            trails: 0,
            events: 0,
        };
        // `list_all_live` has no offset; one call with a huge limit is the
        // whole live catalog (SQL `LIMIT` accepts any i64).
        for repo in &db_repos::list_all_live(self.db(), i64::MAX).await? {
            self.index_repo(repo, &mut stats).await?;
        }
        index(search_index.commit())?;
        Ok(stats)
    }

    async fn index_repo(&self, repo: &RepoRow, stats: &mut IndexStats) -> CoreResult<()> {
        let visibility = visibility_of(repo);
        let search_index = self.search_index();
        // Trails page by number (`after` is the last number seen).
        let mut after = None;
        loop {
            let filter = TrailFilter {
                limit: REBUILD_PAGE,
                after,
                ..Default::default()
            };
            let trails = db_trails::trails_of_repo(self.db(), repo.id, &filter).await?;
            if trails.is_empty() {
                break;
            }
            after = trails.last().map(|trail| trail.number);
            for trail in &trails {
                let comments = db_trails::comments_of(self.db(), trail.id).await?;
                index(search_index.replace_trail(trail_doc(trail, visibility, &comments)))?;
                stats.trails += 1;
            }
            if (trails.len() as i64) < REBUILD_PAGE {
                break;
            }
        }
        for session in db_sessions::sessions_of_repo(self.db(), repo.id, i64::MAX).await? {
            if session.lifecycle != "complete" {
                continue;
            }
            let commits = db_sessions::links_of_session(self.db(), session.id)
                .await?
                .into_iter()
                .map(|link| link.sha)
                .collect::<Vec<_>>();
            let items = self.load_session_items(session.id).await?;
            let docs = event_docs(&session, visibility, &items, &commits);
            stats.events += docs.len() as u64;
            index(search_index.replace_session(session.id, docs))?;
        }
        Ok(())
    }
    /// Queues an indexing job; indexing never blocks or fails a mutation
    /// (plan D5), so a queue failure is logged and swallowed.
    pub(crate) async fn enqueue_index(&self, job: &Job) {
        if let Err(err) = self.enqueue(job).await {
            tracing::warn!(error = %err, "enqueueing search index job");
        }
    }

    /// Replaces one Trail's document from the database (plan D5). A missing
    /// Trail is a no-op (Trails are never deleted alone; a purged repository
    /// drops all of its documents through `index_repo_by_id`); a missing or
    /// deleted repository drops the repository's documents.
    pub(crate) async fn index_trail(&self, trail_id: i64) -> CoreResult<()> {
        let search_index = self.search_index();
        let Some(trail) = db_trails::trail_by_id(self.db(), trail_id).await? else {
            return Ok(());
        };
        let Some(repo) = db_repos::by_id(self.db(), trail.repo_id).await? else {
            index(search_index.drop_repo(trail.repo_id))?;
            index(search_index.commit())?;
            return Ok(());
        };
        if repo.deleted_at.is_some() {
            index(search_index.drop_repo(trail.repo_id))?;
            index(search_index.commit())?;
            return Ok(());
        }
        let comments = db_trails::comments_of(self.db(), trail.id).await?;
        index(search_index.replace_trail(trail_doc(&trail, visibility_of(&repo), &comments)))?;
        index(search_index.commit())?;
        Ok(())
    }

    /// Replaces every event document of one session from the database and
    /// blobs (plan D5). Missing sessions, missing or deleted repositories,
    /// and sessions that are not `complete` drop the session's documents, so
    /// a rebuild and the incremental path produce the same index.
    pub(crate) async fn index_session_events(&self, session_id: i64) -> CoreResult<()> {
        let search_index = self.search_index();
        let Some(session) = db_sessions::session_by_id(self.db(), session_id).await? else {
            index(search_index.drop_session(session_id))?;
            index(search_index.commit())?;
            return Ok(());
        };
        let Some(repo) = db_repos::by_id(self.db(), session.repo_id).await? else {
            index(search_index.drop_session(session_id))?;
            index(search_index.commit())?;
            return Ok(());
        };
        if repo.deleted_at.is_some() || session.lifecycle != "complete" {
            index(search_index.drop_session(session_id))?;
            index(search_index.commit())?;
            return Ok(());
        }
        let commits = db_sessions::links_of_session(self.db(), session_id)
            .await?
            .into_iter()
            .map(|link| link.sha)
            .collect::<Vec<_>>();
        let items = self.load_session_items(session_id).await?;
        let docs = event_docs(&session, visibility_of(&repo), &items, &commits);
        index(search_index.replace_session(session_id, docs))?;
        index(search_index.commit())?;
        Ok(())
    }

    /// Re-indexes every document of one repository from the database (plan D5):
    /// the repository's stale documents are dropped first, then the current
    /// rows are indexed. A missing or deleted repository drops its documents.
    pub(crate) async fn index_repo_by_id(&self, repo_id: i64) -> CoreResult<()> {
        let search_index = self.search_index();
        let Some(repo) = db_repos::by_id(self.db(), repo_id).await? else {
            index(search_index.drop_repo(repo_id))?;
            index(search_index.commit())?;
            return Ok(());
        };
        if repo.deleted_at.is_some() {
            index(search_index.drop_repo(repo_id))?;
            index(search_index.commit())?;
            return Ok(());
        }
        index(search_index.drop_repo(repo_id))?;
        let mut stats = IndexStats {
            trails: 0,
            events: 0,
        };
        self.index_repo(&repo, &mut stats).await?;
        index(search_index.commit())?;
        Ok(())
    }

    /// Removes every event document of one session (delete or purge, plan D5).
    pub(crate) async fn drop_session_docs(&self, session_id: i64) -> CoreResult<()> {
        let search_index = self.search_index();
        index(search_index.drop_session(session_id))?;
        index(search_index.commit())?;
        Ok(())
    }
}
