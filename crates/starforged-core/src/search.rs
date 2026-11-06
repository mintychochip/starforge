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

use std::collections::HashMap;

use starforge_format::{EventKind, kind_name};
use starforged_db::repos as db_repos;
use starforged_db::repos::RepoRow;
use starforged_db::sessions::{self as db_sessions, SessionRow};
use starforged_db::trails::{self as db_trails, TrailCommentRow, TrailFilter, TrailRow};
use starforged_index::{EventDoc, EventQuery, IndexStats, Scope, TrailDoc, TrailQuery};

use crate::accounts::User;
use crate::jobs::Job;
use crate::permission::{Permission, effective, is_member};
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

/// The default page size when the caller supplies none (plan D4).
pub const DEFAULT_PER_PAGE: i64 = 20;
/// The most results one search page may return (plan D4).
pub const MAX_PER_PAGE: i64 = 50;
/// The deepest page a search may request; bounds the valid-result skip.
pub const MAX_PAGE: i64 = 1000;
/// Candidates fetched per index round (plan D3: up to 3x the page size).
const CANDIDATE_FACTOR: usize = 3;
/// Snippets per session result (plan D4).
const MAX_EVENTS_PER_SESSION: usize = 3;

/// One page of search results (plan D4): a 1-based `page` and `per_page`.
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: i64,
    pub per_page: i64,
    pub has_more: bool,
}

/// A snippet plus the byte ranges of the query terms inside it (plan D6).
/// Ranges are byte offsets into `text`; layers render escape-first (text
/// through askama escaping, `<mark>` only around the ranged slices).
#[derive(Debug, Clone, Default)]
pub struct Snippet {
    pub text: String,
    pub highlights: Vec<(usize, usize)>,
}

/// One Trail search result (plan D6).
#[derive(Debug, Clone)]
pub struct TrailResult {
    pub owner: String,
    pub repo: String,
    pub number: i64,
    pub title: String,
    pub state: String,
    pub updated_at: i64,
    pub snippet: Snippet,
}

/// One matched session event (plan D6).
#[derive(Debug, Clone)]
pub struct SessionEventResult {
    pub seq: i64,
    pub kind: String,
    pub snippet: Snippet,
}

/// One session search result: the session plus its best-matching events,
/// at most three (plan D4).
#[derive(Debug, Clone)]
pub struct SessionResult {
    pub owner: String,
    pub repo: String,
    pub session: String,
    pub agent: String,
    pub title: String,
    pub events: Vec<SessionEventResult>,
}

/// The inclusive search filters (plan D4). Dates and the commit SHA are
/// raw strings so this layer owns validation: bad input answers
/// [`CoreError::Invalid`] (422), never silently applied or ignored.
/// Unset `page`/`per_page` default to 1 and 20.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub q: String,
    pub repo: Option<String>,
    pub agent: Option<String>,
    pub model: Option<String>,
    pub author: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub commit: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}

/// `page` (1-based) and `per_page` with the plan-D4 bounds.
fn parse_page(query: &SearchQuery) -> CoreResult<(i64, i64)> {
    let page = query.page.unwrap_or(1);
    if page < 1 {
        return Err(CoreError::Invalid("page must be at least 1".into()));
    }
    if page > MAX_PAGE {
        return Err(CoreError::Invalid(format!(
            "page must be at most {MAX_PAGE}"
        )));
    }
    let per_page = query.per_page.unwrap_or(DEFAULT_PER_PAGE);
    if !(1..=MAX_PER_PAGE).contains(&per_page) {
        return Err(CoreError::Invalid(format!(
            "per_page must be between 1 and {MAX_PER_PAGE}"
        )));
    }
    Ok((page, per_page))
}

/// One RFC 3339 date or date-time as unix seconds (plan D4): a bare date
/// means midnight UTC that day.
fn parse_date(raw: &str, name: &str) -> CoreResult<i64> {
    let candidate = if raw.len() == 10 {
        format!("{raw}T00:00:00Z")
    } else {
        raw.to_owned()
    };
    time::OffsetDateTime::parse(&candidate, &time::format_description::well_known::Rfc3339)
        .map(|parsed| parsed.unix_timestamp())
        .map_err(|_| CoreError::Invalid(format!("invalid {name} date '{raw}'")))
}

/// The inclusive `from`/`to` range, with `from` never after `to`.
fn parse_range(query: &SearchQuery) -> CoreResult<(Option<i64>, Option<i64>)> {
    let from = query
        .from
        .as_deref()
        .map(|raw| parse_date(raw, "from"))
        .transpose()?;
    let to = query
        .to
        .as_deref()
        .map(|raw| parse_date(raw, "to"))
        .transpose()?;
    if let (Some(from), Some(to)) = (from, to)
        && from > to
    {
        return Err(CoreError::Invalid("from must not be after to".into()));
    }
    Ok((from, to))
}

/// The `commit` filter: a full or ≥7-character hex SHA prefix (plan D4),
/// lowercased for the index prefix query.
fn parse_commit(query: &SearchQuery) -> CoreResult<Option<String>> {
    let Some(commit) = query.commit.as_deref() else {
        return Ok(None);
    };
    if !(7..=40).contains(&commit.len()) || !commit.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CoreError::Invalid(format!(
            "invalid commit '{commit}': want a 7 to 40 character hex SHA or prefix"
        )));
    }
    Ok(Some(commit.to_ascii_lowercase()))
}

/// The query tokens, tokenized like the index (unicode lowercase, split on
/// non-alphanumerics), de-duplicated in first-seen order.
fn query_tokens(q: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    for token in q
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        if !tokens.iter().any(|seen| seen == token) {
            tokens.push(token.to_owned());
        }
    }
    tokens
}

/// The snippet with the byte ranges of the query tokens inside it.
/// ASCII case folding preserves byte offsets; non-ASCII words simply get
/// no highlight. Overlapping ranges merge.
fn make_snippet(text: String, q: &str) -> Snippet {
    if text.is_empty() {
        return Snippet::default();
    }
    let lowered = text.to_ascii_lowercase();
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for token in query_tokens(q) {
        let needle = token.to_ascii_lowercase();
        let mut start = 0;
        while let Some(found) = lowered[start..].find(&needle) {
            let at = start + found;
            ranges.push((at, at + needle.len()));
            start = at + needle.len();
        }
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for range in ranges {
        if let Some(last) = merged.last_mut()
            && range.0 < last.1
        {
            last.1 = last.1.max(range.1);
            continue;
        }
        merged.push(range);
    }
    Snippet {
        text,
        highlights: merged,
    }
}

/// The snippet truncation cap, mirroring the index crate's snippets.
const SNIPPET_CHARS: usize = 500;

/// Truncates snippet text to 500 characters (mirroring the index crate).
fn truncate_snippet(text: &str) -> String {
    if text.chars().count() > SNIPPET_CHARS {
        format!("{}…", text.chars().take(SNIPPET_CHARS).collect::<String>())
    } else {
        text.to_owned()
    }
}

fn empty_page<T>(page: i64, per_page: i64) -> Page<T> {
    Page {
        items: Vec::new(),
        page,
        per_page,
        has_more: false,
    }
}

impl Core {
    /// The query-time permission filter (plan D3) for `user`: every live
    /// repository, bucketed by what the viewer can do there. Suspended
    /// users are anonymous. This is only the filter; every hit is still
    /// re-checked against the database before it is returned.
    async fn search_scope(&self, user: Option<&User>) -> CoreResult<Scope> {
        let active = user.filter(|u| u.active);
        let mut scope = Scope {
            signed_in: active.is_some(),
            viewer_id: active.map(|u| u.id),
            ..Default::default()
        };
        for row in db_repos::list_all_live(self.db(), i64::MAX).await? {
            let repo = crate::repos::to_repo(row)?;
            let collected = self.grants_for(&repo, active).await?;
            let grants = collected.as_grants();
            let permission = effective(&grants);
            if permission.is_some() {
                scope.readable.push(repo.id);
            }
            // Site admins read everything (§6.4 row 12), including
            // unpublished sessions on public repositories, but
            // `is_member` excludes them by definition. The query filter
            // must stay a superset of the re-check, so bucket every live
            // repository as a member for a site admin here (and only here
            // — `is_member` itself is unchanged).
            if is_member(&grants) || active.is_some_and(|u| u.is_admin) {
                scope.member.push(repo.id);
            }
            if permission.is_some_and(|p| p >= Permission::Admin) {
                scope.admin.push(repo.id);
            }
        }
        Ok(scope)
    }

    /// The `repo` filter (`owner/name`) as a repository id. A well-formed
    /// repository the viewer cannot read (or that does not exist) yields
    /// `None` — an empty page — so existence stays undiscoverable; only a
    /// malformed value is [`CoreError::Invalid`].
    async fn search_repo_id(&self, user: Option<&User>, raw: &str) -> CoreResult<Option<i64>> {
        let invalid = || CoreError::Invalid(format!("invalid repo '{raw}': want owner/name"));
        let Some((owner, name)) = raw.split_once('/') else {
            return Err(invalid());
        };
        if owner.is_empty() || name.is_empty() || name.contains('/') {
            return Err(invalid());
        }
        let Some(row) = db_repos::by_owner_and_name(self.db(), owner, name).await? else {
            return Ok(None);
        };
        let repo = crate::repos::to_repo(row)?;
        Ok(if self.permission_on(&repo, user).await?.is_some() {
            Some(repo.id)
        } else {
            None
        })
    }

    /// The `author` filter (a handle) as a user id; an unknown handle
    /// matches nothing.
    async fn search_author_id(&self, handle: &str) -> CoreResult<Option<i64>> {
        Ok(self.user_by_handle(handle).await?.map(|u| u.id))
    }

    /// The per-hit re-check for Trails (plan D3): the Trail and its
    /// repository are re-read from the database and the viewer must still
    /// read the repository. A repository that became private, was deleted,
    /// or whose grant was revoked after indexing hides the stale hit.
    async fn recheck_trail(
        &self,
        viewer: Option<&User>,
        hit: &starforged_index::TrailHit,
        q: &str,
    ) -> CoreResult<Option<TrailResult>> {
        let Some(trail) = db_trails::trail_by_id(self.db(), hit.trail_id).await? else {
            return Ok(None);
        };
        let Some(repo_row) = db_repos::by_id(self.db(), trail.repo_id).await? else {
            return Ok(None);
        };
        if repo_row.deleted_at.is_some() {
            return Ok(None);
        }
        let repo = crate::repos::to_repo(repo_row)?;
        if self.permission_on(&repo, viewer).await?.is_none() {
            return Ok(None);
        }
        // The snippet is re-read from the database too: the title plus the
        // intent and comment bodies (the same fields the index covers),
        // so a title-only match still highlights and text edited after
        // indexing cannot leak through the snippet.
        let comments = db_trails::comments_of(self.db(), trail.id).await?;
        let mut text = format!("{}\n\n{}", trail.title, trail.intent);
        for comment in &comments {
            text.push_str("\n\n");
            text.push_str(&comment.body);
        }
        Ok(Some(TrailResult {
            owner: repo.owner,
            repo: repo.name,
            number: trail.number,
            title: trail.title,
            state: trail.state,
            updated_at: trail.updated_at,
            snippet: make_snippet(truncate_snippet(&text), q),
        }))
    }

    /// The per-session re-check (plan D3 plus §6.4): the session and its
    /// repository are re-read from the database and
    /// [`Core::authorize_session_read`] must still pass, so a session
    /// quarantined, unpublished, or deleted after indexing — and a
    /// repository that became private or was deleted — hide the stale hit.
    async fn recheck_session(
        &self,
        viewer: Option<&User>,
        hit: &starforged_index::EventHit,
    ) -> CoreResult<Option<(SessionRow, crate::repos::Repo)>> {
        let Some(session) = db_sessions::session_by_id(self.db(), hit.session_id).await? else {
            return Ok(None);
        };
        if session.repo_id != hit.repo_id || session.lifecycle != "complete" {
            return Ok(None);
        }
        let Some(repo_row) = db_repos::by_id(self.db(), session.repo_id).await? else {
            return Ok(None);
        };
        if repo_row.deleted_at.is_some() {
            return Ok(None);
        }
        let repo = crate::repos::to_repo(repo_row)?;
        match self.authorize_session_read(viewer, &repo, &session).await {
            Ok(()) => Ok(Some((session, repo))),
            Err(CoreError::NotFound) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Trail search (spec §10.5, plan D3/D4): the index pre-filters, the
    /// database re-checks every hit, and the page is filled from up to 3x
    /// candidates per round until it holds `per_page` results or the
    /// candidates run out.
    pub async fn search_trails(
        &self,
        viewer: Option<&User>,
        query: &SearchQuery,
    ) -> CoreResult<Page<TrailResult>> {
        let (page, per_page) = parse_page(query)?;
        let (from, to) = parse_range(query)?;
        let repo_id = match &query.repo {
            Some(raw) => match self.search_repo_id(viewer, raw).await? {
                Some(id) => Some(id),
                None => return Ok(empty_page(page, per_page)),
            },
            None => None,
        };
        let author_id = match &query.author {
            Some(handle) => match self.search_author_id(handle).await? {
                Some(id) => Some(id),
                None => return Ok(empty_page(page, per_page)),
            },
            None => None,
        };
        let scope = self.search_scope(viewer).await?;
        let index_query = TrailQuery {
            q: query.q.clone(),
            repo_id,
            author_id,
            from,
            to,
        };
        let idx = self.search_index();
        let want = per_page as usize;
        let skip = ((page - 1) * per_page) as usize;
        let chunk = want * CANDIDATE_FACTOR;
        let mut offset = 0usize;
        let mut valid_seen = 0usize;
        let mut items: Vec<TrailResult> = Vec::new();
        let mut has_more = false;
        'fill: loop {
            let hits = index(idx.search_trails(&index_query, &scope, offset, chunk))?;
            if hits.is_empty() {
                break;
            }
            for hit in hits {
                offset += 1;
                if let Some(result) = self.recheck_trail(viewer, &hit, &query.q).await? {
                    if valid_seen >= skip {
                        items.push(result);
                        if items.len() > want {
                            has_more = true;
                            items.truncate(want);
                            break 'fill;
                        }
                    }
                    valid_seen += 1;
                }
            }
        }
        Ok(Page {
            items,
            page,
            per_page,
            has_more,
        })
    }

    /// Session search (spec §10.5, plan D3/D4): events group by session in
    /// first-seen (newest first) order with at most three snippets each,
    /// paginated by session. The event-kind of each snippet is re-read
    /// from the session blobs for the sessions on the page.
    pub async fn search_sessions(
        &self,
        viewer: Option<&User>,
        query: &SearchQuery,
    ) -> CoreResult<Page<SessionResult>> {
        let (page, per_page) = parse_page(query)?;
        let (from, to) = parse_range(query)?;
        let commit = parse_commit(query)?;
        let repo_id = match &query.repo {
            Some(raw) => match self.search_repo_id(viewer, raw).await? {
                Some(id) => Some(id),
                None => return Ok(empty_page(page, per_page)),
            },
            None => None,
        };
        let author_id = match &query.author {
            Some(handle) => match self.search_author_id(handle).await? {
                Some(id) => Some(id),
                None => return Ok(empty_page(page, per_page)),
            },
            None => None,
        };
        let scope = self.search_scope(viewer).await?;
        let index_query = EventQuery {
            q: query.q.clone(),
            repo_id,
            agent: query.agent.clone().filter(|v| !v.is_empty()),
            model: query.model.clone().filter(|v| !v.is_empty()),
            author_id,
            from,
            to,
            commit,
        };
        let idx = self.search_index();
        let want = per_page as usize;
        let skip = (page - 1) as usize * want;
        struct Group {
            session: SessionRow,
            repo: crate::repos::Repo,
            events: Vec<starforged_index::EventHit>,
        }
        let mut groups: Vec<Group> = Vec::new();
        let mut positions: HashMap<i64, usize> = HashMap::new();
        let mut checked: HashMap<i64, Option<(SessionRow, crate::repos::Repo)>> = HashMap::new();
        let mut valid_sessions = 0usize;
        let mut has_more = false;
        let chunk = want * CANDIDATE_FACTOR;
        let mut offset = 0usize;
        'fill: loop {
            let hits = index(idx.search_events(&index_query, &scope, offset, chunk))?;
            if hits.is_empty() {
                break;
            }
            for hit in hits {
                offset += 1;
                let status = match checked.get(&hit.session_id) {
                    Some(status) => status.clone(),
                    None => {
                        let status = self.recheck_session(viewer, &hit).await?;
                        checked.insert(hit.session_id, status.clone());
                        status
                    }
                };
                let Some((session, repo)) = status else {
                    continue;
                };
                let position = match positions.get(&hit.session_id) {
                    Some(position) => *position,
                    None => {
                        positions.insert(hit.session_id, groups.len());
                        valid_sessions += 1;
                        groups.push(Group {
                            session,
                            repo,
                            events: Vec::new(),
                        });
                        groups.len() - 1
                    }
                };
                let group = &mut groups[position];
                if group.events.len() < MAX_EVENTS_PER_SESSION {
                    group.events.push(hit);
                }
                if valid_sessions > skip + want {
                    has_more = true;
                    break 'fill;
                }
            }
        }
        let mut results = Vec::new();
        for group in groups.into_iter().skip(skip).take(want) {
            let items = self.load_session_items(group.session.id).await?;
            let events = group
                .events
                .into_iter()
                .map(|hit| {
                    let kind = items
                        .iter()
                        .find_map(|item| match item {
                            SessionPageItem::Event(event)
                                if i64::try_from(event.seq).ok() == Some(hit.seq) =>
                            {
                                Some(kind_name(&event.kind).to_owned())
                            }
                            _ => None,
                        })
                        .unwrap_or_else(|| "event".to_owned());
                    SessionEventResult {
                        seq: hit.seq,
                        kind,
                        snippet: make_snippet(hit.snippet, &query.q),
                    }
                })
                .collect();
            results.push(SessionResult {
                owner: group.repo.owner,
                repo: group.repo.name,
                session: group.session.ulid,
                agent: group.session.agent_name,
                title: group.session.title,
                events,
            });
        }
        Ok(Page {
            items: results,
            page,
            per_page,
            has_more,
        })
    }
}

/// One code search result (plan D6): the branch searched, the commit it
/// resolved to, and the matches there. An empty repository answers with
/// an empty `commit` and no matches.
#[derive(Debug, Clone)]
pub struct CodeSearchResult {
    pub ref_name: String,
    pub commit: String,
    pub matches: Vec<starforged_git::grep::GrepMatch>,
    pub truncated: bool,
}

impl Core {
    /// Code search (spec §10.5, plan S4): a fixed-string `git grep` over
    /// the default branch's tip commit only. Repository read access is
    /// required — a repository the viewer cannot read is `NotFound` — and
    /// archived repositories remain searchable (only pushes refuse them).
    /// An empty query, or one longer than the git layer's cap, is
    /// [`CoreError::Invalid`]; an empty repository (and a repository whose
    /// default branch does not exist) yields an empty result, never an
    /// arbitrary branch.
    pub async fn code_search(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        query: &str,
        case_insensitive: bool,
    ) -> CoreResult<CodeSearchResult> {
        let max_chars = starforged_git::grep::MAX_QUERY_CHARS;
        if query.is_empty() || query.chars().count() > max_chars {
            return Err(CoreError::Invalid(format!(
                "query must be 1..={max_chars} characters"
            )));
        }
        let access = self.repo_for(viewer, owner, repo).await?;
        let branches = self.branches(&access).await?;
        // Default branch only: a missing default branch never falls back to
        // an arbitrary branch. An empty repository (and a repository whose
        // default branch does not exist) yield an empty result.
        if !branches.contains(&access.repo.default_branch) {
            return Ok(CodeSearchResult {
                ref_name: access.repo.default_branch.clone(),
                commit: String::new(),
                matches: Vec::new(),
                truncated: false,
            });
        }
        let ref_name = access.repo.default_branch.clone();
        let resolved = self.resolve(&access, &ref_name).await?;
        let repo_dir = self.repo_path(access.repo.id);
        let result = starforged_git::grep::grep(
            &repo_dir,
            &resolved.commit_id,
            query,
            case_insensitive,
            &starforged_git::grep::GrepLimits::default(),
        )
        .await?;
        Ok(CodeSearchResult {
            ref_name,
            commit: result.commit,
            matches: result.matches,
            truncated: result.truncated,
        })
    }
}
