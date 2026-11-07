//! Session read rules (spec §6.4): who may see a session transcript.
//!
//! Denials are [`CoreError::NotFound`] (never `Forbidden`), so session ULIDs
//! stay undiscoverable — the same convention as [`Core::repo_for`] for
//! repositories the viewer cannot read.

use starforge_format::{Event, EventKind, decompress_bounded, parse_event};
use starforge_redact::redact_event;
use starforged_db::{repos as db_repos, sessions as db_sessions, sessions::SessionRow};

use crate::{
    Core, CoreError, CoreResult,
    accounts::User,
    permission::{self, Permission, Viewer, effective},
    repos::{Repo, RepoAccess},
};

/// Events per session viewer page (spec §10.2, binding).
pub const VIEWER_PER_PAGE: i64 = 200;

/// Maximum hits from one in-session search (D3): at most 200 hits.
pub const SEARCH_MAX_HITS: usize = 200;

/// Maximum query length (chars) for one in-session search (D3): longer
/// queries yield no hits.
pub const SEARCH_MAX_QUERY_CHARS: usize = 200;

/// One in-session search hit (D3): a server-redacted event whose searched
/// text contains the query (case-insensitive substring). `preview` is a
/// snippet of the matched text; redaction ran before the search, so
/// previews never carry a stored secret.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionSearchHit {
    pub seq: u64,
    pub page: i64,
    pub kind: String,
    pub preview: String,
}

/// One commit marker (D3): the session viewer renders it after the event
/// at the link's `seq_end`, linking to the commit page and the split view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitMarker {
    pub sha: String,
    pub short_sha: String,
    pub seq_end: i64,
}

/// One slot on a rendered session page: a server-redacted event, or a marker
/// for a segment whose bytes could not be decoded. Markers render as an
/// inline "unreadable segment" notice, never a 500.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionPageItem {
    Event(Event),
    UnreadableSegment { n: i64 },
}

/// One 1-based page over the concatenated segment event stream in stored
/// order. Paging is a pure function of `(segments, page, VIEWER_PER_PAGE)`.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionPage {
    pub items: Vec<SessionPageItem>,
    pub page: i64,
    pub pages: i64,
    pub total: i64,
}

impl Core {
    /// Whether an explicit grant exists on the repository (D4): user or org
    /// ownership, an org base permission, a covering team grant, or a
    /// collaborator grant. Implicit public/internal read does not count.
    pub async fn is_repo_member(&self, repo_id: i64, user_id: i64) -> CoreResult<bool> {
        let row = db_repos::by_id(self.db(), repo_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let repo = crate::repos::to_repo(row)?;
        let user = self.user_by_id(user_id).await?;
        let Some(user) = user else {
            return Ok(false);
        };
        Ok(permission::is_member(
            &self.grants_for(&repo, Some(&user)).await?.as_grants(),
        ))
    }

    /// The read-rule check over already-loaded rows. The caller must have
    /// established repo readability separately (or use
    /// [`Core::authorize_session_read_by_ulid`], which does); a viewer with no
    /// effective repo permission is denied (row 1). Suspended users are
    /// anonymous.
    pub async fn authorize_session_read(
        &self,
        user: Option<&User>,
        repo: &Repo,
        session: &SessionRow,
    ) -> CoreResult<()> {
        if session.repo_id != repo.id {
            return Err(CoreError::NotFound);
        }
        let active = user.filter(|u| u.active);
        // The grant lookup below serves both the effective-permission check
        // and membership, so no separate `is_repo_member` query is needed
        // here; that helper exists for callers holding only ids.
        let collected = self.grants_for(repo, active).await?;
        let grants = collected.as_grants();
        // Row 1: no effective read → 404 (not 403, so ULIDs stay undiscoverable).
        let permission = effective(&grants).ok_or(CoreError::NotFound)?;
        let viewer = active.map(|u| Viewer {
            user_id: u.id,
            is_admin: u.is_admin,
        });
        let is_member = permission::is_member(&grants);
        let is_admin = permission >= Permission::Admin;
        if can_read_session(viewer, repo, session, is_member, is_admin) {
            Ok(())
        } else {
            Err(CoreError::NotFound)
        }
    }

    /// [`Core::repo_for`] (read precondition — invisible repos 404 here) plus
    /// session lookup (unknown ULIDs 404) plus
    /// [`Core::authorize_session_read`]. Page handlers call this once and never
    /// duplicate the check.
    pub async fn authorize_session_read_by_ulid(
        &self,
        user: Option<&User>,
        owner: &str,
        name: &str,
        ulid: &str,
    ) -> CoreResult<(RepoAccess, SessionRow)> {
        let access = self.repo_for(user, owner, name).await?;
        let session = db_sessions::session_by_ulid(self.db(), access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        self.authorize_session_read(user, &access.repo, &session)
            .await?;
        Ok((access, session))
    }

    /// The raw-segment gate (§11.2): the stored segment blob is served only
    /// when raw storage is enabled for the session (`raw_enabled`) AND the
    /// viewer is the uploader or a site admin. Stored bytes are as-uploaded —
    /// the server re-redacts on every other read path, because low-confidence
    /// scan hits are never scrubbed out of storage — so anyone weaker only
    /// ever sees the re-redacted rendering. Everything else answers
    /// [`CoreError::NotFound`] (indistinguishable from an absent segment).
    pub async fn authorize_raw_segment_read(
        &self,
        user: Option<&User>,
        owner: &str,
        name: &str,
        ulid: &str,
    ) -> CoreResult<(RepoAccess, SessionRow)> {
        let (access, session) = self
            .authorize_session_read_by_ulid(user, owner, name, ulid)
            .await?;
        if session.raw_enabled == 0 {
            return Err(CoreError::NotFound);
        }
        let active = user.filter(|user| user.active);
        let permitted =
            active.is_some_and(|viewer| viewer.id == session.uploader_id || viewer.is_admin);
        if !permitted {
            return Err(CoreError::NotFound);
        }
        Ok((access, session))
    }
}
/// One dashboard session row: its repository coordinates plus the fields
/// the dashboard renders and links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub owner: String,
    pub repo: String,
    pub ulid: String,
    pub agent: String,
    pub title: String,
    pub started_at: i64,
}

/// Narrowing for one repository sessions list page. Only rows the viewer
/// may read under §6.4 are ever considered, so filters never reveal
/// unreadable sessions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoSessionFilter {
    /// Keep only top-level sessions (no readable parent in this repo).
    pub top_level_only: bool,
    /// Exact `agent_name` match, when set.
    pub agent: Option<String>,
    /// Exact `lifecycle` match (`receiving` or `complete`), when set.
    pub state: Option<String>,
}

/// One row of the repository sessions list: the readable session plus how
/// many readable direct subagent sessions name it as `parent_ulid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSessionItem {
    pub session: SessionRow,
    pub subagent_count: usize,
}

/// Dashboard candidate cap (D8): Core filters these through the §6.4 read
/// check for the viewer, then truncates.
const DASHBOARD_SESSION_CANDIDATES: i64 = 100;
/// Dashboard display cap for the sessions section (D8).
const DASHBOARD_SESSIONS: usize = 10;
/// Candidate cap for the readable session listing: export enumerates
/// sessions through it, so a repository past the cap silently truncates.
pub const READABLE_SESSION_LIST_LIMIT: i64 = 10_000;

impl Core {
    /// The viewer's own uploads that pass the §6.4 read check for them now,
    /// newest first, at most 10. Losing read on a repository hides its
    /// sessions immediately; unpublished uploads to public repositories they
    /// are not a member of (rule 2) never appear. Suspended users are
    /// anonymous and see nothing.
    pub async fn recent_sessions_for(&self, user: &User) -> CoreResult<Vec<SessionSummary>> {
        let viewer = user.active.then_some(user);
        let mut out = Vec::new();
        for session in
            db_sessions::sessions_uploaded_by(self.db(), user.id, DASHBOARD_SESSION_CANDIDATES)
                .await?
        {
            let Some(repo_row) = db_repos::by_id(self.db(), session.repo_id).await? else {
                continue;
            };
            if repo_row.deleted_at.is_some() {
                continue;
            }
            let repo = crate::repos::to_repo(repo_row)?;
            if self
                .authorize_session_read(viewer, &repo, &session)
                .await
                .is_err()
            {
                continue;
            }
            out.push(SessionSummary {
                owner: repo.owner.clone(),
                repo: repo.name.clone(),
                ulid: session.ulid.clone(),
                agent: session.agent_name.clone(),
                title: session.title.clone(),
                started_at: session.started_at,
            });
            if out.len() >= DASHBOARD_SESSIONS {
                break;
            }
        }
        Ok(out)
    }
}

impl Core {
    /// The full redacted item stream for `session_id`: segments in stored
    /// order, each decompressed under the configured cap, parsed line by
    /// line, and redacted with the effective server rule set (so stored
    /// secrets render as `[redacted:<id>]` and never raw). Undecodable
    /// segment bytes (missing blob, failed decompression, non-UTF-8) become
    /// [`SessionPageItem::UnreadableSegment`]; unparseable lines are skipped
    /// with a warning, never failing the page.
    pub async fn load_session_items(&self, session_id: i64) -> CoreResult<Vec<SessionPageItem>> {
        let session = db_sessions::session_by_id(self.db(), session_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let rules = self.scan_rules_for(session.repo_id).await?;
        let limit = usize::try_from(self.config().max_decompressed_bytes).unwrap_or(usize::MAX);
        let mut items = Vec::new();
        for segment in db_sessions::segments_of(self.db(), session_id).await? {
            let bytes = match self
                .config()
                .blob_store
                .get_by_hash(&segment.blob_hash)
                .await
            {
                Ok(bytes) => bytes,
                Err(err) => {
                    tracing::warn!(session_id, seg = segment.n, error = %err, "unreadable segment blob");
                    items.push(SessionPageItem::UnreadableSegment { n: segment.n });
                    continue;
                }
            };
            let raw = match decompress_bounded(&bytes, limit) {
                Ok(raw) => raw,
                Err(err) => {
                    tracing::warn!(session_id, seg = segment.n, error = %err, "unreadable segment bytes");
                    items.push(SessionPageItem::UnreadableSegment { n: segment.n });
                    continue;
                }
            };
            let text = match String::from_utf8(raw) {
                Ok(text) => text,
                Err(err) => {
                    tracing::warn!(session_id, seg = segment.n, error = %err, "segment is not UTF-8");
                    items.push(SessionPageItem::UnreadableSegment { n: segment.n });
                    continue;
                }
            };
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                match parse_event(line) {
                    Ok(event) => {
                        let (redacted, _) = redact_event(&rules, &event);
                        items.push(SessionPageItem::Event(redacted));
                    }
                    Err(err) => {
                        tracing::warn!(session_id, seg = segment.n, error = %err, "skipping unparseable event line");
                    }
                }
            }
        }
        Ok(items)
    }

    /// The 1-based page slice of the session transcript. Out-of-range pages
    /// (including unknown sessions) answer [`CoreError::NotFound`].
    pub async fn read_session_page(&self, session_id: i64, page: i64) -> CoreResult<SessionPage> {
        let items = self.load_session_items(session_id).await?;
        let total = items.len() as i64;
        let pages = ((total + VIEWER_PER_PAGE - 1) / VIEWER_PER_PAGE).max(1);
        if page < 1 || page > pages {
            return Err(CoreError::NotFound);
        }
        let start = ((page - 1) * VIEWER_PER_PAGE) as usize;
        let end = (page * VIEWER_PER_PAGE).min(total) as usize;
        Ok(SessionPage {
            items: items[start..end].to_vec(),
            page,
            pages,
            total,
        })
    }

    /// The 1-based page containing event `seq`, for `?focus=<seq>` deep
    /// links. Unknown seqs resolve to page 1 with `found = false` (the
    /// caller renders page 1 with no anchor).
    pub async fn page_for_seq(&self, session_id: i64, seq: i64) -> CoreResult<(i64, bool)> {
        let items = self.load_session_items(session_id).await?;
        let wanted = u64::try_from(seq).ok();
        for (index, item) in items.iter().enumerate() {
            if let SessionPageItem::Event(event) = item
                && wanted.is_some_and(|seq| event.seq == seq)
            {
                return Ok(((index as i64) / VIEWER_PER_PAGE + 1, true));
            }
        }
        Ok((1, false))
    }

    /// In-session search (D3, spec §10.5 scope): case-insensitive substring
    /// over message text (user/assistant messages), tool names, and file
    /// paths, over the same server-redacted items the viewer renders —
    /// tool inputs are never searched. At most [`SEARCH_MAX_HITS`] hits,
    /// each naming the 1-based page and `turn-<seq>` anchor it lives on.
    /// Callers authorize the session first; an empty query yields no hits.
    /// Queries longer than [`SEARCH_MAX_QUERY_CHARS`] chars yield no hits
    /// (before loading the stream — a bound on work per request).
    pub async fn search_session(
        &self,
        session_id: i64,
        query: &str,
    ) -> CoreResult<Vec<SessionSearchHit>> {
        let needle = query.to_lowercase();
        if needle.trim().is_empty() || needle.chars().count() > SEARCH_MAX_QUERY_CHARS {
            return Ok(Vec::new());
        }
        let items = self.load_session_items(session_id).await?;
        let mut hits = Vec::new();
        for (index, item) in items.iter().enumerate() {
            let SessionPageItem::Event(event) = item else {
                continue;
            };
            let Some((kind, text)) = searchable_text(event) else {
                continue;
            };
            if !text.to_lowercase().contains(&needle) {
                continue;
            }
            hits.push(SessionSearchHit {
                seq: event.seq,
                page: (index as i64) / VIEWER_PER_PAGE + 1,
                kind: kind.to_owned(),
                preview: snippet(text),
            });
            if hits.len() >= SEARCH_MAX_HITS {
                break;
            }
        }
        Ok(hits)
    }

    /// Commit markers (D3): one per commit-link row with a `seq_end`, oldest
    /// first, deduplicated by (sha, seq_end). Callers authorize the session
    /// first; links carry no content of their own.
    pub async fn commit_markers(&self, session_id: i64) -> CoreResult<Vec<CommitMarker>> {
        let mut out = Vec::new();
        for link in self.session_links(session_id).await? {
            let Some(seq_end) = link.seq_end else {
                continue;
            };
            if out
                .iter()
                .any(|m: &CommitMarker| m.sha == link.sha && m.seq_end == seq_end)
            {
                continue;
            }
            out.push(CommitMarker {
                short_sha: link.sha.chars().take(7).collect(),
                sha: link.sha,
                seq_end,
            });
        }
        Ok(out)
    }

    /// The full normalized transcript: every redacted event re-serialized to
    /// its canonical JSONL line (the same bytes the viewer renders, and the
    /// bytes a future export bundle will contain). Undecodable segments and
    /// unparseable lines are skipped exactly as in
    /// [`Core::read_session_page`], so the download never fails on stored
    /// evidence the page itself tolerates.
    pub async fn read_session_jsonl(&self, session_id: i64) -> CoreResult<Vec<u8>> {
        let items = self.load_session_items(session_id).await?;
        let mut out = Vec::new();
        for item in &items {
            if let SessionPageItem::Event(event) = item {
                let line = serde_json::to_vec(event)
                    .map_err(|e| CoreError::Internal(format!("encoding event: {e}")))?;
                out.extend_from_slice(&line);
                out.push(b'\n');
            }
        }
        Ok(out)
    }

    /// The commit-link rows filed under the session (trailer + CLI claims),
    /// oldest first. Callers authorize the session first; links carry no
    /// content of their own.
    pub async fn session_links(
        &self,
        session_id: i64,
    ) -> CoreResult<Vec<db_sessions::CommitLinkRow>> {
        Ok(db_sessions::links_of_session(self.db(), session_id).await?)
    }

    /// The sessions of `access.repo` that the §6.4 read rule admits for
    /// `viewer`, oldest first. Backs the readable session listing
    /// (`GET /repos/{owner}/{repo}/sessions`); callers keep the ULIDs
    /// undiscoverable by stamping the same per-row check as
    /// [`Core::authorize_session_read`].
    pub async fn list_readable_sessions(
        &self,
        viewer: Option<&User>,
        access: &RepoAccess,
    ) -> CoreResult<Vec<SessionRow>> {
        Ok(self
            .list_readable_sessions_capped(viewer, access, READABLE_SESSION_LIST_LIMIT)
            .await?
            .0)
    }

    /// [`Core::list_readable_sessions`] with an explicit candidate cap.
    /// One candidate past the cap is fetched so truncation is honest: the
    /// flag is `true` whenever the cap cut the *candidate* list (the
    /// unreadable tail could hide readable sessions), not only when the
    /// readable count itself hit the cap.
    pub async fn list_readable_sessions_capped(
        &self,
        viewer: Option<&User>,
        access: &RepoAccess,
        cap: i64,
    ) -> CoreResult<(Vec<SessionRow>, bool)> {
        let rows =
            db_sessions::sessions_of_repo(self.db(), access.repo.id, cap.saturating_add(1)).await?;
        let truncated = (rows.len() as i64) > cap;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            if self
                .authorize_session_read(viewer, &access.repo, &row)
                .await
                .is_ok()
            {
                out.push(row);
            }
        }
        Ok((out, truncated))
    }

    /// Sessions of `access.repo` readable by `viewer`, newest first by
    /// `started_at`, narrowed by a [`RepoSessionFilter`] and paged
    /// (`page` is 1-based; `per_page` rows).
    ///
    /// Returns the page plus the total filtered count. Readability is the
    /// same per-row [`Core::authorize_session_read`] check as
    /// [`Core::list_readable_sessions`]; only the in-memory ordering,
    /// filtering, child counts, and slicing are new here.
    /// Sessions of `access.repo` readable by `viewer`, newest first by
    /// `started_at`, narrowed by a [`RepoSessionFilter`] and paged
    /// (`page` is 1-based; `per_page` rows).
    ///
    /// Returns the page plus the total filtered count. Readability is the
    /// same per-row [`Core::authorize_session_read`] check as
    /// [`Core::list_readable_sessions`]; only the in-memory ordering,
    /// filtering, child counts, and slicing are new here.
    pub async fn list_repo_sessions_page(
        &self,
        viewer: Option<&User>,
        access: &RepoAccess,
        filter: &RepoSessionFilter,
        page: i64,
        per_page: usize,
    ) -> CoreResult<(Vec<RepoSessionItem>, i64)> {
        self.list_repo_sessions_page_capped(
            viewer,
            access,
            filter,
            page,
            per_page,
            READABLE_SESSION_LIST_LIMIT,
        )
        .await
    }

    /// [`Core::list_repo_sessions_page`] with an explicit candidate cap.
    /// Candidates are the newest sessions first (see
    /// [`db_sessions::sessions_of_repo_newest`]), so a repository past the
    /// cap still shows its newest *readable* sessions instead of letting
    /// old unreadable rows crowd them out. `total` counts the filtered
    /// matches within the cap.
    pub async fn list_repo_sessions_page_capped(
        &self,
        viewer: Option<&User>,
        access: &RepoAccess,
        filter: &RepoSessionFilter,
        page: i64,
        per_page: usize,
        cap: i64,
    ) -> CoreResult<(Vec<RepoSessionItem>, i64)> {
        let candidates =
            db_sessions::sessions_of_repo_newest(self.db(), access.repo.id, cap.saturating_add(1))
                .await?;
        let mut readable = Vec::with_capacity(candidates.len());
        for row in candidates {
            if self
                .authorize_session_read(viewer, &access.repo, &row)
                .await
                .is_ok()
            {
                readable.push(row);
            }
        }
        let readable_ulids: std::collections::HashSet<&str> =
            readable.iter().map(|row| row.ulid.as_str()).collect();
        let mut child_counts: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for row in &readable {
            if let Some(parent) = row.parent_ulid.as_deref() {
                *child_counts.entry(parent).or_insert(0) += 1;
            }
        }
        let mut filtered: Vec<&SessionRow> = readable
            .iter()
            .filter(|row| {
                if filter.top_level_only
                    && let Some(parent) = row.parent_ulid.as_deref()
                    && readable_ulids.contains(parent)
                {
                    return false;
                }
                if let Some(agent) = &filter.agent
                    && row.agent_name != *agent
                {
                    return false;
                }
                if let Some(state) = &filter.state
                    && row.lifecycle != *state
                {
                    return false;
                }
                true
            })
            .collect();
        filtered.sort_by(|a, b| {
            b.started_at
                .cmp(&a.started_at)
                .then_with(|| b.id.cmp(&a.id))
        });
        let total = filtered.len() as i64;
        let page = page.max(1);
        let start = (page - 1).saturating_mul(per_page as i64) as usize;
        let items: Vec<RepoSessionItem> = if start >= filtered.len() {
            Vec::new()
        } else {
            let end = (start + per_page).min(filtered.len());
            filtered[start..end]
                .iter()
                .map(|row| RepoSessionItem {
                    subagent_count: child_counts.get(row.ulid.as_str()).copied().unwrap_or(0),
                    session: (*row).clone(),
                })
                .collect()
        };
        Ok((items, total))
    }

    /// Whether `path` exists in `commit_id` (blob, tree, or submodule
    /// gitlink). Submodules are neither blobs nor trees, so the
    /// history page gates on this instead of `blob`/`tree`.
    pub async fn path_exists(
        &self,
        access: &RepoAccess,
        commit_id: &str,
        path: &str,
    ) -> CoreResult<bool> {
        let repo = self.repo_path(access.repo.id);
        let (commit_id, path) = (commit_id.to_owned(), path.to_owned());
        tokio::task::spawn_blocking(move || {
            starforged_git::read::path_exists(&repo, &commit_id, &path)
        })
        .await
        .map_err(|e| CoreError::Internal(e.to_string()))?
        .map_err(CoreError::from)
    }

    /// The readable parent of `session`, if it names one (`parent_ulid`)
    /// that `viewer` may read in `access.repo`. A missing, cross-repo, or
    /// unreadable parent is `None`, never an error.
    pub async fn readable_parent_session(
        &self,
        viewer: Option<&User>,
        access: &RepoAccess,
        session: &SessionRow,
    ) -> CoreResult<Option<SessionRow>> {
        let Some(parent_ulid) = session.parent_ulid.as_deref() else {
            return Ok(None);
        };
        let Some(parent) =
            db_sessions::session_by_ulid(self.db(), access.repo.id, parent_ulid).await?
        else {
            return Ok(None);
        };
        if self
            .authorize_session_read(viewer, &access.repo, &parent)
            .await
            .is_err()
        {
            return Ok(None);
        }
        Ok(Some(parent))
    }

    /// Direct subagent sessions of `ulid` in `access.repo` that `viewer`
    /// may read, oldest first by `started_at`.
    pub async fn readable_child_sessions(
        &self,
        viewer: Option<&User>,
        access: &RepoAccess,
        ulid: &str,
    ) -> CoreResult<Vec<SessionRow>> {
        let candidates = db_sessions::sessions_by_parent(self.db(), access.repo.id, ulid).await?;
        let mut out = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if self
                .authorize_session_read(viewer, &access.repo, &candidate)
                .await
                .is_ok()
            {
                out.push(candidate);
            }
        }
        Ok(out)
    }

    /// The exact stored bytes of segment `n` of `session_id` (the compressed
    /// JSONL blob, verbatim). Callers authorize the session first; a missing
    /// segment answers [`CoreError::NotFound`].
    pub async fn session_segment_bytes(&self, session_id: i64, n: i64) -> CoreResult<Vec<u8>> {
        let segment = db_sessions::segment_by_n(self.db(), session_id, n)
            .await?
            .ok_or(CoreError::NotFound)?;
        self.config()
            .blob_store
            .get_by_hash(&segment.blob_hash)
            .await
            .map_err(|e| CoreError::Internal(format!("reading segment blob: {e}")))
    }
    /// Links filed under `sha` that `viewer` may read, oldest first, each
    /// paired with its session row.
    ///
    /// Unreadable links are **omitted entirely** (never a locked chip): a
    /// public commit page must not leak the existence — let alone the ULID —
    /// of a session the viewer cannot read. Rows whose upload has not
    /// arrived yet (`session_id IS NULL` with no matching session row) are
    /// skipped: the panel shows uploaded sessions only.
    pub async fn readable_links_for_commit(
        &self,
        access: &RepoAccess,
        viewer: Option<&User>,
        sha: &str,
    ) -> CoreResult<Vec<(db_sessions::CommitLinkRow, SessionRow)>> {
        let links = db_sessions::links_for_sha(self.db(), access.repo.id, sha).await?;
        self.filter_readable_links(access, viewer, links).await
    }

    /// Readable-link counts per sha for a commits list page: one
    /// [`links_for_shas`](db_sessions::links_for_shas) query for every sha,
    /// then the same per-row [`can_read_session`] filter as
    /// [`Core::readable_links_for_commit`]. Shas without a readable link are
    /// absent from the map.
    pub async fn readable_link_counts(
        &self,
        access: &RepoAccess,
        viewer: Option<&User>,
        shas: &[String],
    ) -> CoreResult<std::collections::HashMap<String, usize>> {
        let links = db_sessions::links_for_shas(self.db(), access.repo.id, shas).await?;
        let readable = self.filter_readable_links(access, viewer, links).await?;
        let mut counts = std::collections::HashMap::new();
        for (link, _) in &readable {
            *counts.entry(link.sha.clone()).or_insert(0) += 1;
        }
        Ok(counts)
    }

    /// Resolves each link row to its session (via `session_id`, falling back
    /// to `session_ulid` for trailer-first rows whose upload has since
    /// arrived) and keeps only rows [`can_read_session`] admits for `viewer`.
    pub(crate) async fn filter_readable_links(
        &self,
        access: &RepoAccess,
        viewer: Option<&User>,
        links: Vec<db_sessions::CommitLinkRow>,
    ) -> CoreResult<Vec<(db_sessions::CommitLinkRow, SessionRow)>> {
        // Mirror `authorize_session_read_by_ulid`: suspended users are anonymous.
        let active = viewer.filter(|u| u.active);
        let grants = self.grants_for(&access.repo, active).await?;
        let viewer_opt = active.map(|u| Viewer {
            user_id: u.id,
            is_admin: u.is_admin,
        });
        let is_member = permission::is_member(&grants.as_grants());
        let is_admin = access.permission >= Permission::Admin;
        let mut out = Vec::new();
        for link in links {
            let session = match link.session_id {
                Some(id) => db_sessions::session_by_id(self.db(), id).await?,
                None => {
                    db_sessions::session_by_ulid(self.db(), access.repo.id, &link.session_ulid)
                        .await?
                }
            };
            let Some(session) = session else { continue };
            if session.repo_id != access.repo.id {
                continue;
            }
            if can_read_session(viewer_opt, &access.repo, &session, is_member, is_admin) {
                out.push((link, session));
            }
        }
        Ok(out)
    }
}

/// The searched text of one event under spec §10.5's scope (D3): message
/// text (user/assistant), tool names, and file paths. Tool inputs and
/// outputs are never searched. Returns the event's kind name with the text.
fn searchable_text(event: &Event) -> Option<(&'static str, &str)> {
    match &event.kind {
        EventKind::UserMessage(message) => Some(("user_message", &message.text)),
        EventKind::AssistantMessage(message) => Some(("assistant_message", &message.text)),
        EventKind::ToolCall(call) => Some(("tool_call", &call.tool.name)),
        EventKind::FileChange(change) => Some(("file_change", &change.path)),
        _ => None,
    }
}

/// The first 160 characters of a matched text, for search previews.
/// The input is already server-redacted; callers escape it for HTML.
fn snippet(text: &str) -> String {
    text.chars().take(160).collect()
}

/// Pure read rule: may `viewer` see `session` on `repo`?
///
/// `is_member` is [`Core::is_repo_member`] (explicit grant only — implicit
/// public/internal read does not count); `is_admin` is whether the viewer's
/// effective repo permission is `Admin` or higher (owners and site admins count;
/// see [`effective`]).
///
/// Every arm names the truth-table rows it implements.
pub fn can_read_session(
    viewer: Option<Viewer>,
    repo: &Repo,
    session: &SessionRow,
    is_member: bool,
    is_admin: bool,
) -> bool {
    // Row 12: site admins read everything.
    if viewer.map(|v| v.is_admin).unwrap_or(false) {
        return true;
    }
    let is_owner = viewer.map(|v| v.user_id == repo.owner_id).unwrap_or(false);
    let is_uploader = viewer
        .map(|v| v.user_id == session.uploader_id)
        .unwrap_or(false);
    // Rows 8-10: quarantine gate — uploader or repo admin only.
    if session.quarantine == "quarantined" {
        return is_uploader || is_owner || is_admin;
    }
    // Row 11: `released` follows the normal visibility rules below.
    // Owners read everything that is not quarantined.
    if is_owner {
        return true;
    }
    if session.visibility == "published" {
        // Rows 2, 5, 6: anyone holding repo read (implicit or explicit).
        return repo_readable(viewer, repo, is_member);
    }
    // §6.4: an unpublished session is readable when the repo is not public and
    // the viewer can read the repo (rows 5, 6, 7); on public repos only
    // explicit members (rows 3, 4) — implicit public read does not count.
    if repo.visibility != crate::permission::Visibility::Public {
        return repo_readable(viewer, repo, is_member);
    }
    is_member
}

/// Whether the viewer holds repo read: explicit membership, or the implicit
/// read public repositories give everyone and internal repositories give
/// signed-in users. Mirrors [`effective`] without a collaborator lookup.
fn repo_readable(viewer: Option<Viewer>, repo: &Repo, is_member: bool) -> bool {
    if is_member {
        return true;
    }
    match repo.visibility {
        crate::permission::Visibility::Public => true,
        crate::permission::Visibility::Internal => viewer.is_some(),
        crate::permission::Visibility::Private => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::permission::Visibility;
    use crate::repos::CreateRepo;
    use crate::testing::{Fixture, test_core, user};

    pub(crate) fn repo(visibility: Visibility) -> Repo {
        Repo {
            id: 1,
            owner_id: 7,
            owner: "alice".into(),
            name: "demo".into(),
            description: String::new(),
            visibility,
            default_branch: "main".into(),
            archived_at: None,
            deleted_at: None,
            mirror: false,
            import_state: "none".to_owned(),
            created_at: 0,
            updated_at: 0,
        }
    }

    pub(crate) fn session_row(uploader_id: i64, visibility: &str, quarantine: &str) -> SessionRow {
        SessionRow {
            id: 1,
            repo_id: 1,
            ulid: "01TEST".into(),
            uploader_id,
            agent_name: "pi".into(),
            agent_version: "0.1.0".into(),
            models: "{}".into(),
            title: "t".into(),
            branch: "work".into(),
            head_sha: "abc".into(),
            started_at: 1,
            ended_at: None,
            parent_ulid: None,
            usage_input: 0,
            usage_output: 0,
            usage_cache_read: 0,
            usage_cache_write: 0,
            usage_reasoning: 0,
            files_touched: "[]".into(),
            turn_count: 0,
            tool_call_count: 0,
            lifecycle: "receiving".into(),
            quarantine: quarantine.into(),
            quarantine_reason: String::new(),
            quarantine_detail: String::new(),
            visibility: visibility.into(),
            raw_enabled: 0,
            redaction_fingerprint: String::new(),
            redaction_counts: "{}".into(),
            capture_mode: "full".into(),
            cli_version: "0".into(),
            adapter_verified: 0,
            created_at: 0,
            updated_at: 0,
        }
    }

    const OWNER: i64 = 7;
    const MEMBER: i64 = 8;
    const STRANGER: i64 = 9;

    fn anon() -> Option<Viewer> {
        None
    }

    fn signed(id: i64) -> Option<Viewer> {
        Some(Viewer {
            user_id: id,
            is_admin: false,
        })
    }

    fn admin(id: i64) -> Option<Viewer> {
        Some(Viewer {
            user_id: id,
            is_admin: true,
        })
    }

    /// One case per truth-table row: (repo visibility, viewer, session
    /// visibility, quarantine, uploader, member, admin, expected).
    #[allow(clippy::type_complexity)]
    #[test]
    fn read_rule_truth_table() {
        type Case = (
            Visibility,
            Option<Viewer>,
            &'static str,
            &'static str,
            i64,
            bool,
            bool,
            bool,
        );
        let cases: Vec<Case> = vec![
            // Row 1: no effective read → deny (private/inherit, nobody).
            (
                Visibility::Private,
                anon(),
                "inherit",
                "none",
                MEMBER,
                false,
                false,
                false,
            ),
            // Row 1b: internal + anonymous has no read either.
            (
                Visibility::Internal,
                anon(),
                "published",
                "none",
                MEMBER,
                false,
                false,
                false,
            ),
            // Row 2: public + published → anyone, even anonymous.
            (
                Visibility::Public,
                anon(),
                "published",
                "none",
                MEMBER,
                false,
                false,
                true,
            ),
            (
                Visibility::Public,
                signed(STRANGER),
                "published",
                "none",
                MEMBER,
                false,
                false,
                true,
            ),
            // Row 3: public + unpublished + member → allow.
            (
                Visibility::Public,
                signed(MEMBER),
                "inherit",
                "none",
                OWNER,
                true,
                false,
                true,
            ),
            // Row 4: public + unpublished + implicit-read-only non-member → deny.
            (
                Visibility::Public,
                signed(STRANGER),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            (
                Visibility::Public,
                anon(),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            // Row 5: internal + signed-in + published → allow; inherit + member → allow.
            (
                Visibility::Internal,
                signed(STRANGER),
                "published",
                "none",
                MEMBER,
                false,
                false,
                true,
            ),
            (
                Visibility::Internal,
                signed(MEMBER),
                "inherit",
                "none",
                OWNER,
                true,
                false,
                true,
            ),
            // Row 5b: internal + inherit + signed-in non-member → allow (repo
            // is not public, viewer holds repo read).
            (
                Visibility::Internal,
                signed(STRANGER),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                true,
            ),
            // Internal + inherit + anonymous → deny (no repo read).
            (
                Visibility::Internal,
                anon(),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            // Row 6: private + member with read → allow (published and inherit).
            (
                Visibility::Private,
                signed(MEMBER),
                "inherit",
                "none",
                OWNER,
                true,
                false,
                true,
            ),
            (
                Visibility::Private,
                signed(MEMBER),
                "published",
                "none",
                OWNER,
                true,
                false,
                true,
            ),
            // Row 7: private + non-member → deny.
            (
                Visibility::Private,
                signed(STRANGER),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            (
                Visibility::Private,
                signed(STRANGER),
                "published",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            // Row 8: quarantined + uploader → allow (even without any other grant).
            (
                Visibility::Private,
                signed(STRANGER),
                "inherit",
                "quarantined",
                STRANGER,
                false,
                false,
                true,
            ),
            // Row 9: quarantined + repo admin (not uploader) → allow.
            (
                Visibility::Private,
                signed(MEMBER),
                "inherit",
                "quarantined",
                OWNER,
                true,
                true,
                true,
            ),
            // Row 10: quarantined + member (not uploader/admin) → deny.
            (
                Visibility::Private,
                signed(MEMBER),
                "inherit",
                "quarantined",
                OWNER,
                true,
                false,
                false,
            ),
            (
                Visibility::Public,
                signed(STRANGER),
                "published",
                "quarantined",
                OWNER,
                false,
                false,
                false,
            ),
            // Row 11: released → normal visibility rules apply.
            (
                Visibility::Public,
                signed(MEMBER),
                "inherit",
                "released",
                OWNER,
                true,
                false,
                true,
            ),
            (
                Visibility::Public,
                signed(STRANGER),
                "inherit",
                "released",
                OWNER,
                false,
                false,
                false,
            ),
            (
                Visibility::Public,
                anon(),
                "published",
                "released",
                OWNER,
                false,
                false,
                true,
            ),
            // Row 12: site admin → allow (normal and quarantined).
            (
                Visibility::Private,
                admin(99),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                true,
            ),
            (
                Visibility::Private,
                admin(99),
                "published",
                "quarantined",
                OWNER,
                false,
                false,
                true,
            ),
        ];
        for (i, (visibility, viewer, sess_vis, quarantine, uploader, member, is_admin, expect)) in
            cases.into_iter().enumerate()
        {
            let r = repo(visibility);
            let s = session_row(uploader, sess_vis, quarantine);
            assert_eq!(
                can_read_session(viewer, &r, &s, member, is_admin),
                expect,
                "case {i}: {visibility:?}/{sess_vis}/{quarantine} member={member} admin={is_admin}"
            );
        }
    }

    fn new_session<'a>(
        repo_id: i64,
        ulid: &'a str,
        uploader_id: i64,
        visibility: &'a str,
        quarantine: &'a str,
    ) -> db_sessions::NewSession<'a> {
        db_sessions::NewSession {
            repo_id,
            ulid,
            uploader_id,
            agent_name: "pi",
            agent_version: "0.1.0",
            models: "{}",
            title: "t",
            branch: "work",
            head_sha: "abc",
            started_at: 1,
            ended_at: None,
            parent_ulid: None,
            usage_input: 0,
            usage_output: 0,
            usage_cache_read: 0,
            usage_cache_write: 0,
            usage_reasoning: 0,
            files_touched: "[]",
            turn_count: 0,
            tool_call_count: 0,
            lifecycle: "receiving",
            quarantine,
            quarantine_reason: "",
            quarantine_detail: "",
            visibility,
            raw_enabled: 0,
            redaction_fingerprint: "",
            redaction_counts: "{}",
            capture_mode: "full",
            cli_version: "0",
            adapter_verified: 0,
        }
    }

    async fn mk_repo(core: &Core, owner: &User, name: &str, visibility: Visibility) -> Repo {
        core.create_repo(
            owner,
            &owner.handle,
            CreateRepo {
                name: name.into(),
                description: String::new(),
                visibility,
                readme: false,
            },
        )
        .await
        .expect("create repo")
    }

    fn as_viewer(u: &User) -> Option<Viewer> {
        Some(Viewer {
            user_id: u.id,
            is_admin: u.is_admin,
        })
    }

    struct Seeded {
        _fixture: Fixture,
        core: Core,
        alice: User,
        bob: User,
        carol: User,
        root: User,
        priv_repo: Repo,
        pub_repo: Repo,
        int_repo: Repo,
    }

    impl Seeded {
        async fn session(
            &self,
            repo: &Repo,
            ulid: &str,
            uploader: &User,
            visibility: &str,
            quarantine: &str,
        ) -> SessionRow {
            let id = db_sessions::insert_session(
                self.core.db(),
                &new_session(repo.id, ulid, uploader.id, visibility, quarantine),
            )
            .await
            .unwrap();
            db_sessions::session_by_id(self.core.db(), id)
                .await
                .unwrap()
                .unwrap()
        }

        async fn check(
            &self,
            viewer: Option<Viewer>,
            repo: &Repo,
            session: &SessionRow,
        ) -> Result<(), CoreError> {
            let user = match viewer {
                Some(v) => self.core.user_by_id(v.user_id).await.unwrap(),
                None => None,
            };
            self.core
                .authorize_session_read(user.as_ref(), repo, session)
                .await
        }
    }

    async fn seed() -> Seeded {
        let (core, fixture) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        let carol = user(&core, "carol").await;
        let root = core
            .create_user(CreateUser {
                handle: "root".into(),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let priv_repo = mk_repo(&core, &alice, "secret", Visibility::Private).await;
        let pub_repo = mk_repo(&core, &alice, "open", Visibility::Public).await;
        let int_repo = mk_repo(&core, &alice, "team", Visibility::Internal).await;
        core.set_collaborator(&alice, "alice", "secret", "bob", Permission::Write)
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "open", "bob", Permission::Read)
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "team", "bob", Permission::Read)
            .await
            .unwrap();
        Seeded {
            _fixture: fixture,
            core,
            alice,
            bob,
            carol,
            root,
            priv_repo,
            pub_repo,
            int_repo,
        }
    }

    #[tokio::test]
    async fn authorize_end_to_end_matrix() {
        let s = seed().await;
        // Row 1: private repo invisible to strangers → NotFound.
        let sess = s
            .session(&s.priv_repo, "01E1", &s.alice, "inherit", "none")
            .await;
        assert!(matches!(
            s.check(as_viewer(&s.carol), &s.priv_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            s.check(None, &s.priv_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Row 2: public + published → anonymous Ok.
        let sess = s
            .session(&s.pub_repo, "01E2", &s.alice, "published", "none")
            .await;
        assert!(s.check(None, &s.pub_repo, &sess).await.is_ok());
        // Rows 3/4: public + inherit → member Ok, stranger/anon NotFound.
        let sess = s
            .session(&s.pub_repo, "01E34", &s.alice, "inherit", "none")
            .await;
        assert!(s.check(as_viewer(&s.bob), &s.pub_repo, &sess).await.is_ok());
        assert!(matches!(
            s.check(as_viewer(&s.carol), &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            s.check(None, &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Row 5: internal + published → signed-in Ok; inherit + member Ok; inherit + signed-in non-member Ok.
        let sess = s
            .session(&s.int_repo, "01E5P", &s.alice, "published", "none")
            .await;
        assert!(
            s.check(as_viewer(&s.carol), &s.int_repo, &sess)
                .await
                .is_ok()
        );
        assert!(matches!(
            s.check(None, &s.int_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        let sess = s
            .session(&s.int_repo, "01E5I", &s.alice, "inherit", "none")
            .await;
        assert!(s.check(as_viewer(&s.bob), &s.int_repo, &sess).await.is_ok());
        assert!(
            s.check(as_viewer(&s.carol), &s.int_repo, &sess)
                .await
                .is_ok()
        );
        assert!(matches!(
            s.check(None, &s.int_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Rows 6/7: private + inherit → member Ok, stranger denied.
        let sess = s
            .session(&s.priv_repo, "01E67", &s.alice, "inherit", "none")
            .await;
        assert!(
            s.check(as_viewer(&s.bob), &s.priv_repo, &sess)
                .await
                .is_ok()
        );
        // Row 8: quarantined + uploader → Ok (bob's own session, quarantined).
        let sess = s
            .session(&s.priv_repo, "01E8", &s.bob, "inherit", "quarantined")
            .await;
        assert!(
            s.check(as_viewer(&s.bob), &s.priv_repo, &sess)
                .await
                .is_ok()
        );
        // Row 9: quarantined + owner (repo admin, not uploader) → Ok.
        assert!(
            s.check(as_viewer(&s.alice), &s.priv_repo, &sess)
                .await
                .is_ok()
        );
        // Row 10: quarantined + member (not uploader/admin) → NotFound.
        // (carol cannot read the private repo at all; use a public-repo case instead.)
        let sess = s
            .session(&s.pub_repo, "01E10", &s.alice, "inherit", "quarantined")
            .await;
        assert!(matches!(
            s.check(as_viewer(&s.bob), &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Row 11: released → normal rules (public inherit: member Ok, stranger denied).
        let sess = s
            .session(&s.pub_repo, "01E11", &s.alice, "inherit", "released")
            .await;
        assert!(s.check(as_viewer(&s.bob), &s.pub_repo, &sess).await.is_ok());
        assert!(matches!(
            s.check(as_viewer(&s.carol), &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Row 12: site admin → Ok everywhere, including quarantined as non-uploader.
        let sess = s
            .session(&s.priv_repo, "01E12", &s.alice, "inherit", "quarantined")
            .await;
        assert!(
            s.check(as_viewer(&s.root), &s.priv_repo, &sess)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn authorize_rejects_cross_repo_sessions() {
        let s = seed().await;
        let sess = s
            .session(&s.priv_repo, "01EX", &s.alice, "inherit", "none")
            .await;
        assert!(matches!(
            s.check(as_viewer(&s.alice), &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn authorize_by_ulid_wires_lookup_and_check() {
        let s = seed().await;
        s.session(&s.pub_repo, "01EULID", &s.alice, "published", "none")
            .await;
        let (access, row) = s
            .core
            .authorize_session_read_by_ulid(None, "alice", "open", "01EULID")
            .await
            .unwrap();
        assert_eq!(access.repo.id, s.pub_repo.id);
        assert_eq!(row.ulid, "01EULID");
        assert!(matches!(
            s.core
                .authorize_session_read_by_ulid(None, "alice", "open", "01NOPE")
                .await,
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            s.core
                .authorize_session_read_by_ulid(None, "alice", "secret", "01EULID")
                .await,
            Err(CoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn membership_excludes_implicit_read() {
        let s = seed().await;
        // Owner and explicit collaborators count…
        assert!(
            s.core
                .is_repo_member(s.priv_repo.id, s.alice.id)
                .await
                .unwrap()
        );
        assert!(
            s.core
                .is_repo_member(s.priv_repo.id, s.bob.id)
                .await
                .unwrap()
        );
        // …implicit public/internal read does not.
        assert!(
            !s.core
                .is_repo_member(s.pub_repo.id, s.carol.id)
                .await
                .unwrap()
        );
        assert!(
            !s.core
                .is_repo_member(s.int_repo.id, s.carol.id)
                .await
                .unwrap()
        );
        assert!(
            !s.core
                .is_repo_member(s.priv_repo.id, s.carol.id)
                .await
                .unwrap()
        );
        assert!(matches!(
            s.core.is_repo_member(999_999, s.carol.id).await,
            Err(CoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn candidate_cap_truncation_is_reported() {
        let s = seed().await;
        // Cap 3 over 4 candidates where one is unreadable to anonymous
        // viewers: the readable count (3) never reaches the cap, but the
        // candidate list was cut, and the tail could hide readable sessions.
        s.session(
            &s.pub_repo,
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            &s.alice,
            "published",
            "none",
        )
        .await;
        s.session(
            &s.pub_repo,
            "01ARZ3NDEKTSV4RRFFQ69G5FAW",
            &s.alice,
            "inherit",
            "none",
        )
        .await;
        s.session(
            &s.pub_repo,
            "01ARZ3NDEKTSV4RRFFQ69G5FAX",
            &s.alice,
            "published",
            "none",
        )
        .await;
        s.session(
            &s.pub_repo,
            "01ARZ3NDEKTSV4RRFFQ69G5FAY",
            &s.alice,
            "published",
            "none",
        )
        .await;
        let access = s.core.repo_for(None, "alice", "open").await.unwrap();
        let (readable, truncated) = s
            .core
            .list_readable_sessions_capped(None, &access, 3)
            .await
            .unwrap();
        assert!(truncated, "cap cut the candidates; must report it");
        let ulids: Vec<&str> = readable.iter().map(|row| row.ulid.as_str()).collect();
        assert_eq!(
            ulids,
            vec![
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "01ARZ3NDEKTSV4RRFFQ69G5FAX",
                "01ARZ3NDEKTSV4RRFFQ69G5FAY"
            ],
            "the unreadable session is filtered, the rest oldest-first"
        );
        // A cap past the candidate count reports no truncation.
        let (all, truncated) = s
            .core
            .list_readable_sessions_capped(None, &access, 10)
            .await
            .unwrap();
        assert!(!truncated);
        assert_eq!(all.len(), 3);
    }
}

#[cfg(test)]
mod proptests {
    //! §6.4 property tests (spec §13): [`can_read_session`] equals the
    //! reference implementation written directly from the three numbered
    //! rules of spec §6.4, over the whole consistent fact space (checked
    //! exhaustively; the domains are tiny).
    //!
    //! Rule readings used by both, pinned here:
    //! 1. "can read the repo" = explicit member, owner, public visibility,
    //!    or signed-in on internal. (Effective admins reach this only
    //!    through ownership or an explicit grant, so the fact generator
    //!    keeps `is_admin` consistent with those.)
    //! 2. "repo member" includes the owner (owners read everything that is
    //!    not quarantined).
    //! 3. Quarantined sessions: the uploader or a repo admin only — the
    //!    truth table pins this arm as bypassing rules 1-2.
    //!
    //! Site admins read everything (the implementation's row 12).

    use super::*;
    use crate::permission::{Viewer, Visibility};

    const OWNER: i64 = 7;
    const UPLOADER: i64 = 42;
    const OTHER: i64 = 9;

    /// The reference rule: spec §6.4's three numbered rules, verbatim logic.
    #[allow(clippy::too_many_arguments)]
    fn ref_read(
        site_admin: bool,
        signed_in: bool,
        is_owner: bool,
        is_uploader: bool,
        is_member: bool,
        is_admin: bool,
        visibility: Visibility,
        published: bool,
        quarantined: bool,
    ) -> bool {
        if site_admin {
            return true;
        }
        // Rule 3 (quarantine gate; uploader or repo admin only).
        if quarantined {
            return is_uploader || is_owner || is_admin;
        }
        // Rule 1: the viewer can read the repository.
        let repo_read = is_member
            || is_owner
            || visibility == Visibility::Public
            || (visibility == Visibility::Internal && signed_in);
        // Rule 2: not public, or published, or a repo member (owner counts).
        repo_read && (visibility != Visibility::Public || published || is_member || is_owner)
    }

    /// One consistent viewer/session/repo fact combination. `viewer_id` is
    /// `Some(OWNER)`, `Some(UPLOADER)`, `Some(OTHER)`, `Some(-1)` for the
    /// owner-and-uploader corner, or `None` for anonymous.
    struct Facts {
        site_admin: bool,
        viewer_id: Option<i64>,
        is_member: bool,
        admin_grant: bool,
        visibility: Visibility,
        published: bool,
        quarantined: bool,
    }

    /// Every consistent fact combination. Viewer ids select owner (`OWNER`),
    /// uploader (`UPLOADER`), a stranger, or anonymous; `is_admin` is derived
    /// as owner, site admin, or an explicit admin grant — explicit grants
    /// are the only other source of effective admin, and they make the
    /// viewer a member.
    fn facts() -> Vec<Facts> {
        let mut out = Vec::new();
        for site_admin in [false, true] {
            for viewer in [None, Some(OWNER), Some(UPLOADER), Some(OTHER)] {
                // A site admin is signed in by construction; the anonymous
                // combination cannot arise and must not be counted.
                if site_admin && viewer.is_none() {
                    continue;
                }
                // Owner-and-uploader needs a separate id; use OWNER with
                // `uploader = OWNER` below, covered by the dedicated case.
                for is_member in [false, true] {
                    for admin_grant in [false, true] {
                        if admin_grant && !is_member {
                            continue; // an explicit admin grant is a grant
                        }
                        for visibility in [
                            Visibility::Public,
                            Visibility::Internal,
                            Visibility::Private,
                        ] {
                            for published in [false, true] {
                                for quarantined in [false, true] {
                                    out.push(Facts {
                                        site_admin,
                                        viewer_id: viewer,
                                        is_member,
                                        admin_grant,
                                        visibility,
                                        published,
                                        quarantined,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        // The owner-is-uploader corner (header ids coincide).
        for site_admin in [false, true] {
            for is_member in [false, true] {
                for visibility in [
                    Visibility::Public,
                    Visibility::Internal,
                    Visibility::Private,
                ] {
                    for published in [false, true] {
                        for quarantined in [false, true] {
                            out.push(Facts {
                                site_admin,
                                viewer_id: Some(-1), // sentinel: owner AND uploader
                                is_member,
                                admin_grant: false,
                                visibility,
                                published,
                                quarantined,
                            });
                        }
                    }
                }
            }
        }
        out
    }

    fn check_one(f: Facts) -> bool {
        let Facts {
            site_admin,
            viewer_id,
            is_member,
            admin_grant,
            visibility,
            published,
            quarantined,
        } = f;
        let uploader = match viewer_id {
            Some(-1) => OWNER,
            _ => UPLOADER,
        };
        let viewer = viewer_id.map(|id| Viewer {
            user_id: if id == -1 { OWNER } else { id },
            is_admin: site_admin,
        });
        let signed_in = viewer.is_some();
        let is_owner = viewer.is_some_and(|v| v.user_id == OWNER);
        let is_uploader = viewer.is_some_and(|v| v.user_id == uploader);
        let is_admin = is_owner || site_admin || admin_grant;
        let repo = super::tests::repo(visibility);
        let session = super::tests::session_row(
            uploader,
            if published { "published" } else { "inherit" },
            if quarantined { "quarantined" } else { "none" },
        );
        assert_eq!(
            can_read_session(viewer, &repo, &session, is_member, is_admin),
            ref_read(
                site_admin,
                signed_in,
                is_owner,
                is_uploader,
                is_member,
                is_admin,
                visibility,
                published,
                quarantined,
            ),
            "site={site_admin} viewer={viewer_id:?} member={is_member} grant={admin_grant} vis={visibility:?} pub={published} quar={quarantined}",
        );
        true
    }

    #[test]
    fn can_read_session_matches_spec_reference_exhaustively() {
        let all = facts();
        // Exact coverage: non-admin [4 viewers × 3 grant combos (an admin
        // grant requires membership) + 1 owner-and-uploader viewer × 2
        // memberships] plus admin [3 signed viewers × 3 + 1 × 2], each
        // × 3 visibilities × 2 published × 2 quarantined = 300, with no
        // anonymous-site-admin combinations. Pinning the count so the
        // generator cannot silently shrink.
        assert_eq!(all.len(), 300, "fact space shrank: {}", all.len());
        for fact in all {
            check_one(fact);
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// Sampled agreement: the predicate equals the spec reference on
        /// randomly drawn consistent facts.
        #[test]
        fn can_read_session_matches_spec_reference_sampled(
            site_admin in proptest::bool::ANY,
            viewer in proptest::prop_oneof![
                proptest::strategy::Just(None),
                proptest::strategy::Just(Some(-1)),
                proptest::strategy::Just(Some(OWNER)),
                proptest::strategy::Just(Some(UPLOADER)),
                proptest::strategy::Just(Some(OTHER)),
            ],
            is_member in proptest::bool::ANY,
            want_admin in proptest::bool::ANY,
            visibility in proptest::prop_oneof![
                proptest::strategy::Just(Visibility::Public),
                proptest::strategy::Just(Visibility::Internal),
                proptest::strategy::Just(Visibility::Private),
            ],
            published in proptest::bool::ANY,
            quarantined in proptest::bool::ANY,
        ) {
            proptest::prop_assume!(!(site_admin && viewer.is_none()));
            // An explicit admin grant exists only on top of a grant.
            let admin_grant = is_member && want_admin;
            check_one(Facts {
                site_admin,
                viewer_id: viewer,
                is_member,
                admin_grant,
                visibility,
                published,
                quarantined,
            });
        }
    }
}
