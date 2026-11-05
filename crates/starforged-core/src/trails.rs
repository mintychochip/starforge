//! Trails: issue-like discussion objects scoped to a repository (spec §6.2, M2a).
//!
//! All permission, validation, numbering, and timeline logic lives here; routes
//! delegate. Reads below effective `Read` (or invisible repos) answer
//! `NotFound` so nothing leaks; mutations check the action threshold and answer
//! `Forbidden` above read but below it. `Write` gains no Trail powers in M2a
//! (code-centric per §6.1); assignees need an explicit grant via
//! [`Core::is_repo_member`]. Numbers come from the `trail_sequences` counter inside
//! the insert transaction, so concurrent creates never collide; a `UNIQUE` violation
//! below is only a defensive fallback (rows written behind the sequence's back).
//! `merged` is never written here — the merge path owns it.
//! Only open/close/reopen are audited; everything else is timeline-only.

use starforged_db::changes as db_changes;
use starforged_db::checks as db_checks;
use starforged_db::now;
use starforged_db::sessions as db_sessions;
use starforged_db::sessions::SessionRow;
use starforged_db::trails as db_trails;
use starforged_db::trails::{TimelineEventRow, TrailCommentRow, TrailFilter, TrailRow};

use crate::accounts::User;
use crate::permission::{Permission, Viewer, Visibility};
use crate::read::can_read_session;
use crate::{Core, CoreError, CoreResult};

/// Max title length in chars after trimming.
const MAX_TITLE_CHARS: usize = 200;
/// Max intent / comment body length in chars (64 KiB).
const MAX_TEXT_CHARS: usize = 64 * 1024;
/// Max label length in bytes (labels are ASCII by charset).
const MAX_LABEL_LEN: usize = 50;
/// Max labels / assignees per trail.
const MAX_LABELS: usize = 10;
const MAX_ASSIGNEES: usize = 10;
/// Max review requests per trail (D7; mirrors assignees).
const MAX_REVIEW_REQUESTS: usize = 10;

/// Flat read shape shared by API and web.
#[derive(Debug, Clone)]
pub struct TrailView {
    pub number: i64,
    pub title: String,
    pub intent: String,
    pub state: String,
    pub ready: bool,
    pub author_id: Option<i64>,
    pub author_handle: String,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
    pub review_requests: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub closed_at: Option<i64>,
    pub merged_at: Option<i64>,
}

/// List filters; handles resolve to ids, unknown handles list empty (not 404).
#[derive(Debug, Clone, Default)]
pub struct TrailFilterInput {
    pub state: Option<String>,
    pub label: Option<String>,
    pub assignee: Option<String>,
    pub author: Option<String>,
    /// `Some(true)` keeps Trails with at least one change; `Some(false)`
    /// keeps Trails with none.
    pub has_changes: Option<bool>,
    /// `Some(true)` keeps Trails with at least one session the viewer may
    /// read (§6.4, through commits or by hand); `Some(false)` keeps the rest.
    pub has_sessions: Option<bool>,
    /// Keeps Trails with a pending review request for this handle.
    pub review_requested: Option<String>,
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

/// Max explicit Trail↔session links per Trail (D3).
const MAX_TRAIL_SESSION_LINKS: usize = 50;
/// Session titles render truncated to this many chars (D5 prompt preview).
const MAX_SESSION_TITLE_CHARS: usize = 120;

/// Token totals over sessions (input, output, cache read, cache write,
/// reasoning, and their sum). Shared by per-session rows, commit groups, and
/// the Trail-wide rollup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenTotals {
    pub input: i64,
    pub output: i64,
    pub cache_read: i64,
    pub cache_write: i64,
    pub reasoning: i64,
    pub total: i64,
}

impl TokenTotals {
    fn of(session: &SessionRow) -> TokenTotals {
        let totals = TokenTotals {
            input: session.usage_input,
            output: session.usage_output,
            cache_read: session.usage_cache_read,
            cache_write: session.usage_cache_write,
            reasoning: session.usage_reasoning,
            total: 0,
        };
        let total = totals.input
            + totals.output
            + totals.cache_read
            + totals.cache_write
            + totals.reasoning;
        TokenTotals { total, ..totals }
    }

    fn add(&mut self, other: &TokenTotals) {
        self.input += other.input;
        self.output += other.output;
        self.cache_read += other.cache_read;
        self.cache_write += other.cache_write;
        self.reasoning += other.reasoning;
        self.total += other.total;
    }
}

/// One readable session linked to a Trail: through a commit (`exact` or
/// `heuristic` confidence, with the claim's start sequence) or by hand
/// (`explicit`, no sequence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLinkRow {
    pub ulid: String,
    pub agent: String,
    pub agent_version: String,
    pub models: String,
    pub title: String,
    pub uploader: String,
    pub started_at: i64,
    pub created_at: i64,
    pub confidence: String,
    pub seq_start: Option<i64>,
    pub totals: TokenTotals,
}

/// One Trail commit with its readable sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSessions {
    pub sha: String,
    pub subject: String,
    pub change: i64,
    pub revision: i64,
    pub first_seen_at: i64,
    pub sessions: Vec<SessionLinkRow>,
}
/// One D5 commit-panel row: the session fields plus the link provenance
/// (`trailer` or `cli_claim`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPanelRow {
    pub row: SessionLinkRow,
    pub source: String,
}

/// D5 data: the Trail's readable linked sessions, grouped. `linked` holds
/// the explicit hand links; `totals` roll up distinct sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailSessions {
    pub commits: Vec<CommitSessions>,
    pub linked: Vec<SessionLinkRow>,
    pub totals: TokenTotals,
}

/// One readable session linked through a commit, as a D7 timeline row. `at`
/// is the row's time: the later of the session's `created_at` and the first
/// revision containing its commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineSession {
    pub row: SessionLinkRow,
    pub sha: String,
    pub subject: String,
    pub change: i64,
    pub revision: i64,
    pub at: i64,
}

/// One check status posted on a revision head SHA, as a D7 timeline row.
/// `at` is the row's `updated_at`, so a re-posted context moves with its
/// latest post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineCheck {
    pub row: db_checks::CheckRow,
    pub change: i64,
    pub revision: i64,
    pub at: i64,
}

/// One D7 Conversation timeline entry: a stored event, a readable linked
/// session, or a check on a revision head. Entries come out in time order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrailTimelineEntry {
    Stored(TimelineEventRow),
    Session(TimelineSession),
    Check(TimelineCheck),
}

impl TrailTimelineEntry {
    /// Sort key for the merged timeline.
    pub fn at(&self) -> i64 {
        match self {
            TrailTimelineEntry::Stored(row) => row.created_at,
            TrailTimelineEntry::Session(entry) => entry.at,
            TrailTimelineEntry::Check(entry) => entry.at,
        }
    }
}

/// One dashboard Trail row: its repository coordinates plus the fields the
/// dashboard renders and links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailSummary {
    pub owner: String,
    pub repo: String,
    pub number: i64,
    pub title: String,
    pub updated_at: i64,
}

/// Dashboard candidate cap per section (D8): Core filters these by the
/// viewer's current effective read permission, then truncates.
const DASHBOARD_CANDIDATES: i64 = 100;
/// Dashboard display cap per Trail section (D8).
const DASHBOARD_TRAILS: usize = 20;

/// One keyset page; `next_after` is the last number iff the page was full.
#[derive(Debug, Clone)]
pub struct ListPage {
    pub trails: Vec<TrailView>,
    pub next_after: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CommentView {
    pub id: i64,
    pub author_id: Option<i64>,
    pub author_handle: String,
    pub body: String,
    pub created_at: i64,
    pub edited_at: Option<i64>,
}

/// Full read shape: the trail plus its discussion, timeline, and what the
/// requesting viewer may do with it.
#[derive(Debug, Clone)]
pub struct TrailDetail {
    pub trail: TrailView,
    pub comments: Vec<CommentView>,
    pub timeline: Vec<TimelineEventRow>,
    pub can_edit: bool,
    pub can_triage: bool,
}

fn trail_target(owner: &str, repo: &str, number: i64) -> String {
    format!("trail:{owner}/{repo}#{number}")
}

fn check_title(title: &str) -> CoreResult<String> {
    let t = title.trim();
    if t.is_empty() {
        return Err(CoreError::Invalid("title must not be empty".into()));
    }
    if t.chars().count() > MAX_TITLE_CHARS {
        return Err(CoreError::Invalid("title must be at most 200 chars".into()));
    }
    if t.contains('\n') || t.contains('\r') {
        return Err(CoreError::Invalid("title must be a single line".into()));
    }
    Ok(t.to_string())
}

fn check_intent(intent: &str) -> CoreResult<()> {
    if intent.chars().count() > MAX_TEXT_CHARS {
        return Err(CoreError::Invalid("intent must be at most 64 KiB".into()));
    }
    Ok(())
}

fn check_body(body: &str) -> CoreResult<()> {
    if body.trim().is_empty() {
        return Err(CoreError::Invalid("comment body must not be empty".into()));
    }
    if body.chars().count() > MAX_TEXT_CHARS {
        return Err(CoreError::Invalid(
            "comment body must be at most 64 KiB".into(),
        ));
    }
    Ok(())
}

/// Trim + lowercase; empty after trim, len > 50, or `[^a-z0-9-_.]` → `Invalid`.
pub fn normalize_label(name: &str) -> CoreResult<String> {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() {
        return Err(CoreError::Invalid("label must not be empty".into()));
    }
    if n.len() > MAX_LABEL_LEN {
        return Err(CoreError::Invalid("label must be at most 50 chars".into()));
    }
    if !n
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(CoreError::Invalid(format!("invalid label '{name}'")));
    }
    Ok(n)
}

impl Core {
    fn ensure_writable(repo: &crate::repos::Repo) -> CoreResult<()> {
        if repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        Ok(())
    }

    async fn trail_view(&self, row: &TrailRow) -> CoreResult<TrailView> {
        let (author_id, author_handle) = match row.author_id {
            None => (None, "deleted user".to_owned()),
            Some(id) => match self.user_by_id(id).await? {
                Some(u) => (Some(id), u.handle),
                None => (None, "deleted user".to_owned()),
            },
        };
        let labels = db_trails::labels_of(self.db(), row.id).await?;
        let mut assignees = Vec::new();
        for id in db_trails::assignees_of(self.db(), row.id).await? {
            if let Some(u) = self.user_by_id(id).await? {
                assignees.push(u.handle);
            }
        }
        let mut review_requests = Vec::new();
        for id in db_trails::review_requests_of(self.db(), row.id).await? {
            if let Some(u) = self.user_by_id(id).await? {
                review_requests.push(u.handle);
            }
        }
        Ok(TrailView {
            number: row.number,
            title: row.title.clone(),
            intent: row.intent.clone(),
            state: row.state.clone(),
            ready: row.ready != 0,
            author_id,
            author_handle,
            labels,
            assignees,
            review_requests,
            created_at: row.created_at,
            updated_at: row.updated_at,
            closed_at: row.closed_at,
            merged_at: row.merged_at,
        })
    }

    async fn comment_view(&self, row: &TrailCommentRow) -> CoreResult<CommentView> {
        let (author_id, author_handle) = match row.author_id {
            None => (None, "deleted user".to_owned()),
            Some(id) => match self.user_by_id(id).await? {
                Some(u) => (Some(id), u.handle),
                None => (None, "deleted user".to_owned()),
            },
        };
        Ok(CommentView {
            id: row.id,
            author_id,
            author_handle,
            body: row.body.clone(),
            created_at: row.created_at,
            edited_at: row.edited_at,
        })
    }

    /// The row or `NotFound`; callers already hold at least read via `repo_for`.
    async fn trail_row(&self, repo_id: i64, number: i64) -> CoreResult<TrailRow> {
        db_trails::trail_by_number(self.db(), repo_id, number)
            .await?
            .ok_or(CoreError::NotFound)
    }

    async fn record_timeline(
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

    pub async fn create_trail(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        title: &str,
        intent: &str,
    ) -> CoreResult<TrailView> {
        // `repo_for` guarantees ≥ Read; below that (or invisible) is `NotFound`.
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        let title = check_title(title)?;
        check_intent(intent)?;
        // Single attempt: the sequence allocator inside `insert_trail` serializes
        // concurrent creates, so a unique violation here means a row was written
        // behind the sequence's back — report it, don't loop.
        let row = match db_trails::insert_trail(
            self.db(),
            &db_trails::NewTrail {
                repo_id: access.repo.id,
                title: &title,
                intent,
                author_id: user.id,
            },
            now(),
        )
        .await
        {
            Ok(row) => row,
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Conflict(
                    "could not allocate a trail number; please retry".into(),
                ));
            }
            Err(e) => return Err(e.into()),
        };
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.open",
            Some(user.id),
            serde_json::json!({"number": row.number}),
        )
        .await?;
        self.audit(
            Some(user.id),
            "trail.open",
            &trail_target(owner, repo, row.number),
            "",
        )
        .await?;
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("opened"),
            None,
            row.number,
            None,
        )
        .await;
        self.trail_view(&row).await
    }
    pub async fn trail_by_number(
        &self,
        user: Option<&User>,
        owner: &str,
        repo: &str,
        number: i64,
    ) -> CoreResult<TrailDetail> {
        let access = self.repo_for(user, owner, repo).await?;
        let row = self.trail_row(access.repo.id, number).await?;
        let trail = self.trail_view(&row).await?;
        let mut comments = Vec::new();
        for c in db_trails::comments_of(self.db(), row.id).await? {
            comments.push(self.comment_view(&c).await?);
        }
        let timeline = db_trails::timeline_of_trail(self.db(), row.id).await?;
        let (can_edit, can_triage) = match user {
            None => (false, false),
            Some(u) => {
                let triage = access.permission >= Permission::Triage;
                (triage || row.author_id == Some(u.id), triage)
            }
        };
        Ok(TrailDetail {
            trail,
            comments,
            timeline,
            can_edit,
            can_triage,
        })
    }

    pub async fn list_trails(
        &self,
        user: Option<&User>,
        owner: &str,
        repo: &str,
        f: &TrailFilterInput,
    ) -> CoreResult<ListPage> {
        let access = self.repo_for(user, owner, repo).await?;
        if let Some(s) = f.state.as_deref()
            && !matches!(s, "open" | "merged" | "closed")
        {
            return Err(CoreError::Invalid(format!("invalid state '{s}'")));
        }
        let label = f.label.as_deref().map(normalize_label).transpose()?;
        // Unknown handles match nothing, not a 404.
        let author_id = match f.author.as_deref() {
            None => None,
            Some(h) => match self.user_by_handle(h).await? {
                Some(u) => Some(u.id),
                None => {
                    return Ok(ListPage {
                        trails: Vec::new(),
                        next_after: None,
                    });
                }
            },
        };
        let assignee_id = match f.assignee.as_deref() {
            None => None,
            Some(h) => match self.user_by_handle(h).await? {
                Some(u) => Some(u.id),
                None => {
                    return Ok(ListPage {
                        trails: Vec::new(),
                        next_after: None,
                    });
                }
            },
        };
        let review_requested_id = match f.review_requested.as_deref() {
            None => None,
            Some(h) => match self.user_by_handle(h).await? {
                Some(u) => Some(u.id),
                None => {
                    return Ok(ListPage {
                        trails: Vec::new(),
                        next_after: None,
                    });
                }
            },
        };
        let limit = f.limit.unwrap_or(30).clamp(1, 100);
        // §6.4 viewer facts for the `has_sessions` SQL predicate (same three
        // rules as `can_read_session`): suspended users are anonymous.
        let viewer = user.filter(|u| u.active);
        let session_facts = db_trails::SessionViewerFacts {
            viewer_id: viewer.map(|u| u.id).unwrap_or(0),
            signed_in: viewer.is_some(),
            site_admin: viewer.map(|u| u.is_admin).unwrap_or(false),
            member: match viewer {
                Some(u) if f.has_sessions.is_some() => {
                    self.is_repo_member(access.repo.id, u.id).await?
                }
                _ => false,
            },
            repo_admin: access.permission >= Permission::Admin,
            repo_public: access.repo.visibility == Visibility::Public,
            repo_internal: access.repo.visibility == Visibility::Internal,
        };
        let rows = db_trails::trails_of_repo(
            self.db(),
            access.repo.id,
            &TrailFilter {
                state: f.state.clone(),
                label,
                assignee_id,
                author_id,
                has_changes: f.has_changes,
                has_sessions: f.has_sessions,
                session_facts,
                review_requested_id,
                after: f.after,
                limit,
            },
        )
        .await?;
        let mut trails = Vec::with_capacity(rows.len());
        for row in &rows {
            trails.push(self.trail_view(row).await?);
        }
        let next_after = if rows.len() as i64 == limit {
            trails.last().map(|t| t.number)
        } else {
            None
        };
        Ok(ListPage { trails, next_after })
    }

    /// The dashboard sections, filtered by the viewer's current effective
    /// read permission: open Trails assigned to them, and open Trails with a
    /// pending review request for them, newest `updated_at` first, at most
    /// 20 each. Losing read on a repository hides its Trails immediately.
    /// Suspended users are anonymous and see nothing.
    pub async fn dashboard_trails(
        &self,
        user: &User,
    ) -> CoreResult<(Vec<TrailSummary>, Vec<TrailSummary>)> {
        let viewer = user.active.then_some(user);
        let assigned =
            db_trails::trails_assigned_to(self.db(), user.id, DASHBOARD_CANDIDATES).await?;
        let awaiting =
            db_trails::trails_awaiting_review(self.db(), user.id, DASHBOARD_CANDIDATES).await?;
        Ok((
            self.visible_dashboard_trails(viewer, assigned).await?,
            self.visible_dashboard_trails(viewer, awaiting).await?,
        ))
    }

    /// Keeps the candidate rows the viewer can read now, truncating to the
    /// display cap (newest-first order preserved).
    async fn visible_dashboard_trails(
        &self,
        viewer: Option<&User>,
        rows: Vec<db_trails::DashboardTrailRow>,
    ) -> CoreResult<Vec<TrailSummary>> {
        let mut out = Vec::new();
        for row in rows {
            let Some(repo_row) = starforged_db::repos::by_id(self.db(), row.trail.repo_id).await?
            else {
                continue;
            };
            if repo_row.deleted_at.is_some() {
                continue;
            }
            let repo = crate::repos::to_repo(repo_row)?;
            if self.permission_on(&repo, viewer).await?.is_none() {
                continue;
            }
            out.push(TrailSummary {
                owner: row.owner,
                repo: row.repo,
                number: row.trail.number,
                title: row.trail.title,
                updated_at: row.trail.updated_at,
            });
            if out.len() >= DASHBOARD_TRAILS {
                break;
            }
        }
        Ok(out)
    }

    /// The seven-parameter shape is the M2a interface; the options bundle into one call.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_trail(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        title: Option<&str>,
        intent: Option<&str>,
        ready: Option<bool>,
    ) -> CoreResult<TrailView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        let row = self.trail_row(access.repo.id, number).await?;
        let triage = access.permission >= Permission::Triage;
        let is_author = row.author_id == Some(user.id);
        if !is_author && !triage {
            return Err(CoreError::Forbidden);
        }
        // The ready toggle is triage-only, even for the author.
        if ready.is_some() && !triage {
            return Err(CoreError::Forbidden);
        }
        let new_title = title.map(check_title).transpose()?;
        if let Some(i) = intent {
            check_intent(i)?;
        }
        let new_intent = intent.unwrap_or(&row.intent).to_string();
        let new_title = new_title.unwrap_or(row.title.clone());
        let new_ready = ready.unwrap_or(row.ready != 0);
        let mut fields: Vec<&str> = Vec::new();
        if new_title != row.title {
            fields.push("title");
        }
        if new_intent != row.intent {
            fields.push("intent");
        }
        if new_ready != (row.ready != 0) {
            fields.push("ready");
        }
        if fields.is_empty() {
            return self.trail_view(&row).await;
        }
        let ready_was = row.ready != 0;
        let content_changed = fields.contains(&"title") || fields.contains(&"intent");
        let sender = Some(user.handle.clone());
        let number = row.number;
        let repo_id = access.repo.id;
        let at = now();
        if fields.contains(&"title") || fields.contains(&"intent") {
            db_trails::set_title_intent(self.db(), row.id, &new_title, &new_intent, at).await?;
        }
        if fields.contains(&"ready") {
            db_trails::set_ready(self.db(), row.id, i64::from(new_ready), at).await?;
        }
        self.record_timeline(
            repo_id,
            row.id,
            "trail.edit",
            Some(user.id),
            serde_json::json!({"fields": fields, "field": fields[0]}),
        )
        .await?;
        // Exactly one event per state-changing update: a fresh ready flag
        // reads as `ready`; otherwise title/intent edits read as
        // `updated`/`edited` and clearing ready as `updated`/`ready_cleared`.
        // The timeline row above is the audit; the idempotent early return
        // means reaching here always changed something.
        let (action, cause) = if !ready_was && new_ready {
            (Some("ready"), None)
        } else if content_changed {
            (Some("updated"), Some("edited"))
        } else {
            (Some("updated"), Some("ready_cleared"))
        };
        self.dispatch_trail_event(repo_id, sender, action, cause, number, None)
            .await;
        self.trail_view(&self.trail_row(access.repo.id, number).await?)
            .await
    }
    /// Pure validation for `PATCH`: checks every supplied field (shapes and
    /// permissions) without writing anything, so the handler can reject
    /// before either write lands.
    #[allow(clippy::too_many_arguments)]
    pub async fn check_patch(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        title: Option<&str>,
        intent: Option<&str>,
        ready: Option<bool>,
        state: Option<&str>,
    ) -> CoreResult<()> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        if state.is_none() && title.is_none() && intent.is_none() && ready.is_none() {
            let _ = self.trail_row(access.repo.id, number).await?;
            return Ok(());
        }
        if let Some(next) = state {
            if access.permission < Permission::Triage {
                return Err(CoreError::Forbidden);
            }
            if next == "merged" {
                return Err(CoreError::Invalid("merged is set by the merge path".into()));
            }
            if !matches!(next, "open" | "closed") {
                return Err(CoreError::Invalid(format!("invalid state '{next}'")));
            }
        }
        if title.is_some() || intent.is_some() || ready.is_some() {
            let row = self.trail_row(access.repo.id, number).await?;
            let triage = access.permission >= Permission::Triage;
            let is_author = row.author_id == Some(user.id);
            if !is_author && !triage {
                return Err(CoreError::Forbidden);
            }
            if ready.is_some() && !triage {
                return Err(CoreError::Forbidden);
            }
            if let Some(t) = title {
                check_title(t)?;
            }
            if let Some(i) = intent {
                check_intent(i)?;
            }
        } else if state.is_some() {
            let _ = self.trail_row(access.repo.id, number).await?;
        }
        Ok(())
    }

    /// Only `open`/`closed`. `merged` is owned by the merge path.
    pub async fn set_trail_state(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        state: &str,
    ) -> CoreResult<TrailView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        if access.permission < Permission::Triage {
            return Err(CoreError::Forbidden);
        }
        if state == "merged" {
            return Err(CoreError::Invalid("merged is set by the merge path".into()));
        }
        if !matches!(state, "open" | "closed") {
            return Err(CoreError::Invalid(format!("invalid state '{state}'")));
        }
        let row = self.trail_row(access.repo.id, number).await?;
        if row.state == state {
            return self.trail_view(&row).await;
        }
        let at = now();
        let closed_at = if state == "closed" { Some(at) } else { None };
        db_trails::set_state(self.db(), row.id, state, at, closed_at).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.state",
            Some(user.id),
            serde_json::json!({"from": row.state, "to": state, "state": state}),
        )
        .await?;
        self.audit(
            Some(user.id),
            if state == "closed" {
                "trail.close"
            } else {
                "trail.reopen"
            },
            &trail_target(owner, repo, number),
            "",
        )
        .await?;
        if state == "closed" {
            self.dispatch_trail_event(
                access.repo.id,
                Some(user.handle.clone()),
                Some("closed"),
                None,
                number,
                None,
            )
            .await;
        } else {
            self.dispatch_trail_event(
                access.repo.id,
                Some(user.handle.clone()),
                Some("updated"),
                Some("reopened"),
                number,
                None,
            )
            .await;
        }
        self.trail_view(&self.trail_row(access.repo.id, number).await?)
            .await
    }

    pub async fn add_comment(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        body: &str,
    ) -> CoreResult<CommentView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        let row = self.trail_row(access.repo.id, number).await?;
        check_body(body)?;
        let at = now();
        let saved = db_trails::insert_comment(self.db(), row.id, user.id, body, at).await?;
        db_trails::touch(self.db(), row.id, at).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.comment",
            Some(user.id),
            serde_json::json!({"comment_id": saved.id}),
        )
        .await?;
        self.comment_view(&saved).await
    }

    /// Comment author or effective ≥ `Admin`; else `Forbidden`.
    pub async fn edit_comment(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        comment_id: i64,
        body: &str,
    ) -> CoreResult<CommentView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        let row = self.trail_row(access.repo.id, number).await?;
        let saved = db_trails::comment_by_id(self.db(), comment_id)
            .await?
            .filter(|c| c.trail_id == row.id)
            .ok_or(CoreError::NotFound)?;
        if saved.author_id != Some(user.id) && access.permission < Permission::Admin {
            return Err(CoreError::Forbidden);
        }
        check_body(body)?;
        let at = now();
        db_trails::update_comment(self.db(), comment_id, body, at).await?;
        db_trails::touch(self.db(), row.id, at).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.comment",
            Some(user.id),
            serde_json::json!({"comment_id": comment_id}),
        )
        .await?;
        let updated = db_trails::comment_by_id(self.db(), comment_id)
            .await?
            .ok_or_else(|| CoreError::Internal("comment missing after update".into()))?;
        self.comment_view(&updated).await
    }

    pub async fn add_label(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        name: &str,
    ) -> CoreResult<TrailView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        if access.permission < Permission::Triage {
            return Err(CoreError::Forbidden);
        }
        let name = normalize_label(name)?;
        let row = self.trail_row(access.repo.id, number).await?;
        let current = db_trails::labels_of(self.db(), row.id).await?;
        if !current.contains(&name) && current.len() >= MAX_LABELS {
            return Err(CoreError::Invalid("too many labels on this trail".into()));
        }
        if !db_trails::add_label(self.db(), row.id, &name).await? {
            return self.trail_view(&row).await; // dedupe: no-op, no row.
        }
        db_trails::touch(self.db(), row.id, now()).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.label",
            Some(user.id),
            serde_json::json!({"action": "add", "name": name}),
        )
        .await?;
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("updated"),
            Some("labeled"),
            number,
            None,
        )
        .await;
        self.trail_view(&self.trail_row(access.repo.id, number).await?)
            .await
    }

    pub async fn remove_label(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        name: &str,
    ) -> CoreResult<TrailView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        if access.permission < Permission::Triage {
            return Err(CoreError::Forbidden);
        }
        let name = normalize_label(name)?;
        let row = self.trail_row(access.repo.id, number).await?;
        if !db_trails::remove_label(self.db(), row.id, &name).await? {
            return self.trail_view(&row).await;
        }
        db_trails::touch(self.db(), row.id, now()).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.label",
            Some(user.id),
            serde_json::json!({"action": "remove", "name": name}),
        )
        .await?;
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("updated"),
            Some("unlabeled"),
            number,
            None,
        )
        .await;
        self.trail_view(&self.trail_row(access.repo.id, number).await?)
            .await
    }

    pub async fn add_assignee(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        handle: &str,
    ) -> CoreResult<TrailView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        if access.permission < Permission::Triage {
            return Err(CoreError::Forbidden);
        }
        let target = self
            .user_by_handle(handle)
            .await?
            .ok_or_else(|| CoreError::Invalid(format!("no user named '{handle}'")))?;
        if !self.is_repo_member(access.repo.id, target.id).await? {
            return Err(CoreError::Invalid(format!(
                "'{}' is not a member of this repository",
                target.handle
            )));
        }
        let row = self.trail_row(access.repo.id, number).await?;
        let current = db_trails::assignees_of(self.db(), row.id).await?;
        if !current.contains(&target.id) && current.len() >= MAX_ASSIGNEES {
            return Err(CoreError::Invalid(
                "too many assignees on this trail".into(),
            ));
        }
        if !db_trails::add_assignee(self.db(), row.id, target.id).await? {
            return self.trail_view(&row).await;
        }
        db_trails::touch(self.db(), row.id, now()).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.assignee",
            Some(user.id),
            serde_json::json!({"action": "add", "user": target.handle, "user_id": target.id}),
        )
        .await?;
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("updated"),
            Some("assigned"),
            number,
            None,
        )
        .await;
        self.trail_view(&self.trail_row(access.repo.id, number).await?)
            .await
    }

    pub async fn remove_assignee(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        handle: &str,
    ) -> CoreResult<TrailView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        if access.permission < Permission::Triage {
            return Err(CoreError::Forbidden);
        }
        let target = self
            .user_by_handle(handle)
            .await?
            .ok_or_else(|| CoreError::Invalid(format!("no user named '{handle}'")))?;
        let row = self.trail_row(access.repo.id, number).await?;
        if !db_trails::remove_assignee(self.db(), row.id, target.id).await? {
            return self.trail_view(&row).await;
        }
        db_trails::touch(self.db(), row.id, now()).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.assignee",
            Some(user.id),
            serde_json::json!({"action": "remove", "user": target.handle, "user_id": target.id}),
        )
        .await?;
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("updated"),
            Some("unassigned"),
            number,
            None,
        )
        .await;
        self.trail_view(&self.trail_row(access.repo.id, number).await?)
            .await
    }

    /// D7. Triage+; the requested user must be a member and not the Trail author; ≤ 10; idempotent.
    /// Writes `trail.review_requested`; dispatches trail/updated cause review_requested.
    pub async fn request_review(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        handle: &str,
    ) -> CoreResult<TrailView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        if access.permission < Permission::Triage {
            return Err(CoreError::Forbidden);
        }
        let target = self
            .user_by_handle(handle)
            .await?
            .ok_or_else(|| CoreError::Invalid(format!("no user named '{handle}'")))?;
        if !self.is_repo_member(access.repo.id, target.id).await? {
            return Err(CoreError::Invalid(format!(
                "'{}' is not a member of this repository",
                target.handle
            )));
        }
        let row = self.trail_row(access.repo.id, number).await?;
        if row.author_id == Some(target.id) {
            return Err(CoreError::Invalid(
                "cannot request a review from the Trail's author".into(),
            ));
        }
        let current = db_trails::review_requests_of(self.db(), row.id).await?;
        if !current.contains(&target.id) && current.len() >= MAX_REVIEW_REQUESTS {
            return Err(CoreError::Invalid(
                "too many review requests on this trail".into(),
            ));
        }
        if !db_trails::add_review_request(self.db(), row.id, target.id, user.id, now()).await? {
            return self.trail_view(&row).await;
        }
        db_trails::touch(self.db(), row.id, now()).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.review_requested",
            Some(user.id),
            serde_json::json!({"user": target.handle, "user_id": target.id}),
        )
        .await?;
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("updated"),
            Some("review_requested"),
            number,
            None,
        )
        .await;
        self.trail_view(&self.trail_row(access.repo.id, number).await?)
            .await
    }

    /// Triage+; idempotent. Writes `trail.review_request_removed`; dispatches trail/updated cause review_request_removed.
    pub async fn remove_review_request(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        number: i64,
        handle: &str,
    ) -> CoreResult<TrailView> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        if access.permission < Permission::Triage {
            return Err(CoreError::Forbidden);
        }
        let target = self
            .user_by_handle(handle)
            .await?
            .ok_or_else(|| CoreError::Invalid(format!("no user named '{handle}'")))?;
        let row = self.trail_row(access.repo.id, number).await?;
        if !db_trails::remove_review_request(self.db(), row.id, target.id).await? {
            return self.trail_view(&row).await;
        }
        db_trails::touch(self.db(), row.id, now()).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.review_request_removed",
            Some(user.id),
            serde_json::json!({"user": target.handle, "user_id": target.id}),
        )
        .await?;
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("updated"),
            Some("review_request_removed"),
            number,
            None,
        )
        .await;
        self.trail_view(&self.trail_row(access.repo.id, number).await?)
            .await
    }

    /// D3 explicit link. Triage+ on the repo, or the Trail author for a
    /// session they uploaded; the session must be in the same repo and
    /// readable by the actor (§6.4), else 404. At most 50 explicit links per
    /// Trail (422 beyond). Idempotent: repeats write nothing and still
    /// succeed. A real link writes `trail.session_linked` and dispatches
    /// `trail`/`updated` with cause `session_linked`. Archived repos refuse.
    pub async fn link_trail_session(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        n: i64,
        ulid: &str,
    ) -> CoreResult<()> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        let row = self.trail_row(access.repo.id, n).await?;
        let session = db_sessions::session_by_ulid(self.db(), access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        // Suspended users are anonymous, mirroring `authorize_session_read`.
        let viewer = user.active.then_some(Viewer {
            user_id: user.id,
            is_admin: user.is_admin,
        });
        self.authorize_session_read(viewer, &access.repo, &session)
            .await?;
        let triage = access.permission >= Permission::Triage;
        let own_upload = row.author_id == Some(user.id) && session.uploader_id == user.id;
        if !triage && !own_upload {
            return Err(CoreError::Forbidden);
        }
        if !db_trails::add_trail_session_link(self.db(), row.id, session.id, user.id, now()).await?
        {
            return Ok(());
        }
        if db_trails::trail_session_link_count(self.db(), row.id).await?
            > MAX_TRAIL_SESSION_LINKS as i64
        {
            db_trails::remove_trail_session_link(self.db(), row.id, session.id).await?;
            return Err(CoreError::Invalid(
                "this trail already has 50 explicitly linked sessions".into(),
            ));
        }
        db_trails::touch(self.db(), row.id, now()).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.session_linked",
            Some(user.id),
            serde_json::json!({"session": ulid}),
        )
        .await?;
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("updated"),
            Some("session_linked"),
            n,
            None,
        )
        .await;
        Ok(())
    }

    /// D3 explicit unlink. Same authorization as [`Core::link_trail_session`].
    /// Removing a missing link is a silent no-op; a real unlink writes
    /// `trail.session_unlinked` and dispatches `trail`/`updated` with cause
    /// `session_unlinked`.
    pub async fn unlink_trail_session(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        n: i64,
        ulid: &str,
    ) -> CoreResult<()> {
        let access = self.repo_for(Some(user), owner, repo).await?;
        Self::ensure_writable(&access.repo)?;
        let row = self.trail_row(access.repo.id, n).await?;
        let session = db_sessions::session_by_ulid(self.db(), access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        let viewer = user.active.then_some(Viewer {
            user_id: user.id,
            is_admin: user.is_admin,
        });
        self.authorize_session_read(viewer, &access.repo, &session)
            .await?;
        let triage = access.permission >= Permission::Triage;
        let own_upload = row.author_id == Some(user.id) && session.uploader_id == user.id;
        if !triage && !own_upload {
            return Err(CoreError::Forbidden);
        }
        if !db_trails::remove_trail_session_link(self.db(), row.id, session.id).await? {
            return Ok(());
        }
        db_trails::touch(self.db(), row.id, now()).await?;
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.session_unlinked",
            Some(user.id),
            serde_json::json!({"session": ulid}),
        )
        .await?;
        self.dispatch_trail_event(
            access.repo.id,
            Some(user.handle.clone()),
            Some("updated"),
            Some("session_unlinked"),
            n,
            None,
        )
        .await;
        Ok(())
    }

    /// D5 data: the viewer's readable linked sessions, grouped. Used by F3
    /// (Sessions tab) and F4 (timeline rows). Commit groups hold every
    /// commit of the Trail with at least one readable session, ordered by
    /// first appearance (change number ascending, then revision number
    /// descending, then position); each commit appears once. The group's
    /// `change`/`revision` is that first appearance's occurrence, and
    /// `first_seen_at` is its revision's creation time.
    pub async fn trail_sessions(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        n: i64,
    ) -> CoreResult<TrailSessions> {
        let access = self.repo_for(viewer, owner, repo).await?;
        let trail = self.trail_row(access.repo.id, n).await?;
        // Suspended users are anonymous.
        let viewer = viewer.filter(|u| u.active);
        let viewer_fact = viewer.map(|u| Viewer {
            user_id: u.id,
            is_admin: u.is_admin,
        });
        let is_member = match viewer {
            Some(u) => self.is_repo_member(access.repo.id, u.id).await?,
            None => false,
        };
        let is_admin = access.permission >= Permission::Admin;

        // All cached commits on the trail, first-appearance walk order.
        let mut occurrences = db_changes::revision_commits_of_trail(self.db(), trail.id).await?;
        occurrences.sort_by(|a, b| {
            (
                a.change_number,
                std::cmp::Reverse(a.revision_number),
                a.position,
            )
                .cmp(&(
                    b.change_number,
                    std::cmp::Reverse(b.revision_number),
                    b.position,
                ))
        });
        let mut order: Vec<String> = Vec::new();
        let mut representative: std::collections::HashMap<String, (i64, i64, i64, String)> =
            std::collections::HashMap::new();
        for occurrence in &occurrences {
            if representative.contains_key(&occurrence.sha) {
                continue;
            }
            representative.insert(
                occurrence.sha.clone(),
                (
                    occurrence.change_number,
                    occurrence.revision_number,
                    occurrence.revision_created_at,
                    occurrence.subject.clone(),
                ),
            );
            order.push(occurrence.sha.clone());
        }
        // One commit-link query for every cached sha, then the per-row
        // `can_read_session` filter (mirrors `filter_readable_links`).
        let shas: Vec<String> = order.clone();
        let mut commit_sessions: std::collections::HashMap<String, Vec<SessionLinkRow>> =
            std::collections::HashMap::new();
        let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
        for link in db_sessions::links_for_shas(self.db(), access.repo.id, &shas).await? {
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
            if !can_read_session(viewer_fact, &access.repo, &session, is_member, is_admin) {
                continue;
            }
            seen.insert(session.id);
            commit_sessions.entry(link.sha.clone()).or_default().push(
                self.session_link_row(&link.confidence, link.seq_start, &session)
                    .await?,
            );
        }
        // Explicit links, oldest first, same read filter.
        let mut linked = Vec::new();
        for explicit in db_trails::trail_session_links_of(self.db(), trail.id).await? {
            let Some(session) = db_sessions::session_by_id(self.db(), explicit.session_id).await?
            else {
                continue;
            };
            if session.repo_id != access.repo.id {
                continue;
            }
            if !can_read_session(viewer_fact, &access.repo, &session, is_member, is_admin) {
                continue;
            }
            seen.insert(session.id);
            linked.push(self.session_link_row("explicit", None, &session).await?);
        }
        // Commit groups in walk order, keeping only commits with a readable
        // session; Trail totals over distinct sessions.
        let mut commits = Vec::new();
        for sha in &order {
            let Some(sessions) = commit_sessions.remove(sha) else {
                continue;
            };
            if sessions.is_empty() {
                continue;
            }
            let (change, revision, first_seen_at, subject) = representative
                .remove(sha)
                .expect("walk sha has a representative");
            commits.push(CommitSessions {
                sha: sha.clone(),
                subject,
                change,
                revision,
                first_seen_at,
                sessions,
            });
        }
        let totals = self.trail_session_totals(seen).await?;
        Ok(TrailSessions {
            commits,
            linked,
            totals,
        })
    }

    /// One [`SessionLinkRow`] for a readable session: title truncated to 120
    /// chars (D5 prompt preview), token totals from its usage columns.
    async fn session_link_row(
        &self,
        confidence: &str,
        seq_start: Option<i64>,
        session: &SessionRow,
    ) -> CoreResult<SessionLinkRow> {
        let uploader = self
            .user_by_id(session.uploader_id)
            .await?
            .map(|user| user.handle)
            .unwrap_or_else(|| "deleted user".to_owned());
        Ok(SessionLinkRow {
            ulid: session.ulid.clone(),
            agent: session.agent_name.clone(),
            agent_version: session.agent_version.clone(),
            models: session.models.clone(),
            title: session
                .title
                .chars()
                .take(MAX_SESSION_TITLE_CHARS)
                .collect(),
            uploader,
            started_at: session.started_at,
            created_at: session.created_at,
            confidence: confidence.to_owned(),
            seq_start,
            totals: TokenTotals::of(session),
        })
    }

    /// Trail-wide totals over distinct session ids (a session linked through
    /// two commits counts once).
    async fn trail_session_totals(
        &self,
        session_ids: std::collections::HashSet<i64>,
    ) -> CoreResult<TokenTotals> {
        let mut totals = TokenTotals::default();
        for id in session_ids {
            if let Some(session) = db_sessions::session_by_id(self.db(), id).await? {
                totals.add(&TokenTotals::of(&session));
            }
        }
        Ok(totals)
    }

    /// D5 commit-panel rows: every link filed under `sha` that `viewer` may
    /// read (§6.4), oldest first, as [`SessionLinkRow`]s plus the link
    /// provenance. Unreadable links are omitted entirely, like
    /// [`Core::readable_links_for_commit`]; uploads that never arrived are
    /// skipped.
    pub async fn readable_session_rows_for_commit(
        &self,
        access: &crate::repos::RepoAccess,
        viewer: Option<&User>,
        sha: &str,
    ) -> CoreResult<Vec<CommitPanelRow>> {
        let mut rows = Vec::new();
        for (link, session) in self.readable_links_for_commit(access, viewer, sha).await? {
            rows.push(CommitPanelRow {
                source: link.source.clone(),
                row: self
                    .session_link_row(&link.confidence, link.seq_start, &session)
                    .await?,
            });
        }
        Ok(rows)
    }

    /// D7 Conversation timeline: stored events plus derived rows, in time
    /// order (stable: stored rows in id order, then sessions in
    /// [`Core::trail_sessions`] order, then checks in
    /// (change, revision, context) order).
    ///
    /// Derived rows are computed per request and filtered for the viewer:
    /// one row per readable session linked through commits (timed at the
    /// later of the session's `created_at` and the first revision
    /// containing its commit), and one row per check status posted on a
    /// head SHA of any revision of the Trail's changes (labeled with the
    /// newest revision carrying that head; timed at the check's
    /// `updated_at`). Reads 404 for non-readers, like
    /// [`Core::trail_by_number`].
    pub async fn trail_timeline(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        n: i64,
    ) -> CoreResult<Vec<TrailTimelineEntry>> {
        let access = self.repo_for(viewer, owner, repo).await?;
        let trail = self.trail_row(access.repo.id, n).await?;
        let mut entries: Vec<TrailTimelineEntry> =
            db_trails::timeline_of_trail(self.db(), trail.id)
                .await?
                .into_iter()
                .map(TrailTimelineEntry::Stored)
                .collect();
        let sessions = self.trail_sessions(viewer, owner, repo, n).await?;
        for group in &sessions.commits {
            for row in &group.sessions {
                entries.push(TrailTimelineEntry::Session(TimelineSession {
                    row: row.clone(),
                    sha: group.sha.clone(),
                    subject: group.subject.clone(),
                    change: group.change,
                    revision: group.revision,
                    at: row.created_at.max(group.first_seen_at),
                }));
            }
        }
        // Newest (change, revision) carrying each head SHA; ascending
        // iteration means the last write wins.
        let mut heads: std::collections::HashMap<String, (i64, i64)> =
            std::collections::HashMap::new();
        for change in db_changes::changes_of_trail(self.db(), trail.id).await? {
            for revision in db_changes::revisions_of_change(self.db(), change.id).await? {
                heads.insert(revision.head_sha.clone(), (change.number, revision.number));
            }
        }
        let shas: Vec<String> = heads.keys().cloned().collect();
        let mut labeled: Vec<(i64, i64, String, db_checks::CheckRow)> = Vec::new();
        for row in db_checks::latest_checks_for_shas(self.db(), access.repo.id, &shas).await? {
            if let Some(&(change, revision)) = heads.get(&row.sha) {
                labeled.push((change, revision, row.context.clone(), row));
            }
        }
        labeled.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));
        for (change, revision, _, row) in labeled {
            let at = row.updated_at;
            entries.push(TrailTimelineEntry::Check(TimelineCheck {
                row,
                change,
                revision,
                at,
            }));
        }
        entries.sort_by_key(TrailTimelineEntry::at);
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use starforged_db::trails as db_trails;

    use super::*;
    use crate::accounts::CreateUser;
    use crate::permission::Visibility;
    use crate::repos::CreateRepo;
    use crate::testing::{test_core, user};

    async fn proj(core: &Core, owner: &User, visibility: Visibility) -> String {
        core.create_repo(
            owner,
            CreateRepo {
                name: "proj".into(),
                description: String::new(),
                visibility,
                readme: false,
            },
        )
        .await
        .unwrap();
        "proj".into()
    }

    async fn admin(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    fn wait_next_second() {
        let start = now();
        while now() == start {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    async fn audit_count(core: &Core, action: &str, target: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE action = $1 AND target = $2")
            .bind(action)
            .bind(target)
            .fetch_one(core.db().pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn create_round_trips_number_author_and_empties() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        proj(&core, &alice, Visibility::Private).await;
        let view = core
            .create_trail(&alice, "alice", "proj", "Fix it", "do the thing")
            .await
            .unwrap();
        assert_eq!(view.number, 1);
        assert_eq!(view.author_handle, "alice");
        assert!(view.labels.is_empty() && view.assignees.is_empty());
        assert_eq!(view.state, "open");
        assert!(!view.ready);
        let detail = core
            .trail_by_number(Some(&alice), "alice", "proj", 1)
            .await
            .unwrap();
        assert_eq!(detail.trail.title, "Fix it");
        assert!(detail.comments.is_empty());
        assert_eq!(detail.timeline.len(), 1);
        assert_eq!(detail.timeline[0].kind, "trail.open");
        assert!(detail.can_edit && detail.can_triage); // owner is admin.
    }

    #[tokio::test]
    async fn trail_view_reports_the_author_id_not_the_row_id() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        proj(&core, &alice, Visibility::Private).await;
        // Bob is a collaborator, so trail id (1) differs from his user id (2).
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
            .await
            .unwrap();
        let view = core
            .create_trail(&bob, "alice", "proj", "Bob's trail", "")
            .await
            .unwrap();
        assert_eq!(view.number, 1);
        assert_ne!(
            view.author_id,
            Some(1),
            "author_id must not be the trail row id"
        );
        assert_eq!(view.author_id, Some(bob.id));
        assert_eq!(view.author_handle, "bob");
    }

    #[tokio::test]
    async fn missing_and_invisible_are_not_found() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        proj(&core, &alice, Visibility::Private).await;
        assert!(matches!(
            core.trail_by_number(Some(&alice), "alice", "proj", 99)
                .await,
            Err(CoreError::NotFound)
        ));
        // Stranger on a private repo: get and list are NotFound, never Forbidden.
        assert!(matches!(
            core.trail_by_number(Some(&bob), "alice", "proj", 1).await,
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            core.list_trails(Some(&bob), "alice", "proj", &TrailFilterInput::default())
                .await,
            Err(CoreError::NotFound)
        ));
        // Anonymous too.
        assert!(matches!(
            core.trail_by_number(None, "alice", "proj", 1).await,
            Err(CoreError::NotFound)
        ));
        // Unknown repo is NotFound as well.
        assert!(matches!(
            core.trail_by_number(Some(&alice), "alice", "nope", 1).await,
            Err(CoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn suspended_viewer_is_anonymous() {
        let (core, _f) = test_core().await;
        let root = admin(&core, "root").await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        proj(&core, &alice, Visibility::Private).await;
        core.suspend_user(&root, bob.id).await.unwrap();
        let bob = core.user_by_id(bob.id).await.unwrap().unwrap();
        assert!(!bob.active);
        assert!(matches!(
            core.trail_by_number(Some(&bob), "alice", "proj", 1).await,
            Err(CoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn state_transitions_validate_and_audit() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        proj(&core, &alice, Visibility::Private).await;
        core.create_trail(&alice, "alice", "proj", "T", "")
            .await
            .unwrap();
        let target = "trail:alice/proj#1";
        // merged is owned by the merge path.
        let err = core
            .set_trail_state(&alice, "alice", "proj", 1, "merged")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m.contains("merge path")));
        let err = core
            .set_trail_state(&alice, "alice", "proj", 1, "bogus")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(_)));
        // Close sets closed_at; reopen clears it.
        let closed = core
            .set_trail_state(&alice, "alice", "proj", 1, "closed")
            .await
            .unwrap();
        assert_eq!(closed.state, "closed");
        assert!(closed.closed_at.is_some());
        let open = core
            .set_trail_state(&alice, "alice", "proj", 1, "open")
            .await
            .unwrap();
        assert_eq!(open.state, "open");
        assert!(open.closed_at.is_none());
        assert_eq!(audit_count(&core, "trail.open", target).await, 1);
        assert_eq!(audit_count(&core, "trail.close", target).await, 1);
        assert_eq!(audit_count(&core, "trail.reopen", target).await, 1);
        // Timeline carries from/to/state.
        let detail = core
            .trail_by_number(Some(&alice), "alice", "proj", 1)
            .await
            .unwrap();
        let states: Vec<_> = detail
            .timeline
            .iter()
            .filter(|e| e.kind == "trail.state")
            .collect();
        assert_eq!(states.len(), 2);
        let p: serde_json::Value = serde_json::from_str(&states[0].payload).unwrap();
        assert_eq!(p["from"], "open");
        assert_eq!(p["to"], "closed");
        assert_eq!(p["state"], "closed");
    }

    #[tokio::test]
    async fn state_validation_runs_after_the_permission_gate() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        let stranger = user(&core, "stranger").await;
        proj(&core, &alice, Visibility::Private).await;
        core.create_trail(&alice, "alice", "proj", "T", "")
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
            .await
            .unwrap();
        // Non-reader asking for `merged` learns nothing: NotFound, not Invalid.
        assert!(matches!(
            core.set_trail_state(&stranger, "alice", "proj", 1, "merged")
                .await,
            Err(CoreError::NotFound)
        ));
        // Read-only member gets Forbidden before any state validation.
        assert!(matches!(
            core.set_trail_state(&bob, "alice", "proj", 1, "merged")
                .await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.set_trail_state(&bob, "alice", "proj", 1, "bogus")
                .await,
            Err(CoreError::Forbidden)
        ));
        // Unknown repo is NotFound even for a bogus state.
        assert!(matches!(
            core.set_trail_state(&alice, "alice", "nope", 1, "merged")
                .await,
            Err(CoreError::NotFound)
        ));
        // Triage+ still gets the merge-path message.
        let err = core
            .set_trail_state(&alice, "alice", "proj", 1, "merged")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m.contains("merge path")));
    }

    #[tokio::test]
    async fn labels_normalize_validate_and_dedupe() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        proj(&core, &alice, Visibility::Private).await;
        core.create_trail(&alice, "alice", "proj", "T", "")
            .await
            .unwrap();
        let view = core
            .add_label(&alice, "alice", "proj", 1, "Bug")
            .await
            .unwrap();
        assert_eq!(view.labels, vec!["bug"]);
        // Re-add dedupes: ok, still one label, no extra timeline row.
        let before = db_trails::timeline_of_trail(core.db(), 1)
            .await
            .unwrap()
            .len();
        let view = core
            .add_label(&alice, "alice", "proj", 1, "bug")
            .await
            .unwrap();
        assert_eq!(view.labels, vec!["bug"]);
        let after = db_trails::timeline_of_trail(core.db(), 1)
            .await
            .unwrap()
            .len();
        assert_eq!(before, after);
        assert!(matches!(
            normalize_label("BAD LABEL!").unwrap_err(),
            CoreError::Invalid(_)
        ));
        assert!(matches!(
            normalize_label(&"x".repeat(51)).unwrap_err(),
            CoreError::Invalid(_)
        ));
        assert!(matches!(
            normalize_label("   ").unwrap_err(),
            CoreError::Invalid(_)
        ));
        // Timeline payload shape.
        let detail = core
            .trail_by_number(Some(&alice), "alice", "proj", 1)
            .await
            .unwrap();
        let e = detail
            .timeline
            .iter()
            .find(|e| e.kind == "trail.label")
            .unwrap();
        let p: serde_json::Value = serde_json::from_str(&e.payload).unwrap();
        assert_eq!(p["action"], "add");
        assert_eq!(p["name"], "bug");
        // Cap at 10 labels.
        for i in 0..9 {
            core.add_label(&alice, "alice", "proj", 1, &format!("l{i}"))
                .await
                .unwrap();
        }
        let timelines = || async {
            db_trails::timeline_of_trail(core.db(), 1)
                .await
                .unwrap()
                .len()
        };
        let rows_before = timelines().await;
        assert!(matches!(
            core.add_label(&alice, "alice", "proj", 1, "overflow").await,
            Err(CoreError::Invalid(_))
        ));
        // The rejected 11th label inserts nothing and writes no timeline row.
        let detail = core
            .trail_by_number(Some(&alice), "alice", "proj", 1)
            .await
            .unwrap();
        assert_eq!(detail.trail.labels.len(), 10);
        assert!(!detail.trail.labels.contains(&"overflow".to_string()));
        assert_eq!(timelines().await, rows_before);
        // Remove writes a remove row.
        let view = core
            .remove_label(&alice, "alice", "proj", 1, "BUG")
            .await
            .unwrap();
        assert!(!view.labels.contains(&"bug".to_string()));
        let detail = core
            .trail_by_number(Some(&alice), "alice", "proj", 1)
            .await
            .unwrap();
        let last = detail
            .timeline
            .iter()
            .rfind(|e| e.kind == "trail.label")
            .unwrap();
        let p: serde_json::Value = serde_json::from_str(&last.payload).unwrap();
        assert_eq!(p["action"], "remove");
    }

    #[tokio::test]
    async fn assignees_must_be_members() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        let carol = user(&core, "carol").await;
        proj(&core, &alice, Visibility::Private).await;
        core.create_trail(&alice, "alice", "proj", "T", "")
            .await
            .unwrap();
        // Non-member (no grant) is Invalid, unknown handle too.
        assert!(matches!(
            core.add_assignee(&alice, "alice", "proj", 1, "carol").await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.add_assignee(&alice, "alice", "proj", 1, "ghost").await,
            Err(CoreError::Invalid(_))
        ));
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
            .await
            .unwrap();
        let view = core
            .add_assignee(&alice, "alice", "proj", 1, "BOB")
            .await
            .unwrap();
        assert_eq!(view.assignees, vec!["bob"]);
        let detail = core
            .trail_by_number(Some(&alice), "alice", "proj", 1)
            .await
            .unwrap();
        let e = detail
            .timeline
            .iter()
            .find(|e| e.kind == "trail.assignee")
            .unwrap();
        let p: serde_json::Value = serde_json::from_str(&e.payload).unwrap();
        assert_eq!(p["action"], "add");
        assert_eq!(p["user"], "bob");
        assert_eq!(p["user_id"], bob.id);
        let _ = carol;
        let view = core
            .remove_assignee(&alice, "alice", "proj", 1, "bob")
            .await
            .unwrap();
        assert!(view.assignees.is_empty());
    }

    #[tokio::test]
    async fn comments_need_read_and_edits_need_author_or_admin() {
        let (core, _f) = test_core().await;
        let root = admin(&core, "root").await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        proj(&core, &alice, Visibility::Private).await;
        core.create_trail(&alice, "alice", "proj", "T", "")
            .await
            .unwrap();
        // Stranger without read cannot comment (NotFound, not Forbidden).
        assert!(matches!(
            core.add_comment(&bob, "alice", "proj", 1, "hi").await,
            Err(CoreError::NotFound)
        ));
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
            .await
            .unwrap();
        let c = core
            .add_comment(&bob, "alice", "proj", 1, "hello")
            .await
            .unwrap();
        assert_eq!(c.author_handle, "bob");
        assert!(c.edited_at.is_none());
        // Stranger (carol, no access at all... use dave with read) cannot edit.
        let dave = user(&core, "dave").await;
        core.set_collaborator(&alice, "alice", "proj", "dave", Permission::Read)
            .await
            .unwrap();
        assert!(matches!(
            core.edit_comment(&dave, "alice", "proj", 1, c.id, "hijack")
                .await,
            Err(CoreError::Forbidden)
        ));
        // Author edits: ok, edited_at set.
        let c2 = core
            .edit_comment(&bob, "alice", "proj", 1, c.id, "hello v2")
            .await
            .unwrap();
        assert_eq!(c2.body, "hello v2");
        assert!(c2.edited_at.is_some());
        // Site admin edits anyone's comment.
        let c3 = core
            .edit_comment(&root, "alice", "proj", 1, c.id, "mod edit")
            .await
            .unwrap();
        assert_eq!(c3.body, "mod edit");
        // Comment payload shape.
        let detail = core
            .trail_by_number(Some(&alice), "alice", "proj", 1)
            .await
            .unwrap();
        let e = detail
            .timeline
            .iter()
            .find(|e| e.kind == "trail.comment")
            .unwrap();
        let p: serde_json::Value = serde_json::from_str(&e.payload).unwrap();
        assert!(p.get("comment_id").is_some());
    }

    #[tokio::test]
    async fn triage_gates_curation_and_ready() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        proj(&core, &alice, Visibility::Private).await;
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
            .await
            .unwrap();
        core.create_trail(&alice, "alice", "proj", "T", "i")
            .await
            .unwrap();
        // Read-only bob: labels/state forbidden.
        assert!(matches!(
            core.add_label(&bob, "alice", "proj", 1, "bug").await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.set_trail_state(&bob, "alice", "proj", 1, "closed")
                .await,
            Err(CoreError::Forbidden)
        ));
        // Bob's own trail: may edit title, but not the ready toggle.
        let own = core
            .create_trail(&bob, "alice", "proj", "mine", "i")
            .await
            .unwrap();
        assert_eq!(own.number, 2);
        let edited = core
            .update_trail(&bob, "alice", "proj", 2, Some("mine v2"), None, None)
            .await
            .unwrap();
        assert_eq!(edited.title, "mine v2");
        assert!(matches!(
            core.update_trail(&bob, "alice", "proj", 2, None, None, Some(true))
                .await,
            Err(CoreError::Forbidden)
        ));
        // Stranger cannot edit someone else's title at all.
        assert!(matches!(
            core.update_trail(&bob, "alice", "proj", 1, Some("x"), None, None)
                .await,
            Err(CoreError::Forbidden)
        ));
        // Triage can edit anyone's trail including ready.
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Triage)
            .await
            .unwrap();
        let edited = core
            .update_trail(&bob, "alice", "proj", 1, Some("T2"), Some("i2"), Some(true))
            .await
            .unwrap();
        assert!(edited.ready);
        let detail = core
            .trail_by_number(Some(&bob), "alice", "proj", 1)
            .await
            .unwrap();
        let e = detail
            .timeline
            .iter()
            .find(|e| e.kind == "trail.edit")
            .unwrap();
        let p: serde_json::Value = serde_json::from_str(&e.payload).unwrap();
        let fields = p["fields"].as_array().unwrap();
        assert!(fields.contains(&serde_json::json!("title")));
        assert!(fields.contains(&serde_json::json!("ready")));
        assert_eq!(p["field"], fields[0].clone());
        // No-change update writes no timeline row.
        let n = detail.timeline.len();
        core.update_trail(&bob, "alice", "proj", 1, Some("T2"), Some("i2"), Some(true))
            .await
            .unwrap();
        let detail = core
            .trail_by_number(Some(&bob), "alice", "proj", 1)
            .await
            .unwrap();
        assert_eq!(detail.timeline.len(), n);
    }

    #[tokio::test]
    async fn validation_rejects_bad_input() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        proj(&core, &alice, Visibility::Private).await;
        assert!(matches!(
            core.create_trail(&alice, "alice", "proj", "   ", "i").await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.create_trail(&alice, "alice", "proj", &"x".repeat(201), "i")
                .await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.create_trail(&alice, "alice", "proj", "a\nb", "i")
                .await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.create_trail(&alice, "alice", "proj", "T", &"i".repeat(64 * 1024 + 1))
                .await,
            Err(CoreError::Invalid(_))
        ));
        core.create_trail(&alice, "alice", "proj", "T", "")
            .await
            .unwrap();
        assert!(matches!(
            core.add_comment(&alice, "alice", "proj", 1, "  ").await,
            Err(CoreError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn list_filters_validate_paginate_and_cursor() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        proj(&core, &alice, Visibility::Public).await;
        for i in 1..=3 {
            core.create_trail(&alice, "alice", "proj", &format!("T{i}"), "")
                .await
                .unwrap();
        }
        core.set_trail_state(&alice, "alice", "proj", 2, "closed")
            .await
            .unwrap();
        // Bogus state filter is Invalid; `merged` filters like any other state
        // (empty here — the merge path owns the only writer).
        assert!(matches!(
            core.list_trails(
                Some(&alice),
                "alice",
                "proj",
                &TrailFilterInput {
                    state: Some("bogus".into()),
                    ..Default::default()
                }
            )
            .await,
            Err(CoreError::Invalid(_))
        ));
        let page = core
            .list_trails(
                Some(&alice),
                "alice",
                "proj",
                &TrailFilterInput {
                    state: Some("merged".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(page.trails.is_empty() && page.next_after.is_none());
        // State filter works.
        let page = core
            .list_trails(
                Some(&alice),
                "alice",
                "proj",
                &TrailFilterInput {
                    state: Some("closed".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(page.trails.len(), 1);
        assert_eq!(page.trails[0].number, 2);
        // Unknown author handle lists empty, not 404.
        let page = core
            .list_trails(
                Some(&alice),
                "alice",
                "proj",
                &TrailFilterInput {
                    author: Some("ghost".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(page.trails.is_empty());
        // Keyset pagination: limit 2 → full page carries next_after.
        let page = core
            .list_trails(
                None,
                "alice",
                "proj",
                &TrailFilterInput {
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(page.trails.len(), 2);
        assert_eq!(page.next_after, Some(2));
        let next = page.next_after.unwrap();
        let page2 = core
            .list_trails(
                None,
                "alice",
                "proj",
                &TrailFilterInput {
                    limit: Some(2),
                    after: Some(next),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(page2.trails.len(), 1);
        assert_eq!(page2.next_after, None);
    }

    #[tokio::test]
    async fn every_mutation_appends_exactly_one_timeline_row() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        proj(&core, &alice, Visibility::Private).await;
        let target = "trail:alice/proj#1";
        let count = async || {
            db_trails::timeline_of_trail(core.db(), 1)
                .await
                .unwrap()
                .len() as i64
        };
        core.create_trail(&alice, "alice", "proj", "T", "")
            .await
            .unwrap();
        assert_eq!(count().await, 1);
        core.set_collaborator(&alice, "alice", "proj", "alice", Permission::Admin)
            .await
            .unwrap_err(); // owner already admin: Invalid, timeline untouched.
        core.add_comment(&alice, "alice", "proj", 1, "c")
            .await
            .unwrap();
        assert_eq!(count().await, 2);
        core.add_label(&alice, "alice", "proj", 1, "bug")
            .await
            .unwrap();
        assert_eq!(count().await, 3);
        core.set_trail_state(&alice, "alice", "proj", 1, "closed")
            .await
            .unwrap();
        assert_eq!(count().await, 4);
        // updated_at strictly increases across mutations (second resolution).
        let before = core
            .trail_by_number(Some(&alice), "alice", "proj", 1)
            .await
            .unwrap()
            .trail
            .updated_at;
        wait_next_second();
        core.add_comment(&alice, "alice", "proj", 1, "later")
            .await
            .unwrap();
        let after = core
            .trail_by_number(Some(&alice), "alice", "proj", 1)
            .await
            .unwrap()
            .trail
            .updated_at;
        assert!(after > before);
        // Audit: open/close/reopen only — comments and labels are timeline-only.
        assert_eq!(audit_count(&core, "trail.open", target).await, 1);
        assert_eq!(audit_count(&core, "trail.close", target).await, 1);
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE target = $1")
            .bind(target)
            .fetch_one(core.db().pool())
            .await
            .unwrap();
        assert_eq!(total, 2);
    }
    #[tokio::test]
    async fn deleted_author_keeps_trail_readable_and_triages_can_close() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        let carol = user(&core, "carol").await;
        let dave = user(&core, "dave").await;
        proj(&core, &alice, Visibility::Private).await;
        for h in ["bob", "carol", "dave"] {
            core.set_collaborator(&alice, "alice", "proj", h, Permission::Read)
                .await
                .unwrap();
        }
        core.create_trail(&bob, "alice", "proj", "T", "")
            .await
            .unwrap();
        core.add_comment(&carol, "alice", "proj", 1, "hi")
            .await
            .unwrap();
        starforged_db::users::delete(core.db(), bob.id)
            .await
            .unwrap();
        starforged_db::users::delete(core.db(), carol.id)
            .await
            .unwrap();
        let detail = core
            .trail_by_number(Some(&dave), "alice", "proj", 1)
            .await
            .unwrap();
        assert_eq!(detail.trail.author_id, None);
        assert_eq!(detail.trail.author_handle, "deleted user");
        assert_eq!(detail.comments.len(), 1);
        assert_eq!(detail.comments[0].author_id, None);
        assert_eq!(detail.comments[0].author_handle, "deleted user");
        // A NULL author is never the actor: only triage/admin may edit.
        let closed = core
            .set_trail_state(&alice, "alice", "proj", 1, "closed")
            .await
            .unwrap();
        assert_eq!(closed.state, "closed");
        let edited = core
            .update_trail(&alice, "alice", "proj", 1, Some("T2"), None, None)
            .await
            .unwrap();
        assert_eq!(edited.title, "T2");
    }

    #[tokio::test]
    async fn archived_repo_refuses_trail_mutations_but_keeps_reads() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        proj(&core, &alice, Visibility::Private).await;
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Triage)
            .await
            .unwrap();
        core.create_trail(&alice, "alice", "proj", "T", "")
            .await
            .unwrap();
        core.add_comment(&alice, "alice", "proj", 1, "c")
            .await
            .unwrap();
        // Active repo: create/comment/list still fine.
        core.create_trail(&bob, "alice", "proj", "T2", "")
            .await
            .unwrap();
        let list = core
            .list_trails(Some(&bob), "alice", "proj", &TrailFilterInput::default())
            .await
            .unwrap();
        assert_eq!(list.trails.len(), 2);
        core.archive_repo(&alice, "alice", "proj").await.unwrap();
        // Reads keep working.
        let detail = core
            .trail_by_number(Some(&bob), "alice", "proj", 1)
            .await
            .unwrap();
        assert_eq!(detail.trail.title, "T");
        let list = core
            .list_trails(Some(&bob), "alice", "proj", &TrailFilterInput::default())
            .await
            .unwrap();
        assert_eq!(list.trails.len(), 2);
        // Every mutation refuses with the same message.
        let err = core
            .create_trail(&bob, "alice", "proj", "T3", "")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m == "repository is archived"));
        let err = core
            .add_comment(&bob, "alice", "proj", 1, "x")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m == "repository is archived"));
        let err = core
            .edit_comment(&alice, "alice", "proj", 1, 1, "x")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m == "repository is archived"));
        let err = core
            .update_trail(&bob, "alice", "proj", 1, Some("x"), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m == "repository is archived"));
        let err = core
            .set_trail_state(&bob, "alice", "proj", 1, "closed")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m == "repository is archived"));
        let err = core
            .add_label(&bob, "alice", "proj", 1, "bug")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m == "repository is archived"));
        let err = core
            .remove_label(&bob, "alice", "proj", 1, "bug")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m == "repository is archived"));
        let err = core
            .add_assignee(&bob, "alice", "proj", 1, "bob")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m == "repository is archived"));
        let err = core
            .remove_assignee(&bob, "alice", "proj", 1, "bob")
            .await
            .unwrap_err();
        assert!(matches!(err, CoreError::Invalid(m) if m == "repository is archived"));
    }
}
