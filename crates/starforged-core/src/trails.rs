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

use starforged_db::now;
use starforged_db::trails as db_trails;
use starforged_db::trails::{TimelineEventRow, TrailCommentRow, TrailFilter, TrailRow};

use crate::accounts::User;
use crate::permission::Permission;
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
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

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
        // `merged` lists empty in M2a, never 422.
        if f.state.as_deref() == Some("merged") {
            return Ok(ListPage {
                trails: Vec::new(),
                next_after: None,
            });
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
        let limit = f.limit.unwrap_or(30).clamp(1, 100);
        let rows = db_trails::trails_of_repo(
            self.db(),
            access.repo.id,
            &TrailFilter {
                state: f.state.clone(),
                label,
                assignee_id,
                author_id,
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
        let at = now();
        if fields.contains(&"title") || fields.contains(&"intent") {
            db_trails::set_title_intent(self.db(), row.id, &new_title, &new_intent, at).await?;
        }
        if fields.contains(&"ready") {
            db_trails::set_ready(self.db(), row.id, i64::from(new_ready), at).await?;
        }
        self.record_timeline(
            access.repo.id,
            row.id,
            "trail.edit",
            Some(user.id),
            serde_json::json!({"fields": fields, "field": fields[0]}),
        )
        .await?;
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
        self.trail_view(&self.trail_row(access.repo.id, number).await?)
            .await
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
        // Bogus state filter is Invalid; merged lists empty.
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
