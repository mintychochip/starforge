//! Commit statuses on any SHA (spec §6.5, M2c H2): validation and
//! permission live here; storage is `starforged-db::checks` (H1).
//!
//! Limits (H2 assignment): sha is 40 lowercase hex; context is 1–100 chars;
//! state is one of `pending`/`success`/`failure`/`error`; `target_url` is
//! empty or `http(s)://…`; description is at most 140 chars. A status is a CI
//! push, not a Trail edit, so writes need ≥ `Write` repo permission (reads
//! need read visibility). Status writes are timeline-free and audit-free —
//! they fire at CI cadence and §6.5's audit list covers permission/security
//! events, not per-status churn; submissions log at `info` via `tracing`
//! instead. Reads write nothing. An archived repository refuses submissions
//! (`Invalid`, like the trail/change precedent); reads stay available.

use starforged_db::{checks as db_checks, now};

use crate::accounts::User;
use crate::permission::Permission;
use crate::{Core, CoreError, CoreResult};

/// One commit status: the latest row for its `(sha, context)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusDto {
    pub sha: String,
    pub context: String,
    pub state: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
    pub creator_handle: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// The combined status of every latest-per-context row for one SHA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CombinedDto {
    pub sha: String,
    pub state: String,
    pub statuses: Vec<StatusDto>,
}

fn valid_sha(sha: &str) -> bool {
    sha.len() == 40
        && sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn validate_status(
    sha: &str,
    state: &str,
    context: &str,
    target_url: Option<&str>,
    description: Option<&str>,
) -> CoreResult<()> {
    if !valid_sha(sha) {
        return Err(CoreError::Invalid(format!("invalid sha '{sha}'")));
    }
    if !matches!(state, "pending" | "success" | "failure" | "error") {
        return Err(CoreError::Invalid(format!("invalid state '{state}'")));
    }
    let context_len = context.chars().count();
    if context_len == 0 || context_len > 100 {
        return Err(CoreError::Invalid(
            "context must be 1-100 characters".into(),
        ));
    }
    if let Some(url) = target_url
        && !url.is_empty()
        && !(url.starts_with("http://") || url.starts_with("https://"))
    {
        return Err(CoreError::Invalid(
            "target_url must be an http(s) URL".into(),
        ));
    }
    if description.is_some_and(|d| d.chars().count() > 140) {
        return Err(CoreError::Invalid(
            "description must be at most 140 characters".into(),
        ));
    }
    Ok(())
}

async fn status_dto(core: &Core, row: db_checks::CheckRow) -> CoreResult<StatusDto> {
    let creator_handle = match row.creator_id {
        None => None,
        Some(id) => core.user_by_id(id).await?.map(|user| user.handle.clone()),
    };
    Ok(StatusDto {
        sha: row.sha,
        context: row.context,
        state: row.state,
        target_url: row.target_url,
        description: row.description,
        creator_handle,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

impl Core {
    /// Submits (upserts) the status for `(sha, context)`: caller needs ≥
    /// `Write` on a non-archived repo. Returns the current row.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_status(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        sha: &str,
        state: &str,
        context: &str,
        target_url: Option<&str>,
        description: Option<&str>,
    ) -> CoreResult<StatusDto> {
        validate_status(sha, state, context, target_url, description)?;
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Write)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        let url = target_url.filter(|u| !u.is_empty());
        let row = db_checks::insert_check(
            self.db(),
            access.repo.id,
            sha,
            context,
            state,
            url,
            description,
            Some(user.id),
            now(),
        )
        .await?;
        tracing::info!(
            repo = %format!("{owner}/{repo}"),
            %sha,
            %context,
            %state,
            actor = %user.handle,
            "status submitted"
        );
        status_dto(self, row).await
    }

    /// The latest status per context for `sha` (context order). The viewer
    /// needs read visibility (`NotFound` otherwise — never `Forbidden`, so
    /// private repos do not leak). An unknown sha yields no rows.
    pub async fn list_statuses(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> CoreResult<Vec<StatusDto>> {
        if !valid_sha(sha) {
            return Err(CoreError::Invalid(format!("invalid sha '{sha}'")));
        }
        let access = self.repo_for(viewer, owner, repo).await?;
        let mut out = Vec::new();
        for row in db_checks::latest_statuses(self.db(), access.repo.id, sha).await? {
            out.push(status_dto(self, row).await?);
        }
        Ok(out)
    }

    /// The combined status for `sha`: the latest-per-context rows folded with
    /// error > failure > pending > success precedence (the same fold as
    /// `starforged-db::checks::combined_state`, over the DTO states); an
    /// unknown sha (no rows) is `pending` with an empty list.
    pub async fn combined_status(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> CoreResult<CombinedDto> {
        let statuses = self.list_statuses(viewer, owner, repo, sha).await?;
        let state = if statuses.iter().any(|s| s.state == "error") {
            "error"
        } else if statuses.iter().any(|s| s.state == "failure") {
            "failure"
        } else if statuses.iter().any(|s| s.state == "pending") || statuses.is_empty() {
            "pending"
        } else {
            "success"
        };
        Ok(CombinedDto {
            sha: sha.to_owned(),
            state: state.to_owned(),
            statuses,
        })
    }
}
