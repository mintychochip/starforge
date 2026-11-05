//! Commit statuses on any SHA (spec §6.5, M2c H2): validation and
//! permission live here; storage is `starforged-db::checks` (H1).
//!
//! Limits (H2 assignment): sha is 40 lowercase hex; context is 1–255 chars;
//! state is one of `pending`/`success`/`failure`/`error`; `target_url` is
//! empty or `http(s)://…` of at most 2048 chars; description is at most 1024
//! chars. A status is a CI push, not a Trail edit, so writes need ≥ `Write`
//! repo permission (reads need read visibility). Status writes are
//! timeline-free and audit-free — they fire at CI cadence and §6.5's audit
//! list covers permission/security events, not per-status churn; submissions
//! log at `info` via `tracing` instead. Reads write nothing. An archived
//! repository refuses submissions (`Invalid`, like the trail/change
//! precedent); reads stay available.

use starforged_db::{checks as db_checks, now};
use starforged_git::{read, refpolicy};

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

/// H2's status-context rule (1–255 chars, no control characters), reused by
/// gate-rule contexts. Control characters are refused so a newline-bearing
/// context cannot impersonate a line of trusted CLI output.
pub(crate) fn validate_context(context: &str) -> CoreResult<()> {
    let context_len = context.chars().count();
    if context_len == 0 || context_len > 255 {
        return Err(CoreError::Invalid(
            "context must be 1-255 characters".into(),
        ));
    }
    if context.chars().any(char::is_control) {
        return Err(CoreError::Invalid(
            "context must not contain control characters".into(),
        ));
    }
    Ok(())
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
    validate_context(context)?;
    if let Some(url) = target_url
        && !url.is_empty()
        && !(url.starts_with("http://") || url.starts_with("https://"))
    {
        return Err(CoreError::Invalid(
            "target_url must be an http(s) URL".into(),
        ));
    }
    if target_url.is_some_and(|u| u.chars().count() > 2048) {
        return Err(CoreError::Invalid(
            "target_url must be at most 2048 characters".into(),
        ));
    }
    if description.is_some_and(|d| d.chars().count() > 1024) {
        return Err(CoreError::Invalid(
            "description must be at most 1024 characters".into(),
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
        self.dispatch(
            access.repo.id,
            "status.updated",
            serde_json::json!({"sha": sha, "context": context, "state": state}),
        )
        .await;
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

    /// The combined status for `sha`: the latest-per-context rows folded by
    /// `starforged-db::checks::combined_state` (error > failure > pending >
    /// success); an unknown sha (no rows) is `pending` with an empty list.
    pub async fn combined_status(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> CoreResult<CombinedDto> {
        if !valid_sha(sha) {
            return Err(CoreError::Invalid(format!("invalid sha '{sha}'")));
        }
        self.combined_fold(viewer, owner, repo, sha).await
    }

    /// Combined status for `reference` (D10): lowercase 40/64-hex goes as-is;
    /// else `refs/heads/<reference>`, else `refs/tags/<reference>` peeled to
    /// its commit, via `starforged_git::read` helpers on the blocking pool;
    /// unresolvable → `NotFound`. Visibility and the fold are those of
    /// `combined_status` (a branch shadows a tag of the same name).
    pub async fn combined_status_for_ref(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        reference: &str,
    ) -> CoreResult<CombinedDto> {
        if refpolicy::is_oid(reference) {
            return self.combined_fold(viewer, owner, repo, reference).await;
        }
        let access = self.repo_for(viewer, owner, repo).await?;
        let repo_path = self.repo_path(access.repo.id);
        let name = reference.to_owned();
        let sha = tokio::task::spawn_blocking(move || -> CoreResult<Option<String>> {
            if let Some(branch) = read::branch_list(&repo_path)?
                .into_iter()
                .find(|branch| branch.name == name)
            {
                return Ok(Some(branch.tip.id));
            }
            let tag = read::tag_list(&repo_path)?
                .into_iter()
                .find(|tag| tag.name == name);
            Ok(tag.map(|tag| tag.commit_id))
        })
        .await
        .map_err(|err| CoreError::Internal(err.to_string()))??;
        let Some(sha) = sha else {
            return Err(CoreError::NotFound);
        };
        self.combined_fold(viewer, owner, repo, &sha).await
    }

    /// Visibility plus the `combined_state` fold shared by [`Core::combined_status`]
    /// and [`Core::combined_status_for_ref`].
    async fn combined_fold(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
        sha: &str,
    ) -> CoreResult<CombinedDto> {
        let access = self.repo_for(viewer, owner, repo).await?;
        let rows = db_checks::latest_statuses(self.db(), access.repo.id, sha).await?;
        let state = db_checks::combined_state(&rows).await;
        let mut statuses = Vec::new();
        for row in rows {
            statuses.push(status_dto(self, row).await?);
        }
        Ok(CombinedDto {
            sha: sha.to_owned(),
            state: state.to_owned(),
            statuses,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::validate_context;

    #[test]
    fn context_rejects_interior_control_characters() {
        for context in ["ci/\nunit", "ci\tlint", "ci\ru", "ci\u{7f}unit"] {
            let err = validate_context(context).unwrap_err().to_string();
            assert_eq!(
                err, "context must not contain control characters",
                "{context:?}"
            );
        }
    }

    #[test]
    fn context_accepts_normal_names_with_punctuation() {
        for context in [
            "ci/unit",
            "ci/unit:linux-x86_64",
            "lint.ok",
            "a-b_c.d:e/f",
            &"c".repeat(255),
        ] {
            assert!(validate_context(context).is_ok(), "{context:?} must pass");
        }
        assert!(validate_context("").is_err());
        assert!(validate_context(&"c".repeat(256)).is_err());
    }
}
