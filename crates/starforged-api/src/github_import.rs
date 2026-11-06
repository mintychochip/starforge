//! The GitHub metadata import endpoints (M4c G3, spec §8.6):
//! `POST /repos/{owner}/{repo}/import/github` starts an import and
//! `GET /repos/{owner}/{repo}/import/github` reports its status.
//!
//! The GitHub token is accepted only in the request body. It is sealed
//! server-side by [`Core::start_github_import`], deleted when the import
//! finishes or fails, and never echoed: the status JSON carries counts,
//! progress, and the scrubbed error, but no token field at all.

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use starforged_core::github::status::GithubImportView;
use starforged_core::tokens::Scope;

#[derive(Deserialize)]
pub struct StartGithubImportBody {
    /// The GitHub repository, `"owner/repo"` (`slug` is accepted as an alias).
    #[serde(default, alias = "slug")]
    pub repository: String,
    /// The read-only GitHub token. Write-only: never stored in clear,
    /// never logged, never rendered back.
    pub token: String,
}

#[derive(Serialize)]
pub struct GithubImportJson {
    pub id: i64,
    pub repo_id: i64,
    pub source: String,
    pub state: String,
    pub cursor_kind: String,
    pub cursor_page: i64,
    pub cursor_number: Option<i64>,
    pub issues_count: i64,
    pub pulls_count: i64,
    pub comments_count: i64,
    pub reviews_count: i64,
    pub review_comments_count: i64,
    pub dropped_assignees: Vec<String>,
    pub has_token: bool,
    pub error: Option<String>,
    pub failures: i64,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

fn import_json(row: &GithubImportView) -> GithubImportJson {
    GithubImportJson {
        id: row.id,
        repo_id: row.repo_id,
        source: row.source.clone(),
        state: row.state.clone(),
        cursor_kind: row.cursor_kind.clone(),
        cursor_page: row.cursor_page,
        cursor_number: row.cursor_number,
        issues_count: row.issues_count,
        pulls_count: row.pulls_count,
        comments_count: row.comments_count,
        reviews_count: row.reviews_count,
        review_comments_count: row.review_comments_count,
        dropped_assignees: row
            .dropped_assignees
            .split(';')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        has_token: row.has_token,
        error: row.error.clone(),
        failures: row.failures,
        started_at: row.started_at,
        finished_at: row.finished_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// `POST /repos/{owner}/{repo}/import/github` with
/// `{"repository": "octo/proj", "token": "…"}`: starts the import.
///
/// Repository admin only, enforced in core (`Forbidden` below admin,
/// `NotFound` for non-readers); archived repositories and repositories
/// that already have Trails answer `422`. The token is sealed at once
/// and never appears in the response.
pub async fn start_github_import(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    Json(body): Json<StartGithubImportBody>,
) -> Result<(StatusCode, Json<GithubImportJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let row = state
        .core
        .start_github_import(&auth.user, &owner, &repo, &body.repository, &body.token)
        .await?;
    let view = GithubImportView::from(&row);
    Ok((StatusCode::ACCEPTED, Json(import_json(&view))))
}

/// `GET /repos/{owner}/{repo}/import/github`: the import status for
/// readers (mirroring `GET …/import`); `404` when no import exists or
/// the caller cannot read the repository.
pub async fn get_github_import(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<GithubImportJson>, ApiError> {
    let Some(row) = state
        .core
        .github_import_for(auth.reader()?, &owner, &repo)
        .await?
    else {
        return Err(ApiError::NotFound);
    };
    Ok(Json(import_json(&row)))
}
