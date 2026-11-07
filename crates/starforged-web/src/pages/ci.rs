//! CI run pages (plan M6c C4): the run list and run detail for
//! `/{owner}/{repo}/ci`, plus the run `[logs]` sub-page and the cancel
//! form. Every field the runner or the repository can influence (job name,
//! commit, log bytes, artifact names) renders through askama's escaping;
//! logs are runner-supplied text and are never marked safe. Reads need
//! `Read` on the repository (Core enforces it, so a private repository
//! answers 404 anonymously); cancel needs `Write` (Core enforces it).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use starforged_core::CoreError;
use starforged_core::ci::{ArtifactView, CiRunView};
use starforged_core::permission::Permission;

use crate::AppState;
use crate::auth::{CsrfForm, MaybeUser, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};

/// One run row for the list: the commit is linked to its page, the job
/// name is plain (escaped) text.
pub struct RunRow {
    job_id: i64,
    commit_sha: String,
    job_name: String,
    state: String,
    created_at: String,
    finished_at: Option<String>,
}

fn run_row(run: CiRunView) -> RunRow {
    RunRow {
        job_id: run.job_id,
        commit_sha: run.commit_sha,
        job_name: run.job_name,
        state: run.state,
        created_at: crate::views::format_time(run.created_at),
        finished_at: run.finished_at.map(crate::views::format_time),
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "ci_runs.html")]
pub struct RunsPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    runs: Vec<RunRow>,
}

/// `/{owner}/{repo}/ci`: the repository's CI runs, newest first (Core caps
/// the list). Anonymous readers see public repositories only (Core `Read`).
pub async fn runs(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<RunsPage, WebError> {
    let viewer = session.as_ref().map(|s| &s.user);
    let rows = state.core.list_ci_runs(viewer, &owner, &repo, 50).await?;
    let access = state.core.repo_for(viewer, &owner, &repo).await?;
    Ok(RunsPage {
        nav_user: session.as_ref().map(NavUser::from_session),
        head: RepoHead::new(&access, "ci", None),
        runs: rows.into_iter().map(run_row).collect(),
    })
}

/// One artifact row for the run detail: metadata only (no filesystem path;
/// downloads go through the API's artifact-token path).
pub struct ArtifactRow {
    name: String,
    size: i64,
    blake3: String,
    sha256: Option<String>,
    expires_at: String,
}

fn artifact_row(artifact: ArtifactView) -> ArtifactRow {
    ArtifactRow {
        name: artifact.name,
        size: artifact.size,
        blake3: artifact.blake3,
        sha256: artifact.sha256,
        expires_at: crate::views::format_time(artifact.expires_at),
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "ci_run.html")]
pub struct RunPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    csrf: String,
    run: RunRow,
    artifacts: Vec<ArtifactRow>,
    sessions: Vec<String>,
    logs: String,
    logs_href: String,
    gate_href: String,
    can_cancel: bool,
}

/// `/{owner}/{repo}/ci/{id}`: run detail — state, commit, logs (escaped),
/// artifacts, sessions, the gate panel link, and the cancel form (Write+).
pub async fn run(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<RunPage, WebError> {
    let viewer = session.as_ref().map(|s| &s.user);
    let detail = state.core.get_ci_run(viewer, &owner, &repo, id).await?;
    let logs = state
        .core
        .get_ci_job_logs(viewer, &owner, &repo, id)
        .await?;
    let access = state.core.repo_for(viewer, &owner, &repo).await?;
    let can_cancel = access.permission >= Permission::Write
        && !matches!(
            detail.run.state.as_str(),
            "succeeded" | "failed" | "error" | "canceled"
        );
    Ok(RunPage {
        nav_user: session.as_ref().map(NavUser::from_session),
        head: RepoHead::new(&access, "ci", None),
        csrf: session
            .as_ref()
            .map(|s| s.csrf_token.clone())
            .unwrap_or_default(),
        run: run_row(detail.run),
        artifacts: detail.artifacts.into_iter().map(artifact_row).collect(),
        sessions: detail.sessions,
        logs,
        logs_href: format!("/{owner}/{repo}/ci/{id}/logs"),
        gate_href: format!("/{owner}/{repo}/settings/protection"),
        can_cancel,
    })
}

/// `/{owner}/{repo}/ci/{id}/logs`: the full log text. It is
/// runner-supplied, so it is served `no-store` (never cached) and the
/// caller needs `Read` (enforced by Core).
pub async fn logs(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<Response, WebError> {
    let viewer = session.as_ref().map(|s| &s.user);
    let logs = state
        .core
        .get_ci_job_logs(viewer, &owner, &repo, id)
        .await?;
    let mut response = (StatusCode::OK, logs).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("Cookie, Authorization"),
    );
    Ok(response)
}

/// `POST /{owner}/{repo}/ci/{id}/cancel`: requests the cancellation (the
/// runner observes it on its next trace/finish and cancel wins). Success
/// redirects to the run detail; a job of another repository answers 404.
pub async fn cancel(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .cancel_ci_job(&session.user, &owner, &repo, id)
        .await
    {
        Ok(()) => Ok(Redirect::to(&format!("/{owner}/{repo}/ci/{id}")).into_response()),
        Err(CoreError::NotFound) => Err(WebError::NotFound),
        Err(other) => Err(other.into()),
    }
}
