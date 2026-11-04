use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::permission::Permission;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};

#[derive(Deserialize)]
pub struct AddForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    handle: String,
    permission: String,
}

pub struct CollaboratorRow {
    handle: String,
    permission: &'static str,
}

#[derive(Template, WebTemplate)]
#[template(path = "collaborators.html")]
pub struct CollaboratorsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    collaborators: Vec<CollaboratorRow>,
    permission_choices: Vec<&'static str>,
    error: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<CollaboratorsPage, WebError> {
    page(&state, &session, &owner, &repo, None).await
}

pub async fn add(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<AddForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let permission = Permission::parse(&form.permission)
        .ok_or_else(|| WebError::BadRequest("unknown permission".into()))?;
    match state
        .core
        .set_collaborator(&session.user, &owner, &repo, &form.handle, permission)
        .await
    {
        Ok(()) => Ok(
            Redirect::to(&settings_path(&state, &session, &owner, &repo).await?).into_response(),
        ),
        Err(CoreError::Invalid(message)) => {
            let page = page(&state, &session, &owner, &repo, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn remove(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, handle)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .remove_collaborator(&session.user, &owner, &repo, &handle)
        .await?;
    Ok(Redirect::to(&settings_path(&state, &session, &owner, &repo).await?).into_response())
}

/// The settings URL built from the repository's stored names (never from raw path input).
async fn settings_path(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
) -> Result<String, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), owner, repo)
        .await?;
    Ok(format!(
        "/{}/{}/settings/collaborators",
        access.repo.owner, access.repo.name
    ))
}

async fn page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
) -> Result<CollaboratorsPage, WebError> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Admin)
        .await?;
    let collaborators = state
        .core
        .collaborators(&session.user, owner, repo)
        .await?
        .into_iter()
        .map(|c| CollaboratorRow {
            handle: c.handle,
            permission: c.permission.as_str(),
        })
        .collect();
    Ok(CollaboratorsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "collaborators",
        collaborators,
        permission_choices: Permission::ALL
            .into_iter()
            .map(Permission::as_str)
            .collect(),
        error,
    })
}
