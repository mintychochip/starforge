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
use crate::views::{NavUser, RepoHead, format_time};

#[derive(Deserialize)]
pub struct AddKeyForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    title: String,
    key: String,
}

#[derive(Deserialize)]
pub struct AddDeployKeyForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    title: String,
    key: String,
    #[serde(default)]
    read_write: Option<String>,
}

pub struct KeyRow {
    id: i64,
    title: String,
    fingerprint: String,
    created: String,
    last_used: String,
}

pub struct DeployKeyRow {
    id: i64,
    title: String,
    fingerprint: String,
    access: &'static str,
    created: String,
    last_used: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "sshkeys.html")]
pub struct SshKeysPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    keys: Vec<KeyRow>,
    error: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "deploy_keys.html")]
pub struct DeployKeysPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    keys: Vec<DeployKeyRow>,
    error: Option<String>,
}

pub async fn user_list(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<SshKeysPage, WebError> {
    page(&state, &session, None).await
}

pub async fn user_add(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<AddKeyForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .add_ssh_key(&session.user, &form.title, &form.key)
        .await
    {
        Ok(_) => Ok(Redirect::to("/settings/keys").into_response()),
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            page(&state, &session, Some(message)).await?,
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

pub async fn user_remove(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state.core.remove_ssh_key(&session.user, id).await?;
    Ok(Redirect::to("/settings/keys").into_response())
}

async fn page(
    state: &AppState,
    session: &WebSession,
    error: Option<String>,
) -> Result<SshKeysPage, WebError> {
    let keys = state
        .core
        .ssh_keys(&session.user)
        .await?
        .into_iter()
        .map(|k| KeyRow {
            id: k.id,
            title: k.title,
            fingerprint: k.fingerprint,
            created: format_time(k.created_at),
            last_used: k
                .last_used_at
                .map(format_time)
                .unwrap_or_else(|| "never".into()),
        })
        .collect();
    Ok(SshKeysPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "keys",
        keys,
        error,
    })
}

pub async fn deploy_list(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<DeployKeysPage, WebError> {
    deploy_page(&state, &session, &owner, &repo, None).await
}

pub async fn deploy_add(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<AddDeployKeyForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let read_write = form.read_write.is_some();
    match state
        .core
        .add_deploy_key(
            &session.user,
            &owner,
            &repo,
            &form.title,
            &form.key,
            read_write,
        )
        .await
    {
        Ok(_) => {
            Ok(Redirect::to(&deploy_path(&state, &session, &owner, &repo).await?).into_response())
        }
        Err(CoreError::Invalid(message)) => {
            let page = deploy_page(&state, &session, &owner, &repo, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn deploy_remove(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .remove_deploy_key(&session.user, &owner, &repo, id)
        .await?;
    Ok(Redirect::to(&deploy_path(&state, &session, &owner, &repo).await?).into_response())
}

async fn deploy_path(
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
        "/{}/{}/settings/keys",
        access.repo.owner, access.repo.name
    ))
}

async fn deploy_page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
) -> Result<DeployKeysPage, WebError> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Admin)
        .await?;
    let keys = state
        .core
        .deploy_keys(&session.user, owner, repo)
        .await?
        .into_iter()
        .map(|k| DeployKeyRow {
            id: k.id,
            title: k.title,
            fingerprint: k.fingerprint,
            access: if k.read_write {
                "read-write"
            } else {
                "read-only"
            },
            created: format_time(k.created_at),
            last_used: k
                .last_used_at
                .map(format_time)
                .unwrap_or_else(|| "never".into()),
        })
        .collect();
    Ok(DeployKeysPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "keys",
        keys,
        error,
    })
}
