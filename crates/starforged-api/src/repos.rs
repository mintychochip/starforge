use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::{CreateRepo, RepoAccess};
use starforged_core::tokens::Scope;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;

#[derive(Serialize)]
pub(crate) struct RepoJson {
    pub(crate) id: i64,
    pub(crate) owner: String,
    pub(crate) name: String,
    pub(crate) full_name: String,
    pub(crate) description: String,
    pub(crate) visibility: &'static str,
    pub(crate) default_branch: String,
    pub(crate) archived: bool,
    pub(crate) clone_url: String,
    pub(crate) permission: &'static str,
    pub(crate) import_state: String,
    pub(crate) mirror: bool,
    pub(crate) ssh_public_key: Option<String>,
    pub(crate) created_at: i64,
}

pub(crate) fn repo_json(state: &ApiState, access: RepoAccess) -> RepoJson {
    let repo = access.repo;
    RepoJson {
        clone_url: format!("{}/{}/{}.git", state.base_url, repo.owner, repo.name),
        full_name: repo.full_name(),
        id: repo.id,
        description: repo.description,
        visibility: repo.visibility.as_str(),
        default_branch: repo.default_branch,
        archived: repo.archived_at.is_some(),
        import_state: repo.import_state.clone(),
        mirror: repo.mirror,
        ssh_public_key: None,
        permission: access.permission.as_str(),
        created_at: repo.created_at,
        owner: repo.owner,
        name: repo.name,
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateRepoBody {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) description: String,
    #[serde(default = "private")]
    pub(crate) visibility: String,
    /// Commit a README as the first commit.
    #[serde(default)]
    pub(crate) readme: bool,
    #[serde(default)]
    pub(crate) import: Option<ImportBody>,
}

fn private() -> String {
    "private".to_owned()
}

/// The `import` half of a repository-creation body (M4b D3):
/// `{"url": ..., "auth": {"kind": "none|https|ssh", "username": ..., "password"|"token": ...}}`.
#[derive(Deserialize)]
pub(crate) struct ImportBody {
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) auth: Option<ImportAuthBody>,
}

/// The `auth` half of an import body. For `https` the username and
/// password/token travel here and are sealed server-side; for `ssh` the
/// server generates the keypair.
#[derive(Deserialize)]
pub(crate) struct ImportAuthBody {
    #[serde(default)]
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) username: String,
    #[serde(default)]
    pub(crate) password: String,
    #[serde(default)]
    pub(crate) token: String,
}

/// Parses an import `auth` object into the core value; anything else is
/// 422. Shared by repository creation and import start/retry.
pub(crate) fn parse_import_auth(
    auth: Option<ImportAuthBody>,
) -> Result<starforged_core::remotes::ImportAuth, ApiError> {
    let Some(auth) = auth else {
        return Ok(starforged_core::remotes::ImportAuth::None);
    };
    let password = if auth.password.is_empty() {
        auth.token
    } else {
        auth.password
    };
    match auth.kind.as_str() {
        "" | "none" => Ok(starforged_core::remotes::ImportAuth::None),
        "https" => {
            if auth.username.trim().is_empty() || password.is_empty() {
                return Err(ApiError::Invalid(
                    "https import requires a username and a password or token".into(),
                ));
            }
            Ok(starforged_core::remotes::ImportAuth::Https {
                username: auth.username,
                password,
            })
        }
        "ssh" => Ok(starforged_core::remotes::ImportAuth::Ssh),
        other => Err(ApiError::Invalid(format!(
            "import auth kind `{other}` is not supported"
        ))),
    }
}

/// Parses a creation body's `import` object, if present.
pub(crate) fn parse_import(
    import: Option<ImportBody>,
) -> Result<Option<starforged_core::remotes::ImportInput>, ApiError> {
    let Some(import) = import else {
        return Ok(None);
    };
    if import.url.trim().is_empty() {
        return Err(ApiError::Invalid("import url is empty".into()));
    }
    Ok(Some(starforged_core::remotes::ImportInput {
        url: import.url,
        auth: parse_import_auth(import.auth)?,
    }))
}

pub async fn create(
    State(state): State<ApiState>,
    auth: ApiAuth,
    body: Result<Json<CreateRepoBody>, JsonRejection>,
) -> Result<(StatusCode, Json<RepoJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let visibility = Visibility::parse(&body.visibility).ok_or_else(|| {
        ApiError::Invalid("visibility must be public, internal, or private".into())
    })?;
    let import = parse_import(body.import)?;
    let repo = state
        .core
        .create_repo_with_import(
            &auth.user,
            &auth.user.handle,
            CreateRepo {
                name: body.name,
                description: body.description,
                visibility,
                readme: body.readme,
            },
            import,
        )
        .await?;
    let mut json = repo_json(
        &state,
        RepoAccess {
            repo,
            permission: Permission::Admin,
        },
    );
    if let Some(view) = state.core.import_for(json.id).await? {
        json.ssh_public_key = view.ssh_public_key;
    }
    Ok((StatusCode::CREATED, Json(json)))
}

pub async fn show(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<RepoJson>, ApiError> {
    let access = state.core.repo_for(auth.reader()?, &owner, &repo).await?;
    Ok(Json(repo_json(&state, access)))
}

#[derive(Serialize)]
pub struct CollaboratorJson {
    handle: String,
    permission: &'static str,
}

pub async fn list_collaborators(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<CollaboratorJson>>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let collaborators = state.core.collaborators(&auth.user, &owner, &repo).await?;
    Ok(Json(
        collaborators
            .into_iter()
            .map(|c| CollaboratorJson {
                handle: c.handle,
                permission: c.permission.as_str(),
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct SetCollaboratorBody {
    permission: String,
}

pub async fn set_collaborator(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, handle)): Path<(String, String, String)>,
    body: Result<Json<SetCollaboratorBody>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let permission = Permission::parse(&body.permission).ok_or_else(|| {
        ApiError::Invalid("permission must be read, triage, write, maintain, or admin".into())
    })?;
    state
        .core
        .set_collaborator(&auth.user, &owner, &repo, &handle, permission)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_collaborator(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, handle)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .remove_collaborator(&auth.user, &owner, &repo, &handle)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
#[derive(Deserialize)]
pub struct PatchRepoBody {
    pub refs_for_access: Option<String>,
}

/// `PATCH /repos/{owner}/{repo}` (`{"refs_for_access": …}`): flips the
/// `refs/for` push policy between `anyone_with_read` and `members`.
/// Maintain+ via the repo-settings power; anything else in the body is 422.
pub async fn patch(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<PatchRepoBody>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let Some(value) = body.refs_for_access else {
        return Err(ApiError::Invalid("refs_for_access is required".into()));
    };
    let value = state
        .core
        .set_refs_for_access(&auth.user, &owner, &repo, &value)
        .await?;
    Ok(Json(serde_json::json!({ "refs_for_access": value })))
}

#[derive(Deserialize)]
pub struct TransferRepoBody {
    new_owner: String,
}

/// `POST /repos/{owner}/{repo}/transfer` (`{"new_owner": "<handle>"}`):
/// moves the repository to the actor or to an org the actor owns (D6).
/// Anything else in the body is 422.
pub async fn transfer(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<TransferRepoBody>, JsonRejection>,
) -> Result<Json<RepoJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    if body.new_owner.trim().is_empty() {
        return Err(ApiError::Invalid("new_owner is required".into()));
    }
    let moved = state
        .core
        .transfer_repo(&auth.user, &owner, &repo, &body.new_owner)
        .await?;
    Ok(Json(repo_json(
        &state,
        RepoAccess {
            repo: moved,
            permission: Permission::Admin,
        },
    )))
}

/// What the API shows for a repository's import source: never a secret,
/// only `has_credentials` and, for SSH, the public key.
#[derive(Serialize)]
pub struct ImportJson {
    repo_id: i64,
    state: String,
    url: String,
    auth: String,
    has_credentials: bool,
    ssh_public_key: Option<String>,
    last_error: String,
}

fn import_json(view: starforged_core::remotes::ImportView) -> ImportJson {
    ImportJson {
        repo_id: view.repo_id,
        state: view.state,
        url: view.url,
        auth: view.auth,
        has_credentials: view.has_credentials,
        ssh_public_key: view.ssh_public_key,
        last_error: view.last_error,
    }
}

/// `GET /repos/{owner}/{repo}/import`: readers see the import state;
/// anyone who cannot read gets 404 (via `repo_for`).
pub async fn get_import(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<ImportJson>, ApiError> {
    let access = state.core.repo_for(auth.reader()?, &owner, &repo).await?;
    let Some(view) = state.core.import_for(access.repo.id).await? else {
        return Err(ApiError::NotFound);
    };
    Ok(Json(import_json(view)))
}

#[derive(Deserialize)]
pub struct StartImportBody {
    #[serde(default)]
    pub auth: Option<ImportAuthBody>,
}

/// `POST /repos/{owner}/{repo}/import/start`: "start import" and retry.
/// The optional body replaces the stored credentials (the "fix
/// credentials" retry); without it they run unchanged.
pub async fn start_import(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Option<Json<StartImportBody>>,
) -> Result<Json<ImportJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let new_auth = match body {
        Some(Json(parsed)) => match parsed.auth {
            Some(a) => Some(parse_import_auth(Some(a))?),
            None => None,
        },
        None => None,
    };
    let view = state
        .core
        .start_import(&auth.user, &owner, &repo, new_auth)
        .await?;
    Ok(Json(import_json(view)))
}

/// `DELETE /repos/{owner}/{repo}/import`: deletes the import source,
/// returning the repository to a normal empty one.
pub async fn delete_import(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state.core.delete_import(&auth.user, &owner, &repo).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// What the API shows for a pull mirror: never a secret, only
/// and, for SSH, the public key (mirroring the import shape).
#[derive(Serialize)]
pub struct PullMirrorJson {
    repo_id: i64,
    url: String,
    auth: String,
    has_credentials: bool,
    ssh_public_key: Option<String>,
    interval_secs: i64,
    enabled: bool,
    last_attempt_at: Option<i64>,
    last_success_at: Option<i64>,
    last_error: String,
}

fn pull_mirror_json(view: starforged_core::remotes::PullMirrorView) -> PullMirrorJson {
    PullMirrorJson {
        repo_id: view.repo_id,
        url: view.url,
        auth: view.auth,
        has_credentials: view.has_credentials,
        ssh_public_key: view.ssh_public_key,
        interval_secs: view.interval_secs,
        enabled: view.enabled,
        last_attempt_at: view.last_attempt_at,
        last_success_at: view.last_success_at,
        last_error: view.last_error,
    }
}

#[derive(Deserialize)]
pub struct PullMirrorBody {
    pub url: String,
    #[serde(default)]
    pub auth: Option<ImportAuthBody>,
    #[serde(default = "default_interval")]
    pub interval_secs: i64,
}

fn default_interval() -> i64 {
    3600
}

/// `PUT /repos/{owner}/{repo}/mirror/pull` (M4b D4): configure or update
/// the pull mirror. Maintain+ (enforced in core); the URL policy runs at
/// save time and again before every fetch. 422 for a policy refusal or an
/// interval below 300 seconds.
pub async fn put_pull_mirror(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<PullMirrorBody>, JsonRejection>,
) -> Result<Json<PullMirrorJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    if body.url.trim().is_empty() {
        return Err(ApiError::Invalid("mirror url is empty".into()));
    }
    let view = state
        .core
        .set_pull_mirror(
            &auth.user,
            &owner,
            &repo,
            &starforged_core::remotes::PullMirrorInput {
                url: body.url,
                auth: parse_import_auth(body.auth)?,
                interval_secs: body.interval_secs,
            },
        )
        .await?;
    Ok(Json(pull_mirror_json(view)))
}

/// `GET /repos/{owner}/{repo}/mirror/pull`: readers see the configuration.
pub async fn get_pull_mirror(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<PullMirrorJson>, ApiError> {
    let view = state
        .core
        .get_pull_mirror(auth.reader()?, &owner, &repo)
        .await?;
    Ok(Json(pull_mirror_json(view)))
}

/// `DELETE /repos/{owner}/{repo}/mirror/pull`: deletes the mirror;
/// pushes are restored.
pub async fn delete_pull_mirror(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .delete_pull_mirror(&auth.user, &owner, &repo)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /repos/{owner}/{repo}/mirror/pull/sync`: queues an immediate
/// sync (deduplicated per repository).
pub async fn sync_pull_mirror(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<PullMirrorJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let view = state
        .core
        .sync_pull_mirror(&auth.user, &owner, &repo)
        .await?;
    Ok(Json(pull_mirror_json(view)))
}

/// `POST /repos/{owner}/{repo}/mirror/pull/enabled` (`{"enabled": bool}`):
/// toggles the mirror without forgetting its configuration.
pub async fn set_pull_mirror_enabled(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<EnableBody>, JsonRejection>,
) -> Result<Json<PullMirrorJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let view = state
        .core
        .set_pull_mirror_enabled(&auth.user, &owner, &repo, body.enabled)
        .await?;
    Ok(Json(pull_mirror_json(view)))
}

#[derive(Deserialize)]
pub struct EnableBody {
    enabled: bool,
}
