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

#[derive(Serialize, utoipa::ToSchema)]
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

#[derive(Deserialize, utoipa::ToSchema)]
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
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct ImportBody {
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) auth: Option<ImportAuthBody>,
}

/// The `auth` half of an import body. For `https` the username and
/// password/token travel here and are sealed server-side; for `ssh` the
/// server generates the keypair.
#[derive(Deserialize, utoipa::ToSchema)]
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

#[utoipa::path(
    post,
    path = "/api/v1/user/repos",
    request_body = CreateRepoBody,
    responses(
        (status = 201, description = "Created repository", body = RepoJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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

#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Repository", body = RepoJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security((), ("bearer_auth" = [])),
)]

pub async fn show(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<RepoJson>, ApiError> {
    let access = state.core.repo_for(auth.reader()?, &owner, &repo).await?;
    Ok(Json(repo_json(&state, access)))
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct CollaboratorJson {
    handle: String,
    permission: &'static str,
}

#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/collaborators",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Collaborators", body = Vec<CollaboratorJson>),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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

#[derive(Deserialize, utoipa::ToSchema)]
pub struct SetCollaboratorBody {
    permission: String,
}

#[utoipa::path(
    put,
    path = "/api/v1/repos/{owner}/{repo}/collaborators/{handle}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("handle" = String, Path, description = "User handle"),
    ),
    request_body = SetCollaboratorBody,
    responses(
        (status = 204, description = "Collaborator set"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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

#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/collaborators/{handle}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("handle" = String, Path, description = "User handle"),
    ),
    responses(
        (status = 204, description = "Collaborator removed"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[derive(Deserialize, utoipa::ToSchema)]
pub struct PatchRepoBody {
    pub refs_for_access: Option<String>,
    /// Per-repo CI secret policy: resolve secrets for `refs/for` jobs.
    #[serde(default)]
    pub ci_allow_secrets_on_refs_for: Option<bool>,
    /// Per-repo CI secret policy: deliver secrets as env vars on E2B.
    #[serde(default)]
    pub ci_env_secrets: Option<bool>,
}

/// `PATCH /repos/{owner}/{repo}` (`{"refs_for_access": …}`): flips the
/// `anyone_with_read` and `members`, and/or the per-repo CI secret policy
/// (`ci_allow_secrets_on_refs_for`, `ci_env_secrets`; Admin).
/// Maintain+ via the repo-settings power for `refs_for_access`; Admin for
/// the CI secret policy. At least one field is required; anything else in
/// the body is 422.
#[utoipa::path(
    patch,
    path = "/api/v1/repos/{owner}/{repo}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = PatchRepoBody,
    responses(
        (status = 200, description = "Updated repository settings", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn patch(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<PatchRepoBody>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    if body.refs_for_access.is_none()
        && body.ci_allow_secrets_on_refs_for.is_none()
        && body.ci_env_secrets.is_none()
    {
        return Err(ApiError::Invalid(
            "at least one of refs_for_access, ci_allow_secrets_on_refs_for, ci_env_secrets is required"
                .into(),
        ));
    }
    let mut out = serde_json::Map::new();
    // The CI policy needs Admin, the stricter check: apply it first so a
    // Maintain caller that sends both fields cannot change `refs_for_access`
    // and then be refused.
    if body.ci_allow_secrets_on_refs_for.is_some() || body.ci_env_secrets.is_some() {
        let (allow_refs_for, env_secrets) = state
            .core
            .set_ci_secret_policy(
                &auth.user,
                &owner,
                &repo,
                body.ci_allow_secrets_on_refs_for,
                body.ci_env_secrets,
            )
            .await?;
        if body.ci_allow_secrets_on_refs_for.is_some() {
            out.insert(
                "ci_allow_secrets_on_refs_for".to_owned(),
                serde_json::Value::Bool(allow_refs_for),
            );
        }
        if body.ci_env_secrets.is_some() {
            out.insert(
                "ci_env_secrets".to_owned(),
                serde_json::Value::Bool(env_secrets),
            );
        }
    }
    if let Some(value) = body.refs_for_access.clone() {
        let value = state
            .core
            .set_refs_for_access(&auth.user, &owner, &repo, &value)
            .await?;
        out.insert(
            "refs_for_access".to_owned(),
            serde_json::Value::String(value),
        );
    }
    Ok(Json(serde_json::Value::Object(out)))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct TransferRepoBody {
    new_owner: String,
}

/// `POST /repos/{owner}/{repo}/transfer` (`{"new_owner": "<handle>"}`):
/// moves the repository to the actor or to an org the actor owns (D6).
/// Anything else in the body is 422.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/transfer",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = TransferRepoBody,
    responses(
        (status = 200, description = "Repository transferred", body = RepoJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[derive(Serialize, utoipa::ToSchema)]
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
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/import",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Import status", body = ImportJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security((), ("bearer_auth" = [])),
)]

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

#[derive(Deserialize, utoipa::ToSchema)]
pub struct StartImportBody {
    #[serde(default)]
    pub auth: Option<ImportAuthBody>,
}

/// `POST /repos/{owner}/{repo}/import/start`: "start import" and retry.
/// The optional body replaces the stored credentials (the "fix
/// credentials" retry); without it they run unchanged.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/import/start",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = StartImportBody,
    responses(
        (status = 200, description = "Import started", body = ImportJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/import",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 204, description = "Import deleted"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[derive(Serialize, utoipa::ToSchema)]
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

#[derive(Deserialize, utoipa::ToSchema)]
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
#[utoipa::path(
    put,
    path = "/api/v1/repos/{owner}/{repo}/mirror/pull",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = PullMirrorBody,
    responses(
        (status = 200, description = "Pull mirror configured", body = PullMirrorJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/mirror/pull",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Pull mirror", body = PullMirrorJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security((), ("bearer_auth" = [])),
)]

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
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/mirror/pull",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 204, description = "Pull mirror deleted"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/mirror/pull/sync",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Pull mirror sync queued", body = PullMirrorJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/mirror/pull/enabled",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = EnableBody,
    responses(
        (status = 200, description = "Pull mirror updated", body = PullMirrorJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

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

/// What the API shows for one push mirror: never a secret, only
/// `has_credentials` and, for SSH, the public key (mirroring the pull shape).
#[derive(Serialize, utoipa::ToSchema)]
pub struct PushMirrorJson {
    id: i64,
    repo_id: i64,
    url: String,
    auth: String,
    has_credentials: bool,
    ssh_public_key: Option<String>,
    enabled: bool,
    last_attempt_at: Option<i64>,
    last_success_at: Option<i64>,
    last_error: String,
}

fn push_mirror_json(view: starforged_core::remotes::PushMirrorView) -> PushMirrorJson {
    PushMirrorJson {
        id: view.id,
        repo_id: view.repo_id,
        url: view.url,
        auth: view.auth,
        has_credentials: view.has_credentials,
        ssh_public_key: view.ssh_public_key,
        enabled: view.enabled,
        last_attempt_at: view.last_attempt_at,
        last_success_at: view.last_success_at,
        last_error: view.last_error,
    }
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct PushMirrorBody {
    pub url: String,
    #[serde(default)]
    pub auth: Option<ImportAuthBody>,
}

/// `POST /repos/{owner}/{repo}/mirror/push` (M4b D5): adds one push mirror
/// (at most 10 per repository). Maintain+ (enforced in core); the URL
/// policy runs at save time and again before every push. 422 for a policy
/// refusal or a full mirror list.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/mirror/push",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = PushMirrorBody,
    responses(
        (status = 201, description = "Push mirror added", body = PushMirrorJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn add_push_mirror(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<PushMirrorBody>, JsonRejection>,
) -> Result<(StatusCode, Json<PushMirrorJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    if body.url.trim().is_empty() {
        return Err(ApiError::Invalid("mirror url is empty".into()));
    }
    let view = state
        .core
        .add_push_mirror(
            &auth.user,
            &owner,
            &repo,
            &starforged_core::remotes::PushMirrorInput {
                url: body.url,
                auth: parse_import_auth(body.auth)?,
            },
        )
        .await?;
    Ok((StatusCode::CREATED, Json(push_mirror_json(view))))
}

/// `GET /repos/{owner}/{repo}/mirror/push`: readers see the push mirrors
/// with their last result and (scrubbed) error.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/mirror/push",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Push mirrors", body = Vec<PushMirrorJson>),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security((), ("bearer_auth" = [])),
)]

pub async fn list_push_mirrors(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Vec<PushMirrorJson>>, ApiError> {
    let views = state
        .core
        .list_push_mirrors(auth.reader()?, &owner, &repo)
        .await?;
    Ok(Json(views.into_iter().map(push_mirror_json).collect()))
}

/// `DELETE /repos/{owner}/{repo}/mirror/push/{id}`: deletes one push
/// mirror. Maintain+ (enforced in core).
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/mirror/push/{id}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("id" = i64, Path, description = "Push mirror id"),
    ),
    responses(
        (status = 204, description = "Push mirror deleted"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn delete_push_mirror(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .delete_push_mirror(&auth.user, &owner, &repo, id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /repos/{owner}/{repo}/mirror/push/{id}/sync`: queues an immediate
/// run (deduplicated per remote).
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/mirror/push/{id}/sync",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("id" = i64, Path, description = "Push mirror id"),
    ),
    responses(
        (status = 200, description = "Push mirror sync queued", body = PushMirrorJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]

pub async fn sync_push_mirror(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, id)): Path<(String, String, i64)>,
) -> Result<Json<PushMirrorJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let view = state
        .core
        .sync_push_mirror(&auth.user, &owner, &repo, id)
        .await?;
    Ok(Json(push_mirror_json(view)))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct EnableBody {
    enabled: bool,
}
