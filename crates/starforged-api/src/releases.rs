//! Release and archive routes (Phase 3):
//! `GET /repos/{owner}/{repo}/archive/{*rest}` and the
//! `/repos/{owner}/{repo}/releases…` + `/release-assets…` family.
//!
//! Handlers authenticate and delegate; all permission, validation,
//! tag creation, and asset storage logic lives on [`Core`]. Reads need
//! repository read access (non-readers surface as `404`); mutations need
//! `Scope::RepoWrite` and ≥ write permission in `Core`. Timestamps render
//! as RFC 3339 (`…Z`).
//!
//! Asset uploads carry raw bytes like the CI artifact upload: the body is
//! capped at `MAX_ASSET_BYTES` (413 over it) and the `Content-Type` header
//! is stored with the asset. Downloads return the bytes with
//! `Content-Disposition: attachment`.

use axum::Json;
use axum::body::Body;
use axum::extract::Path;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starforged_core::content::ArchiveFormat;
use starforged_core::releases::{AssetView, ReleaseEdit, ReleaseInput, ReleaseView};
use starforged_core::tokens::Scope;
use tokio::io::AsyncReadExt;

use crate::ApiState;
use crate::auth::ApiAuth;
use crate::error::ApiError;
use crate::time::{opt_ts, rfc3339};

fn asset_url(base_url: &str, owner: &str, repo: &str, tag: &str, name: &str) -> String {
    format!("{base_url}/api/v1/repos/{owner}/{repo}/release-assets/{tag}/{name}")
}

fn asset_json(state: &ApiState, owner: &str, repo: &str, tag: &str, view: &AssetView) -> AssetJson {
    AssetJson {
        id: view.id,
        name: view.name.clone(),
        size: view.size,
        content_type: view.content_type.clone(),
        created_at: rfc3339(view.created_at),
        download_url: asset_url(&state.base_url, owner, repo, tag, &view.name),
    }
}

fn release_json(state: &ApiState, owner: &str, repo: &str, view: &ReleaseView) -> ReleaseJson {
    ReleaseJson {
        id: view.id,
        tag: view.tag.clone(),
        title: view.title.clone(),
        notes: view.notes.clone(),
        draft: view.draft,
        prerelease: view.prerelease,
        commit_id: view.commit_id.clone(),
        author: view.author.clone(),
        created_at: rfc3339(view.created_at),
        published_at: opt_ts(view.published_at),
        assets: view
            .assets
            .iter()
            .map(|a| asset_json(state, owner, repo, &view.tag, a))
            .collect(),
    }
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct AssetJson {
    pub id: i64,
    pub name: String,
    pub size: i64,
    pub content_type: String,
    pub created_at: String,
    pub download_url: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ReleaseJson {
    pub id: i64,
    pub tag: String,
    pub title: String,
    pub notes: String,
    pub draft: bool,
    pub prerelease: bool,
    pub commit_id: String,
    pub author: Option<String>,
    pub created_at: String,
    pub published_at: Option<String>,
    pub assets: Vec<AssetJson>,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateReleaseBody {
    pub tag: String,
    pub target: Option<String>,
    pub title: String,
    pub notes: String,
    pub draft: bool,
    pub prerelease: bool,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchReleaseBody {
    pub title: Option<String>,
    pub notes: Option<String>,
    pub draft: Option<bool>,
    pub prerelease: Option<bool>,
}

/// Splits `{tag}/{asset name}` at the LAST `/`: tags may contain `/`, asset
/// names may not.
fn split_tag_asset(rest: &str) -> Result<(&str, &str), ApiError> {
    rest.rsplit_once('/')
        .filter(|(tag, name)| !tag.is_empty() && !name.is_empty())
        .ok_or(ApiError::NotFound)
}

/// `GET /repos/{owner}/{repo}/archive/{*rest}` (200): a zip or tar.gz of
/// the tree at the branch, tag, or commit named before the extension.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/archive/{*rest}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("rest" = String, Path, description = "Revision followed by `.zip` or `.tar.gz`"),
    ),
    responses(
        (status = 200, description = "Archive bytes"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security((), ("bearer_auth" = [])),
)]
pub async fn download_archive(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let user = auth.reader()?;
    let Some((rev, format)) = ArchiveFormat::parse(&rest) else {
        return Err(ApiError::NotFound);
    };
    let access = state.core.repo_for(user, &owner, &repo).await?;
    let download = state.core.archive(&access, rev, format).await?;
    let mut stdout = download.stdout;
    let mut bytes = Vec::new();
    stdout
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| ApiError::Internal(format!("reading archive: {e}")))?;
    let mut response = axum::response::Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(download.content_type),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        header::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", download.filename))
            .map_err(|_| ApiError::Internal("bad filename".into()))?,
    );
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

/// `GET /repos/{owner}/{repo}/releases` (200): the repo's releases,
/// newest first. Drafts only for writers.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/releases",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    responses(
        (status = 200, description = "Releases", body = serde_json::Value),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security((), ("bearer_auth" = [])),
)]
pub async fn list_releases(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let views = state.core.releases(auth.reader()?, &owner, &repo).await?;
    Ok(Json(json!({
        "releases": views.iter().map(|v| release_json(&state, &owner, &repo, v)).collect::<Vec<_>>(),
    })))
}

/// `POST /repos/{owner}/{repo}/releases` (201): creates a release for a
/// tag, creating the lightweight tag from `target` when it is missing.
#[utoipa::path(
    post,
    path = "/api/v1/repos/{owner}/{repo}/releases",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
    ),
    request_body = CreateReleaseBody,
    responses(
        (status = 201, description = "Created release", body = ReleaseJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 409, description = "Conflict", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn create_release(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo)): Path<(String, String)>,
    body: Result<Json<CreateReleaseBody>, JsonRejection>,
) -> Result<(StatusCode, Json<ReleaseJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let input = ReleaseInput {
        tag: &body.tag,
        target: body.target.as_deref(),
        title: &body.title,
        notes: &body.notes,
        draft: body.draft,
        prerelease: body.prerelease,
    };
    let view = state
        .core
        .create_release(&auth.user, &owner, &repo, &input)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(release_json(&state, &owner, &repo, &view)),
    ))
}

/// `GET /repos/{owner}/{repo}/releases/{*tag}` (200): one release, with
/// its assets. Drafts are `404` below write permission.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/releases/{*tag}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("tag" = String, Path, description = "Release tag"),
    ),
    responses(
        (status = 200, description = "Release", body = ReleaseJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security((), ("bearer_auth" = [])),
)]
pub async fn get_release(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, tag)): Path<(String, String, String)>,
) -> Result<Json<ReleaseJson>, ApiError> {
    let view = state
        .core
        .release(auth.reader()?, &owner, &repo, &tag)
        .await?;
    Ok(Json(release_json(&state, &owner, &repo, &view)))
}

/// `PATCH /repos/{owner}/{repo}/releases/{*tag}` (200): the patch body
/// carries optional fields; missing fields keep their value. Publishing a
/// draft sets `published_at`.
#[utoipa::path(
    patch,
    path = "/api/v1/repos/{owner}/{repo}/releases/{*tag}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("tag" = String, Path, description = "Release tag"),
    ),
    request_body = PatchReleaseBody,
    responses(
        (status = 200, description = "Updated release", body = ReleaseJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn patch_release(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, tag)): Path<(String, String, String)>,
    body: Result<Json<PatchReleaseBody>, JsonRejection>,
) -> Result<Json<ReleaseJson>, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let Json(body) = body.map_err(|e| ApiError::Invalid(e.body_text()))?;
    let current = state
        .core
        .release(Some(&auth.user), &owner, &repo, &tag)
        .await?;
    let edit = ReleaseEdit {
        title: body.title.as_deref().unwrap_or(&current.title),
        notes: body.notes.as_deref().unwrap_or(&current.notes),
        draft: body.draft.unwrap_or(current.draft),
        prerelease: body.prerelease.unwrap_or(current.prerelease),
    };
    let view = state
        .core
        .update_release(&auth.user, &owner, &repo, &tag, &edit)
        .await?;
    Ok(Json(release_json(&state, &owner, &repo, &view)))
}
/// `DELETE /repos/{owner}/{repo}/releases/{*tag}` (204): removes the
/// release (and its asset rows); the git tag stays.
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/releases/{*tag}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("tag" = String, Path, description = "Release tag"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn delete_release(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, tag)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    state
        .core
        .delete_release(&auth.user, &owner, &repo, &tag)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /repos/{owner}/{repo}/release-assets/{*rest}` (201): uploads an
/// asset to the release named by the tag in `rest`. The raw body is the
/// file; its `Content-Type` is stored.
#[utoipa::path(
    put,
    path = "/api/v1/repos/{owner}/{repo}/release-assets/{*rest}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("rest" = String, Path, description = "Release tag and asset name, split at the last `/`"),
    ),
    responses(
        (status = 201, description = "Stored asset", body = AssetJson),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 409, description = "Conflict", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
        (status = 413, description = "Asset too large", body = crate::openapi::ApiErrorBody),
        (status = 422, description = "Invalid", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn put_release_asset(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, rest)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<AssetJson>), ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let (tag, name) = split_tag_asset(&rest)?;
    if body.len() as i64 > starforged_core::releases::MAX_ASSET_BYTES {
        return Err(ApiError::PayloadTooLarge(
            "asset exceeds the 1 GiB cap".into(),
        ));
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream");
    let view = state
        .core
        .upload_release_asset(
            &auth.user,
            &owner,
            &repo,
            tag,
            &starforged_core::releases::AssetUpload {
                name,
                content_type,
                bytes: &body,
            },
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(asset_json(&state, &owner, &repo, tag, &view)),
    ))
}

/// `GET /repos/{owner}/{repo}/release-assets/{*rest}` (200): an asset's
/// bytes with `Content-Disposition: attachment`.
#[utoipa::path(
    get,
    path = "/api/v1/repos/{owner}/{repo}/release-assets/{*rest}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("rest" = String, Path, description = "Release tag and asset name, split at the last `/`"),
    ),
    responses(
        (status = 200, description = "Asset bytes"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security((), ("bearer_auth" = [])),
)]
pub async fn get_release_asset(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<Response, ApiError> {
    let (tag, name) = split_tag_asset(&rest)?;
    let (view, bytes) = state
        .core
        .release_asset(auth.reader()?, &owner, &repo, tag, name)
        .await?;
    let mut response = axum::response::Response::new(Body::from(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_str(&view.content_type)
            .unwrap_or_else(|_| header::HeaderValue::from_static("application/octet-stream")),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        header::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", view.name))
            .map_err(|_| ApiError::Internal("bad filename".into()))?,
    );
    *response.status_mut() = StatusCode::OK;
    Ok(response)
}

/// `DELETE /repos/{owner}/{repo}/release-assets/{*rest}` (204): removes
/// an asset (its blob loses one reference).
#[utoipa::path(
    delete,
    path = "/api/v1/repos/{owner}/{repo}/release-assets/{*rest}",
    params(
        ("owner" = String, Path, description = "Repository owner"),
        ("repo" = String, Path, description = "Repository name"),
        ("rest" = String, Path, description = "Release tag and asset name, split at the last `/`"),
    ),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Unauthenticated", body = crate::openapi::ApiErrorBody),
        (status = 403, description = "Forbidden", body = crate::openapi::ApiErrorBody),
        (status = 404, description = "Not found", body = crate::openapi::ApiErrorBody),
        (status = 400, description = "Bad request", body = crate::openapi::ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn delete_release_asset(
    State(state): State<ApiState>,
    auth: ApiAuth,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let auth = auth.require(Scope::RepoWrite)?;
    let (tag, name) = split_tag_asset(&rest)?;
    state
        .core
        .delete_release_asset(&auth.user, &owner, &repo, tag, name)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
