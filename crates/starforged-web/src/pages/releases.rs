//! Release web UI (forge-basics design §6): a per-repository release list,
//! a show page with notes and downloadable assets, and the new/edit forms.
//! Reads 404 for non-readers and hide drafts below Write exactly like
//! [`starforged_core::releases`]; writes need Write (enforced by Core, so a
//! reader's POST is refused with 403) and carry the session CSRF token.
//! Notes render through [`crate::markdown::render_prose`]; everything else
//! relies on askama escaping.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::permission::Permission;
use starforged_core::releases::{AssetUpload, ReleaseEdit, ReleaseInput, ReleaseView};

use crate::AppState;
use crate::auth::{CsrfForm, MaybeUser, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::markdown;
use crate::views::{NavUser, RepoHead, encode_path, format_time, nav};

/// `/{owner}/{repo}/releases/tag/{tag}` for a tag that may contain `/`.
fn release_href(owner: &str, repo: &str, tag: &str) -> String {
    format!("/{owner}/{repo}/releases/tag/{}", encode_path(tag))
}

/// One row of the release list.
pub struct ReleaseRow {
    href: String,
    tag: String,
    title: String,
    draft: bool,
    prerelease: bool,
    has_published: bool,
    published: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "releases.html")]
pub struct ReleasesPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    releases: Vec<ReleaseRow>,
    can_new: bool,
}

/// `GET /{owner}/{repo}/releases`: the newest first, with a New release
/// link for Write and above.
pub async fn list(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<ReleasesPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let meta = &access.repo;
    let releases = state
        .core
        .releases(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?
        .into_iter()
        .map(|r| ReleaseRow {
            href: release_href(&meta.owner, &meta.name, &r.tag),
            tag: r.tag,
            title: r.title,
            draft: r.draft,
            prerelease: r.prerelease,
            has_published: r.published_at.is_some(),
            published: r.published_at.map(format_time).unwrap_or_default(),
        })
        .collect();
    Ok(ReleasesPage {
        can_new: access.permission >= Permission::Write,
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "releases", None),
        releases,
    })
}

#[derive(Template, WebTemplate)]
#[template(path = "release_form.html")]
pub struct ReleaseFormPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    csrf: String,
    /// True for the new form (tag and target fields), false for edit.
    is_new: bool,
    tag: String,
    target: String,
    title: String,
    notes: String,
    draft: bool,
    prerelease: bool,
    error: Option<String>,
    action: String,
}

/// `GET /{owner}/{repo}/releases/new`.
pub async fn new_form(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<ReleaseFormPage, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    Ok(ReleaseFormPage {
        nav_user: Some(NavUser::from_session(&session)),
        head: RepoHead::new(&access, "releases", None),
        csrf: session.csrf_token.clone(),
        is_new: true,
        tag: String::new(),
        target: String::new(),
        title: String::new(),
        notes: String::new(),
        draft: false,
        prerelease: false,
        error: None,
        action: format!("/{}/{}/releases/new", access.repo.owner, access.repo.name),
    })
}

#[derive(Deserialize)]
pub struct ReleaseForm {
    #[serde(rename = "_csrf", default)]
    csrf: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    notes: String,
    /// A checkbox: present means "save as draft", absent means published.
    #[serde(default)]
    draft: Option<String>,
    /// A checkbox: present means "mark as prerelease", absent means stable.
    #[serde(default)]
    prerelease: Option<String>,
}

/// `POST /{owner}/{repo}/releases/new`: creates the release and redirects to
/// its page. `Invalid`/`Conflict` re-render the form with 422 instead of
/// dropping the input, like the Trail form.
pub async fn create(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<ReleaseForm>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let target = form.target.trim();
    let target = (!target.is_empty()).then_some(target);
    let input = ReleaseInput {
        tag: form.tag.trim(),
        target,
        title: &form.title,
        notes: &form.notes,
        draft: form.draft.is_some(),
        prerelease: form.prerelease.is_some(),
    };
    match state
        .core
        .create_release(&session.user, &owner, &repo, &input)
        .await
    {
        Ok(view) => Ok(Redirect::to(&release_href(
            &access.repo.owner,
            &access.repo.name,
            &view.tag,
        ))
        .into_response()),
        Err(CoreError::Invalid(message)) | Err(CoreError::Conflict(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            ReleaseFormPage {
                nav_user: Some(NavUser::from_session(&session)),
                head: RepoHead::new(&access, "releases", None),
                csrf: session.csrf_token.clone(),
                is_new: true,
                tag: form.tag.clone(),
                target: form.target.clone(),
                title: form.title.clone(),
                notes: form.notes.clone(),
                draft: form.draft.is_some(),
                prerelease: form.prerelease.is_some(),
                error: Some(message),
                action: format!("/{}/{}/releases/new", access.repo.owner, access.repo.name),
            },
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

/// `GET /{owner}/{repo}/releases/edit/{tag}`: the edit form prefilled from
/// the stored release.
pub async fn edit_form(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, tag)): Path<(String, String, String)>,
) -> Result<ReleaseFormPage, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    let view = state
        .core
        .release(Some(&session.user), &owner, &repo, &tag)
        .await?;
    Ok(ReleaseFormPage {
        nav_user: Some(NavUser::from_session(&session)),
        head: RepoHead::new(&access, "releases", None),
        csrf: session.csrf_token.clone(),
        is_new: false,
        tag: view.tag.clone(),
        target: String::new(),
        title: view.title.clone(),
        notes: view.notes.clone(),
        draft: view.draft,
        prerelease: view.prerelease,
        error: None,
        action: format!(
            "/{}/{}/releases/edit/{}",
            access.repo.owner,
            access.repo.name,
            encode_path(&view.tag)
        ),
    })
}

/// `POST /{owner}/{repo}/releases/edit/{tag}`: replaces the release's
/// title, notes, and flags and redirects to its page. `Invalid`/`Conflict`
/// re-render the form with 422.
pub async fn update(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, tag)): Path<(String, String, String)>,
    Form(form): Form<ReleaseForm>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let edit = ReleaseEdit {
        title: &form.title,
        notes: &form.notes,
        draft: form.draft.is_some(),
        prerelease: form.prerelease.is_some(),
    };
    match state
        .core
        .update_release(&session.user, &owner, &repo, &tag, &edit)
        .await
    {
        Ok(view) => Ok(Redirect::to(&release_href(
            &access.repo.owner,
            &access.repo.name,
            &view.tag,
        ))
        .into_response()),
        Err(CoreError::Invalid(message)) | Err(CoreError::Conflict(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            ReleaseFormPage {
                nav_user: Some(NavUser::from_session(&session)),
                head: RepoHead::new(&access, "releases", None),
                csrf: session.csrf_token.clone(),
                is_new: false,
                tag: tag.clone(),
                target: String::new(),
                title: form.title.clone(),
                notes: form.notes.clone(),
                draft: form.draft.is_some(),
                prerelease: form.prerelease.is_some(),
                error: Some(message),
                action: format!(
                    "/{}/{}/releases/edit/{}",
                    access.repo.owner,
                    access.repo.name,
                    encode_path(&tag)
                ),
            },
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

/// One uploaded asset on the show page.
pub struct AssetRow {
    download_href: String,
    name: String,
    size: String,
    content_type: String,
    delete_action: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "release.html")]
pub struct ReleasePage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    csrf: String,
    tag: String,
    title: String,
    draft: bool,
    prerelease: bool,
    has_published: bool,
    published: String,
    created: String,
    author: String,
    zip_href: String,
    tar_gz_href: String,
    has_notes: bool,
    notes_html: String,
    assets: Vec<AssetRow>,
    can_write: bool,
    edit_href: String,
    delete_action: String,
    upload_action: String,
}

/// Builds the show view from a stored release; shared by the viewer and the
/// asset-upload 422 re-render.
fn show_page(
    access: &starforged_core::repos::RepoAccess,
    session: Option<&starforged_core::sessions::WebSession>,
    view: &ReleaseView,
) -> ReleasePage {
    let repo = &access.repo;
    ReleasePage {
        nav_user: nav(session),
        head: RepoHead::new(access, "releases", None),
        csrf: session.map_or_else(String::new, |s| s.csrf_token.clone()),
        tag: view.tag.clone(),
        title: view.title.clone(),
        draft: view.draft,
        prerelease: view.prerelease,
        has_published: view.published_at.is_some(),
        published: view.published_at.map(format_time).unwrap_or_default(),
        created: format_time(view.created_at),
        author: view.author.clone().unwrap_or_default(),
        zip_href: format!(
            "/{}/{}/archive/{}.zip",
            repo.owner,
            repo.name,
            encode_path(&view.tag)
        ),
        tar_gz_href: format!(
            "/{}/{}/archive/{}.tar.gz",
            repo.owner,
            repo.name,
            encode_path(&view.tag)
        ),
        has_notes: !view.notes.is_empty(),
        notes_html: markdown::render_prose(&view.notes),
        assets: view
            .assets
            .iter()
            .map(|a| AssetRow {
                download_href: format!(
                    "/{}/{}/releases/download/{}/{}",
                    repo.owner,
                    repo.name,
                    encode_path(&view.tag),
                    encode_path(&a.name)
                ),
                name: a.name.clone(),
                size: format!("{} bytes", a.size),
                content_type: a.content_type.clone(),
                delete_action: format!(
                    "/{}/{}/releases/asset-delete/{}/{}",
                    repo.owner,
                    repo.name,
                    encode_path(&view.tag),
                    encode_path(&a.name)
                ),
            })
            .collect(),
        can_write: access.permission >= Permission::Write,
        edit_href: format!(
            "/{}/{}/releases/edit/{}",
            repo.owner,
            repo.name,
            encode_path(&view.tag)
        ),
        delete_action: format!(
            "/{}/{}/releases/delete/{}",
            repo.owner,
            repo.name,
            encode_path(&view.tag)
        ),
        upload_action: format!(
            "/{}/{}/releases/assets/{}",
            repo.owner,
            repo.name,
            encode_path(&view.tag)
        ),
    }
}

/// `GET /{owner}/{repo}/releases/tag/{tag}`: the release's notes, its
/// assets, and the zip/tar.gz source links for its tag.
pub async fn show(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, tag)): Path<(String, String, String)>,
) -> Result<ReleasePage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let view = state
        .core
        .release(session.as_ref().map(|s| &s.user), &owner, &repo, &tag)
        .await?;
    Ok(show_page(&access, session.as_ref(), &view))
}

/// `POST /{owner}/{repo}/releases/delete/{tag}`: deletes the release (the
/// git tag stays) and returns to the list.
pub async fn delete(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, tag)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .delete_release(&session.user, &owner, &repo, &tag)
        .await?;
    Ok(Redirect::to(&format!(
        "/{}/{}/releases",
        access.repo.owner, access.repo.name
    ))
    .into_response())
}

/// `POST /{owner}/{repo}/releases/assets/{tag}` (multipart): uploads the
/// `asset` file field to the release and returns to its page. The file's
/// own name and content type become the asset's; a missing content type
/// stores `application/octet-stream`.
pub async fn upload_asset(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, tag)): Path<(String, String, String)>,
    mut multipart: Multipart,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    let mut csrf = String::new();
    let mut file: Option<(String, String, Vec<u8>)> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| WebError::BadRequest(e.to_string()))?
    {
        match field.name() {
            Some("_csrf") => {
                csrf = field
                    .text()
                    .await
                    .map_err(|e| WebError::BadRequest(e.to_string()))?;
            }
            Some("asset") => {
                let name = field.file_name().unwrap_or_default().to_owned();
                let content_type = field
                    .content_type()
                    .unwrap_or("application/octet-stream")
                    .to_owned();
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| WebError::BadRequest(e.to_string()))?;
                file = Some((name, content_type, bytes.to_vec()));
            }
            _ => {}
        }
    }
    verify_csrf(&session.csrf_token, &csrf)?;
    let Some((name, content_type, bytes)) = file else {
        return Err(WebError::BadRequest("no asset file sent".into()));
    };
    let upload = AssetUpload {
        name: &name,
        content_type: &content_type,
        bytes: &bytes,
    };
    match state
        .core
        .upload_release_asset(&session.user, &owner, &repo, &tag, &upload)
        .await
    {
        Ok(_) => Ok(
            Redirect::to(&release_href(&access.repo.owner, &access.repo.name, &tag))
                .into_response(),
        ),
        Err(CoreError::Invalid(_)) | Err(CoreError::Conflict(_)) => {
            let view = state
                .core
                .release(Some(&session.user), &owner, &repo, &tag)
                .await?;
            Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                show_page(&access, Some(&session), &view),
            )
                .into_response())
        }
        Err(other) => Err(other.into()),
    }
}

/// Splits a `{tag}/{asset name}` rest at the last `/`: the tag may itself
/// contain `/`, while an asset name never does.
fn split_tag_asset(rest: &str) -> Option<(&str, &str)> {
    let at = rest.rfind('/')?;
    Some((&rest[..at], &rest[at + 1..]))
}

/// `POST /{owner}/{repo}/releases/asset-delete/{tag}/{name}`: deletes the
/// one asset and returns to the release's page.
pub async fn delete_asset(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(Some(&session.user), &owner, &repo)
        .await?;
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let Some((tag, name)) = split_tag_asset(&rest) else {
        return Err(WebError::NotFound);
    };
    state
        .core
        .delete_release_asset(&session.user, &owner, &repo, tag, name)
        .await?;
    Ok(Redirect::to(&release_href(&access.repo.owner, &access.repo.name, tag)).into_response())
}

/// `GET /{owner}/{repo}/releases/download/{tag}/{name}`: the asset's bytes
/// as an attachment with the stored content type.
pub async fn download_asset(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<Response, WebError> {
    let Some((tag, name)) = split_tag_asset(&rest) else {
        return Err(WebError::NotFound);
    };
    let (asset, bytes) = state
        .core
        .release_asset(session.as_ref().map(|s| &s.user), &owner, &repo, tag, name)
        .await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&asset.content_type)
            .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", asset.name))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    Ok((headers, bytes).into_response())
}
