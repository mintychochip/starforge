use askama::Template;
use askama_web::WebTemplate;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Response};
use starforged_core::repos::RepoAccess;
use starforged_core::sessions::WebSession;
use starforged_git::read::{Blob, EntryKind, TreeEntry, classify};
use tokio_util::io::ReaderStream;

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::highlight;
use crate::markdown;
use crate::views::{Crumb, NavUser, RepoHead, content_href, crumbs, nav};

const README_NAMES: [&str; 3] = ["readme.md", "readme.markdown", "readme"];

pub struct EntryRow {
    name: String,
    /// Empty for submodules, which have nothing to browse.
    href: String,
    is_dir: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "tree.html")]
pub struct TreePage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    clone_url: String,
    empty: bool,
    ref_name: String,
    crumbs: Vec<Crumb>,
    entries: Vec<EntryRow>,
    readme_html: Option<String>,
}

#[derive(Template, WebTemplate)]
#[template(path = "blob.html")]
pub struct BlobPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    ref_name: String,
    path: String,
    file_name: String,
    crumbs: Vec<Crumb>,
    raw_href: String,
    size: usize,
    lines: Vec<String>,
    highlighted: bool,
    notice: Option<&'static str>,
}

/// The default branch when it exists, else the first branch by name; `None` for an empty repository.
pub(crate) async fn default_ref(
    state: &AppState,
    access: &RepoAccess,
) -> Result<Option<String>, WebError> {
    let branches = state.core.branches(access).await?;
    Ok(if branches.contains(&access.repo.default_branch) {
        Some(access.repo.default_branch.clone())
    } else {
        branches.into_iter().next()
    })
}

/// `/{owner}/{repo}`: the default branch's root directory, or push instructions for an empty repository.
pub async fn repo_home(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let Some(default) = default_ref(&state, &access).await? else {
        return Ok(tree_page(
            &state,
            session.as_ref(),
            &access,
            None,
            "",
            Vec::new(),
            None,
        )
        .into_response());
    };
    let resolved = state.core.resolve(&access, &default).await?;
    render_tree(
        &state,
        session.as_ref(),
        &access,
        &resolved.ref_name,
        &resolved.commit_id,
        "",
    )
    .await
}

pub async fn tree(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let resolved = state.core.resolve(&access, &rest).await?;
    render_tree(
        &state,
        session.as_ref(),
        &access,
        &resolved.ref_name,
        &resolved.commit_id,
        &resolved.path,
    )
    .await
}

pub async fn blob(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<BlobPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let resolved = state.core.resolve(&access, &rest).await?;
    let file = state
        .core
        .blob(&access, &resolved.commit_id, &resolved.path)
        .await?;
    let size = usize::try_from(file.size).unwrap_or(usize::MAX);
    let (dir, file_name) = resolved
        .path
        .rsplit_once('/')
        .unwrap_or(("", resolved.path.as_str()));
    let (lines, highlighted, notice) = match file.bytes {
        None => (
            Vec::new(),
            false,
            Some("This file is too large to display."),
        ),
        Some(bytes) => match classify(bytes) {
            Blob::Text(text) => {
                let (lines, highlighted) = render_lines(file_name.to_owned(), text).await?;
                (lines, highlighted, None)
            }
            Blob::Binary => (Vec::new(), false, Some("Binary file not shown.")),
        },
    };
    let repo = &access.repo;
    Ok(BlobPage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "code", Some(&resolved.ref_name)),
        ref_name: resolved.ref_name.clone(),
        crumbs: crumbs(&repo.owner, &repo.name, &resolved.ref_name, dir),
        file_name: file_name.to_owned(),
        raw_href: content_href(
            &repo.owner,
            &repo.name,
            "raw",
            &resolved.ref_name,
            &resolved.path,
        ),
        path: resolved.path.clone(),
        size,
        lines,
        highlighted,
        notice,
    })
}

/// The file's lines as highlighted HTML (`true`), or as plain text when highlighting does not apply
/// (`false`). Runs on the blocking pool: highlighting a large file takes a while.
async fn render_lines(file_name: String, text: String) -> Result<(Vec<String>, bool), WebError> {
    tokio::task::spawn_blocking(
        move || match highlight::highlight_lines(&file_name, &text) {
            Some(lines) => (lines, true),
            None => (text.lines().map(str::to_owned).collect(), false),
        },
    )
    .await
    .map_err(|e| WebError::Internal(e.to_string()))
}

/// Raw file bytes: plain text or an attachment, inside a CSP sandbox, never rendered as HTML (spec §11.1).
pub async fn raw(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let resolved = state.core.resolve(&access, &rest).await?;
    let file = state
        .core
        .blob(&access, &resolved.commit_id, &resolved.path)
        .await?;
    let Some(bytes) = file.bytes else {
        // Large files are always served as attachments, with no text sniffing.
        let stdout = state.core.blob_stream(&access, &file.id).await?;
        let length = HeaderValue::from_str(&file.size.to_string()).map_err(|_| {
            WebError::Internal(format!("unrepresentable content length: {}", file.size))
        })?;
        return Ok((
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                ),
                (
                    header::CONTENT_DISPOSITION,
                    HeaderValue::from_static("attachment"),
                ),
                (header::CONTENT_LENGTH, length),
                (
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("sandbox"),
                ),
            ],
            Body::from_stream(ReaderStream::new(stdout)),
        )
            .into_response());
    };
    let is_text =
        !bytes[..bytes.len().min(8000)].contains(&0) && std::str::from_utf8(&bytes).is_ok();
    let mut response = bytes.into_response();
    let headers = response.headers_mut();
    if is_text {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_static("attachment"),
        );
    }
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox"),
    );
    Ok(response)
}

async fn render_tree(
    state: &AppState,
    session: Option<&WebSession>,
    access: &RepoAccess,
    ref_name: &str,
    commit_id: &str,
    dir: &str,
) -> Result<Response, WebError> {
    let entries = state.core.tree(access, commit_id, dir).await?;
    let readme_html = readme(state, access, commit_id, dir, &entries).await?;
    let repo = &access.repo;
    let rows = entries
        .into_iter()
        .map(|entry| {
            let child = if dir.is_empty() {
                entry.name.clone()
            } else {
                format!("{dir}/{}", entry.name)
            };
            let href = match entry.kind {
                EntryKind::Tree => content_href(&repo.owner, &repo.name, "tree", ref_name, &child),
                EntryKind::Blob | EntryKind::Symlink => {
                    content_href(&repo.owner, &repo.name, "blob", ref_name, &child)
                }
                EntryKind::Submodule => String::new(),
            };
            EntryRow {
                is_dir: entry.kind == EntryKind::Tree,
                href,
                name: entry.name,
            }
        })
        .collect();
    Ok(tree_page(
        state,
        session,
        access,
        Some(ref_name),
        dir,
        rows,
        readme_html,
    )
    .into_response())
}

fn tree_page(
    state: &AppState,
    session: Option<&WebSession>,
    access: &RepoAccess,
    ref_name: Option<&str>,
    dir: &str,
    entries: Vec<EntryRow>,
    readme_html: Option<String>,
) -> TreePage {
    let repo = &access.repo;
    let current = ref_name.unwrap_or_default();
    TreePage {
        nav_user: nav(session),
        head: RepoHead::new(access, "code", ref_name),
        clone_url: format!(
            "{}/{}/{}.git",
            state.settings.base_url, repo.owner, repo.name
        ),
        empty: ref_name.is_none(),
        ref_name: current.to_owned(),
        crumbs: crumbs(&repo.owner, &repo.name, current, dir),
        entries,
        readme_html,
    }
}

/// Rendered README of `dir`, if it has one that is text and fits the inline limit.
async fn readme(
    state: &AppState,
    access: &RepoAccess,
    commit_id: &str,
    dir: &str,
    entries: &[TreeEntry],
) -> Result<Option<String>, WebError> {
    let found = README_NAMES.iter().find_map(|wanted| {
        entries
            .iter()
            .find(|e| e.kind == EntryKind::Blob && e.name.to_ascii_lowercase() == *wanted)
    });
    let Some(entry) = found else { return Ok(None) };
    let file = if dir.is_empty() {
        entry.name.clone()
    } else {
        format!("{dir}/{}", entry.name)
    };
    let blob = state.core.blob(access, commit_id, &file).await?;
    // A README over the inline limit has `bytes == None` and is skipped.
    let Some(bytes) = blob.bytes else {
        return Ok(None);
    };
    let lower = entry.name.to_ascii_lowercase();
    Ok(match classify(bytes) {
        Blob::Text(text) if lower.ends_with(".md") || lower.ends_with(".markdown") => {
            Some(markdown::render(&text))
        }
        Blob::Text(text) => Some(markdown::plain(&text)),
        Blob::Binary => None,
    })
}
