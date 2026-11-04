use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use starforged_core::repos::RepoAccess;
use starforged_core::sessions::WebSession;
use starforged_git::diff::{FileStatus, LineKind};

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::pages::code::default_ref;
use crate::views::{NavUser, RepoHead, format_time, nav};

pub const PER_PAGE: usize = 50;

#[derive(Deserialize)]
pub struct PageQuery {
    page: Option<usize>,
}

pub struct CommitRow {
    id: String,
    short_id: String,
    summary: String,
    author: String,
    when: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "commits.html")]
pub struct CommitsPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    /// Empty when the repository has no commits yet.
    ref_name: String,
    commits: Vec<CommitRow>,
    page: usize,
    has_next: bool,
}

pub struct LineView {
    class: &'static str,
    old: String,
    new: String,
    text: String,
}

pub struct HunkView {
    header: String,
    lines: Vec<LineView>,
}

pub struct FileView {
    status: &'static str,
    path: String,
    binary: bool,
    hunks: Vec<HunkView>,
}

#[derive(Template, WebTemplate)]
#[template(path = "commit.html")]
pub struct CommitPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    id: String,
    summary: String,
    body: String,
    author: String,
    when: String,
    parents: Vec<String>,
    files: Vec<FileView>,
    truncated: bool,
}

pub async fn commits(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, rest)): Path<(String, String, String)>,
    Query(query): Query<PageQuery>,
) -> Result<CommitsPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let resolved = state.core.resolve(&access, &rest).await?;
    if !resolved.path.is_empty() {
        return Err(WebError::NotFound);
    }
    commits_page(
        &state,
        session.as_ref(),
        &access,
        Some((resolved.ref_name, resolved.commit_id)),
        query.page,
    )
    .await
}

/// `/{owner}/{repo}/commits`: the default branch's history; an empty repository shows "No commits yet."
pub async fn default_commits(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<PageQuery>,
) -> Result<CommitsPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let target = match default_ref(&state, &access).await? {
        Some(name) => {
            let resolved = state.core.resolve(&access, &name).await?;
            Some((resolved.ref_name, resolved.commit_id))
        }
        None => None,
    };
    commits_page(&state, session.as_ref(), &access, target, query.page).await
}

/// One page of the history of `target` (ref name, commit id); `None` lists nothing.
async fn commits_page(
    state: &AppState,
    session: Option<&WebSession>,
    access: &RepoAccess,
    target: Option<(String, String)>,
    page: Option<usize>,
) -> Result<CommitsPage, WebError> {
    let page = page.unwrap_or(1).max(1);
    let (ref_name, mut commits) = match target {
        Some((ref_name, commit_id)) => {
            let commits = state
                .core
                .log(
                    access,
                    &commit_id,
                    (page - 1).saturating_mul(PER_PAGE),
                    PER_PAGE + 1,
                )
                .await?;
            (ref_name, commits)
        }
        None => (String::new(), Vec::new()),
    };
    let has_next = commits.len() > PER_PAGE;
    commits.truncate(PER_PAGE);
    let head = RepoHead::new(
        access,
        "commits",
        Some(ref_name.as_str()).filter(|r| !r.is_empty()),
    );
    Ok(CommitsPage {
        nav_user: nav(session),
        head,
        ref_name,
        commits: commits
            .into_iter()
            .map(|c| CommitRow {
                short_id: c.short_id().to_owned(),
                author: c.author_name.clone(),
                when: format_time(c.author_time),
                summary: c.summary,
                id: c.id,
            })
            .collect(),
        page,
        has_next,
    })
}

pub async fn commit(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, id)): Path<(String, String, String)>,
) -> Result<CommitPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let head = RepoHead::new(&access, "commits", None);
    let info = state.core.commit(&access, &id).await?;
    let diff = state.core.diff(&access, &info.id).await?;
    let files = diff
        .files
        .into_iter()
        .map(|file| FileView {
            status: match file.status {
                FileStatus::Added => "added",
                FileStatus::Deleted => "deleted",
                FileStatus::Modified => "modified",
                FileStatus::Renamed => "renamed",
            },
            path: match (file.status, &file.old_path) {
                (FileStatus::Renamed, Some(old)) => format!("{old} → {}", file.display_path()),
                _ => file.display_path().to_owned(),
            },
            binary: file.binary,
            hunks: file
                .hunks
                .into_iter()
                .map(|hunk| HunkView {
                    header: hunk.header,
                    lines: hunk
                        .lines
                        .into_iter()
                        .map(|line| LineView {
                            class: match line.kind {
                                LineKind::Context => "ctx",
                                LineKind::Added => "add",
                                LineKind::Removed => "del",
                                LineKind::NoNewline => "nonl",
                            },
                            old: line.old_line.map(|n| n.to_string()).unwrap_or_default(),
                            new: line.new_line.map(|n| n.to_string()).unwrap_or_default(),
                            text: line.text,
                        })
                        .collect(),
                })
                .collect(),
        })
        .collect();
    let body = info
        .message
        .split_once('\n')
        .map(|(_, rest)| rest.trim().to_owned())
        .unwrap_or_default();
    Ok(CommitPage {
        nav_user: nav(session.as_ref()),
        head,
        summary: info.summary,
        body,
        author: info.author_name,
        when: format_time(info.author_time),
        parents: info.parents,
        id: info.id,
        files,
        truncated: diff.truncated,
    })
}
