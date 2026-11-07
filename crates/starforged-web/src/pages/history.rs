use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use starforged_core::repos::RepoAccess;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::pages::code::default_ref;
use crate::views::{
    CommitRow, Crumb, FileView, NavUser, RepoHead, SessionChip, crumbs, file_views, format_time,
    nav,
};

pub const PER_PAGE: usize = 50;

#[derive(Deserialize)]
pub struct PageQuery {
    page: Option<usize>,
}

#[derive(Template, WebTemplate)]
#[template(path = "commits.html")]
pub struct CommitsPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    /// Empty when the repository has no commits yet.
    ref_name: String,
    /// The history of one path, when filtered; `None` is the full history.
    path_history: Option<PathHistory>,
    commits: Vec<CommitRow>,
    page: usize,
    has_next: bool,
}

/// Header of a per-path history: the path's breadcrumb (directory levels link to
/// their trees; the last segment is plain) and the full-history href.
pub struct PathHistory {
    crumbs: Vec<Crumb>,
    name: String,
    history_href: String,
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
    /// Sessions the viewer may read linked to this commit (unreadable links
    /// are omitted entirely — never a locked chip). Empty renders no card.
    sessions: Vec<SessionChip>,
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
    let path = if resolved.path.is_empty() {
        None
    } else {
        // A path missing at this ref is 404, whatever the full history shows.
        // `path_exists` covers submodule gitlinks, which `blob` and `tree`
        // both reject.
        let exists = state
            .core
            .path_exists(&access, &resolved.commit_id, &resolved.path)
            .await?;
        if !exists {
            return Err(WebError::NotFound);
        }
        Some(resolved.path.clone())
    };
    commits_page(
        &state,
        session.as_ref(),
        &access,
        Some((resolved.ref_name, resolved.commit_id)),
        path,
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
    commits_page(&state, session.as_ref(), &access, target, None, query.page).await
}

/// One page of the history of `target` (ref name, commit id); `None` lists nothing.
/// With `path`, only commits that touched it are listed.
async fn commits_page(
    state: &AppState,
    session: Option<&WebSession>,
    access: &RepoAccess,
    target: Option<(String, String)>,
    path: Option<String>,
    page: Option<usize>,
) -> Result<CommitsPage, WebError> {
    let page = page.unwrap_or(1).max(1);
    let (ref_name, mut commits) = match target {
        Some((ref_name, commit_id)) => {
            let skip = (page - 1).saturating_mul(PER_PAGE);
            let commits = match &path {
                Some(path) => {
                    state
                        .core
                        .log_path(access, &commit_id, path, skip, PER_PAGE + 1)
                        .await?
                }
                None => {
                    state
                        .core
                        .log(access, &commit_id, skip, PER_PAGE + 1)
                        .await?
                }
            };
            (ref_name, commits)
        }
        None => (String::new(), Vec::new()),
    };
    let has_next = commits.len() > PER_PAGE;
    commits.truncate(PER_PAGE);
    let shas: Vec<String> = commits.iter().map(|c| c.id.clone()).collect();
    let counts = state
        .core
        .readable_link_counts(access, session.as_ref().map(|s| &s.user), &shas)
        .await?;
    let head = RepoHead::new(
        access,
        "commits",
        Some(ref_name.as_str()).filter(|r| !r.is_empty()),
    );
    let path_history = path.map(|path| {
        let (dir, name) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        PathHistory {
            crumbs: crumbs(&access.repo.owner, &access.repo.name, &ref_name, dir),
            name: name.to_owned(),
            history_href: head.commits_href.clone(),
        }
    });
    Ok(CommitsPage {
        nav_user: nav(session),
        head,
        ref_name,
        path_history,
        commits: commits
            .into_iter()
            .map(|c| {
                let mut row = CommitRow::from(c);
                row.session_count = counts.get(&row.id).copied().unwrap_or(0);
                row
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
    let files = file_views(diff.files);
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
        id: info.id.clone(),
        files,
        truncated: diff.truncated,
        sessions: state
            .core
            .readable_session_rows_for_commit(&access, session.as_ref().map(|s| &s.user), &info.id)
            .await?
            .iter()
            .map(|panel| SessionChip::from_panel_row(&access.repo.owner, &access.repo.name, panel))
            .collect(),
    })
}
