//! The branches and tags of a repository (forge-basics design §6).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, RepoHead, content_href, encode_path, format_age, format_time, nav};
use starforged_core::permission::Permission;

pub struct BranchRow {
    name: String,
    tree_href: String,
    commits_href: String,
    /// Empty for the default branch or for viewers who cannot create trails.
    new_trail_href: String,
    is_default: bool,
    summary: String,
    author: String,
    age: String,
    when: String,
    /// Empty for the default branch, or when the default branch does not exist.
    compare_href: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "branches.html")]
pub struct BranchesPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    branches: Vec<BranchRow>,
}

pub struct TagRow {
    name: String,
    tree_href: String,
    commit_id: String,
    short_id: String,
    annotation: String,
    when: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "tags.html")]
pub struct TagsPage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    tags: Vec<TagRow>,
}

fn unix_now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// `/{owner}/{repo}/branches`: the default branch first, then the newest tips.
pub async fn branches(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<BranchesPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let mut list = state.core.branch_list(&access).await?;
    let repo = &access.repo;
    let default = repo.default_branch.as_str();
    if let Some(at) = list.iter().position(|b| b.name == default) {
        let first = list.remove(at);
        list.insert(0, first);
    }
    let has_default = list.first().is_some_and(|b| b.name == default);
    let can_new_trail = session.is_some() && access.permission >= Permission::Triage;
    let now = unix_now();
    let branches = list
        .into_iter()
        .map(|b| BranchRow {
            tree_href: content_href(&repo.owner, &repo.name, "tree", &b.name, ""),
            commits_href: format!(
                "/{}/{}/commits/{}",
                repo.owner,
                repo.name,
                encode_path(&b.name)
            ),
            new_trail_href: if can_new_trail && b.name != default {
                format!(
                    "/{}/{}/trails/new?head={}",
                    repo.owner,
                    repo.name,
                    encode_path(&b.name)
                )
            } else {
                String::new()
            },
            is_default: b.name == default,
            compare_href: if has_default && b.name != default {
                format!(
                    "/{}/{}/compare/{}...{}",
                    repo.owner,
                    repo.name,
                    encode_path(default),
                    encode_path(&b.name)
                )
            } else {
                String::new()
            },
            summary: b.tip.summary,
            author: b.tip.author_name,
            age: format_age(now, b.committed_at),
            when: format_time(b.committed_at),
            name: b.name,
        })
        .collect();
    Ok(BranchesPage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "branches", None),
        branches,
    })
}

/// `/{owner}/{repo}/tags`: the newest first.
pub async fn tags(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<TagsPage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let repo = &access.repo;
    let tags = state
        .core
        .tag_list(&access)
        .await?
        .into_iter()
        .map(|t| TagRow {
            tree_href: content_href(&repo.owner, &repo.name, "tree", &t.name, ""),
            short_id: t.commit_id[..t.commit_id.len().min(10)].to_owned(),
            commit_id: t.commit_id,
            annotation: t.annotation.unwrap_or_default(),
            when: format_time(t.date),
            name: t.name,
        })
        .collect();
    Ok(TagsPage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "tags", None),
        tags,
    })
}
