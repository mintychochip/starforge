//! Comparing two refs (forge-basics design §6): the commits `head` adds to `base`, and the diff from their
//! merge base to `head`.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use starforged_core::repos::RepoAccess;

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::pages::code::default_ref;
use crate::views::{CommitRow, FileView, NavUser, RepoHead, encode_path, file_views, nav};

#[derive(Deserialize)]
pub struct PickQuery {
    base: Option<String>,
    head: Option<String>,
}

pub struct RefOption {
    name: String,
    selected: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "compare.html")]
pub struct ComparePage {
    nav_user: Option<NavUser>,
    head: RepoHead,
    base_options: Vec<RefOption>,
    head_options: Vec<RefOption>,
    /// False on the picker page, which shows only the form.
    compared: bool,
    base_ref: String,
    head_ref: String,
    /// The refs share history.
    related: bool,
    commits: Vec<CommitRow>,
    total: usize,
    /// Commits beyond the listed ones.
    more: usize,
    files: Vec<FileView>,
    truncated: bool,
}

/// `/{owner}/{repo}/compare`: two branch pickers. With `?base=…&head=…` it answers 303 to the comparison.
pub async fn pick(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo)): Path<(String, String)>,
    Query(query): Query<PickQuery>,
) -> Result<Response, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let base = query.base.filter(|b| !b.is_empty());
    let head = query.head.filter(|h| !h.is_empty());
    if let (Some(base), Some(head)) = (&base, &head) {
        return Ok(Redirect::to(&compare_href(&access, base, head)).into_response());
    }
    let branches = state.core.branches(&access).await?;
    let base = match base {
        Some(base) => base,
        None => default_ref(&state, &access).await?.unwrap_or_default(),
    };
    let head = head
        .or_else(|| branches.iter().find(|b| **b != base).cloned())
        .unwrap_or_else(|| base.clone());
    Ok(ComparePage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "compare", None),
        base_options: options(&branches, &base),
        head_options: options(&branches, &head),
        compared: false,
        base_ref: base,
        head_ref: head,
        related: false,
        commits: Vec::new(),
        total: 0,
        more: 0,
        files: Vec::new(),
        truncated: false,
    }
    .into_response())
}

/// `/{owner}/{repo}/compare/{base}...{head}`. A valid ref never contains `...`, so the first one splits.
pub async fn compare(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path((owner, repo, spec)): Path<(String, String, String)>,
) -> Result<ComparePage, WebError> {
    let access = state
        .core
        .repo_for(session.as_ref().map(|s| &s.user), &owner, &repo)
        .await?;
    let (base, head) = spec.split_once("...").ok_or(WebError::NotFound)?;
    let comparison = state.core.compare(&access, base, head).await?;
    let branches = state.core.branches(&access).await?;
    let total = comparison.total_commits;
    let more = total - comparison.commits.len();
    Ok(ComparePage {
        nav_user: nav(session.as_ref()),
        head: RepoHead::new(&access, "compare", None),
        base_options: options(&branches, &comparison.base.ref_name),
        head_options: options(&branches, &comparison.head.ref_name),
        compared: true,
        base_ref: comparison.base.ref_name,
        head_ref: comparison.head.ref_name,
        related: comparison.merge_base.is_some(),
        commits: comparison
            .commits
            .into_iter()
            .map(CommitRow::from)
            .collect(),
        total,
        more,
        files: file_views(comparison.diff.files),
        truncated: comparison.diff.truncated,
    })
}

fn compare_href(access: &RepoAccess, base: &str, head: &str) -> String {
    format!(
        "/{}/{}/compare/{}...{}",
        access.repo.owner,
        access.repo.name,
        encode_path(base),
        encode_path(head)
    )
}

/// The branches as options with `selected` chosen. A name that is not a branch (a tag or a commit id) comes
/// first, so the form still shows what is compared.
fn options(branches: &[String], selected: &str) -> Vec<RefOption> {
    let mut options: Vec<RefOption> = branches
        .iter()
        .map(|name| RefOption {
            selected: name == selected,
            name: name.clone(),
        })
        .collect();
    if !selected.is_empty() && !branches.iter().any(|b| b == selected) {
        options.insert(
            0,
            RefOption {
                name: selected.to_owned(),
                selected: true,
            },
        );
    }
    options
}
