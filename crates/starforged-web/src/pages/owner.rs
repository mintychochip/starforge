use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, RepoItem, nav};

#[derive(Template, WebTemplate)]
#[template(path = "owner.html")]
pub struct OwnerPage {
    nav_user: Option<NavUser>,
    owner: String,
    repos: Vec<RepoItem>,
}

pub async fn show(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path(owner): Path<String>,
) -> Result<OwnerPage, WebError> {
    let viewer = session.as_ref().map(|s| &s.user);
    let repos = state
        .core
        .repos_of(viewer, &owner)
        .await?
        .into_iter()
        .map(RepoItem::from)
        .collect();
    Ok(OwnerPage {
        nav_user: nav(session.as_ref()),
        owner: owner.to_ascii_lowercase(),
        repos,
    })
}
