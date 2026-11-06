use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};

use super::orgs::{lookup_org, org_page};
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

/// `/{owner}`: the org profile when the handle names an org, else the user
/// profile. The handle namespace is public, so both are public pages listing
/// only repositories the viewer can read.
pub async fn show(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
    Path(owner): Path<String>,
) -> Result<Response, WebError> {
    let viewer = session.as_ref().map(|s| &s.user);
    if let Some(view) = lookup_org(&state, viewer, &owner).await? {
        let repos = state
            .core
            .repos_of(viewer, &view.handle)
            .await?
            .into_iter()
            .map(RepoItem::from)
            .collect();
        return Ok(org_page(session.as_ref(), view, repos).into_response());
    }
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
    }
    .into_response())
}
