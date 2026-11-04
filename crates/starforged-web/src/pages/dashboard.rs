use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, RepoItem, nav};

#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    nav_user: Option<NavUser>,
    repos: Vec<RepoItem>,
    sign_up_open: bool,
}

pub async fn show(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
) -> Result<DashboardPage, WebError> {
    let repos = match &session {
        Some(session) => state
            .core
            .dashboard_repos(&session.user)
            .await?
            .into_iter()
            .map(RepoItem::from)
            .collect(),
        None => Vec::new(),
    };
    Ok(DashboardPage {
        nav_user: nav(session.as_ref()),
        repos,
        sign_up_open: state.core.sign_up_open(),
    })
}
