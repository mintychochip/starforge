//! Site administration overview (spec §12).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use starforged_core::accounts::User;
use starforged_core::admin::{AdminOverview, UserSummary};

use crate::AppState;
use crate::auth::RequireAdmin;
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Template, WebTemplate)]
#[template(path = "admin_overview.html")]
pub struct OverviewPage {
    nav_user: Option<NavUser>,
    // Plan-mandated shape; the overview has no form, so only `nav_user`'s token reaches `base.html`.
    #[allow(dead_code)]
    csrf: String,
    admin_tab: &'static str,
    overview: AdminOverview,
    git_version: String,
    app_version: &'static str,
}

pub async fn overview(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
) -> Result<OverviewPage, WebError> {
    let overview = state.core.admin_overview(&session.user).await?;
    let (major, minor) = starforged_git::command::check_version()
        .await
        .map_err(|e| WebError::Internal(e.to_string()))?;
    Ok(OverviewPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "overview",
        overview,
        git_version: format!("{major}.{minor}"),
        app_version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_users.html")]
pub struct UsersPage {
    nav_user: Option<NavUser>,
    #[allow(dead_code)]
    csrf: String,
    admin_tab: &'static str,
    query: String,
    users: Vec<User>,
}

#[derive(Deserialize)]
pub struct ListParams {
    q: Option<String>,
}

pub async fn users(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Query(params): Query<ListParams>,
) -> Result<UsersPage, WebError> {
    let query = params.q.unwrap_or_default();
    let list = state
        .core
        .admin_list_users(&session.user, &query.to_lowercase(), 200)
        .await?;
    Ok(UsersPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "users",
        query,
        users: list,
    })
}

#[derive(Template, WebTemplate)]
#[template(path = "admin_user.html")]
pub struct DetailPage {
    nav_user: Option<NavUser>,
    csrf: String,
    admin_tab: &'static str,
    summary: UserSummary,
}

pub async fn user_detail(
    State(state): State<AppState>,
    RequireAdmin(session): RequireAdmin,
    Path(handle): Path<String>,
) -> Result<DetailPage, WebError> {
    let summary = state
        .core
        .admin_get_user(&session.user, &handle.to_lowercase())
        .await?;
    Ok(DetailPage {
        nav_user: Some(NavUser::from_session(&session)),
        csrf: session.csrf_token.clone(),
        admin_tab: "users",
        summary,
    })
}
