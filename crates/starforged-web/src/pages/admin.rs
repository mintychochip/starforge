//! Site administration overview (spec §12).

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use starforged_core::admin::AdminOverview;

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
