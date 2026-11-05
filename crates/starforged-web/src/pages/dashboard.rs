use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;

use crate::AppState;
use crate::auth::MaybeUser;
use crate::error::WebError;
use crate::views::{NavUser, RepoItem, nav};

pub struct DashboardTrail {
    owner: String,
    repo: String,
    number: i64,
    title: String,
}

pub struct DashboardSession {
    owner: String,
    repo: String,
    ulid: String,
    agent: String,
    title: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    nav_user: Option<NavUser>,
    repos: Vec<RepoItem>,
    assigned: Vec<DashboardTrail>,
    awaiting: Vec<DashboardTrail>,
    sessions: Vec<DashboardSession>,
    sign_up_open: bool,
}

pub async fn show(
    State(state): State<AppState>,
    MaybeUser(session): MaybeUser,
) -> Result<DashboardPage, WebError> {
    let (repos, assigned, awaiting, sessions) = match &session {
        Some(session) => {
            let repos = state
                .core
                .dashboard_repos(&session.user)
                .await?
                .into_iter()
                .map(RepoItem::from)
                .collect();
            let (assigned_rows, awaiting_rows) = state.core.dashboard_trails(&session.user).await?;
            let assigned = assigned_rows
                .into_iter()
                .map(|t| DashboardTrail {
                    owner: t.owner,
                    repo: t.repo,
                    number: t.number,
                    title: t.title,
                })
                .collect();
            let awaiting = awaiting_rows
                .into_iter()
                .map(|t| DashboardTrail {
                    owner: t.owner,
                    repo: t.repo,
                    number: t.number,
                    title: t.title,
                })
                .collect();
            // Sessions carry their own shape (ULID + agent instead of a
            // Trail number); the two Trail sections share DashboardTrail.
            let sessions = state
                .core
                .recent_sessions_for(&session.user)
                .await?
                .into_iter()
                .map(|s| DashboardSession {
                    owner: s.owner,
                    repo: s.repo,
                    ulid: s.ulid,
                    agent: s.agent,
                    title: s.title,
                })
                .collect();
            (repos, assigned, awaiting, sessions)
        }
        None => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
    };
    Ok(DashboardPage {
        nav_user: nav(session.as_ref()),
        repos,
        assigned,
        awaiting,
        sessions,
        sign_up_open: state.core.sign_up_open(),
    })
}
