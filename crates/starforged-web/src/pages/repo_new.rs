use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::permission::Visibility;
use starforged_core::repos::CreateRepo;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Deserialize)]
pub struct NewRepoForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    name: String,
    #[serde(default)]
    description: String,
    visibility: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_new.html")]
pub struct RepoNewPage {
    nav_user: Option<NavUser>,
    csrf: String,
    owner: String,
    name: String,
    description: String,
    error: Option<String>,
}

fn page(
    session: &WebSession,
    name: String,
    description: String,
    error: Option<String>,
) -> RepoNewPage {
    RepoNewPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        owner: session.user.handle.clone(),
        name,
        description,
        error,
    }
}

pub async fn form(RequireUser(session): RequireUser) -> RepoNewPage {
    page(&session, String::new(), String::new(), None)
}

pub async fn submit(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<NewRepoForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let visibility = Visibility::parse(&form.visibility)
        .ok_or_else(|| WebError::BadRequest("unknown visibility".into()))?;
    let input = CreateRepo {
        name: form.name.clone(),
        description: form.description.clone(),
        visibility,
    };
    match state.core.create_repo(&session.user, input).await {
        Ok(repo) => Ok(Redirect::to(&format!("/{}/{}", repo.owner, repo.name)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(&session, form.name, form.description, Some(message));
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}
