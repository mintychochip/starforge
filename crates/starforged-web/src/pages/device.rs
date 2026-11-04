use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;

use crate::AppState;
use crate::auth::{RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Deserialize)]
pub struct DeviceQuery {
    user_code: Option<String>,
}

#[derive(Deserialize)]
pub struct ApproveForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    user_code: String,
    decision: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "device.html")]
pub struct DevicePage {
    nav_user: Option<NavUser>,
    csrf: String,
    user_code: String,
    approved: Option<String>,
    error: Option<String>,
}

/// `GET /oauth/device`: the CLI prints this URI; the signed-in user types or
/// pastes the shown `user_code` and approves or denies the login.
pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Query(query): Query<DeviceQuery>,
) -> DevicePage {
    page(
        &state,
        &session,
        query.user_code.unwrap_or_default(),
        None,
        None,
    )
}

/// `POST /oauth/device/approve`: binds the signed-in user to the pending code
/// (approve) or marks it denied. Re-renders the page with a banner, the same
/// created/error pattern as the tokens settings page. No JS.
pub async fn approve(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<ApproveForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let decision = match form.decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => {
            return Ok((
                StatusCode::UNPROCESSABLE_ENTITY,
                page(
                    &state,
                    &session,
                    form.user_code,
                    None,
                    Some("Choose Approve or Deny.".to_owned()),
                ),
            )
                .into_response());
        }
    };
    match state
        .core
        .approve_device_code(&session.user, &form.user_code, decision)
        .await
    {
        Ok(()) => {
            let banner = if decision {
                "Device approved. You can return to your terminal."
            } else {
                "Device denied. The login attempt was rejected."
            };
            Ok(page(
                &state,
                &session,
                String::new(),
                Some(banner.to_owned()),
                None,
            )
            .into_response())
        }
        Err(CoreError::NotFound) => Err(WebError::NotFound),
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            page(&state, &session, form.user_code, None, Some(message)),
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

fn page(
    _state: &AppState,
    session: &starforged_core::sessions::WebSession,
    user_code: String,
    approved: Option<String>,
    error: Option<String>,
) -> DevicePage {
    DevicePage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        user_code,
        approved,
        error,
    }
}
