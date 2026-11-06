//! Two-factor authentication settings (spec §10.1): enroll, confirm,
//! disable, and regenerate recovery codes. Recovery codes are shown
//! exactly once, in the response that issued them.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::sessions::WebSession;
use starforged_core::totp::TotpEnrollment;

use crate::AppState;
use crate::auth::{RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Template, WebTemplate)]
#[template(path = "settings_two_factor.html")]
pub struct TwoFactorPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    enabled: bool,
    pending: Option<TotpEnrollment>,
    codes: Option<Vec<String>>,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct TwoFactorForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    action: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    code: String,
}

async fn page(
    state: &AppState,
    session: &WebSession,
    codes: Option<Vec<String>>,
    notice: Option<String>,
    error: Option<String>,
) -> Result<TwoFactorPage, WebError> {
    let status = state.core.two_factor_status(&session.user).await?;
    Ok(TwoFactorPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "two-factor",
        enabled: status.enabled,
        pending: status.pending,
        codes,
        notice,
        error,
    })
}

pub async fn index(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<TwoFactorPage, WebError> {
    page(&state, &session, None, None, None).await
}

pub async fn submit(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<TwoFactorForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result: starforged_core::CoreResult<Option<Vec<String>>> = match form.action.as_str() {
        "enroll" => state
            .core
            .begin_totp_enrollment(&session.user)
            .await
            .map(|_| None),
        "confirm" => state
            .core
            .confirm_totp_enrollment(&session.user, &form.code)
            .await
            .map(Some),
        "disable" => state
            .core
            .disable_totp(&session.user, &form.password, &form.code)
            .await
            .map(|_| None),
        "regenerate" => state
            .core
            .regenerate_recovery_codes(&session.user, &form.code)
            .await
            .map(Some),
        _ => Err(CoreError::Invalid("Unknown action.".into())),
    };
    match result {
        Ok(codes) => {
            let notice = if form.action == "disable" {
                Some("Two-factor authentication is disabled.".to_owned())
            } else if form.action == "enroll" {
                Some(
                    "Scan the code or enter the secret, then confirm with a 6-digit code."
                        .to_owned(),
                )
            } else if form.action == "confirm" {
                Some("Two-factor authentication is enabled. Save these recovery codes — they are shown once.".to_owned())
            } else {
                Some("Save these new recovery codes — they are shown once. The old codes no longer work.".to_owned())
            };
            Ok(page(&state, &session, codes, notice, None)
                .await?
                .into_response())
        }
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            page(&state, &session, None, None, Some(message)).await?,
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}
