//! Email confirmation links (forge-basics design §4.2). `GET` shows a Confirm button and `POST` uses the link,
//! so mail scanners that prefetch links cannot use them up.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{CsrfForm, MaybeUser, anonymous_csrf, verify_anonymous_csrf, verify_csrf};
use crate::error::WebError;
use crate::pages::message::MessagePage;
use crate::views::{NavUser, nav};

#[derive(Template, WebTemplate)]
#[template(path = "verify.html")]
pub struct ConfirmPage {
    nav_user: Option<NavUser>,
    csrf: String,
    token: String,
}

#[derive(Deserialize)]
pub struct ResendForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    email: String,
}

fn invalid_link(session: Option<&WebSession>) -> Response {
    (
        StatusCode::NOT_FOUND,
        MessagePage::new(
            nav(session),
            "Link not valid",
            "This link is invalid, was already used, or has expired.",
        ),
    )
        .into_response()
}

pub async fn confirm_form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Path(token): Path<String>,
) -> Result<Response, WebError> {
    if !state.core.email_link_valid(&token).await? {
        return Ok(invalid_link(session.as_ref()));
    }
    // Signed-in visitors already carry a CSRF token (the page header's sign-out form uses it).
    let (jar, csrf) = match &session {
        Some(session) => (jar, session.csrf_token.clone()),
        None => anonymous_csrf(jar, state.settings.secure_cookies),
    };
    let page = ConfirmPage {
        nav_user: nav(session.as_ref()),
        csrf,
        token,
    };
    Ok((jar, page).into_response())
}

pub async fn confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Path(token): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    match &session {
        Some(session) => verify_csrf(&session.csrf_token, &form.csrf)?,
        None => verify_anonymous_csrf(&jar, &form.csrf)?,
    }
    match state.core.verify_email(&token).await {
        Ok(_) => {
            let (href, text) = if session.is_some() {
                ("/", "Continue")
            } else {
                ("/login", "Sign in")
            };
            let page = MessagePage::new(
                nav(session.as_ref()),
                "Email verified",
                "Your email address is verified.",
            )
            .with_link(href, text);
            Ok(page.into_response())
        }
        Err(CoreError::NotFound) => Ok(invalid_link(session.as_ref())),
        Err(other) => Err(other.into()),
    }
}

pub async fn resend(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ResendForm>,
) -> Result<MessagePage, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    state.core.resend_verification(&form.email).await?;
    Ok(MessagePage::new(
        None,
        "Check your email",
        "If an unverified account uses that address, we sent it a new link. It expires in 24 hours.",
    ))
}
