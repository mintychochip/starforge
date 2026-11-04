//! Password recovery pages (forge-basics design §4.5): `/forgot` asks for a link, `/reset/{token}` uses it.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::Form;
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;
use starforged_core::CoreError;

use crate::AppState;
use crate::auth::{MaybeUser, SESSION_COOKIE, anonymous_csrf, removal, verify_anonymous_csrf};
use crate::error::WebError;
use crate::pages::message::MessagePage;
use crate::views::{NavUser, nav};

#[derive(Template, WebTemplate)]
#[template(path = "forgot.html")]
pub struct ForgotPage {
    nav_user: Option<NavUser>,
    csrf: String,
}

#[derive(Template, WebTemplate)]
#[template(path = "reset.html")]
pub struct ResetPage {
    nav_user: Option<NavUser>,
    csrf: String,
    token: String,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct ForgotForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    email: String,
}

#[derive(Deserialize)]
pub struct ResetForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    password: String,
    confirm: String,
}

pub async fn forgot_form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
) -> Result<Response, WebError> {
    if !state.core.mail_enabled() {
        return Err(WebError::NotFound);
    }
    let (jar, csrf) = anonymous_csrf(jar, state.settings.secure_cookies);
    let page = ForgotPage {
        nav_user: nav(session.as_ref()),
        csrf,
    };
    Ok((jar, page).into_response())
}

pub async fn forgot(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ForgotForm>,
) -> Result<MessagePage, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    state.core.request_password_reset(&form.email).await?;
    Ok(MessagePage::new(
        None,
        "Check your email",
        "If an account uses that address, we sent it a link to choose a new password. The link expires in 1 hour.",
    ))
}

pub async fn reset_form(
    State(state): State<AppState>,
    jar: CookieJar,
    MaybeUser(session): MaybeUser,
    Path(token): Path<String>,
) -> Result<Response, WebError> {
    if !state.core.password_reset_valid(&token).await? {
        let page = MessagePage::new(
            nav(session.as_ref()),
            "Link not valid",
            "This reset link is invalid, already used, or expired.",
        );
        return Ok((StatusCode::NOT_FOUND, page).into_response());
    }
    let (jar, csrf) = anonymous_csrf(jar, state.settings.secure_cookies);
    let page = ResetPage {
        nav_user: nav(session.as_ref()),
        csrf,
        token,
        error: None,
    };
    Ok((jar, page).into_response())
}

pub async fn reset(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(token): Path<String>,
    Form(form): Form<ResetForm>,
) -> Result<Response, WebError> {
    verify_anonymous_csrf(&jar, &form.csrf)?;
    let error = if form.password != form.confirm {
        "The two passwords do not match.".to_owned()
    } else {
        match state.core.reset_password(&token, &form.password).await {
            Ok(_) => {
                // The reset ended every session of the account, including any in this browser.
                let page = MessagePage::new(
                    None,
                    "Password changed",
                    "Your password is changed, and every session of your account was signed out.",
                )
                .with_link("/login", "Sign in");
                return Ok((jar.remove(removal(SESSION_COOKIE)), page).into_response());
            }
            Err(CoreError::Invalid(message)) => message,
            Err(other) => return Err(other.into()),
        }
    };
    let page = ResetPage {
        nav_user: None,
        csrf: form.csrf,
        token,
        error: Some(error),
    };
    Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
}
