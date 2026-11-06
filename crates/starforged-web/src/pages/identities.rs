//! Linked sign-in identities (spec §10.1, plan D6): list the provider
//! identities linked to the account, link the provider (a `link`-intent
//! OIDC flow), and unlink — refused when it is the account's only way
//! to sign in.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::CoreError;
use starforged_core::oidc::LinkedIdentity;
use starforged_core::sessions::WebSession;

use crate::AppState;
use crate::auth::{RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::NavUser;

#[derive(Template, WebTemplate)]
#[template(path = "settings_identities.html")]
pub struct IdentitiesPage {
    nav_user: Option<NavUser>,
    csrf: String,
    settings_tab: &'static str,
    identities: Vec<LinkedIdentity>,
    oidc_enabled: bool,
    notice: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
pub struct IdentitiesForm {
    #[serde(rename = "_csrf")]
    csrf: String,
}

async fn page(
    state: &AppState,
    session: &WebSession,
    notice: Option<String>,
    error: Option<String>,
) -> Result<IdentitiesPage, WebError> {
    Ok(IdentitiesPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        settings_tab: "identities",
        identities: state.core.linked_identities(session.user.id).await?,
        oidc_enabled: state.core.oidc_enabled(),
        notice,
        error,
    })
}

pub async fn index(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<IdentitiesPage, WebError> {
    page(&state, &session, None, None).await
}

/// Starts a `link`-intent flow: the provider redirect carries the
/// challenge token in the OIDC cookie; the callback finishes the link.
pub async fn link(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<IdentitiesForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .oidc_begin(starforged_core::oidc::OidcIntent::Link {
            user_id: session.user.id,
        })
        .await
    {
        Ok((challenge, url)) => {
            let cookie = crate::auth::oidc_cookie(challenge, state.settings.secure_cookies);
            let jar = axum_extra::extract::cookie::CookieJar::new().add(cookie);
            Ok((jar, Redirect::to(&url)).into_response())
        }
        Err(_) => {
            let page = page(
                &state,
                &session,
                None,
                Some("Single sign-on is not available right now.".to_owned()),
            )
            .await?;
            Ok((StatusCode::BAD_GATEWAY, page).into_response())
        }
    }
}

pub async fn unlink(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
    Form(form): Form<IdentitiesForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state.core.unlink_identity(&session.user, id, "", "").await {
        Ok(()) => Ok(
            page(&state, &session, Some("Sign-in removed.".to_owned()), None)
                .await?
                .into_response(),
        ),
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            page(&state, &session, None, Some(message)).await?,
        )
            .into_response()),
        Err(CoreError::NotFound) => Ok((
            StatusCode::NOT_FOUND,
            page(
                &state,
                &session,
                None,
                Some("That sign-in is not linked to this account.".to_owned()),
            )
            .await?,
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}
