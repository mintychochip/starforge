use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::accounts::User;
use starforged_core::sessions::WebSession;
use starforged_core::tokens::{self, CreatedToken, Scope};
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, format_time};

#[derive(Deserialize)]
pub struct CreateTokenForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
    expires_days: u32,
}

pub struct TokenRow {
    id: i64,
    name: String,
    hint: String,
    scopes: String,
    expires: String,
    last_used: String,
    revoked: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "tokens.html")]
pub struct TokensPage {
    nav_user: Option<NavUser>,
    csrf: String,
    tokens: Vec<TokenRow>,
    scope_choices: Vec<&'static str>,
    created: Option<String>,
    error: Option<String>,
}

pub async fn list(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
) -> Result<TokensPage, WebError> {
    page(&state, &session, None, None).await
}

pub async fn create(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<CreateTokenForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match create_from_form(&state, &session.user, &form).await {
        Ok(created) => Ok(page(&state, &session, Some(created.secret), None)
            .await?
            .into_response()),
        Err(CoreError::Invalid(message)) => Ok((
            StatusCode::UNPROCESSABLE_ENTITY,
            page(&state, &session, None, Some(message)).await?,
        )
            .into_response()),
        Err(other) => Err(other.into()),
    }
}

pub async fn revoke(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path(id): Path<i64>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state.core.revoke_token(&session.user, id).await?;
    Ok(Redirect::to("/settings/tokens").into_response())
}

async fn create_from_form(
    state: &AppState,
    user: &User,
    form: &CreateTokenForm,
) -> CoreResult<CreatedToken> {
    let scopes = tokens::parse_scopes(&form.scopes.join(","))?;
    state
        .core
        .create_token(user, &form.name, &scopes, form.expires_days)
        .await
}

async fn page(
    state: &AppState,
    session: &WebSession,
    created: Option<String>,
    error: Option<String>,
) -> Result<TokensPage, WebError> {
    let rows = state
        .core
        .list_tokens(&session.user)
        .await?
        .into_iter()
        .map(|t| TokenRow {
            id: t.id,
            name: t.name,
            hint: t.hint,
            scopes: tokens::format_scopes(&t.scopes),
            expires: format_time(t.expires_at),
            last_used: t
                .last_used_at
                .map(format_time)
                .unwrap_or_else(|| "never".into()),
            revoked: t.revoked,
        })
        .collect();
    let scope_choices = Scope::ALL
        .into_iter()
        .filter(|s| *s != Scope::Admin || session.user.is_admin)
        .map(Scope::as_str)
        .collect();
    Ok(TokensPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        tokens: rows,
        scope_choices,
        created,
        error,
    })
}
