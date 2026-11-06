//! The branch protection settings page (M3b B3, D6): gate rules with
//! their push restrictions and the tag-protection list, maintainer-only.
//! Every form carries the full rule specification (absent checkboxes mean
//! false, blank inputs mean empty) and answers 303 or a 422 re-render.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::gate_rules::{GateRuleDto, GateRuleInput};
use starforged_core::permission::Permission;
use starforged_core::protection::{PushAllowlistInput, TagProtectionDto, TagProtectionInput};
use starforged_core::sessions::WebSession;
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};

#[derive(Template, WebTemplate)]
#[template(path = "protection.html")]
pub struct ProtectionPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    gate_rules: Vec<GateRuleDto>,
    tag_protections: Vec<TagProtectionDto>,
    error: Option<String>,
}

/// A gate-rule form: every field is optional so an unchecked checkbox
/// (absent) and an untouched text input both survive the round trip.
/// Contexts, methods, users, and teams are comma-separated text; a blank
/// input means none.
#[derive(Deserialize)]
pub struct ProtectionRuleForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    required_approvals: Option<String>,
    #[serde(default)]
    dismiss_on_push: Option<String>,
    #[serde(default)]
    block_on_request_changes: Option<String>,
    #[serde(default)]
    required_contexts: Option<String>,
    #[serde(default)]
    require_up_to_date: Option<String>,
    #[serde(default)]
    require_threads_resolved: Option<String>,
    #[serde(default)]
    require_session_evidence: Option<String>,
    #[serde(default)]
    allowed_methods: Option<String>,
    #[serde(default)]
    block_direct_push: Option<String>,
    #[serde(default)]
    block_force_push: Option<String>,
    #[serde(default)]
    block_deletion: Option<String>,
    #[serde(default)]
    push_users: Option<String>,
    #[serde(default)]
    push_teams: Option<String>,
}

/// Splits a comma-separated form input; blank means none, anything else is
/// passed through whole so invalid entries fail validation (never dropped).
fn split_list(raw: Option<&str>) -> Vec<String> {
    match raw.map(str::trim) {
        None | Some("") => Vec::new(),
        Some(text) => text
            .split(',')
            .map(|entry| entry.trim().to_owned())
            .collect(),
    }
}

/// Builds the Core input from the settings form. Both the create and the
/// edit forms are full specifications: an absent checkbox means false and a
/// blank text input means empty, so unchecking a box or clearing the
/// allow-list stores that. Editing stays in place rather than
/// delete-then-recreate so no window opens where the branch is unprotected.
fn form_input(form: &ProtectionRuleForm) -> CoreResult<GateRuleInput> {
    let approvals = match &form.required_approvals {
        None => None,
        Some(raw) => Some(Some(raw.trim().parse::<i64>().map_err(|_| {
            CoreError::Invalid(format!(
                "invalid required_approvals '{}' (expected 0-20)",
                raw.trim()
            ))
        })?)),
    };
    Ok(GateRuleInput {
        pattern: Some(form.pattern.clone()),
        required_approvals: approvals,
        dismiss_on_push: Some(Some(form.dismiss_on_push.is_some())),
        block_on_request_changes: Some(Some(form.block_on_request_changes.is_some())),
        required_contexts: Some(Some(split_list(form.required_contexts.as_deref()))),
        require_up_to_date: Some(Some(form.require_up_to_date.is_some())),
        require_threads_resolved: Some(Some(form.require_threads_resolved.is_some())),
        require_session_evidence: Some(Some(form.require_session_evidence.is_some())),
        allowed_methods: Some(Some(split_list(form.allowed_methods.as_deref()))),
        block_direct_push: Some(Some(form.block_direct_push.is_some())),
        block_force_push: Some(Some(form.block_force_push.is_some())),
        block_deletion: Some(Some(form.block_deletion.is_some())),
        push_allowlist: Some(Some(PushAllowlistInput {
            users: split_list(form.push_users.as_deref()),
            teams: split_list(form.push_teams.as_deref()),
        })),
    })
}

#[derive(Deserialize)]
pub struct TagProtectionForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    pattern: Option<String>,
}

pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<ProtectionPage, WebError> {
    page(&state, &session, &owner, &repo, None)
        .await
        .map_err(WebError::from)
}

/// Creates a gate rule from the protection form (Maintain+); success
/// redirects 303 back to the protection page.
pub async fn create_rule(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<ProtectionRuleForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let input = match form_input(&form) {
        Ok(input) => input,
        Err(message @ CoreError::Invalid(_)) => {
            return invalid(&state, &session, &owner, &repo, message.to_string()).await;
        }
        Err(other) => return Err(other.into()),
    };
    match state
        .core
        .create_gate_rule(&session.user, &owner, &repo, &input)
        .await
    {
        Ok(_) => Ok(protection_redirect(&owner, &repo).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            invalid(&state, &session, &owner, &repo, message).await
        }
        Err(other) => Err(other.into()),
    }
}

/// Replaces a gate rule in place (Maintain+): editing is in place because
/// delete-then-recreate would open a window where the branch is
/// unprotected and a merge can slip through. Success redirects 303.
pub async fn update_rule(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    Form(form): Form<ProtectionRuleForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let input = match form_input(&form) {
        Ok(input) => input,
        Err(message @ CoreError::Invalid(_)) => {
            return invalid(&state, &session, &owner, &repo, message.to_string()).await;
        }
        Err(other) => return Err(other.into()),
    };
    match state
        .core
        .update_gate_rule(&session.user, &owner, &repo, id, &input)
        .await
    {
        Ok(_) => Ok(protection_redirect(&owner, &repo).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            invalid(&state, &session, &owner, &repo, message).await
        }
        Err(other) => Err(other.into()),
    }
}

/// Deletes a gate rule (Maintain+); success redirects 303. Refused input
/// (for example an archived repository) re-renders with 422.
pub async fn delete_rule(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .delete_gate_rule(&session.user, &owner, &repo, id)
        .await
    {
        Ok(()) => Ok(protection_redirect(&owner, &repo).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            invalid(&state, &session, &owner, &repo, message).await
        }
        Err(other) => Err(other.into()),
    }
}

/// Adds a tag protection (Maintain+); success redirects 303.
pub async fn create_tag(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<TagProtectionForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let input = TagProtectionInput {
        pattern: form.pattern.clone(),
    };
    match state
        .core
        .create_tag_protection(&session.user, &owner, &repo, &input)
        .await
    {
        Ok(_) => Ok(protection_redirect(&owner, &repo).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            invalid(&state, &session, &owner, &repo, message).await
        }
        Err(other) => Err(other.into()),
    }
}

/// Removes a tag protection (Maintain+); success redirects 303. Refused
/// input (for example an archived repository) re-renders with 422.
pub async fn delete_tag(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .delete_tag_protection(&session.user, &owner, &repo, id)
        .await
    {
        Ok(()) => Ok(protection_redirect(&owner, &repo).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            invalid(&state, &session, &owner, &repo, message).await
        }
        Err(other) => Err(other.into()),
    }
}

fn protection_redirect(owner: &str, repo: &str) -> Redirect {
    Redirect::to(&format!("/{owner}/{repo}/settings/protection"))
}

async fn invalid(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: String,
) -> Result<Response, WebError> {
    let page = page(state, session, owner, repo, Some(error)).await?;
    Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
}

async fn page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
) -> CoreResult<ProtectionPage> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Maintain)
        .await?;
    let gate_rules = state
        .core
        .list_gate_rules(Some(&session.user), owner, repo)
        .await?;
    let tag_protections = state
        .core
        .list_tag_protections(Some(&session.user), owner, repo)
        .await?;
    Ok(ProtectionPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "protection",
        gate_rules,
        tag_protections,
        error,
    })
}
