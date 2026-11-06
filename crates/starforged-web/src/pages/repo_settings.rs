//! The repository settings page (forge-basics design §5.2): general settings for maintainers; visibility and
//! the actions after it for admins.

use askama::Template;
use askama_web::WebTemplate;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::Form;
use serde::Deserialize;
use starforged_core::gate_rules::{GateRuleDto, GateRuleInput};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::Repo;
use starforged_core::sessions::WebSession;
use starforged_core::{CoreError, CoreResult};

use crate::AppState;
use crate::auth::{CsrfForm, RequireUser, verify_csrf};
use crate::error::WebError;
use crate::views::{NavUser, RepoHead};

pub struct BranchOption {
    name: String,
    selected: bool,
}

pub struct VisibilityChoice {
    value: &'static str,
    label: &'static str,
    checked: bool,
}
pub struct RefsForAccessChoice {
    value: &'static str,
    label: &'static str,
    selected: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_settings.html")]
pub struct RepoSettingsPage {
    nav_user: Option<NavUser>,
    csrf: String,
    head: RepoHead,
    settings_page: &'static str,
    description: String,
    branches: Vec<BranchOption>,
    visibility_choices: Vec<VisibilityChoice>,
    refs_for_access_choices: Vec<RefsForAccessChoice>,
    error: Option<String>,
    gate_rules: Vec<GateRuleDto>,
}

#[derive(Deserialize)]
pub struct GeneralForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    description: String,
    /// Absent while the repository has no branches.
    #[serde(default)]
    default_branch: String,
}

#[derive(Deserialize)]
pub struct VisibilityForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    visibility: String,
}

pub async fn show(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
) -> Result<RepoSettingsPage, WebError> {
    page(&state, &session, &owner, &repo, None).await
}

pub async fn save_general(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<GeneralForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let user = &session.user;
    let branch = if form.default_branch.is_empty() {
        Ok(())
    } else {
        state
            .core
            .set_default_branch(user, &owner, &repo, &form.default_branch)
            .await
            .map(|_| ())
    };
    let result = match branch {
        Ok(()) => {
            state
                .core
                .set_repo_description(user, &owner, &repo, &form.description)
                .await
        }
        Err(err) => Err(err),
    };
    finish(&state, &session, &owner, &repo, result).await
}

pub async fn change_visibility(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<VisibilityForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let visibility = Visibility::parse(&form.visibility)
        .ok_or_else(|| WebError::BadRequest("unknown visibility".into()))?;
    let result = state
        .core
        .set_visibility(&session.user, &owner, &repo, visibility)
        .await;
    finish(&state, &session, &owner, &repo, result).await
}
#[derive(Deserialize)]
pub struct RefsForAccessForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    refs_for_access: String,
}

/// Who may push `refs/for/*`: anyone with read access, or members only.
/// Maintain+ (the page gate); unknown values answer 422 through `finish`.
pub async fn change_refs_for_access(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<RefsForAccessForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = match state
        .core
        .set_refs_for_access(&session.user, &owner, &repo, &form.refs_for_access)
        .await
    {
        Ok(_) => state
            .core
            .repo_for(Some(&session.user), &owner, &repo)
            .await
            .map(|access| access.repo),
        Err(err) => Err(err),
    };
    finish(&state, &session, &owner, &repo, result).await
}

/// Merge-gate rule form: every field is optional so an unchecked checkbox
/// (absent) and an untouched text input both survive the round trip.
/// Contexts and methods are comma-separated text; a blank input means none.
#[derive(Deserialize)]
pub struct GateRuleForm {
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
/// edit forms are full specifications: an absent checkbox means false (the
/// pre-checked "Block on request changes" default lives only in the
/// template, so unchecking it stores false) and an absent text input means
/// empty. Editing stays in place rather than delete-then-recreate so no
/// window opens where the branch is unprotected.
fn form_input(form: &GateRuleForm) -> CoreResult<GateRuleInput> {
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
    })
}

async fn gate_rule_page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: String,
) -> Result<Response, WebError> {
    let page = page(state, session, owner, repo, Some(error)).await?;
    Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
}

/// Creates a gate rule from the settings form (Maintain+); success
/// redirects 303 back to the settings page.
pub async fn create_gate_rule(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<GateRuleForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let input = match form_input(&form) {
        Ok(input) => input,
        Err(message @ CoreError::Invalid(_)) => {
            return gate_rule_page(&state, &session, &owner, &repo, message.to_string()).await;
        }
        Err(other) => return Err(other.into()),
    };
    match state
        .core
        .create_gate_rule(&session.user, &owner, &repo, &input)
        .await
    {
        Ok(_) => Ok(Redirect::to(&format!("/{owner}/{repo}/settings")).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            gate_rule_page(&state, &session, &owner, &repo, message).await
        }
        Err(other) => Err(other.into()),
    }
}

/// Replaces a gate rule in place (Maintain+): editing is in place because
/// delete-then-recreate would open a window where the branch is
/// unprotected and a merge can slip through. Success redirects 303.
pub async fn update_gate_rule(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    Form(form): Form<GateRuleForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let input = match form_input(&form) {
        Ok(input) => input,
        Err(message @ CoreError::Invalid(_)) => {
            return gate_rule_page(&state, &session, &owner, &repo, message.to_string()).await;
        }
        Err(other) => return Err(other.into()),
    };
    match state
        .core
        .update_gate_rule(&session.user, &owner, &repo, id, &input)
        .await
    {
        Ok(_) => Ok(Redirect::to(&format!("/{owner}/{repo}/settings")).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            gate_rule_page(&state, &session, &owner, &repo, message).await
        }
        Err(other) => Err(other.into()),
    }
}

/// Deletes a gate rule (Maintain+); success redirects 303.
pub async fn delete_gate_rule(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo, id)): Path<(String, String, i64)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .delete_gate_rule(&session.user, &owner, &repo, id)
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}/settings")).into_response())
}

#[derive(Deserialize)]
pub struct RenameForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    new_name: String,
}

pub async fn rename(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<RenameForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = state
        .core
        .rename_repo(&session.user, &owner, &repo, &form.new_name)
        .await;
    finish(&state, &session, &owner, &repo, result).await
}

#[derive(Deserialize)]
pub struct TransferForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    new_owner: String,
}

/// Moves the repository to another owner: the actor, or an org the actor
/// owns. The old path keeps working through the rename redirect. Admins
/// only; success lands on the repository's new home.
pub async fn transfer(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<TransferForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    if form.new_owner.trim().is_empty() {
        let page = page(
            &state,
            &session,
            &owner,
            &repo,
            Some("choose a new owner".into()),
        )
        .await?;
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response());
    }
    match state
        .core
        .transfer_repo(&session.user, &owner, &repo, &form.new_owner)
        .await
    {
        Ok(updated) => {
            Ok(Redirect::to(&format!("/{}/{}", updated.owner, updated.name)).into_response())
        }
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(&state, &session, &owner, &repo, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

pub async fn archive(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = state.core.archive_repo(&session.user, &owner, &repo).await;
    finish(&state, &session, &owner, &repo, result).await
}

pub async fn unarchive(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<CsrfForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let result = state
        .core
        .unarchive_repo(&session.user, &owner, &repo)
        .await;
    finish(&state, &session, &owner, &repo, result).await
}

#[derive(Deserialize)]
pub struct DeleteForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    confirm: String,
}

/// After deleting, owners land on Settings → Repositories (where Restore is); site admins deleting someone
/// else's repository land on the owner's page.
pub async fn delete(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<DeleteForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    match state
        .core
        .delete_repo(&session.user, &owner, &repo, &form.confirm)
        .await
    {
        Ok(deleted) => {
            let next = if deleted.owner_id == session.user.id {
                "/settings/repositories".to_owned()
            } else {
                format!("/{}", deleted.owner)
            };
            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => finish(&state, &session, &owner, &repo, Err(err)).await,
    }
}

/// After a settings action: back to the settings page under the repository's current name, or this page
/// again with the message when the input was refused.
pub(crate) async fn finish(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    result: CoreResult<Repo>,
) -> Result<Response, WebError> {
    match result {
        Ok(updated) => Ok(
            Redirect::to(&format!("/{}/{}/settings", updated.owner, updated.name)).into_response(),
        ),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(state, session, owner, repo, Some(message)).await?;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

async fn page(
    state: &AppState,
    session: &WebSession,
    owner: &str,
    repo: &str,
    error: Option<String>,
) -> Result<RepoSettingsPage, WebError> {
    let access = state
        .core
        .require_repo(Some(&session.user), owner, repo, Permission::Maintain)
        .await?;
    let branches = state
        .core
        .branches(&access)
        .await?
        .into_iter()
        .map(|name| BranchOption {
            selected: name == access.repo.default_branch,
            name,
        })
        .collect();
    let current = access.repo.visibility;
    let visibility_choices = [
        (Visibility::Private, "Private"),
        (
            Visibility::Internal,
            "Internal (every signed-in user can read)",
        ),
        (Visibility::Public, "Public"),
    ]
    .into_iter()
    .map(|(visibility, label)| VisibilityChoice {
        value: visibility.as_str(),
        label,
        checked: visibility == current,
    })
    .collect();
    let current_access = state.core.refs_for_access(access.repo.id).await?;
    let refs_for_access_choices = [
        ("anyone_with_read", "Anyone with read access"),
        ("members", "Repository members only"),
    ]
    .into_iter()
    .map(|(value, label)| RefsForAccessChoice {
        value,
        label,
        selected: value == current_access,
    })
    .collect();
    let gate_rules = state
        .core
        .list_gate_rules(Some(&session.user), owner, repo)
        .await?;
    Ok(RepoSettingsPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        head: RepoHead::new(&access, "settings", None),
        settings_page: "general",
        description: access.repo.description.clone(),
        branches,
        visibility_choices,
        refs_for_access_choices,
        error,
        gate_rules,
    })
}
