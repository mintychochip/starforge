use askama::Template;
use askama_web::WebTemplate;
use axum::extract::Path;
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
    /// The owner handle: the user or an org they own. Empty means the user.
    #[serde(default)]
    owner: String,
    name: String,
    #[serde(default)]
    description: String,
    visibility: String,
    /// The "Initialize with a README" checkbox: present only when ticked.
    #[serde(default)]
    readme: Option<String>,
    /// "Import from URL": empty (or absent) means no import.
    #[serde(default)]
    import_url: String,
    /// `""`/`none`, `https`, or `ssh`.
    #[serde(default)]
    import_auth: String,
    #[serde(default)]
    import_username: String,
    #[serde(default)]
    import_password: String,
}

pub struct OwnerOption {
    value: String,
    selected: bool,
}

#[derive(Template, WebTemplate)]
#[template(path = "repo_new.html")]
pub struct RepoNewPage {
    nav_user: Option<NavUser>,
    csrf: String,
    owners: Vec<OwnerOption>,
    name: String,
    description: String,
    readme: bool,
    import_url: String,
    import_auth: String,
    import_username: String,
    error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn page(
    state: &AppState,
    session: &WebSession,
    owner: String,
    name: String,
    description: String,
    readme: bool,
    import_url: String,
    import_auth: String,
    import_username: String,
    error: Option<String>,
) -> RepoNewPage {
    let mut owners = vec![OwnerOption {
        selected: owner == session.user.handle,
        value: session.user.handle.clone(),
    }];
    // `create_repo` rechecks ownership at submit; a failed lookup here only
    // hides the selector options, never grants anything.
    if let Ok(orgs) = state.core.owned_orgs(&session.user).await {
        for handle in orgs {
            owners.push(OwnerOption {
                selected: owner == handle,
                value: handle,
            });
        }
    }
    RepoNewPage {
        nav_user: Some(NavUser::from_session(session)),
        csrf: session.csrf_token.clone(),
        owners,
        name,
        description,
        readme,
        import_url,
        import_auth,
        import_username,
        error,
    }
}

pub async fn form(State(state): State<AppState>, RequireUser(session): RequireUser) -> RepoNewPage {
    let owner = session.user.handle.clone();
    page(
        &state,
        &session,
        owner,
        String::new(),
        String::new(),
        false,
        String::new(),
        String::new(),
        String::new(),
        None,
    )
    .await
}

pub async fn submit(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Form(form): Form<NewRepoForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let owner = if form.owner.trim().is_empty() {
        session.user.handle.clone()
    } else {
        form.owner.trim().to_ascii_lowercase()
    };
    let visibility = Visibility::parse(&form.visibility)
        .ok_or_else(|| WebError::BadRequest("unknown visibility".into()))?;
    let readme = form.readme.is_some();
    let import = if form.import_url.trim().is_empty() {
        None
    } else {
        let auth = match form.import_auth.trim() {
            "https" => starforged_core::remotes::ImportAuth::Https {
                username: form.import_username.trim().to_owned(),
                password: form.import_password.clone(),
            },
            "ssh" => starforged_core::remotes::ImportAuth::Ssh,
            "" | "none" => starforged_core::remotes::ImportAuth::None,
            _ => return Err(WebError::BadRequest("unknown import auth".into())),
        };
        Some(starforged_core::remotes::ImportInput {
            url: form.import_url.trim().to_owned(),
            auth,
        })
    };
    let input = CreateRepo {
        name: form.name.clone(),
        description: form.description.clone(),
        visibility,
        readme,
    };
    match state
        .core
        .create_repo_with_import(&session.user, &owner, input, import)
        .await
    {
        Ok(repo) => Ok(Redirect::to(&format!("/{}/{}", repo.owner, repo.name)).into_response()),
        Err(CoreError::Invalid(message) | CoreError::Conflict(message)) => {
            let page = page(
                &state,
                &session,
                owner,
                form.name,
                form.description,
                readme,
                starforged_git::remote::scrub(&form.import_url, &form.import_url),
                form.import_auth,
                form.import_username,
                Some(message),
            )
            .await;
            Ok((StatusCode::UNPROCESSABLE_ENTITY, page).into_response())
        }
        Err(other) => Err(other.into()),
    }
}

#[derive(Deserialize)]
pub struct ImportStartForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(default)]
    import_auth: String,
    #[serde(default)]
    import_username: String,
    #[serde(default)]
    import_password: String,
}

/// `POST /{owner}/{repo}/import/start`: "start import" and retry from the
/// repository banner. Optional re-entered credentials fix a failed import.
pub async fn import_start(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<ImportStartForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    let new_auth = match form.import_auth.trim() {
        "https" => Some(starforged_core::remotes::ImportAuth::Https {
            username: form.import_username.trim().to_owned(),
            password: form.import_password.clone(),
        }),
        "ssh" => Some(starforged_core::remotes::ImportAuth::Ssh),
        _ => None,
    };
    state
        .core
        .start_import(&session.user, &owner, &repo, new_auth)
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}")).into_response())
}

#[derive(Deserialize)]
pub struct ImportDeleteForm {
    #[serde(rename = "_csrf")]
    csrf: String,
}

/// `POST /{owner}/{repo}/import/delete`: deletes the import source.
pub async fn import_delete(
    State(state): State<AppState>,
    RequireUser(session): RequireUser,
    Path((owner, repo)): Path<(String, String)>,
    Form(form): Form<ImportDeleteForm>,
) -> Result<Response, WebError> {
    verify_csrf(&session.csrf_token, &form.csrf)?;
    state
        .core
        .delete_import(&session.user, &owner, &repo)
        .await?;
    Ok(Redirect::to(&format!("/{owner}/{repo}")).into_response())
}
