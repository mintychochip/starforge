//! `sessions publish`/`unpublish`/`delete`: server-side session
//! administration through the JSON API.
//!
//! Each handler takes an injected [`ApiClient`] and returns `(output, exit
//! code)` in the trail-command style: success text on stdout-equivalent,
//! `error: …` on stderr-equivalent. `delete` additionally requires an
//! explicit confirmation (`--yes`): without it the handler refuses before
//! touching the server, so an accidental invocation can never destroy a
//! session.

use std::path::Path;

use crate::api::ApiClient;
use crate::config::CliPaths;

/// Resolve the server, effective `owner/repo`, and bearer token for
/// `repo_dir`: server + token through the usual discovery, with
/// `owner_repo` overridden by `--repo` when given (the `--repo` value must
/// be `owner/name`). Returns `(api_url, owner_repo, token)`.
pub async fn resolve_parts(
    repo_dir: &Path,
    paths: &CliPaths,
    repo_override: Option<&str>,
) -> Result<(String, String, String), String> {
    let (server, owner_repo, _remote) = crate::commands::status::resolve_server(repo_dir, paths)
        .await
        .map_err(|err| err.to_string())?;
    let owner_repo = match repo_override {
        Some(override_) => validate_owner_repo(override_)?,
        None => owner_repo,
    };
    let host = crate::cli::sync_host_key(&server.api_url)
        .ok_or_else(|| format!("invalid server api_url: {}", server.api_url))?;
    let token = crate::auth::resolve_token(paths, &host, |key| std::env::var(key).ok())
        .map_err(|err| err.to_string())?;
    Ok((server.api_url, owner_repo, token.token().to_string()))
}

/// Resolve the API client for `repo_dir` (see [`resolve_parts`]).
pub async fn resolve_api(
    repo_dir: &Path,
    paths: &CliPaths,
    repo_override: Option<&str>,
) -> Result<ApiClient, String> {
    let (api_url, owner_repo, token) = resolve_parts(repo_dir, paths, repo_override).await?;
    ApiClient::new(&api_url, &owner_repo, &token).map_err(|err| err.to_string())
}
/// A `--repo` override must be exactly `owner/name`, both parts non-empty.
fn validate_owner_repo(value: &str) -> Result<String, String> {
    let (owner, name) = value
        .split_once('/')
        .ok_or_else(|| format!("invalid --repo '{value}': want owner/name"))?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return Err(format!("invalid --repo '{value}': want owner/name"));
    }
    Ok(value.to_string())
}

/// `POST sessions/{ulid}/publish`: flip the session to `published`.
pub async fn publish(api: &ApiClient, ulid: &str) -> (String, u8) {
    match api
        .post(&format!("sessions/{ulid}/publish"), &serde_json::json!({}))
        .await
    {
        Ok(_) => (format!("published {ulid}"), 0),
        Err(err) => api.render_error(err),
    }
}

/// `POST sessions/{ulid}/unpublish`: back to `inherit` (an `Ok` no-op when
/// the session was never published).
pub async fn unpublish(api: &ApiClient, ulid: &str) -> (String, u8) {
    match api
        .post(
            &format!("sessions/{ulid}/unpublish"),
            &serde_json::json!({}),
        )
        .await
    {
        Ok(_) => (format!("unpublished {ulid}"), 0),
        Err(err) => api.render_error(err),
    }
}

/// `DELETE sessions/{ulid}`: remove the session, its segments (blob
/// refcounts decremented), and its commit links. Refuses without
/// `confirmed` before any request; `404` (unknown session or no delete
/// permission) renders as the standard API error.
pub async fn delete(api: &ApiClient, ulid: &str, confirmed: bool) -> (String, u8) {
    if !confirmed {
        return (
            format!("error: refusing to delete session {ulid} without --yes"),
            1,
        );
    }
    match api.delete(&format!("sessions/{ulid}")).await {
        Ok(()) => (format!("deleted {ulid}"), 0),
        Err(err) => api.render_error(err),
    }
}
