//! `auth ssh-key add`: register an OpenSSH public key for `git push` over SSH.
//!
//! `auth login` authenticates the CLI's own API calls only and never hands
//! its token to git, so pushing still needs git's own credentials. This
//! command runs a *new* device flow requesting only [`SSH_KEY_SCOPE`]
//! (`repo:write`, required by `POST /api/v1/user/keys`), uses the resulting
//! token for exactly one key registration, then discards it. The stored
//! login token (the credentials file) is never read for writing and is left
//! untouched; the only credentials-file read happens when the server has to
//! be inferred from the single stored host (no `--server`, no repo).

use std::path::{Path, PathBuf};

use crate::auth::{AuthError, DeviceFlow, SSH_KEY_SCOPE, load_credentials, normalize_server};
use crate::config::CliPaths;
use crate::queue::Sleeper;

/// Default public-key candidates under `<home>/.ssh/`, first existing wins.
pub const DEFAULT_KEY_NAMES: [&str; 3] = ["id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"];

/// A key registered on the server (fields the CLI reports back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedKey {
    pub fingerprint: String,
    pub algorithm: String,
    pub title: String,
}

/// Resolve the public key to register: `(path, single-line key text)`.
///
/// - `explicit` set: a path ending in `.pub` is read as-is; a path without
///   `.pub` is redirected to `<path>.pub` when that exists, and otherwise
///   refused *without reading* (it would be a private key file; private keys
///   are never read or sent). `~` expands against `home`.
/// - `explicit` unset: the first existing of [`DEFAULT_KEY_NAMES`] under
///   `<home>/.ssh/`.
///
/// The file content must be a single-line OpenSSH public key.
pub fn resolve_public_key(
    home: &Path,
    explicit: Option<PathBuf>,
) -> Result<(PathBuf, String), AuthError> {
    let path = match explicit {
        Some(given) => {
            let expanded = expand_home(home, given);
            if has_pub_suffix(&expanded) {
                expanded
            } else {
                let sibling = sibling_pub(&expanded);
                if sibling.exists() {
                    sibling
                } else {
                    return Err(AuthError::Config(format!(
                        "refusing to use {}: it is not a public key file; \
                         give a .pub file (a private key is never read or sent)",
                        expanded.display()
                    )));
                }
            }
        }
        None => {
            let mut found = None;
            for name in DEFAULT_KEY_NAMES {
                let candidate = home.join(".ssh").join(name);
                if candidate.exists() {
                    found = Some(candidate);
                    break;
                }
            }
            found.ok_or_else(|| {
                AuthError::Config(format!(
                    "no public key found (looked for {} under {}); \
                     pass a public key path or run ssh-keygen -t ed25519",
                    DEFAULT_KEY_NAMES.join(", "),
                    home.join(".ssh").display()
                ))
            })?
        }
    };
    let content = std::fs::read_to_string(&path)
        .map_err(|err| AuthError::Io(format!("{}: {err}", path.display())))?;
    let key = validate_public_key(&content, &path)?;
    Ok((path, key))
}

/// Expand a leading `~/` (or bare `~`) against `home`.
fn expand_home(home: &Path, path: PathBuf) -> PathBuf {
    if path == Path::new("~") {
        return home.to_path_buf();
    }
    if let Ok(rest) = path.strip_prefix("~") {
        let mut out = home.to_path_buf();
        out.push(rest);
        return out;
    }
    path
}

fn has_pub_suffix(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "pub")
}

fn sibling_pub(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".pub");
    PathBuf::from(name)
}

/// Validate file content as one OpenSSH public-key line; returns the trimmed
/// line (trailing newline stripped). Private key material, multi-line files,
/// and non-OpenSSH content are refused.
fn validate_public_key(content: &str, path: &Path) -> Result<String, AuthError> {
    let refuse = |why: &str| {
        AuthError::Config(format!(
            "{}: not a single-line OpenSSH public key ({why})",
            path.display()
        ))
    };
    if content.contains("PRIVATE KEY") || content.trim_start().starts_with("-----BEGIN") {
        return Err(AuthError::Config(format!(
            "refusing to use {}: it is a private key; only .pub files are read or sent",
            path.display()
        )));
    }
    let key = content.trim_end_matches(['\r', '\n']);
    if key.is_empty() {
        return Err(refuse("file is empty"));
    }
    if key.contains('\n') || key.contains('\r') {
        return Err(refuse("only one key per file"));
    }
    let mut parts = key.split_whitespace();
    let algorithm = parts.next().ok_or_else(|| refuse("empty"))?;
    const ACCEPTED: [&str; 5] = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-rsa",
    ];
    if !ACCEPTED.contains(&algorithm) {
        return Err(refuse(&format!("unsupported key type {algorithm:?}")));
    }
    let blob = parts.next().ok_or_else(|| refuse("key data is missing"))?;
    if blob.is_empty()
        || !blob
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
    {
        return Err(refuse("key data is not valid base64"));
    }
    Ok(key.trim().to_string())
}

/// Default title: the key comment when present, else `ssh key`.
fn default_title(key: &str) -> String {
    let comment = key.split_whitespace().skip(2).collect::<Vec<_>>().join(" ");
    if comment.is_empty() {
        "ssh key".to_string()
    } else {
        comment
    }
}

/// Build the SSH remote form `ssh://git@<host>:<port>/<owner>/<repo>.git`
/// from a discovered `ssh_url` base (e.g. `ssh://git@127.0.0.1:2222`) and a
/// discovered `owner/repo`. `None` when either is missing.
pub fn ssh_remote_url(ssh_url: &str, owner_repo: &str) -> Option<String> {
    let base = ssh_url.trim().trim_end_matches('/');
    if base.is_empty() || owner_repo.trim().is_empty() {
        return None;
    }
    Some(format!("{base}/{owner_repo}.git"))
}

/// Register `key` on the server at `api_base` via one `repo:write` device
/// flow. The flow token authenticates exactly one `POST /user/keys` and is
/// then dropped; nothing is stored.
pub async fn register_key(
    api_base: &str,
    key: &str,
    title: &str,
    sleeper: &impl Sleeper,
    now: time::OffsetDateTime,
) -> Result<CreatedKey, AuthError> {
    let flow = DeviceFlow::new(api_base.to_string());
    let creds = flow.login_with_scopes(sleeper, now, SSH_KEY_SCOPE).await?;
    // One-time token: used once below, then revoked server-side and dropped
    // with `creds`; nothing is stored.
    let created = register_with_token(&flow, &creds.access_token, key, title).await?;
    if let Err(err) = revoke_refresh_token(&flow, &creds.refresh_token).await {
        eprintln!(
            "warning: the SSH key was registered, but revoking the one-time token failed: {err}"
        );
    }
    Ok(created)
}

/// Best-effort `POST /api/v1/oauth/revoke` (RFC 7009) for the one-time
/// refresh token minted by the `repo:write` device flow.
async fn revoke_refresh_token(flow: &DeviceFlow, refresh_token: &str) -> Result<(), AuthError> {
    let url = format!("{}/api/v1/oauth/revoke", flow.base_url);
    let resp = flow
        .client
        .post(&url)
        .form(&[("token", refresh_token)])
        .send()
        .await
        .map_err(|err| AuthError::Http(err.to_string()))?;
    if !resp.status().is_success() {
        return Err(AuthError::Http(format!(
            "revoke endpoint answered {}",
            resp.status()
        )));
    }
    Ok(())
}

/// `POST /api/v1/user/keys` with an already-obtained bearer token.
async fn register_with_token(
    flow: &DeviceFlow,
    token: &str,
    key: &str,
    title: &str,
) -> Result<CreatedKey, AuthError> {
    let url = format!("{}/api/v1/user/keys", flow.base_url);
    let resp = flow
        .client
        .post(&url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "title": title, "key": key }))
        .send()
        .await
        .map_err(|err| AuthError::Http(err.to_string()))?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|err| AuthError::Http(err.to_string()))?;
    if !status.is_success() {
        let api_err = crate::api::parse_error(status.as_u16(), &body);
        return Err(map_server_error(api_err));
    }
    let value: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|err| AuthError::Http(format!("invalid key response: {err}")))?;
    Ok(CreatedKey {
        fingerprint: value
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        algorithm: value
            .get("algorithm")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        title: value
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or(title)
            .to_string(),
    })
}

/// Map an API failure onto [`AuthError`], with a clear report for the
/// already-registered-key case (HTTP 422 `"this key is already in use"`).
fn map_server_error(err: crate::api::ApiError) -> AuthError {
    match err {
        crate::api::ApiError::Auth { message, .. } => {
            AuthError::Rejected(format!("authentication failed ({message})"))
        }
        crate::api::ApiError::Status { message, .. } if message.contains("already in use") => {
            AuthError::Rejected(format!("this SSH key is already registered ({message})"))
        }
        crate::api::ApiError::Status { code, message, .. } => {
            AuthError::Rejected(format!("server rejected the key ({code}): {message}"))
        }
        crate::api::ApiError::Transport(cause) => AuthError::Http(cause),
        crate::api::ApiError::Decode(cause) => AuthError::Http(cause),
    }
}

/// Resolved server endpoints for the registration + the SSH output line.
struct Target {
    api_base: String,
    ssh_url: String,
    owner_repo: String,
}

/// Determine `api_base`, `ssh_url`, and `owner_repo`:
/// `--server` wins outright; otherwise the repo's discovered server; otherwise
/// the single stored host. `ssh_url` is read from the server's well-known
/// document when reachable (best-effort: empty when the server does not
/// answer, in which case no SSH remote line is printed).
async fn target(paths: &CliPaths, repo: &Path, server: Option<&str>) -> Result<Target, AuthError> {
    if let Some(server) = server {
        // `--server` wins outright: the well-known document is read only from
        // the named server, never from remotes found in the repo.
        let (_, api_base) = normalize_server(server)?;
        let ssh_url = fetch_ssh_url(&api_base).await;
        return Ok(Target {
            api_base,
            ssh_url,
            owner_repo: owner_repo_local(repo).unwrap_or_default(),
        });
    }
    match crate::commands::status::resolve_server(repo, paths).await {
        Ok((info, owner_repo, _)) => Ok(Target {
            api_base: info.api_url,
            ssh_url: info.ssh_url,
            owner_repo,
        }),
        Err(discovery_err) => {
            // Not inside a (resolvable) repo: fall back to a lone stored host.
            let map = load_credentials(paths)?;
            let mut hosts: Vec<&String> = map.keys().collect();
            hosts.sort();
            match hosts.len() {
                0 | 1 => {
                    let Some(host) = hosts.first() else {
                        return Err(AuthError::Config(format!(
                            "{discovery_err}; run `starforge auth ssh-key add --server <host>`"
                        )));
                    };
                    let (_, api_base) = normalize_server(host)?;
                    let ssh_url = fetch_ssh_url(&api_base).await;
                    Ok(Target {
                        api_base,
                        ssh_url,
                        owner_repo: owner_repo_local(repo).unwrap_or_default(),
                    })
                }
                _ => Err(AuthError::Config(format!(
                    "{discovery_err}; several hosts are stored ({}), \
                     run `starforge auth ssh-key add --server <host>`",
                    hosts
                        .iter()
                        .map(|h| h.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))),
            }
        }
    }
}

/// Local-only `api_base` for `--dry-run`: `--server` wins outright, then
/// `starforge.server` git config, then the first remote's probe base, then
/// a single stored host. No HTTP.
fn dry_run_api_base(
    paths: &CliPaths,
    repo: &Path,
    server: Option<&str>,
) -> Result<String, AuthError> {
    if let Some(server) = server {
        return Ok(normalize_server(server)?.1);
    }
    let (configured, _, candidates) =
        crate::discovery::local_config(repo).map_err(|err| AuthError::Config(err.to_string()))?;
    if let Some(configured) = configured.filter(|v| !v.trim().is_empty()) {
        if let Some(base) = crate::discovery::probe_base_for_remote(&configured) {
            return Ok(base);
        }
        return Ok(normalize_server(&configured)?.1);
    }
    for (_, remote_url) in candidates {
        if let Some(base) = crate::discovery::probe_base_for_remote(&remote_url) {
            return Ok(base);
        }
    }
    let map = load_credentials(paths)?;
    let mut hosts: Vec<&String> = map.keys().collect();
    hosts.sort();
    match hosts.len() {
        0 | 1 => match hosts.first() {
            Some(host) => Ok(normalize_server(host)?.1),
            None => Err(AuthError::Config(
                "no server configured; run `starforge auth ssh-key add --server <host>`"
                    .to_string(),
            )),
        },
        _ => Err(AuthError::Config(format!(
            "several hosts are stored ({}), \
             run `starforge auth ssh-key add --server <host>`",
            hosts
                .iter()
                .map(|h| h.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// `owner/repo` from local git config alone (no network).
fn owner_repo_local(repo: &Path) -> Option<String> {
    let (_, owner_repo, candidates) = crate::discovery::local_config(repo).ok()?;
    if let Some(configured) = owner_repo.filter(|v| !v.trim().is_empty()) {
        return Some(configured);
    }
    candidates
        .first()
        .map(|(_, url)| crate::discovery::owner_repo_from_remote(url))
        .filter(|v| !v.is_empty())
}

/// Best-effort `GET {api_base}/.well-known/starforge.json` → `ssh_url`.
async fn fetch_ssh_url(api_base: &str) -> String {
    let client = match crate::discovery::forge_client(std::time::Duration::from_secs(5)) {
        Ok(client) => client,
        Err(_) => return String::new(),
    };
    let url = format!("{api_base}/.well-known/starforge.json");
    let body = match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.bytes().await {
            Ok(bytes) => bytes,
            Err(_) => return String::new(),
        },
        _ => return String::new(),
    };
    match crate::discovery::parse_well_known(&body) {
        Ok(info) => info.ssh_url,
        Err(_) => String::new(),
    }
}

/// Run `auth ssh-key add [<public-key-path>] [--server <host>] [--title <title>]`.
/// Returns the message for stdout. Dry-run prints the plan without any HTTP.
#[allow(clippy::too_many_arguments)]
pub async fn add_ssh_key(
    paths: &CliPaths,
    repo: &Path,
    public_key_path: Option<PathBuf>,
    server: Option<&str>,
    title: Option<&str>,
    sleeper: &impl Sleeper,
    now: time::OffsetDateTime,
    dry_run: bool,
) -> Result<String, AuthError> {
    let (key_path, key) = resolve_public_key(&paths.home, public_key_path)?;
    let title = title
        .map(str::to_string)
        .unwrap_or_else(|| default_title(&key));
    if title.is_empty() || title.chars().count() > 128 {
        return Err(AuthError::Config(
            "key titles are 1-128 characters".to_string(),
        ));
    }
    if dry_run {
        let api_base = dry_run_api_base(paths, repo, server)?;
        return Ok(format!(
            "would request a one-time device-code approval for scope={SSH_KEY_SCOPE} \
             from {}, then POST {}/api/v1/user/keys with title={title:?} and the key \
             from {} (stored credentials unchanged); the approval token would be discarded",
            api_base,
            api_base,
            key_path.display()
        ));
    }
    let target = target(paths, repo, server).await?;
    let created = register_key(&target.api_base, &key, &title, sleeper, now).await?;
    let mut out = format!(
        "registered SSH key {} ({}) on {}",
        created.fingerprint, created.algorithm, target.api_base
    );
    if let Some(remote) = ssh_remote_url(&target.ssh_url, &target.owner_repo) {
        out.push_str(&format!("\nssh remote: {remote}"));
    }
    Ok(out)
}
