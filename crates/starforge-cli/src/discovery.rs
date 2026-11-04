//! Server discovery via `/.well-known/starforge.json` + `.git/config` (C3).
//!
//! Precedence (binding): explicit `starforge.server` git-config wins outright
//! (remotes are never probed then); else the remote named `starforge`, then
//! `origin`, then `upstream`, then the remaining remotes in `.git/config`
//! order — the first whose host answers wins.
//!
//! Probing: `GET {base}/.well-known/starforge.json` with a 5 s timeout and
//! one retry on transport errors. Non-200, invalid JSON, or missing fields
//! fall through to the next candidate; only the final "nothing answered" is
//! an error. For `http(s)` remotes `{base}` is the remote's own
//! scheme+authority — which is also what lets tests point remotes at an
//! in-process stub without a special seam or real network. `user@host:path`
//! (scp-style) remotes probe `https://{host}`; `ssh://`, `file://`, bare
//! paths, and anything else unparseable are skipped, never errors.
//!
//! The sync half ([`local_config`], [`order_candidates`],
//! [`probe_base_for_remote`], [`parse_well_known`]) is pure and unit-testable;
//! only the HTTP fetch is async.

use std::path::Path;
use std::time::Duration;

/// Server endpoints discovered via `/.well-known/starforge.json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServerInfo {
    pub api_url: String,
    pub ssh_url: String,
    pub version: String,
}

/// Discovery failures.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Nothing to probe: no `starforge.server` config and no remote with an
    /// HTTP(S) counterpart.
    #[error(
        "no server configured for repo at {0}; set starforge.server (`git config starforge.server <url>`) or add a remote"
    )]
    NoServer(String),
    /// Hosts were probed but none answered with a valid document.
    #[error("no starforge server answered (tried: {0})")]
    Unreachable(String),
    /// The well-known document was present but invalid.
    #[error("invalid well-known document: {0}")]
    Invalid(String),
    /// The `git` binary failed.
    #[error("git: {0}")]
    Git(String),
}

/// Pre-C3 spelling kept so both names resolve.
pub type DiscoverError = DiscoveryError;

impl From<crate::git::GitError> for DiscoveryError {
    fn from(err: crate::git::GitError) -> Self {
        DiscoveryError::Git(err.to_string())
    }
}

/// Parse a `{"starforge": "<version>", "api_url": "<url>", "ssh_url": "<url>"}`
/// body; all three fields are required (missing `api_url` is the classic
/// shape error, but a document missing any field cannot be used either).
pub fn parse_well_known(body: &[u8]) -> Result<ServerInfo, DiscoveryError> {
    #[derive(serde::Deserialize)]
    struct Raw {
        #[serde(default)]
        starforge: Option<String>,
        #[serde(default)]
        api_url: Option<String>,
        #[serde(default)]
        ssh_url: Option<String>,
    }
    let raw: Raw = serde_json::from_slice(body)
        .map_err(|err| DiscoveryError::Invalid(format!("not valid JSON: {err}")))?;
    match (raw.starforge, raw.api_url, raw.ssh_url) {
        (Some(version), Some(api_url), Some(ssh_url))
            if !version.is_empty() && !api_url.is_empty() && !ssh_url.is_empty() =>
        {
            Ok(ServerInfo {
                api_url,
                ssh_url,
                version,
            })
        }
        (version, api_url, ssh_url) => {
            let mut missing = Vec::new();
            if version.as_deref().is_none_or(str::is_empty) {
                missing.push("starforge");
            }
            if api_url.as_deref().is_none_or(str::is_empty) {
                missing.push("api_url");
            }
            if ssh_url.as_deref().is_none_or(str::is_empty) {
                missing.push("ssh_url");
            }
            Err(DiscoveryError::Invalid(format!(
                "missing field(s): {}",
                missing.join(", ")
            )))
        }
    }
}

/// The probe base (`scheme://authority`, no trailing slash) for a remote URL,
/// or `None` when the remote has no HTTP(S) counterpart and must be skipped.
///
/// - `https://host/owner/repo(.git)` → `https://host`
/// - `http://host:port/…` → `http://host:port` (scheme + port preserved, so
///   loopback stubs work without a special seam)
/// - `user@host:owner/repo(.git)` → `https://host`
/// - `ssh://…`, `file://…`, bare paths, unparseable → `None`
pub fn probe_base_for_remote(remote_url: &str) -> Option<String> {
    let remote_url = remote_url.trim();
    if remote_url.is_empty() {
        return None;
    }
    if let Some((scheme, _)) = remote_url.split_once("://") {
        if !matches!(scheme, "http" | "https") {
            return None;
        }
        let parsed = url::Url::parse(remote_url).ok()?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return None;
        }
        let host = parsed.host_str()?;
        let authority = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        return Some(format!("{}://{authority}", parsed.scheme()));
    }
    // Possible scp-style `user@host:path` / `host:path`. A `/` before the
    // first `:` means it is a local path, not a remote.
    let colon = remote_url.find(':')?;
    let (left, _) = remote_url.split_at(colon);
    if left.contains('/') || left.is_empty() {
        return None;
    }
    let host = left.rsplit('@').next().unwrap_or(left);
    if host.is_empty() || host.contains(' ') {
        return None;
    }
    Some(format!("https://{host}"))
}

/// Order remotes for probing: `starforge` → `origin` → `upstream`, then the
/// rest in `.git/config` order.
pub fn order_candidates(remotes: &[(String, String)]) -> Vec<(String, String)> {
    let mut ordered = Vec::with_capacity(remotes.len());
    for preferred in ["starforge", "origin", "upstream"] {
        if let Some(hit) = remotes.iter().find(|(name, _)| name == preferred) {
            ordered.push(hit.clone());
        }
    }
    for remote in remotes {
        if !ordered.iter().any(|(name, _)| name == &remote.0) {
            ordered.push(remote.clone());
        }
    }
    ordered
}

/// Derive `owner/repo` from a remote URL (trailing `.git` stripped). Returns
/// an empty string when no two trailing path segments exist.
pub fn owner_repo_from_remote(remote_url: &str) -> String {
    let path = if let Some((_, _)) = remote_url.split_once("://") {
        url::Url::parse(remote_url.trim())
            .map(|u| u.path().to_string())
            .unwrap_or_default()
    } else if let Some(colon) = remote_url.find(':') {
        let (left, right) = remote_url.split_at(colon);
        if left.contains('/') {
            remote_url.to_string()
        } else {
            right.trim_start_matches(':').to_string()
        }
    } else {
        remote_url.to_string()
    };
    let mut segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return String::new();
    }
    if let Some(last) = segments.last_mut()
        && let Some(stripped) = last.strip_suffix(".git")
    {
        *last = stripped;
    }
    if segments.len() >= 2 {
        let n = segments.len();
        format!("{}/{}", segments[n - 2], segments[n - 1])
    } else {
        segments.join("/")
    }
}

/// Sync local resolution: configured server URL, configured `owner/repo`,
/// and ordered probe candidates. No I/O beyond `git`.
pub type LocalConfig = (Option<String>, Option<String>, Vec<(String, String)>);

/// Sync, pure local half of resolution. No I/O beyond `git`.
pub fn local_config(repo: &Path) -> Result<LocalConfig, DiscoveryError> {
    let server = crate::git::config_get(repo, "starforge.server")?;
    let owner_repo = crate::git::config_get(repo, "starforge.repo")?;
    let candidates = order_candidates(&crate::git::remotes(repo)?);
    Ok((server, owner_repo, candidates))
}

/// Probe one remote URL: `GET {base}/.well-known/starforge.json` (5 s
/// timeout, one retry on transport errors). Returns `None` for skipped
/// remotes and for every non-usable answer — discovery never fails a command
/// by itself; only the final "no server anywhere" is an error.
pub async fn probe_well_known(client: &reqwest::Client, remote_url: &str) -> Option<ServerInfo> {
    let base = probe_base_for_remote(remote_url)?;
    fetch_well_known(client, &format!("{base}/.well-known/starforge.json")).await
}

async fn fetch_well_known(client: &reqwest::Client, url: &str) -> Option<ServerInfo> {
    for attempt in 0..2 {
        match client.get(url).timeout(Duration::from_secs(5)).send().await {
            Ok(resp) => {
                if !resp.status().is_success() {
                    return None; // definitive: try the next candidate
                }
                let bytes = resp.bytes().await.ok()?;
                return parse_well_known(&bytes).ok();
            }
            Err(_) if attempt == 0 => continue, // one retry on transport errors
            Err(_) => return None,
        }
    }
    None
}

/// Strip credential userinfo from a remote URL, preserving everything else.
///
/// `https://user:token@host/o/r.git` and `https://ghp_xxx@host/o/r.git` both
/// become `https://host/o/r.git`, so tokens never reach the spool
/// (`meta.repo.remote_urls`), `sessions show`, `status`, or the wire. A
/// token can be either the password or the username (PAT-in-username remote
/// shapes are common in CI), so ANY `scheme://` URL carrying a username or
/// password loses its userinfo. scp-style `git@host:path` has no `://` and
/// keeps its `user@` (scp needs it). Unparseable input is returned unchanged.
pub fn sanitize_remote_url(url: &str) -> String {
    if !url.contains("://") {
        return url.to_string();
    }
    match url::Url::parse(url) {
        Ok(mut parsed) if !parsed.username().is_empty() || parsed.password().is_some() => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.to_string()
        }
        _ => url.to_string(),
    }
}

/// Display/error base for a configured server URL: `scheme://host[:port]`
/// with any `user:pass@` userinfo stripped, so credentials embedded in
/// `starforge.server` never reach stderr, logs, or stored records. Fetching
/// still uses the full configured URL.
fn sanitized_base(server: &str) -> String {
    if let Ok(parsed) = url::Url::parse(server)
        && let Some(host) = parsed.host_str()
    {
        let authority = match parsed.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };
        return format!("{}://{authority}", parsed.scheme());
    }
    // Unparseable input: hide any leading userinfo rather than echoing it.
    match server.rsplit_once('@') {
        Some((_, rest)) => rest.to_string(),
        None => server.to_string(),
    }
}

/// Full resolution: `starforge.server` git-config wins outright (remotes are
/// never probed then); else per-remote well-known in [`order_candidates`]
/// order; `starforge.repo` supplies the `owner/repo` path, else it is derived
/// from the winning remote URL.
///
/// Returns `(server, owner_repo, chosen_remote_url)`; the chosen URL is the
/// sanitized configured server base (no userinfo) when `starforge.server` wins.
pub async fn resolve_server(
    client: &reqwest::Client,
    repo: &Path,
) -> Result<(ServerInfo, String, String), DiscoveryError> {
    let (configured, configured_repo, candidates) = local_config(repo)?;

    if let Some(server) = configured {
        let trimmed = server.trim().trim_end_matches('/');
        let full = if trimmed.contains("://") {
            trimmed.to_string()
        } else {
            format!("https://{trimmed}")
        };
        // Fetch with the full configured URL, but never let userinfo reach
        // errors, logs, or the returned chosen URL.
        let display = sanitized_base(&full);
        let url = format!("{full}/.well-known/starforge.json");
        if let Some(info) = fetch_well_known(client, &url).await {
            let owner_repo = configured_repo.unwrap_or_default();
            return Ok((info, owner_repo, display));
        }
        return Err(DiscoveryError::Unreachable(display));
    }

    let mut tried = Vec::new();
    for (_, remote_url) in &candidates {
        let Some(base) = probe_base_for_remote(remote_url) else {
            continue;
        };
        tried.push(base.clone());
        if let Some(info) =
            fetch_well_known(client, &format!("{base}/.well-known/starforge.json")).await
        {
            let owner_repo = configured_repo
                .clone()
                .unwrap_or_else(|| owner_repo_from_remote(remote_url));
            return Ok((info, owner_repo, sanitize_remote_url(remote_url)));
        }
    }
    if tried.is_empty() {
        Err(DiscoveryError::NoServer(repo.display().to_string()))
    } else {
        Err(DiscoveryError::Unreachable(tried.join(", ")))
    }
}
