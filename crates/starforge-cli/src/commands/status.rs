//! `starforge status`: repo, server, capture state, and queued uploads.
//!
//! Resolves the server for the current repo (same precedence as discovery),
//! then reports the chosen server/remote, installed hook markers, spooled
//! sessions, queue depth, and credential presence (host names only — tokens
//! never appear in output).

use std::path::Path;

use crate::config::CliPaths;
use crate::discovery::{DiscoveryError, ServerInfo};

/// Shared resolution helper used by C5–C7: anonymous well-known discovery for
/// `repo`. `paths` is accepted for call-site uniformity (credentials enter
/// later via `token_for`); it is unused by discovery itself.
pub async fn resolve_server(
    repo: &Path,
    _paths: &CliPaths,
) -> Result<(ServerInfo, String, String), DiscoveryError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|err| DiscoveryError::Unreachable(format!("cannot build http client: {err}")))?;
    crate::discovery::resolve_server(&client, repo).await
}

/// Render `status` for `repo`: server URLs, owner/repo, chosen remote, hook
/// markers, session/queue counts, and credential hosts.
pub async fn status(repo: &Path, paths: &CliPaths, dry_run: bool) -> (String, u8) {
    tracing::debug!("status: repo={} dry_run={dry_run}", repo.display());
    if dry_run {
        return match crate::discovery::local_config(repo) {
            Ok(_) => (format!("would show status for {}", repo.display()), 0),
            Err(err) => (format!("error: {err}"), 1),
        };
    }
    let (server, owner_repo, chosen) = match resolve_server(repo, paths).await {
        Ok(resolved) => resolved,
        Err(err) => return (format!("error: {err}"), 1),
    };
    let ssh = if server.ssh_url.is_empty() {
        "disabled".to_owned()
    } else {
        server.ssh_url.clone()
    };
    let mut out = format!(
        "server: {}\nversion: {}\nssh: {}\nrepo: {}\nremote: {}\n",
        server.api_url, server.version, ssh, owner_repo, chosen
    );
    out.push_str(&spool_lines(repo));
    out.push_str(&credential_line(paths));
    (out, 0)
}

/// Spool summary lines: hook markers, session count/table, queue depth.
/// Read-only; never fails the command (gaps render as `unknown`).
fn spool_lines(repo: &Path) -> String {
    let common = match crate::git::common_dir(repo) {
        Ok(common) => common,
        Err(_) => return "spool: unknown (not a git repo)\n".to_string(),
    };
    let spool = crate::spool::Spool::open(&common);
    let hooks_dir = common.join("hooks");
    let mut installed = 0u8;
    let mut missing = Vec::new();
    for hook in crate::hooks::HOOKS {
        let path = hooks_dir.join(hook);
        let managed = std::fs::read(&path)
            .map(|bytes| String::from_utf8_lossy(&bytes).contains(crate::hooks::MANAGED_MARKER))
            .unwrap_or(false);
        if managed {
            installed += 1;
        } else {
            missing.push(hook.to_string());
        }
    }
    let hooks = if missing.is_empty() {
        format!("hooks: installed ({installed}/3)\n")
    } else {
        format!(
            "hooks: installed ({installed}/3), missing: {}\n",
            missing.join(", ")
        )
    };
    let sessions = match std::fs::read_dir(spool.root.join("sessions")) {
        Ok(entries) => entries
            .filter(|e| e.as_ref().is_ok_and(|e| e.path().is_dir()))
            .count(),
        Err(_) => 0,
    };
    let queue = crate::queue::read_queue(&spool)
        .map(|q| q.len())
        .unwrap_or(0);
    format!("{hooks}sessions: {sessions}\nqueue: {queue} pending\n")
}

/// Credential presence: host names only, never tokens.
fn credential_line(paths: &CliPaths) -> String {
    match crate::auth::load_credentials(paths) {
        Ok(map) if map.is_empty() => "credentials: none\n".to_string(),
        Ok(map) => {
            let mut hosts: Vec<&String> = map.keys().collect();
            hosts.sort();
            format!(
                "credentials: {}\n",
                hosts
                    .into_iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Err(_) => "credentials: unknown\n".to_string(),
    }
}
