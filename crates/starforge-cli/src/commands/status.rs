//! `starforge status`: show the resolved server (C3).

use std::path::Path;
use std::time::Duration;

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
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|err| DiscoveryError::Unreachable(format!("cannot build http client: {err}")))?;
    crate::discovery::resolve_server(&client, repo).await
}

/// Render `status` for `repo`: server URLs, owner/repo, and chosen remote.
/// Returns the stdout text plus the exit code (0 resolved, else 1).
pub async fn status(repo: &Path, paths: &CliPaths, dry_run: bool) -> (String, u8) {
    if dry_run {
        match crate::discovery::local_config(repo) {
            Ok((server, _, candidates)) => {
                let mut out = format!("would resolve server for {}\n", repo.display());
                if let Some(server) = server {
                    out.push_str(&format!(
                        "would probe configured starforge.server {server}\n"
                    ));
                } else {
                    for (_, url) in candidates {
                        if let Some(base) = crate::discovery::probe_base_for_remote(&url) {
                            out.push_str(&format!(
                                "would probe {base}/.well-known/starforge.json\n"
                            ));
                        }
                    }
                }
                let _ = paths;
                return (out, 0);
            }
            Err(err) => return (format!("error: {err}"), 1),
        }
    }
    match resolve_server(repo, paths).await {
        Ok((server, owner_repo, chosen)) => (
            format!(
                "server: {}\nversion: {}\nssh: {}\nrepo: {}\nremote: {}\n",
                server.api_url, server.version, server.ssh_url, owner_repo, chosen
            ),
            0,
        ),
        Err(err) => (format!("error: {err}"), 1),
    }
}
