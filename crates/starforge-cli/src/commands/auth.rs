//! `auth login/logout/status` handlers.

use crate::auth::AuthError;
use crate::auth::{
    DeviceFlow, credentials_for, load_credentials, logout_host, normalize_server,
    redact_for_status, save_credentials,
};
use crate::config::CliPaths;
use crate::queue::Sleeper;

/// Run `auth login <server>`: device flow, then store per-host credentials.
/// Returns the message for stdout. Dry-run prints the requests it would make
/// and writes nothing.
pub async fn login(
    paths: &CliPaths,
    server: &str,
    sleeper: &impl Sleeper,
    now: time::OffsetDateTime,
    dry_run: bool,
) -> Result<String, AuthError> {
    let (host, api_base) = normalize_server(server)?;
    if dry_run {
        return Ok(format!(
            "would POST {api_base}/api/v1/oauth/device/code \
             with client_id=starforge-cli&scope=sessions:read sessions:write, \
             poll POST {api_base}/api/v1/oauth/token, \
             and store [{host}] in {}",
            paths.credential_file.display()
        ));
    }
    let flow = DeviceFlow::new(api_base);
    let creds = flow.login(sleeper, now).await?;
    let mut map = load_credentials(paths)?;
    map.insert(host.clone(), creds);
    save_credentials(paths, &map)?;
    Ok(format!("logged in to {host}"))
}

/// Run `auth logout [server]`: remove the host entry (and the file itself
/// when the last entry goes). A second logout reports "not logged in" and is
/// still exit 0. Dry-run writes nothing.
pub fn logout(paths: &CliPaths, server: Option<&str>, dry_run: bool) -> Result<String, AuthError> {
    let host = match server {
        Some(server) => normalize_server(server)?.0,
        None => single_host(paths)?,
    };
    if dry_run {
        return Ok(format!(
            "would remove [{host}] from {}",
            paths.credential_file.display()
        ));
    }
    if logout_host(paths, &host, dry_run)? {
        Ok(format!("logged out from {host}"))
    } else {
        Ok(format!("not logged in to {host}"))
    }
}

/// Pick the single stored host for a bare `logout`; errors when zero or
/// several hosts are stored.
fn single_host(paths: &CliPaths) -> Result<String, AuthError> {
    let map = load_credentials(paths)?;
    let mut hosts: Vec<&String> = map.keys().collect();
    hosts.sort();
    match hosts.len() {
        0 => Err(AuthError::Config(
            "not logged in (no stored credentials)".to_string(),
        )),
        1 => Ok(hosts[0].clone()),
        _ => Err(AuthError::Config(format!(
            "several hosts are stored ({}); run `starforge auth logout <server>`",
            hosts
                .iter()
                .map(|h| h.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Render `auth status`: one line per stored host with a redacted token.
/// Returns the text plus the exit code (0 when logged in anywhere, else 1).
pub fn status(paths: &CliPaths) -> (String, u8) {
    let map = match load_credentials(paths) {
        Ok(map) => map,
        Err(err) => return (format!("error: {err}"), 1),
    };
    if map.is_empty() {
        return ("not logged in".to_string(), 1);
    }
    let mut hosts: Vec<&String> = map.keys().collect();
    hosts.sort();
    let mut out = String::new();
    for host in hosts {
        if let Some(creds) = credentials_for(&map, host) {
            out.push_str(&redact_for_status(host, &creds.access_token));
            out.push('\n');
        }
    }
    (out, 0)
}
