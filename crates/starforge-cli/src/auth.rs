//! Credentials + OAuth device-flow login (C2).
//!
//! Token resolution order (used by later tasks): `STARFORGE_TOKEN` env wins,
//! else the credentials file entry for the target host, else an error naming
//! both. [`resolve_token`] takes an injected env lookup so tests never touch
//! the global environment.
//!
//! The credentials file shape is `{ [servers."<host>"] = Credentials }`,
//! stored at [`CliPaths::credential_file`] with mode `0600` on unix.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;

use crate::config::CliPaths;
use crate::queue::Sleeper;

/// Credentials for one server host.
///
/// `Debug` is redacted by hand: tokens never appear in logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    pub access_token: String,
    pub refresh_token: String,
    /// RFC 3339 expiry (`now + expires_in` at login time).
    pub expires_at: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// On-disk shape: `{ [servers."<host>"] = Credentials }`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct CredentialFile {
    #[serde(default)]
    servers: BTreeMap<String, Credentials>,
}

/// Auth failures.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// HTTP transport or protocol error.
    #[error("http: {0}")]
    Http(String),
    /// Server refused the grant (`access_denied`, unknown error codes).
    #[error("auth rejected: {0}")]
    Rejected(String),
    /// Device flow expired before approval.
    #[error("device flow expired")]
    Expired,
    /// Filesystem error.
    #[error("i/o: {0}")]
    Io(String),
    /// Config error (bad server URL, missing credentials, bad file).
    #[error("config: {0}")]
    Config(String),
}

/// Where a resolved token came from.
///
/// `Debug` is redacted by hand like [`Credentials`]: the bearer token must
/// never appear in logs.
#[derive(Clone, PartialEq, Eq)]
pub enum ResolvedToken {
    /// `STARFORGE_TOKEN` env var.
    Env(String),
    /// Credentials file entry for the host.
    File(String),
}

impl fmt::Debug for ResolvedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            ResolvedToken::Env(_) => "Env",
            ResolvedToken::File(_) => "File",
        };
        f.debug_tuple(variant).field(&"<redacted>").finish()
    }
}

impl ResolvedToken {
    /// The bearer token itself.
    pub fn token(&self) -> &str {
        match self {
            ResolvedToken::Env(t) | ResolvedToken::File(t) => t,
        }
    }
}

/// Resolve the token for `host`: `STARFORGE_TOKEN` env wins, else the
/// credentials file entry, else an error naming both.
///
/// `lookup_env` is injected so tests never touch the global environment;
/// production passes `|k| std::env::var(k).ok()`.
pub fn resolve_token(
    paths: &CliPaths,
    host: &str,
    lookup_env: impl Fn(&str) -> Option<String>,
) -> Result<ResolvedToken, AuthError> {
    if let Some(token) = lookup_env("STARFORGE_TOKEN")
        && !token.is_empty()
    {
        return Ok(ResolvedToken::Env(token));
    }
    let map = load_credentials(paths)?;
    if let Some(creds) = map.get(host) {
        return Ok(ResolvedToken::File(creds.access_token.clone()));
    }
    Err(AuthError::Config(format!(
        "no token for host {host:?}: set STARFORGE_TOKEN or run `starforge auth login {host}` (credentials file: {})",
        paths.credential_file.display()
    )))
}

/// Load all stored credentials. A missing file loads as empty (callers can
/// distinguish "no creds" from errors).
pub fn load_credentials(paths: &CliPaths) -> Result<BTreeMap<String, Credentials>, AuthError> {
    let raw = match std::fs::read_to_string(&paths.credential_file) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(err) => return Err(AuthError::Io(err.to_string())),
    };
    let file: CredentialFile =
        toml::from_str(&raw).map_err(|err| AuthError::Config(err.to_string()))?;
    Ok(file.servers)
}

/// Save all credentials atomically (temp file + rename), creating
/// `config_dir` recursively. Mode `0600` on unix (documented no-op elsewhere:
/// on Windows the file inherits the profile ACL).
pub fn save_credentials(
    paths: &CliPaths,
    map: &BTreeMap<String, Credentials>,
) -> Result<(), AuthError> {
    std::fs::create_dir_all(&paths.config_dir).map_err(|err| AuthError::Io(err.to_string()))?;
    let file = CredentialFile {
        servers: map.clone(),
    };
    let raw = toml::to_string_pretty(&file).map_err(|err| AuthError::Config(err.to_string()))?;
    let tmp = paths.credential_file.with_extension("toml.tmp");
    // Drop a stale temp file first so the `mode(0o600)` below always applies
    // at creation time (it has no effect when opening an existing file). The
    // temp file holds secrets, so it is created with the restrictive mode up
    // front — not chmod-after-write, which leaves a world-readable window.
    // `rename` preserves the mode on the final path.
    let _ = std::fs::remove_file(&tmp);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(raw.as_bytes())
            })
            .map_err(|err| AuthError::Io(err.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp, raw).map_err(|err| AuthError::Io(err.to_string()))?;
    }
    std::fs::rename(&tmp, &paths.credential_file).map_err(|err| AuthError::Io(err.to_string()))?;
    Ok(())
}

/// Look up the credentials for one server host.
pub fn credentials_for(
    map: &BTreeMap<String, Credentials>,
    server_host: &str,
) -> Option<Credentials> {
    map.get(server_host).cloned()
}

/// Split a `login <server>` argument into `(host_key, api_base)`.
///
/// Accepts a bare host (`example.com`), host:port, or a full URL. The host key
/// is the lowercased host plus an explicit port when present, so stub servers
/// on `127.0.0.1:port` get distinct entries. `api_base` has no trailing slash.
pub fn normalize_server(server: &str) -> Result<(String, String), AuthError> {
    let server = server.trim();
    if server.is_empty() {
        return Err(AuthError::Config("server must not be empty".to_string()));
    }
    let with_scheme = if server.contains("://") {
        server.to_string()
    } else {
        format!("https://{server}")
    };
    let url = url::Url::parse(&with_scheme)
        .map_err(|err| AuthError::Config(format!("invalid server {server:?}: {err}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AuthError::Config(format!(
            "invalid server {server:?}: scheme must be http or https"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| AuthError::Config(format!("invalid server {server:?}: no host")))?
        .to_lowercase();
    let host_key = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    Ok((host_key, format!("{}://{authority}", url.scheme())))
}

/// One-line `auth status` entry: host plus a redacted token (last 4 chars).
pub fn redact_for_status(host: &str, token: &str) -> String {
    let tail: String = token
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{host}: …{tail}")
}

/// Remove one host entry. Deletes the file itself when the last entry goes.
/// Returns `true` when an entry was removed, `false` for "not logged in"
/// (still exit 0). `dry_run` prints nothing and writes nothing.
pub fn logout_host(paths: &CliPaths, host: &str, dry_run: bool) -> Result<bool, AuthError> {
    let mut map = load_credentials(paths)?;
    if map.remove(host).is_none() {
        return Ok(false);
    }
    if dry_run {
        return Ok(true);
    }
    if map.is_empty() {
        match std::fs::remove_file(&paths.credential_file) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(AuthError::Io(err.to_string())),
        }
        return Ok(true);
    }
    save_credentials(paths, &map)?;
    Ok(true)
}

/// OAuth device flow against `{base_url}/api/v1/oauth/device/code` and
/// `/api/v1/oauth/token` (RFC 8628 grant).
///
/// `base_url` is the api base with no trailing slash.
pub struct DeviceFlow {
    pub client: reqwest::Client,
    pub base_url: String,
}

impl DeviceFlow {
    /// Build a flow for `base_url` (trailing slashes are trimmed).
    pub fn new(base_url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Run the device flow: request a device code, print the user code +
    /// verification URI to stdout, then poll the token endpoint every
    /// `interval` via `sleeper` until `expires_in` elapses.
    ///
    /// `now` is the caller-supplied clock (never `Utc::now` inside the flow);
    /// success stores `expires_at = now + expires_in` as RFC 3339.
    pub async fn login(
        &self,
        sleeper: &impl Sleeper,
        now: time::OffsetDateTime,
    ) -> Result<Credentials, AuthError> {
        let device = self.request_device_code().await?;
        println!("To authorize, visit: {}", device.verification_uri);
        println!("Enter code: {}", device.user_code);

        let mut interval = device.interval;
        let mut elapsed = std::time::Duration::ZERO;
        loop {
            if elapsed >= device.expires_in {
                return Err(AuthError::Expired);
            }
            match self.poll_token(&device.device_code).await? {
                PollOutcome::Success(creds, expires_in) => {
                    let expires_at = now + time::Duration::seconds(expires_in);
                    let expires_at = expires_at
                        .format(&Rfc3339)
                        .map_err(|err| AuthError::Config(err.to_string()))?;
                    return Ok(Credentials {
                        access_token: creds.0,
                        refresh_token: creds.1,
                        expires_at,
                    });
                }
                // Wait `interval` after each non-terminal poll; `slow_down`
                // waits out the current interval, then applies +5s to the next.
                PollOutcome::Pending => {
                    sleeper.sleep(interval).await;
                    elapsed += interval;
                }
                PollOutcome::SlowDown => {
                    sleeper.sleep(interval).await;
                    elapsed += interval;
                    interval += std::time::Duration::from_secs(5);
                }
            }
        }
    }

    async fn request_device_code(&self) -> Result<DeviceCode, AuthError> {
        let url = format!("{}/api/v1/oauth/device/code", self.base_url);
        let resp = self
            .client
            .post(&url)
            .form(&[("client_id", "starforge-cli"), ("scope", "session:upload")])
            .send()
            .await
            .map_err(|err| AuthError::Http(err.to_string()))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|err| AuthError::Http(err.to_string()))?;
        if !status.is_success() {
            return Err(AuthError::Rejected(error_field(&body)));
        }
        DeviceCode::parse(&body)
    }

    async fn poll_token(&self, device_code: &str) -> Result<PollOutcome, AuthError> {
        let url = format!("{}/api/v1/oauth/token", self.base_url);
        let resp = self
            .client
            .post(&url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device_code),
                ("client_id", "starforge-cli"),
            ])
            .send()
            .await
            .map_err(|err| AuthError::Http(err.to_string()))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|err| AuthError::Http(err.to_string()))?;
        if let Some(access) = body.get("access_token").and_then(|v| v.as_str()) {
            let refresh = body
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AuthError::Http("token response missing refresh_token".to_string())
                })?;
            let expires_in = body
                .get("expires_in")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| AuthError::Http("token response missing expires_in".to_string()))?;
            return Ok(PollOutcome::Success(
                (access.to_string(), refresh.to_string()),
                expires_in,
            ));
        }
        match body.get("error").and_then(|v| v.as_str()) {
            Some("authorization_pending") => Ok(PollOutcome::Pending),
            Some("slow_down") => Ok(PollOutcome::SlowDown),
            Some("expired_token") => Err(AuthError::Expired),
            Some("access_denied") => Err(AuthError::Rejected("access_denied".to_string())),
            Some(other) => Err(AuthError::Rejected(other.to_string())),
            None => Err(AuthError::Http(format!(
                "unexpected token response: {body}"
            ))),
        }
    }
}

struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    interval: std::time::Duration,
    expires_in: std::time::Duration,
}

impl DeviceCode {
    fn parse(body: &serde_json::Value) -> Result<Self, AuthError> {
        let get = |key: &str| {
            body.get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| AuthError::Http(format!("device-code response missing {key}")))
                .map(str::to_string)
        };
        let interval_secs = body.get("interval").and_then(|v| v.as_u64()).unwrap_or(5);
        let expires_secs = body
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(900);
        let verification_uri = get("verification_uri")?;
        Ok(Self {
            device_code: get("device_code")?,
            user_code: get("user_code")?,
            verification_uri,
            interval: std::time::Duration::from_secs(interval_secs),
            expires_in: std::time::Duration::from_secs(expires_secs),
        })
    }
}

enum PollOutcome {
    Success((String, String), i64),
    Pending,
    SlowDown,
}

fn error_field(body: &serde_json::Value) -> String {
    body.get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown error")
        .to_string()
}
