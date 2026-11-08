//! Outbound git remote URL policy (M4b): the one gate every import and
//! mirror URL passes at save time and again before every fetch or push.
//!
//! Allowed: `https`, and `ssh` (`ssh://` and scp-like `user@host:path`),
//! plus `http` only when the resolved host is loopback and the test-only
//! `remotes.allow_file_urls` flag is set. Refused: `file://`, local paths,
//! `ext::`, `fd::`, and every other transport — unless the test-only flag
//! is set, which also admits loopback hosts. Hosts are refused by the same
//! SSRF rules as the webhook delivery gate
//! ([`crate::webhooks::host_allowed`]): private, loopback (unless
//! flagged), link-local including the metadata endpoint, unique-local,
//! multicast, and the other non-global ranges. The first allowed resolved
//! address is pinned on the returned [`PinnedRemote`] so git cannot be
//! redirected by a DNS change between the check and the connection.
//!
//! DNS is injectable through [`HostResolver`] so unit tests stub
//! resolution; production uses [`LookupResolver`] (the system resolver).

use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};

use starforged_git::remote::{PinnedRemote, RemoteScheme};

use crate::webhooks::host_allowed;
use crate::{Core, CoreError, CoreResult};

/// Re-exported so callers of the policy need only `starforged_core`.
pub use starforged_git::remote::{FetchOutcome, LsRemoteHead, RemoteCreds};

/// Resolves a host to candidate addresses. Injectable for tests; the
/// production implementation uses the system resolver.
pub trait HostResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String>;
}

/// The system resolver (`ToSocketAddrs`).
pub struct LookupResolver;

impl HostResolver for LookupResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
        (host, port)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect())
            .map_err(|e| format!("{host} does not resolve: {e}"))
    }
}

/// A resolver returning fixed addresses for every host (unit tests).
pub struct FixedResolver {
    pub addrs: Vec<IpAddr>,
}

impl HostResolver for FixedResolver {
    fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        Ok(self.addrs.clone())
    }
}

/// A resolver returning per-host addresses (unit tests).
pub struct MapResolver {
    pub map: HashMap<String, Vec<IpAddr>>,
}

impl HostResolver for MapResolver {
    fn resolve(&self, host: &str, _port: u16) -> Result<Vec<IpAddr>, String> {
        self.map
            .get(host)
            .cloned()
            .ok_or_else(|| format!("{host} does not resolve"))
    }
}

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::Invalid(message.into())
}

/// The policy check behind [`Core::check_remote_url`], with an injectable
/// resolver. `allow_file_urls` is the test-only `remotes.allow_file_urls`
/// flag: it admits `file://`/local paths and loopback hosts (and `http` to
/// loopback), and nothing else changes.
pub fn check_url(
    url: &str,
    allow_file_urls: bool,
    resolver: &dyn HostResolver,
) -> CoreResult<PinnedRemote> {
    let url = url.trim();
    if url.is_empty() {
        return Err(invalid("remote url is empty"));
    }
    // A leading `-` would be parsed as an option by git/ssh
    // (e.g. `-oProxyCommand=…`); control characters or whitespace have no
    // place in a remote URL either.
    if url.starts_with('-') {
        return Err(invalid("remote url must not start with '-'"));
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(invalid(
            "remote url contains whitespace or control characters",
        ));
    }
    // Transports spelled `ext::`, `fd::`, … (anything of the form
    // `<name>::<command>` with no `/` in the name) run arbitrary commands.
    if let Some((name, _)) = url.split_once("::")
        && !name.is_empty()
        && !name.contains('/')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return Err(invalid(format!(
            "remote url transport `{name}::` is not allowed"
        )));
    }
    if url.starts_with("file://") {
        if !allow_file_urls {
            return Err(invalid("file:// remote urls are not allowed"));
        }
        // Credentials arrive only via the explicit auth fields (sealed):
        // any userinfo in a `file://` URL is refused outright, so a secret
        // can never be stored, echoed, or audited via the URL.
        let parsed = url::Url::parse(url).map_err(|_| invalid("remote url does not parse"))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(invalid("file:// remote urls must not carry credentials"));
        }
        return Ok(PinnedRemote {
            url: parsed.to_string(),
            scheme: RemoteScheme::File,
            host: String::new(),
            port: 0,
            pinned_ip: None,
        });
    }
    // Scp-like SSH syntax (`user@host:path`) has no `://`.
    if !url.contains("://") {
        // An scp-like attempt whose user or host starts with `-` (the
        // `-oProxyCommand=…` ssh-option injection) must be refused
        // outright, not fall through to local-path handling below.
        if let Some((before_colon, _)) = url.split_once(':')
            && !before_colon.contains('/')
            && let Some((user, host)) = before_colon.rsplit_once('@')
            && (user.starts_with('-')
                || host.starts_with('-')
                || user.chars().any(|c| c.is_control() || c.is_whitespace())
                || host.chars().any(|c| c.is_control() || c.is_whitespace()))
        {
            return Err(invalid(
                "remote url user or host must not start with '-' or contain whitespace",
            ));
        }
        if let Some(scp) = parse_scp_like(url) {
            return check_host(
                url.to_owned(),
                RemoteScheme::Ssh,
                scp.0,
                scp.1,
                22,
                allow_file_urls,
                resolver,
            );
        }
        // Anything else without a scheme is a local path.
        if !allow_file_urls {
            return Err(invalid("local-path remote urls are not allowed"));
        }
        return Ok(PinnedRemote {
            url: url.to_owned(),
            scheme: RemoteScheme::File,
            host: String::new(),
            port: 0,
            pinned_ip: None,
        });
    }
    let parsed = url::Url::parse(url).map_err(|_| invalid("remote url does not parse"))?;
    let scheme = match parsed.scheme() {
        "https" => RemoteScheme::Https,
        "http" => RemoteScheme::Http,
        "ssh" => RemoteScheme::Ssh,
        other => {
            return Err(invalid(format!(
                "remote url scheme `{other}` is not allowed"
            )));
        }
    };
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid("remote url has no host"))?
        .to_owned();
    // A dash-leading username or host is an ssh `-o…` option injection
    // (`ssh://-oProxyCommand=…@host/`, `ssh://git@-oProxyCommand=…/`).
    let username = parsed.username();
    if username.starts_with('-')
        || host.starts_with('-')
        || username
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
        || host.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(invalid(
            "remote url user or host must not start with '-' or contain whitespace",
        ));
    }
    // `Url::port_or_known_default` does not know `ssh`, so fall back to the
    // scheme default explicitly.
    let port = parsed.port().unwrap_or(match scheme {
        RemoteScheme::Https => 443,
        RemoteScheme::Http => 80,
        RemoteScheme::Ssh => 22,
        RemoteScheme::File => 0,
    });
    // The URL git receives carries no password: credentials travel via the
    // `http.extraHeader` env, never the URL.
    let mut sanitized = parsed.clone();
    let _ = sanitized.set_password(None);
    check_host(
        sanitized.to_string(),
        scheme,
        host,
        String::new(),
        port,
        allow_file_urls,
        resolver,
    )
    .map(|mut pinned| {
        // Preserve the parsed (bracketed-IPv6) host form in the URL; the
        // bare host lives in `pinned.host` for pinning arguments.
        pinned.url = sanitized.to_string();
        pinned
    })
}

/// Parses scp-like `user@host:path` (or bare `host:path`), returning the
/// host and the user. `None` when the string is not scp-like.
fn parse_scp_like(url: &str) -> Option<(String, String)> {
    let (before_colon, _path) = url.split_once(':')?;
    if before_colon.contains('/') {
        return None;
    }
    let (user, host) = match before_colon.rsplit_once('@') {
        Some((user, host)) => (user.to_owned(), host.to_owned()),
        None => (String::new(), before_colon.to_owned()),
    };
    // A dash-leading user or host is an ssh `-o…` option injection
    // (`-oProxyCommand=…@host:path`, `git@-oProxyCommand=…:path`); refuse
    // it, along with any whitespace/control character.
    let bad =
        |s: &str| s.starts_with('-') || s.chars().any(|c| c.is_control() || c.is_whitespace());
    if bad(&user) {
        return None;
    }
    if host.is_empty() || host.contains(['/', '@']) || bad(&host) {
        return None;
    }
    // A bare `host:path` with no `@` and a dotless single label is more
    // likely a Windows path or a typo than SSH; require the `@` form or a
    // dotted host.
    if user.is_empty() && !host.contains('.') && host.parse::<IpAddr>().is_err() {
        return None;
    }
    Some((host, user))
}

/// Applies the SSRF host rules to `host` and pins the first allowed
/// address. `http` additionally requires loopback plus the test flag.
#[allow(clippy::too_many_arguments)]
fn check_host(
    url: String,
    scheme: RemoteScheme,
    host: String,
    _user: String,
    port: u16,
    allow_file_urls: bool,
    resolver: &dyn HostResolver,
) -> CoreResult<PinnedRemote> {
    // `host_str` keeps IPv6 brackets; strip them before parsing.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host);
    // Belt and braces: a dash-leading host is an ssh `-o…` injection.
    if bare.starts_with('-') || bare.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(invalid(format!("remote host {host} is not allowed")));
    }
    let pinned_ip = if let Ok(ip) = bare.parse::<IpAddr>() {
        if !host_allowed(ip, allow_file_urls) {
            return Err(invalid(format!("remote host {host} is not allowed")));
        }
        // IP literals never consult DNS: nothing to pin.
        None
    } else {
        let addrs = resolver.resolve(bare, port).map_err(invalid)?;
        if addrs.is_empty() {
            return Err(invalid(format!("remote host {host} does not resolve")));
        }
        let mut pinned = None;
        for ip in &addrs {
            if host_allowed(*ip, allow_file_urls) {
                pinned = Some(*ip);
                break;
            }
        }
        match pinned {
            Some(ip) => Some(ip),
            None => {
                return Err(invalid(format!(
                    "remote host {host} resolves to no allowed address"
                )));
            }
        }
    };
    if scheme == RemoteScheme::Http {
        // `http` only to loopback, and only under the test flag.
        let ip = pinned_ip.or_else(|| bare.parse::<IpAddr>().ok());
        let is_loopback = ip.is_some_and(|ip| ip.is_loopback());
        if !(allow_file_urls && is_loopback) {
            return Err(invalid(
                "http remote urls are only allowed to loopback in tests",
            ));
        }
    }
    Ok(PinnedRemote {
        url,
        scheme,
        host: bare.to_owned(),
        port,
        pinned_ip,
    })
}

impl Core {
    /// Checks a remote URL against the outbound policy and returns the
    /// pinned remote git should talk to (see the module docs). Uses the
    /// system resolver; see [`Core::check_remote_url_with_resolver`] for
    /// the injectable-resolver form.
    pub fn check_remote_url(&self, url: &str) -> CoreResult<PinnedRemote> {
        check_url(url, self.config().allow_file_urls, &LookupResolver)
    }

    /// Like [`Core::check_remote_url`] with an injectable resolver (tests).
    pub fn check_remote_url_with_resolver(
        &self,
        url: &str,
        resolver: &dyn HostResolver,
    ) -> CoreResult<PinnedRemote> {
        check_url(url, self.config().allow_file_urls, resolver)
    }
}

// --- One-time import (M4b D2, D3). -----------------------------------------
//
// A repository created with an `import` body starts empty with
// `import_state = pending`; the `ImportRepo` job fetches only
// `refs/heads/*` and `refs/tags/*` and points HEAD at the remote's default
// branch. While `pending` or `running`, pushes are refused through the
// hook snapshot (`STARFORGE_IMPORT_IN_PROGRESS`). For SSH imports the
// repository waits in `pending` until the user presses "start import" after
// installing the generated deploy key upstream.

use std::time::Duration;

use starforged_db::remotes as db_remotes;
use starforged_db::repos as db_repos;

use crate::accounts::User;
use crate::permission::Permission;

/// Fetch timeout for one import (M4b global constraints).
pub const IMPORT_FETCH_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Only these refs ever leave an import source (M4b D3).
pub const IMPORT_REFSPECS: [&str; 2] = ["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"];

/// Fetch timeout for one mirror sync (M4b global constraints: 10 minutes).
pub const PULL_MIRROR_FETCH_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Minimum pull-mirror interval (M4b D4), in seconds.
pub const PULL_MIRROR_MIN_INTERVAL_SECS: i64 = 300;
/// Push timeout for one mirror push (M4b global constraints: 10 minutes).
pub const PUSH_MIRROR_PUSH_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Debounce after an accepted push before the push-mirror job runs (M4b D5).
pub const PUSH_MIRROR_DEBOUNCE_SECS: i64 = 30;
/// Backoff after a failed push-mirror run before the retry (M4b global
/// constraints: failures are backed off, never hammered).
pub const PUSH_MIRROR_BACKOFF_SECS: i64 = 300;
/// Maximum push mirrors per repository (M4b D5 / D2).
pub const PUSH_MIRROR_MAX: usize = 10;
/// Only these refs ever leave a push mirror (M4b D5): branches and tags.
/// `refs/trails/*` and `refs/for/*` never go out.
pub const PUSH_MIRROR_REFSPECS: [&str; 2] =
    ["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"];

/// The `POST …/mirror/push` body in core terms (M4b D5). Credentials travel
/// exactly like an import's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushMirrorInput {
    pub url: String,
    pub auth: ImportAuth,
}

/// The pull-mirror pause notice: an archived repository is read-only, so a
/// sync records this (not a real failure) and reschedules at the normal
/// interval.
const MIRROR_PAUSED_MESSAGE: &str = "repository is archived; mirror paused";

/// What the API and pages show for one push mirror: never a secret, only
/// `has_credentials` and, for SSH, the public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushMirrorView {
    pub id: i64,
    pub repo_id: i64,
    pub url: String,
    pub auth: String,
    pub has_credentials: bool,
    pub ssh_public_key: Option<String>,
    pub enabled: bool,
    pub last_attempt_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: String,
}

fn push_mirror_view(row: &db_remotes::RemoteRow) -> PushMirrorView {
    PushMirrorView {
        id: row.id,
        repo_id: row.repo_id,
        url: row.url.clone(),
        auth: row.auth.clone(),
        has_credentials: row.sealed_secret.is_some(),
        ssh_public_key: row.ssh_public_key.clone(),
        enabled: row.enabled != 0,
        last_attempt_at: row.last_attempt_at,
        last_success_at: row.last_success_at,
        last_error: row.last_error.clone(),
    }
}

/// The `PUT …/mirror/pull` body in core terms (M4b D4). Credentials travel
/// exactly like an import's: HTTPS username + password/token, or SSH with a
/// server-generated keypair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullMirrorInput {
    pub url: String,
    pub auth: ImportAuth,
    pub interval_secs: i64,
}

/// What the API and pages show for a repository's pull mirror: never a
/// secret, only `has_credentials` and, for SSH, the public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullMirrorView {
    pub repo_id: i64,
    pub url: String,
    pub auth: String,
    pub has_credentials: bool,
    pub ssh_public_key: Option<String>,
    pub interval_secs: i64,
    pub enabled: bool,
    pub last_attempt_at: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_error: String,
}

/// Inserts one pull remote row. The `repo_remotes` insert carries the
/// default interval, so the interval is applied right after.
async fn insert_pull_remote(
    core: &Core,
    actor_id: i64,
    repo_id: i64,
    prepared: &PreparedImport,
    interval_secs: i64,
) -> CoreResult<i64> {
    let id = db_remotes::insert(
        core.db(),
        &db_remotes::NewRemote {
            repo_id,
            role: "pull",
            url: &prepared.url,
            auth: prepared.auth,
            username: &prepared.username,
            sealed_secret: prepared.sealed_secret.as_deref(),
            ssh_public_key: prepared.ssh_public_key.as_deref(),
            created_by: actor_id,
        },
    )
    .await?;
    db_remotes::update_pull_config(
        core.db(),
        id,
        &prepared.url,
        prepared.auth,
        &prepared.username,
        prepared.sealed_secret.as_deref(),
        prepared.ssh_public_key.as_deref(),
        interval_secs,
    )
    .await?;
    Ok(id)
}

/// Opens one remote row's sealed credentials for a git command. The
/// unreadable seal reads as "credentials unreadable; re-enter them" (the
/// secret-key-loss case), never a panic.
fn pull_creds(core: &Core, row: &db_remotes::RemoteRow) -> Result<RemoteCreds, String> {
    match row.auth.as_str() {
        "https" => {
            let sealed = row
                .sealed_secret
                .clone()
                .ok_or_else(|| "credentials unreadable; re-enter them".to_owned())?;
            let plain = core
                .config()
                .credential_box
                .open(&sealed)
                .map_err(|_| "credentials unreadable; re-enter them".to_owned())?;
            let password = String::from_utf8(plain)
                .map_err(|_| "credentials unreadable; re-enter them".to_owned())?;
            Ok(RemoteCreds::Basic {
                username: row.username.clone(),
                password,
            })
        }
        "ssh" => {
            let sealed = row
                .sealed_secret
                .clone()
                .ok_or_else(|| "credentials unreadable; re-enter them".to_owned())?;
            let plain = core
                .config()
                .credential_box
                .open(&sealed)
                .map_err(|_| "credentials unreadable; re-enter them".to_owned())?;
            let private_key = String::from_utf8(plain)
                .map_err(|_| "credentials unreadable; re-enter them".to_owned())?;
            Ok(RemoteCreds::SshKey { private_key })
        }
        _ => Ok(RemoteCreds::None),
    }
}

/// The per-remote SSH known-hosts file (`<data_dir>/known_hosts/<remote
/// id>`): every import and mirror trusts only the keys recorded for its
/// own remote. The git layer creates it (0600, parent 0700) on demand.
fn remote_known_hosts(core: &Core, remote_id: i64) -> std::path::PathBuf {
    let data_dir = core
        .config()
        .repos_dir
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| core.config().repos_dir.clone());
    data_dir.join("known_hosts").join(remote_id.to_string())
}

fn now_plus(secs: i64) -> i64 {
    starforged_db::now().saturating_add(secs)
}

/// Credentials for an import source, as the API and web form express them.
/// HTTPS carries a username and password/token; SSH asks the server to
/// generate an ed25519 keypair whose private half is sealed and never
/// displayed. Neither ever travels in the URL.
#[derive(Clone, PartialEq, Eq)]
pub enum ImportAuth {
    None,
    Https { username: String, password: String },
    Ssh,
}

impl std::fmt::Debug for ImportAuth {
    /// Redacted: the HTTPS password/token never renders in any format, so a
    /// `Debug` print of any input or view struct carrying this value cannot
    /// disclose it (the derived `Debug` on the wrapper structs uses this).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportAuth::None => f.write_str("None"),
            ImportAuth::Https { username, .. } => {
                write!(
                    f,
                    "Https {{ username: {username:?}, password: <redacted> }}"
                )
            }
            ImportAuth::Ssh => f.write_str("Ssh"),
        }
    }
}

/// The `import` body of a repository-creation request (M4b D3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportInput {
    pub url: String,
    pub auth: ImportAuth,
}

/// What the API and pages show for a repository's import source: never a
/// secret, only `has_credentials` and, for SSH, the public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportView {
    pub repo_id: i64,
    pub state: String,
    pub url: String,
    pub auth: String,
    pub has_credentials: bool,
    pub ssh_public_key: Option<String>,
    pub last_error: String,
}

/// Whether pushes must be refused for this import state (M4b D3).
pub fn import_in_progress(state: &str) -> bool {
    matches!(state, "pending" | "running")
}

/// The sealed-credential record for one import, ready to insert or to write
/// back on retry.
pub(crate) struct PreparedImport {
    pub(crate) url: String,
    pub(crate) auth: &'static str,
    pub(crate) username: String,
    pub(crate) sealed_secret: Option<String>,
    pub(crate) ssh_public_key: Option<String>,
}

/// Refuses to start an import/pull-mirror fetch when the repository is
/// already at or above `limits.max_repo_bytes` (0 disables the check).
/// The error is a plain message: the callers record it on the remote row
/// exactly like a fetch failure. A measurement failure fails open with a
/// warning, matching the pre-receive hook.
async fn check_repo_size_for_fetch(core: &Core, repo_id: i64) -> Result<(), String> {
    let limit = core.config().max_repo_bytes;
    if limit == 0 {
        return Ok(());
    }
    match crate::protection::repo_disk_size(&core.repo_path(repo_id)).await {
        Ok(size) if size >= limit => Err(format!(
            "repository size limit reached ({} MiB of {} MiB); fetch refused",
            size / (1024 * 1024),
            limit / (1024 * 1024)
        )),
        Ok(_) => Ok(()),
        Err(err) => {
            tracing::warn!(error = %err, repo_id, "measuring repository size failed; allowing fetch");
            Ok(())
        }
    }
}

impl Core {
    /// Validates an import URL and seals its credentials. `Invalid` maps to
    /// 422 at creation (M4b D3). For SSH this generates a fresh ed25519
    /// keypair via `ssh-keygen`; the private half is sealed and only the
    /// public half is kept for display.
    pub(crate) async fn prepare_import(&self, input: &ImportInput) -> CoreResult<PreparedImport> {
        let pinned = self.check_remote_url(&input.url)?;
        let (auth, username, sealed_secret, ssh_public_key) = match &input.auth {
            ImportAuth::None => ("none", String::new(), None, None),
            ImportAuth::Https { username, password } => {
                let username = username.trim().to_owned();
                if username.is_empty() || password.is_empty() {
                    return Err(CoreError::Invalid(
                        "https import requires a username and a password or token".into(),
                    ));
                }
                let sealed = self.config().credential_box.seal(password.as_bytes());
                ("https", username, Some(sealed), None)
            }
            ImportAuth::Ssh => {
                let (private_key, public_key) = generate_import_key().await?;
                let sealed = self.config().credential_box.seal(private_key.as_bytes());
                ("ssh", String::new(), Some(sealed), Some(public_key))
            }
        };
        Ok(PreparedImport {
            url: pinned.url,
            auth,
            username,
            sealed_secret,
            ssh_public_key,
        })
    }

    fn import_view(&self, repo_id: i64, state: String, row: &db_remotes::RemoteRow) -> ImportView {
        ImportView {
            repo_id,
            state,
            url: row.url.clone(),
            auth: row.auth.clone(),
            has_credentials: row.sealed_secret.is_some(),
            ssh_public_key: row.ssh_public_key.clone(),
            last_error: row.last_error.clone(),
        }
    }

    /// The import source of one repository, if any.
    pub async fn import_for(&self, repo_id: i64) -> CoreResult<Option<ImportView>> {
        let Some(row) = db_remotes::by_repo_role(self.db(), repo_id, "import").await? else {
            return Ok(None);
        };
        let state = db_repos::import_state(self.db(), repo_id).await?;
        Ok(Some(self.import_view(repo_id, state, &row)))
    }

    /// Records the import source for a freshly created repository and
    /// queues the `ImportRepo` job — except for SSH, which waits in
    /// `pending` until "start import" is pressed (M4b D3).
    pub(crate) async fn create_import_for_repo(
        &self,
        actor_id: i64,
        repo_id: i64,
        full_name: &str,
        prepared: PreparedImport,
    ) -> CoreResult<ImportView> {
        let ssh = prepared.auth == "ssh";
        db_remotes::insert(
            self.db(),
            &db_remotes::NewRemote {
                repo_id,
                role: "import",
                url: &prepared.url,
                auth: prepared.auth,
                username: &prepared.username,
                sealed_secret: prepared.sealed_secret.as_deref(),
                ssh_public_key: prepared.ssh_public_key.as_deref(),
                created_by: actor_id,
            },
        )
        .await?;
        db_repos::set_import_state(self.db(), repo_id, "pending").await?;
        self.audit(
            Some(actor_id),
            "repo.import",
            &format!("repo:{full_name}"),
            &prepared.url,
        )
        .await?;
        if !ssh {
            self.enqueue(&crate::jobs::Job::ImportRepo { repo_id })
                .await?;
        }
        let row = db_remotes::by_repo_role(self.db(), repo_id, "import")
            .await?
            .ok_or(CoreError::Internal("import remote vanished".into()))?;
        Ok(self.import_view(repo_id, "pending".to_owned(), &row))
    }

    /// "Start import" (and retry after a failure). Maintain+ only; anything
    /// below that is 403 and anyone who cannot read is 404. `new_auth`
    /// replaces stored credentials (the "fix credentials" retry); without
    /// it the stored credentials run unchanged.
    pub async fn start_import(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        new_auth: Option<ImportAuth>,
    ) -> CoreResult<ImportView> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid(
                "archived repositories cannot import".into(),
            ));
        }
        let Some(row) = db_remotes::by_repo_role(self.db(), access.repo.id, "import").await? else {
            return Err(CoreError::NotFound);
        };
        if let Some(auth) = new_auth {
            let prepared = self
                .prepare_import(&ImportInput {
                    url: row.url.clone(),
                    auth,
                })
                .await?;
            db_remotes::update_credentials(
                self.db(),
                row.id,
                prepared.auth,
                &prepared.username,
                prepared.sealed_secret.as_deref(),
                prepared.ssh_public_key.as_deref(),
            )
            .await?;
        }
        db_repos::set_import_state(self.db(), access.repo.id, "pending").await?;
        self.enqueue(&crate::jobs::Job::ImportRepo {
            repo_id: access.repo.id,
        })
        .await?;
        self.import_for(access.repo.id)
            .await?
            .ok_or(CoreError::Internal("import remote vanished".into()))
    }

    /// Deletes the import source, returning the repository to a normal
    /// empty one (`import_state = none`).
    pub async fn delete_import(&self, actor: &User, owner: &str, name: &str) -> CoreResult<()> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        let Some(row) = db_remotes::by_repo_role(self.db(), access.repo.id, "import").await? else {
            return Err(CoreError::NotFound);
        };
        db_remotes::delete(self.db(), row.id).await?;
        db_repos::set_import_state(self.db(), access.repo.id, "none").await?;
        Ok(())
    }

    /// Runs one import: `pending|running` → `done` or `failed`. Failures
    /// are recorded (scrubbed) on the remote row and the job succeeds, so
    /// the failure is a stable `failed` state a human retries — never the
    /// job retry ladder spinning on bad credentials.
    pub(crate) async fn run_import(&self, repo_id: i64) -> CoreResult<()> {
        let Some(row) = db_remotes::by_repo_role(self.db(), repo_id, "import").await? else {
            return Ok(());
        };
        let state = db_repos::import_state(self.db(), repo_id).await?;
        if state != "pending" && state != "running" {
            return Ok(());
        }
        if !db_remotes::set_import_state_if_remote(self.db(), repo_id, "running").await? {
            return Ok(());
        }
        let outcome = self.fetch_import(repo_id, &row).await;
        // The remote row may have been deleted mid-fetch: never write a
        // terminal state against a deleted row.
        match outcome {
            Ok(()) => {
                if db_remotes::set_import_state_if_remote(self.db(), repo_id, "done").await? {
                    db_remotes::record_attempt(self.db(), row.id, true, "").await?;
                }
            }
            Err(message) => {
                if db_remotes::set_import_state_if_remote(self.db(), repo_id, "failed").await? {
                    db_remotes::record_attempt(self.db(), row.id, false, &message).await?;
                }
            }
        }
        Ok(())
    }

    async fn fetch_import(&self, repo_id: i64, row: &db_remotes::RemoteRow) -> Result<(), String> {
        // The fetch writes refs inside the repository: hold the shared
        // lock for the duration (plan M5b O1).
        let _repo_lock = self
            .repo_lock_shared(repo_id)
            .await
            .map_err(|e| e.to_string())?;
        check_repo_size_for_fetch(self, repo_id).await?;
        let pinned = self
            .check_remote_url(&row.url)
            .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        let creds = match row.auth.as_str() {
            "https" => {
                let sealed = row
                    .sealed_secret
                    .clone()
                    .ok_or_else(|| "credentials unreadable; re-enter them".to_owned())?;
                let plain = self
                    .config()
                    .credential_box
                    .open(&sealed)
                    .map_err(|_| "credentials unreadable; re-enter them".to_owned())?;
                let password = String::from_utf8(plain)
                    .map_err(|_| "credentials unreadable; re-enter them".to_owned())?;
                RemoteCreds::Basic {
                    username: row.username.clone(),
                    password,
                }
            }
            "ssh" => {
                let sealed = row
                    .sealed_secret
                    .clone()
                    .ok_or_else(|| "credentials unreadable; re-enter them".to_owned())?;
                let plain = self
                    .config()
                    .credential_box
                    .open(&sealed)
                    .map_err(|_| "credentials unreadable; re-enter them".to_owned())?;
                let private_key = String::from_utf8(plain)
                    .map_err(|_| "credentials unreadable; re-enter them".to_owned())?;
                RemoteCreds::SshKey { private_key }
            }
            _ => RemoteCreds::None,
        };
        let repo_dir = self.repo_path(repo_id);
        let known_hosts = remote_known_hosts(self, row.id);
        let refspecs: Vec<String> = IMPORT_REFSPECS.iter().map(|s| s.to_string()).collect();
        starforged_git::remote::fetch(
            &repo_dir,
            &pinned,
            &creds,
            &refspecs,
            IMPORT_FETCH_TIMEOUT,
            &known_hosts,
        )
        .await
        .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        let head = starforged_git::remote::ls_remote_head(
            &repo_dir,
            &pinned,
            &creds,
            IMPORT_FETCH_TIMEOUT,
            &known_hosts,
        )
        .await
        .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        let default_branch = head
            .symref
            .as_deref()
            .and_then(|target| target.strip_prefix("refs/heads/"))
            .unwrap_or("main")
            .to_owned();
        starforged_git::write::set_head(&repo_dir, &default_branch)
            .await
            .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        db_repos::set_default_branch(self.db(), repo_id, &default_branch)
            .await
            .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        Ok(())
    }

    // --- Pull mirrors (M4b D4). -------------------------------------------
    //
    // A pull mirror is one `pull` remote per repository: `git fetch --prune`
    // with the import refspecs, on a schedule (`interval_secs`, >= 300) plus
    // "sync now". While it is enabled `repos.mirror` is true: the hook
    // snapshot refuses every branch/tag push (refs/for still works) and
    // `Core::merge_change` refuses with the mirror message. Every moved
    // branch goes through the same branch-move ingest as post-receive, and
    // push webhooks fire with `sender: null`. Disabling (or deleting) the
    // remote restores pushes.

    /// Configures (or reconfigures) the pull mirror of one repository.
    /// Maintain+ only; archived repositories refuse. The URL passes the
    /// outbound policy and credentials are sealed, exactly like an import.
    /// Enabling (or re-enabling) sets `repos.mirror` and queues a sync.
    pub async fn set_pull_mirror(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        input: &PullMirrorInput,
    ) -> CoreResult<PullMirrorView> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid(
                "archived repositories cannot mirror".into(),
            ));
        }
        if input.interval_secs < 300 || input.interval_secs > 30 * 24 * 3600 {
            return Err(CoreError::Invalid(
                "mirror interval must be between 300 and 2592000 seconds (30 days)".into(),
            ));
        }
        let prepared = self
            .prepare_import(&ImportInput {
                url: input.url.clone(),
                auth: input.auth.clone(),
            })
            .await?;
        let target = format!("repo:{owner}/{name}");
        match db_remotes::by_repo_role(self.db(), access.repo.id, "pull").await? {
            Some(row) => {
                let creds_changed = prepared.sealed_secret.is_some();
                db_remotes::update_pull_config(
                    self.db(),
                    row.id,
                    &prepared.url,
                    prepared.auth,
                    &prepared.username,
                    prepared.sealed_secret.as_deref(),
                    prepared.ssh_public_key.as_deref(),
                    input.interval_secs,
                )
                .await?;
                self.audit(Some(actor.id), "mirror.update", &target, &prepared.url)
                    .await?;
                if creds_changed {
                    self.audit(
                        Some(actor.id),
                        "mirror.credentials_changed",
                        &target,
                        "pull",
                    )
                    .await?;
                }
            }
            None => {
                insert_pull_remote(
                    self,
                    actor.id,
                    access.repo.id,
                    &prepared,
                    input.interval_secs,
                )
                .await?;
                self.audit(Some(actor.id), "mirror.create", &target, &prepared.url)
                    .await?;
                if prepared.sealed_secret.is_some() {
                    self.audit(
                        Some(actor.id),
                        "mirror.credentials_changed",
                        &target,
                        "pull",
                    )
                    .await?;
                }
            }
        }
        db_repos::set_mirror(self.db(), access.repo.id, true).await?;
        self.enqueue_or_expedite(&crate::jobs::Job::PullMirror {
            repo_id: access.repo.id,
        })
        .await?;
        self.pull_mirror_for(access.repo.id)
            .await?
            .ok_or(CoreError::Internal("pull remote vanished".into()))
    }

    /// The pull mirror of one repository; readers may see it (404 otherwise).
    pub async fn pull_mirror_for(&self, repo_id: i64) -> CoreResult<Option<PullMirrorView>> {
        let Some(row) = db_remotes::by_repo_role(self.db(), repo_id, "pull").await? else {
            return Ok(None);
        };
        Ok(Some(PullMirrorView {
            repo_id,
            url: row.url.clone(),
            auth: row.auth.clone(),
            has_credentials: row.sealed_secret.is_some(),
            ssh_public_key: row.ssh_public_key.clone(),
            interval_secs: row.interval_secs,
            enabled: row.enabled != 0,
            last_attempt_at: row.last_attempt_at,
            last_success_at: row.last_success_at,
            last_error: row.last_error.clone(),
        }))
    }

    /// `GET …/mirror/pull` backing: readers see the configuration.
    pub async fn get_pull_mirror(
        &self,
        actor: Option<&User>,
        owner: &str,
        name: &str,
    ) -> CoreResult<PullMirrorView> {
        let access = self.repo_for(actor, owner, name).await?;
        self.pull_mirror_for(access.repo.id)
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// Enables or disables the pull mirror without forgetting it.
    /// Disabling sets `repos.mirror` back to false and restores pushes.
    pub async fn set_pull_mirror_enabled(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        enabled: bool,
    ) -> CoreResult<PullMirrorView> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        let Some(row) = db_remotes::by_repo_role(self.db(), access.repo.id, "pull").await? else {
            return Err(CoreError::NotFound);
        };
        db_remotes::set_enabled(self.db(), row.id, enabled).await?;
        db_repos::set_mirror(self.db(), access.repo.id, enabled).await?;
        self.audit(
            Some(actor.id),
            "mirror.update",
            &format!("repo:{owner}/{name}"),
            if enabled { "enabled" } else { "disabled" },
        )
        .await?;
        if enabled {
            self.enqueue_or_expedite(&crate::jobs::Job::PullMirror {
                repo_id: access.repo.id,
            })
            .await?;
        }
        self.pull_mirror_for(access.repo.id)
            .await?
            .ok_or(CoreError::Internal("pull remote vanished".into()))
    }

    /// Deletes the pull mirror, returning the repository to a normal one.
    pub async fn delete_pull_mirror(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        let Some(row) = db_remotes::by_repo_role(self.db(), access.repo.id, "pull").await? else {
            return Err(CoreError::NotFound);
        };
        db_remotes::delete(self.db(), row.id).await?;
        db_repos::set_mirror(self.db(), access.repo.id, false).await?;
        self.audit(
            Some(actor.id),
            "mirror.delete",
            &format!("repo:{owner}/{name}"),
            &row.url,
        )
        .await?;
        Ok(())
    }

    /// "Sync now": queues an immediate sync (deduplicated per repository).
    pub async fn sync_pull_mirror(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
    ) -> CoreResult<PullMirrorView> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid(
                "repository is archived; mirror paused".into(),
            ));
        }
        let row = db_remotes::by_repo_role(self.db(), access.repo.id, "pull")
            .await?
            .ok_or(CoreError::NotFound)?;
        if row.enabled == 0 {
            return Err(CoreError::Invalid("mirror is disabled".into()));
        }
        self.enqueue_or_expedite(&crate::jobs::Job::PullMirror {
            repo_id: access.repo.id,
        })
        .await?;
        self.pull_mirror_for(access.repo.id)
            .await?
            .ok_or(CoreError::Internal("pull remote vanished".into()))
    }

    /// One pull-mirror sync: fetch, ingest the moves, re-enqueue at the
    /// configured interval. Failures are recorded (scrubbed) on the remote
    /// row and re-enqueued after the backoff floor, so a failing upstream
    /// is never hammered and never blocks the repository.
    pub(crate) async fn run_pull_mirror(&self, repo_id: i64) -> CoreResult<()> {
        let Some(row) = db_remotes::by_repo_role(self.db(), repo_id, "pull").await? else {
            return Ok(());
        };
        if row.enabled == 0 {
            return Ok(());
        }
        // Archived repositories are read-only: never fetch into them. The
        // pause is the remote's last error; rescheduling still runs, so
        // unarchiving resumes syncing with no reconfiguration.
        let archived = db_repos::by_id(self.db(), repo_id)
            .await?
            .is_some_and(|repo| repo.archived_at.is_some());
        if archived {
            db_remotes::record_attempt(self.db(), row.id, false, MIRROR_PAUSED_MESSAGE).await?;
            return Ok(());
        }
        let outcome = self.fetch_pull(repo_id, &row).await;
        match outcome {
            Ok(()) => {
                db_remotes::record_attempt(self.db(), row.id, true, "").await?;
            }
            Err(message) => {
                db_remotes::record_attempt(self.db(), row.id, false, &message).await?;
            }
        }
        Ok(())
    }

    /// Schedules the next pull-mirror sync after a finished run (called by
    /// the job runner once the current row is done, so the insert never
    /// collides with the dedupe key the running job still holds): at the
    /// mirror's interval after a success, or the 300 s backoff floor after
    /// a failure. A disabled or deleted mirror never reschedules.
    pub(crate) async fn reschedule_pull_mirror(&self, repo_id: i64) -> CoreResult<()> {
        let Some(row) = db_remotes::by_repo_role(self.db(), repo_id, "pull").await? else {
            return Ok(());
        };
        if row.enabled == 0 {
            return Ok(());
        }
        let delay = if row.last_error.is_empty() || row.last_error == MIRROR_PAUSED_MESSAGE {
            row.interval_secs.max(300)
        } else {
            300
        };
        self.enqueue_at(&crate::jobs::Job::PullMirror { repo_id }, now_plus(delay))
            .await?;
        Ok(())
    }

    /// Re-queues a sync for every enabled pull mirror and a run for every
    /// enabled push mirror. Self-rescheduling alone has no recovery: a
    /// worker stop between completion and reschedule, or a job exhausted
    /// by lease expiry, would silently stop the mirror forever. Runs at
    /// worker start and from the hourly cleanup; the per-key dedupe makes
    /// each enqueue idempotent (a queued job is left alone, whatever its
    /// `run_at`). Push mirrors enqueue at `now` here (not debounced):
    /// reconciliation only fires when no run is queued at all.
    pub async fn reconcile_mirror_schedules(&self) -> CoreResult<()> {
        for repo_id in db_remotes::enabled_pull_repo_ids(self.db()).await? {
            self.enqueue(&crate::jobs::Job::PullMirror { repo_id })
                .await?;
        }
        for remote_id in db_remotes::enabled_push_remote_ids(self.db()).await? {
            self.enqueue(&crate::jobs::Job::PushMirror { remote_id })
                .await?;
        }
        Ok(())
    }

    async fn fetch_pull(&self, repo_id: i64, row: &db_remotes::RemoteRow) -> Result<(), String> {
        // The fetch writes refs inside the repository: hold the shared
        // lock for the fetch and the resulting ingest (plan M5b O1).
        let _repo_lock = self
            .repo_lock_shared(repo_id)
            .await
            .map_err(|e| e.to_string())?;
        check_repo_size_for_fetch(self, repo_id).await?;
        let pinned = self
            .check_remote_url(&row.url)
            .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        let creds =
            pull_creds(self, row).map_err(|e| starforged_git::remote::scrub(&e, &row.url))?;
        let repo_dir = self.repo_path(repo_id);
        let before = self.snapshot_refs(&repo_dir).await;
        let refspecs: Vec<String> = IMPORT_REFSPECS.iter().map(|s| s.to_string()).collect();
        starforged_git::remote::fetch(
            &repo_dir,
            &pinned,
            &creds,
            &refspecs,
            PULL_MIRROR_FETCH_TIMEOUT,
            &remote_known_hosts(self, row.id),
        )
        .await
        .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        // A snapshot failure must not silently drop the moves: the failed
        // fetch is recorded and backed off instead.
        let Some(before) = before else {
            return Err("ref snapshot failed".to_owned());
        };
        let Some(after) = self.snapshot_refs(&repo_dir).await else {
            return Err("ref snapshot failed".to_owned());
        };
        // Diff the tips and run the same ingest as post-receive (D4):
        // revisions for branch changes, mergeability, push webhooks with
        // `sender: null` (no pusher).
        let zero = "0".repeat(40);
        let mut moves: Vec<(String, Option<String>, String)> = Vec::new();
        let mut updates: Vec<crate::changes::RefUpdate> = Vec::new();
        for (name, tip) in &after {
            if !name.starts_with("refs/heads/") && !name.starts_with("refs/tags/") {
                continue;
            }
            let old = before.get(name);
            if old == Some(tip) {
                continue;
            }
            moves.push((name.clone(), old.cloned(), tip.clone()));
            updates.push(crate::changes::RefUpdate {
                name: name.clone(),
                old: old.cloned().unwrap_or_else(|| zero.clone()),
                new: tip.clone(),
            });
        }
        for (name, old) in &before {
            if !name.starts_with("refs/heads/") && !name.starts_with("refs/tags/") {
                continue;
            }
            if after.contains_key(name) {
                continue;
            }
            // Pruned by `--prune`: a delete still recomputes mergeability.
            moves.push((name.clone(), Some(old.clone()), zero.clone()));
            updates.push(crate::changes::RefUpdate {
                name: name.clone(),
                old: old.clone(),
                new: zero.clone(),
            });
        }
        if moves.is_empty() {
            return Ok(());
        }
        let ingest = self.repo_ingest_lock(repo_id).await;
        self.ingest_branch_moves(&ingest, repo_id, None, &moves)
            .await;
        self.record_push(repo_id, None, &updates).await;
        Ok(())
    }

    // --- Push mirrors (M4b D5). ------------------------------------------
    //
    // Up to 10 `push` remotes per repository. After every accepted push the
    // post-receive scan enqueues one `PushMirror` job per enabled remote at
    // now + 30 s, deduped per remote, so pushes inside the window coalesce
    // into one run. The job runs `git push --prune` with the explicit
    // branches/tags refspecs: a true mirror, where a deleted branch or tag
    // disappears upstream too. `refs/trails/*` and `refs/for/*` never go
    // out. Failures are recorded (scrubbed) on the remote row and retried
    // after the backoff; a successful run does not reschedule itself — the
    // next accepted push debounces a fresh run. A push mirror never blocks
    // the repository's own pushes.

    /// Adds one push mirror. Maintain+ only; archived repositories refuse.
    /// The URL passes the outbound policy and credentials are sealed,
    /// exactly like an import. The 11th mirror is refused (422).
    pub async fn add_push_mirror(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        input: &PushMirrorInput,
    ) -> CoreResult<PushMirrorView> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid(
                "archived repositories cannot mirror".into(),
            ));
        }
        let prepared = self
            .prepare_import(&ImportInput {
                url: input.url.clone(),
                auth: input.auth.clone(),
            })
            .await?;
        let target = format!("repo:{owner}/{name}");
        // Count and insert serialize under the repository row lock
        // (`insert_push_remote_capped`), so concurrent adds cannot
        // exceed the cap.
        let Some(id) = db_remotes::insert_push_remote_capped(
            self.db(),
            &db_remotes::NewRemote {
                repo_id: access.repo.id,
                role: "push",
                url: &prepared.url,
                auth: prepared.auth,
                username: &prepared.username,
                sealed_secret: prepared.sealed_secret.as_deref(),
                ssh_public_key: prepared.ssh_public_key.as_deref(),
                created_by: actor.id,
            },
            PUSH_MIRROR_MAX as i64,
        )
        .await?
        else {
            return Err(CoreError::Invalid(format!(
                "a repository may have at most {PUSH_MIRROR_MAX} push mirrors"
            )));
        };
        self.audit(Some(actor.id), "mirror.create", &target, &prepared.url)
            .await?;
        if prepared.sealed_secret.is_some() {
            self.audit(
                Some(actor.id),
                "mirror.credentials_changed",
                &target,
                "push",
            )
            .await?;
        }
        self.enqueue_at(
            &crate::jobs::Job::PushMirror { remote_id: id },
            now_plus(PUSH_MIRROR_DEBOUNCE_SECS),
        )
        .await?;
        let row = db_remotes::by_id(self.db(), id)
            .await?
            .ok_or(CoreError::Internal("push remote vanished".into()))?;
        Ok(push_mirror_view(&row))
    }

    /// Every push mirror of one repository; readers may see them (404
    /// otherwise).
    pub async fn list_push_mirrors(
        &self,
        actor: Option<&User>,
        owner: &str,
        name: &str,
    ) -> CoreResult<Vec<PushMirrorView>> {
        let access = self.repo_for(actor, owner, name).await?;
        Ok(db_remotes::list_by_repo(self.db(), access.repo.id)
            .await?
            .into_iter()
            .filter(|row| row.role == "push")
            .map(|row| push_mirror_view(&row))
            .collect())
    }

    /// The push mirrors of one repository for the settings page (already
    /// access-checked by the caller).
    pub async fn push_mirrors_for(&self, repo_id: i64) -> CoreResult<Vec<PushMirrorView>> {
        Ok(db_remotes::list_by_repo(self.db(), repo_id)
            .await?
            .into_iter()
            .filter(|row| row.role == "push")
            .map(|row| push_mirror_view(&row))
            .collect())
    }

    /// Deletes one push mirror. Queued jobs for it become no-ops.
    pub async fn delete_push_mirror(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        remote_id: i64,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        let Some(row) = db_remotes::by_id(self.db(), remote_id).await? else {
            return Err(CoreError::NotFound);
        };
        if row.repo_id != access.repo.id || row.role != "push" {
            return Err(CoreError::NotFound);
        }
        db_remotes::delete(self.db(), row.id).await?;
        self.audit(
            Some(actor.id),
            "mirror.delete",
            &format!("repo:{owner}/{name}"),
            &row.url,
        )
        .await?;
        Ok(())
    }

    /// "Sync now" for one push mirror: queues an immediate run (deduped per
    /// remote; a queued debounced run is expedited).
    pub async fn sync_push_mirror(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        remote_id: i64,
    ) -> CoreResult<PushMirrorView> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        let Some(row) = db_remotes::by_id(self.db(), remote_id).await? else {
            return Err(CoreError::NotFound);
        };
        if row.repo_id != access.repo.id || row.role != "push" {
            return Err(CoreError::NotFound);
        }
        self.enqueue_or_expedite(&crate::jobs::Job::PushMirror { remote_id })
            .await?;
        Ok(push_mirror_view(&row))
    }

    /// One debounced run after an accepted push: enqueue every enabled push
    /// mirror of the repository at now + 30 s, deduped per remote. Called by
    /// the post-receive scan; never fails the push (the caller logs and
    /// ignores errors).
    pub(crate) async fn enqueue_push_mirrors(&self, repo_id: i64) -> CoreResult<()> {
        for row in db_remotes::list_by_repo(self.db(), repo_id).await? {
            if row.role != "push" || row.enabled == 0 {
                continue;
            }
            self.enqueue_at(
                &crate::jobs::Job::PushMirror { remote_id: row.id },
                now_plus(PUSH_MIRROR_DEBOUNCE_SECS),
            )
            .await?;
        }
        Ok(())
    }

    /// One push-mirror run: `git push --prune` with the explicit
    /// branches/tags refspecs. Failures are recorded (scrubbed) on the
    /// remote row and the job succeeds, so a failing target never blocks
    /// the repository; the post-run reschedule backs it off.
    pub(crate) async fn run_push_mirror(&self, remote_id: i64) -> CoreResult<()> {
        let Some(row) = db_remotes::by_id(self.db(), remote_id).await? else {
            return Ok(());
        };
        if row.role != "push" || row.enabled == 0 {
            return Ok(());
        }
        let outcome = self.push_remote(&row).await;
        match outcome {
            Ok(()) => {
                db_remotes::record_attempt(self.db(), row.id, true, "").await?;
            }
            Err(message) => {
                db_remotes::record_attempt(self.db(), row.id, false, &message).await?;
            }
        }
        Ok(())
    }

    /// Schedules the retry after a failed run (called by the job runner once
    /// the current row is done, so the insert never collides with the
    /// dedupe key the running job still holds): at the backoff after a
    /// failure. A successful run does not reschedule — the next accepted
    /// push debounces a fresh run. A disabled or deleted mirror never
    /// reschedules.
    pub(crate) async fn reschedule_push_mirror(&self, remote_id: i64) -> CoreResult<()> {
        let Some(row) = db_remotes::by_id(self.db(), remote_id).await? else {
            return Ok(());
        };
        if row.role != "push" || row.enabled == 0 || row.last_error.is_empty() {
            return Ok(());
        }
        self.enqueue_at(
            &crate::jobs::Job::PushMirror { remote_id },
            now_plus(PUSH_MIRROR_BACKOFF_SECS),
        )
        .await?;
        Ok(())
    }

    async fn push_remote(&self, row: &db_remotes::RemoteRow) -> Result<(), String> {
        // A push reads every ref tip of the repository: hold the shared repo
        // lock for the whole push so a concurrent exclusive writer (backup,
        // purge) cannot move refs mid-push (O1).
        let _guard = self
            .repo_lock_shared(row.repo_id)
            .await
            .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        let pinned = self
            .check_remote_url(&row.url)
            .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        let creds =
            pull_creds(self, row).map_err(|e| starforged_git::remote::scrub(&e, &row.url))?;
        let repo_dir = self.repo_path(row.repo_id);
        let refspecs: Vec<String> = PUSH_MIRROR_REFSPECS.iter().map(|s| s.to_string()).collect();
        starforged_git::remote::push(
            &repo_dir,
            &pinned,
            &creds,
            &refspecs,
            PUSH_MIRROR_PUSH_TIMEOUT,
            &remote_known_hosts(self, row.id),
        )
        .await
        .map_err(|e| starforged_git::remote::scrub(&e.to_string(), &row.url))?;
        Ok(())
    }

    /// The repository's import-in-progress flag for the hook snapshot
    /// (`Core::git_rpc_env`).
    pub async fn import_in_progress(&self, repo_id: i64) -> CoreResult<bool> {
        Ok(import_in_progress(
            &db_repos::import_state(self.db(), repo_id).await?,
        ))
    }
}

/// Generates one ed25519 keypair for an SSH import with `ssh-keygen`
/// (the same tools the SSH remote itself needs): the private key is
/// returned for sealing and the public line for display.
pub async fn generate_import_key() -> CoreResult<(String, String)> {
    let dir = tempfile::TempDir::with_prefix("starforge-import-")
        .map_err(|e| CoreError::Internal(e.to_string()))?;
    let key_path = dir.path().join("import_key");
    let output = tokio::process::Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg("starforge-import")
        .arg("-f")
        .arg(&key_path)
        .output()
        .await
        .map_err(|e| CoreError::Internal(format!("running ssh-keygen: {e}")))?;
    if !output.status.success() {
        return Err(CoreError::Internal(format!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let private_key =
        std::fs::read_to_string(&key_path).map_err(|e| CoreError::Internal(e.to_string()))?;
    let public_key = std::fs::read_to_string(key_path.with_extension("pub"))
        .map_err(|e| CoreError::Internal(e.to_string()))?;
    // The TempDir guard removes the directory — the unsealed private key —
    // on every return path.
    drop(dir);
    Ok((private_key, public_key.trim().to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn public() -> FixedResolver {
        FixedResolver {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
        }
    }

    fn private() -> FixedResolver {
        FixedResolver {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
        }
    }

    #[test]
    fn refuses_disallowed_transports_and_hosts() {
        let r = public();
        for url in [
            "file:///srv/repos/x.git",
            "/srv/repos/x.git",
            "./local.git",
            "../local.git",
            "ext::sh -c 'id'",
            "fd::17",
            "git://git.example.com/x.git",
            "ftp://git.example.com/x.git",
            "https://",
            "",
        ] {
            assert!(check_url(url, false, &r).is_err(), "{url} must be refused");
        }
        // Private, loopback (flag off), and metadata IPs are refused.
        assert!(check_url("https://10.0.0.1/x.git", false, &r).is_err());
        assert!(check_url("https://127.0.0.1/x.git", false, &r).is_err());
        assert!(check_url("https://169.254.169.254/x.git", false, &r).is_err());
        assert!(check_url("https://[::1]/x.git", false, &r).is_err());
        // A public hostname resolving only to private addresses is refused.
        assert!(check_url("https://evil.example.com/x.git", false, &private()).is_err());
        // Plain http to a public host is refused.
        assert!(check_url("http://git.example.com/x.git", false, &r).is_err());
    }

    #[test]
    fn accepts_https_and_ssh_to_public_hosts() {
        let r = public();
        let pinned = check_url("https://git.example.com/owner/repo.git", false, &r).unwrap();
        assert_eq!(pinned.scheme, RemoteScheme::Https);
        assert_eq!(pinned.port, 443);
        assert_eq!(
            pinned.pinned_ip,
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        );
        // Pinning arguments are produced.
        let args = pinned.config_args();
        assert!(
            args.iter()
                .any(|a| a == "http.curloptResolve=git.example.com:443:93.184.216.34"),
            "{args:?}"
        );
        let ssh = check_url("ssh://git@git.example.com/owner/repo.git", false, &r).unwrap();
        assert_eq!(ssh.scheme, RemoteScheme::Ssh);
        assert_eq!(ssh.port, 22);
        let scp = check_url("git@git.example.com:owner/repo.git", false, &r).unwrap();
        assert_eq!(scp.scheme, RemoteScheme::Ssh);
        assert_eq!(scp.host, "git.example.com");
        // Passwords are stripped from the URL git receives.
        let with_pw = check_url("https://git:tok@git.example.com/x.git", false, &r).unwrap();
        assert!(!with_pw.url.contains("tok"), "{}", with_pw.url);
    }

    #[test]
    fn test_flag_admits_file_urls_and_loopback() {
        let r = FixedResolver {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
        };
        let file = check_url("file:///srv/repos/x.git", true, &r).unwrap();
        assert_eq!(file.scheme, RemoteScheme::File);
        let local = check_url("/srv/repos/x.git", true, &r).unwrap();
        assert_eq!(local.scheme, RemoteScheme::File);
        // Loopback under the flag: https, ssh, and http all pass.
        assert!(check_url("https://127.0.0.1/x.git", true, &r).is_ok());
        assert!(check_url("http://127.0.0.1:8080/x.git", true, &r).is_ok());
        assert!(check_url("ssh://git@127.0.0.1/x.git", true, &r).is_ok());
        // Private addresses stay refused even under the flag.
        let priv_r = private();
        assert!(check_url("https://192.168.1.1/x.git", true, &priv_r).is_err());
        // And http to a non-loopback host stays refused under the flag.
        assert!(check_url("http://git.example.com/x.git", true, &public()).is_err());
    }

    #[test]
    fn refuses_dash_leading_user_host_and_url() {
        let r = public();
        // ssh `-oProxyCommand=` option injection, scp-like and ssh:// forms.
        for url in [
            "-oProxyCommand=id@evil.com:repo",
            "git@-oProxyCommand=id:repo",
            "-oProxyCommand=id",
            "ssh://-oProxyCommand=id@git.example.com/repo.git",
            "ssh://git@-oProxyCommand=id/repo.git",
            "-https://git.example.com/repo.git",
        ] {
            assert!(check_url(url, false, &r).is_err(), "{url} must be refused");
            // …even under the test flag (no local-path fall-through).
            assert!(
                check_url(url, true, &r).is_err(),
                "{url} must be refused under the flag"
            );
        }
        // Control characters and whitespace in user/host are refused.
        assert!(check_url("git@evil host:repo", false, &r).is_err());
        assert!(check_url("git@evil\thost:repo", false, &r).is_err());
        assert!(check_url("https://git.example.com/repo\x07.git", false, &r).is_err());
        // The scp-like parser itself refuses them too.
        assert_eq!(parse_scp_like("-oProxyCommand=id@evil.com:repo"), None);
        assert_eq!(parse_scp_like("git@-oProxyCommand=id:repo"), None);
        assert_eq!(parse_scp_like("git@evil host:repo"), None);
        // A normal scp-like URL still parses.
        assert_eq!(
            parse_scp_like("git@git.example.com:owner/repo.git"),
            Some(("git.example.com".to_owned(), "git".to_owned()))
        );
    }
}
