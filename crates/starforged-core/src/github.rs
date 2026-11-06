//! A small GitHub REST v3 client for the M4c metadata import (spec §8.6).
//!
//! Only the endpoints the import needs: repository metadata, issues, pull
//! requests, issue comments, review comments, and reviews, `Link`-header
//! paginated. Every request goes to the configured `github.api_url` base
//! (default `https://api.github.com`; GitHub Enterprise allowed) and obeys
//! the plan's outbound rules:
//!
//! - the host is checked with the webhook SSRF rules
//!   ([`crate::webhooks::host_allowed`]): private, link-local (including
//!   the metadata endpoint), unique-local, multicast, and the other
//!   non-global ranges are refused fail-closed, and the checked address is
//!   pinned so DNS cannot change between the check and the connection.
//!   Only the test-only `allow_loopback` flag admits loopback.
//! - no redirects, a 30 s per-request timeout, and every response body
//!   capped at 10 MiB, read chunk by chunk.
//! - pagination follows only `Link: rel="next"` URLs on the same origin as
//!   `api_url` (scheme, host, and port); a cross-origin next link ends the
//!   page walk instead of being followed.
//! - a 403 or 429 carrying `X-RateLimit-Remaining: 0` or a `Retry-After`
//!   header maps to [`GithubError::RateLimited`] with the reset time, so
//!   the import job can save its cursor and re-enqueue itself.
//!
//! The token travels as a bearer credential and is never logged or
//! rendered; the error strings in this module carry no token either.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::webhooks::host_allowed;

/// Per-request timeout (plan Global Constraints).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Response body cap (plan Global Constraints): 10 MiB.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Errors from the GitHub client. `RateLimited` is control flow for the
/// import job (save the cursor, re-enqueue at the reset time), not a
/// failure; everything else follows the job's retry ladder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubError {
    /// The API answered 403/429 with `X-RateLimit-Remaining: 0` or
    /// `Retry-After`. `reset_at` is unix seconds.
    RateLimited { reset_at: i64 },
    /// The API answered a non-success status that is not a rate limit.
    Http { status: u16, message: String },
    /// The request was refused before it was sent (bad `api_url`, SSRF).
    Invalid(String),
    /// A transport failure (including the 30 s timeout, or an over-cap
    /// response body).
    Transport(String),
}

impl std::fmt::Display for GithubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GithubError::RateLimited { reset_at } => {
                write!(f, "github rate limit reached, resets at {reset_at}")
            }
            GithubError::Http { status, message } => {
                write!(f, "github api returned {status}: {message}")
            }
            GithubError::Invalid(message) => write!(f, "{message}"),
            GithubError::Transport(message) => write!(f, "github request failed: {message}"),
        }
    }
}

impl std::error::Error for GithubError {}

pub type GithubResult<T> = Result<T, GithubError>;

/// One `Link`-header page: the objects plus the same-origin `next` URL
/// when the API offered one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next: Option<String>,
}

/// A GitHub user as the import uses it (D1): the login, plus the public
/// email carried on the API objects for verified-email matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhUser {
    pub login: String,
    #[serde(default)]
    pub email: Option<String>,
}

/// A label name (D1: labels are created by name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhLabel {
    pub name: String,
}

/// An issue (spec §8.6): becomes a Trail without changes. `pull_request`
/// is present exactly for pull requests, which the issues listing skips
/// (D5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhIssue {
    pub id: i64,
    pub number: i64,
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    pub state: String,
    /// `null` for a deleted GitHub account.
    #[serde(default)]
    pub user: Option<GhUser>,
    #[serde(default)]
    pub labels: Vec<GhLabel>,
    #[serde(default)]
    pub assignees: Vec<GhUser>,
    #[serde(default)]
    pub pull_request: Option<GhPullRequestRef>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub closed_at: Option<String>,
}

/// Presence-only marker: an issues-listing object that is a pull request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhPullRequestRef {}

/// A branch ref on a pull request (D3: `base.ref` / `head.ref`+`head.sha`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhRef {
    #[serde(rename = "ref")]
    pub name: String,
    pub sha: String,
}

/// A pull request (D3): becomes a Trail with one `imported` change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhPull {
    pub id: i64,
    pub number: i64,
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    pub state: String,
    #[serde(default)]
    pub user: Option<GhUser>,
    #[serde(default)]
    pub labels: Vec<GhLabel>,
    #[serde(default)]
    pub assignees: Vec<GhUser>,
    pub head: GhRef,
    pub base: GhRef,
    #[serde(default)]
    pub merged_at: Option<String>,
    #[serde(default)]
    pub merge_commit_sha: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub closed_at: Option<String>,
    #[serde(default)]
    pub html_url: Option<String>,
}

/// One comment object, shared by issue comments and review comments
/// (D4): the review-comment fields (`path`, `line`, `original_line`,
/// `side`, `in_reply_to_id`) are absent on issue comments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhComment {
    pub id: i64,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub user: Option<GhUser>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub html_url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub line: Option<i64>,
    #[serde(default)]
    pub original_line: Option<i64>,
    #[serde(default)]
    pub side: Option<String>,
    #[serde(default)]
    pub in_reply_to_id: Option<i64>,
    /// `pull_request_review_id` on review comments (D4).
    #[serde(default)]
    pub pull_request_review_id: Option<i64>,
}

/// A pull-request review (D4): `state` is `APPROVED`, `CHANGES_REQUESTED`,
/// `COMMENTED`, or `PENDING`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhReview {
    pub id: i64,
    pub state: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub user: Option<GhUser>,
    #[serde(default)]
    pub submitted_at: Option<String>,
    #[serde(default)]
    pub html_url: Option<String>,
}

/// Repository metadata the import uses (D3: `clone_url` for the pull-head
/// fetch, `full_name` for the source slug).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GhRepository {
    pub id: i64,
    pub full_name: String,
    pub clone_url: String,
}

/// The GitHub API client. Cheap to clone per job run; build one with
/// [`GithubClient::new`] and share it across the pages of one import.
#[derive(Clone)]
pub struct GithubClient {
    base: url::Url,
    token: String,
    allow_loopback: bool,
}

impl std::fmt::Debug for GithubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubClient")
            .field("base", &self.base)
            .field("token", &"<redacted>")
            .field("allow_loopback", &self.allow_loopback)
            .finish()
    }
}

impl GithubClient {
    /// Builds a client for `api_url` (e.g. `https://api.github.com`).
    /// `api_url` must be `https` — or `http` to a loopback host when
    /// `allow_loopback` (the test-only flag) is set — and its host must
    /// pass the webhook SSRF rules. Literal-IP hosts are classified here;
    /// hostnames resolve (and pin) on the first request.
    pub fn new(api_url: &str, token: &str, allow_loopback: bool) -> GithubResult<GithubClient> {
        let base = url::Url::parse(api_url)
            .map_err(|_| GithubError::Invalid("github api_url is not a valid url".into()))?;
        let host = base
            .host_str()
            .ok_or_else(|| GithubError::Invalid("github api_url has no host".into()))?;
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        match base.scheme() {
            "https" => {}
            "http" if allow_loopback => {
                let is_loopback = bare
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback());
                if !is_loopback {
                    return Err(GithubError::Invalid(
                        "github api_url http is only allowed to loopback hosts".into(),
                    ));
                }
            }
            _ => {
                return Err(GithubError::Invalid("github api_url must be https".into()));
            }
        }
        if let Ok(ip) = bare.parse::<std::net::IpAddr>()
            && !host_allowed(ip, allow_loopback)
        {
            return Err(GithubError::Invalid(format!(
                "github api host {host} is not allowed"
            )));
        }
        Ok(GithubClient {
            base,
            token: token.to_owned(),
            allow_loopback,
        })
    }

    /// Repository metadata for `owner/repo` (D3: `clone_url`).
    pub async fn get_repository(&self, owner: &str, repo: &str) -> GithubResult<GhRepository> {
        self.get(&format!("repos/{owner}/{repo}")).await
    }

    /// Issues (`state=all`), ascending by number (D5).
    pub async fn list_issues(
        &self,
        owner: &str,
        repo: &str,
        page: u32,
    ) -> GithubResult<Page<GhIssue>> {
        let path = format!("repos/{owner}/{repo}/issues?state=all&per_page=100&page={page}");
        self.page(&path).await
    }

    /// Pull requests (`state=all`), ascending by number (D5).
    pub async fn list_pulls(
        &self,
        owner: &str,
        repo: &str,
        page: u32,
    ) -> GithubResult<Page<GhPull>> {
        let path = format!("repos/{owner}/{repo}/pulls?state=all&per_page=100&page={page}");
        self.page(&path).await
    }

    /// Comments on one issue or pull request, ascending by id (D5).
    pub async fn list_issue_comments(
        &self,
        owner: &str,
        repo: &str,
        number: i64,
        page: u32,
    ) -> GithubResult<Page<GhComment>> {
        let path =
            format!("repos/{owner}/{repo}/issues/{number}/comments?per_page=100&page={page}");
        self.page(&path).await
    }

    /// Review comments on pull request `number`, ascending by id (D4/D5).
    pub async fn list_review_comments(
        &self,
        owner: &str,
        repo: &str,
        number: i64,
        page: u32,
    ) -> GithubResult<Page<GhComment>> {
        let path = format!("repos/{owner}/{repo}/pulls/{number}/comments?per_page=100&page={page}");
        self.page(&path).await
    }

    /// Reviews on pull request `number`, ascending by id (D4/D5).
    pub async fn list_reviews(
        &self,
        owner: &str,
        repo: &str,
        number: i64,
        page: u32,
    ) -> GithubResult<Page<GhReview>> {
        let path = format!("repos/{owner}/{repo}/pulls/{number}/reviews?per_page=100&page={page}");
        self.page(&path).await
    }

    fn url_for(&self, path: &str) -> GithubResult<url::Url> {
        self.base
            .join(path)
            .map_err(|_| GithubError::Invalid("github api path is invalid".into()))
    }

    async fn page<T: serde::de::DeserializeOwned>(&self, path: &str) -> GithubResult<Page<T>> {
        let url = self.url_for(path)?;
        let (items, next) = self.get_page(&url).await?;
        Ok(Page { items, next })
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> GithubResult<T> {
        let url = self.url_for(path)?;
        let (value, _next) = self.get_page::<T>(&url).await?;
        Ok(value)
    }

    /// GETs `url` (already same-origin with `api_url`) and decodes the
    /// JSON body, returning the same-origin `rel="next"` link if any.
    async fn get_page<T: serde::de::DeserializeOwned>(
        &self,
        url: &url::Url,
    ) -> GithubResult<(T, Option<String>)> {
        let client = self.http_client().await?;
        let response = client
            .get(url.as_str())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    GithubError::Transport("github request timed out after 30s".into())
                } else {
                    GithubError::Transport(format!("github request failed: {e}"))
                }
            })?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        if (status == 403 || status == 429)
            && let Some(reset_at) = rate_limit_reset(&headers)
        {
            return Err(GithubError::RateLimited { reset_at });
        }
        let mut body = Vec::new();
        let mut response = response;
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|e| GithubError::Transport(format!("github request failed: {e}")))?;
            let Some(bytes) = chunk else { break };
            if body.len() + bytes.len() > MAX_BODY_BYTES {
                return Err(GithubError::Transport(
                    "github response body exceeds the 10 MiB cap".into(),
                ));
            }
            body.extend_from_slice(&bytes);
        }
        if !(200..300).contains(&status) {
            let message = String::from_utf8_lossy(&body);
            let message = message.trim();
            let message = if message.is_empty() {
                format!("unexpected status {status}")
            } else {
                message.to_owned()
            };
            return Err(GithubError::Http { status, message });
        }
        let next = parse_next_link(headers.get("Link"), &self.base);
        let value: T = serde_json::from_slice(&body).map_err(|e| {
            GithubError::Transport(format!("github response is not valid json: {e}"))
        })?;
        Ok((value, next))
    }

    /// The pinned client: resolves `api_url`'s host once per client (the
    /// first request pins the first SSRF-allowed address) and connects to
    /// exactly that address, never re-resolving.
    async fn http_client(&self) -> GithubResult<reqwest::Client> {
        let mut builder = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none());
        if let Some((domain, target)) = self.pinned_target().await? {
            builder = builder.resolve(&domain, target);
        }
        builder
            .build()
            .map_err(|e| GithubError::Transport(format!("building the github client failed: {e}")))
    }

    async fn pinned_target(&self) -> GithubResult<Option<(String, SocketAddr)>> {
        let host = self
            .base
            .host_str()
            .ok_or_else(|| GithubError::Invalid("github api_url has no host".into()))?;
        let port = self
            .base
            .port_or_known_default()
            .ok_or_else(|| GithubError::Invalid("github api_url has no port".into()))?;
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        // IP literals were classified in `new`; nothing to pin.
        if bare.parse::<std::net::IpAddr>().is_ok() {
            return Ok(None);
        }
        let mut allowed: Option<SocketAddr> = None;
        let addrs = tokio::net::lookup_host((host, port)).await.map_err(|e| {
            GithubError::Invalid(format!("github api host {host} does not resolve: {e}"))
        })?;
        for addr in addrs {
            if allowed.is_none() && host_allowed(addr.ip(), self.allow_loopback) {
                allowed = Some(addr);
            }
        }
        allowed
            .map(|addr| (host.to_owned(), addr))
            .map(Some)
            .ok_or_else(|| {
                GithubError::Invalid(format!(
                    "github api host {host} resolves to no allowed address"
                ))
            })
    }
}

/// The reset time when a 403/429 is a rate limit: `X-RateLimit-Remaining:
/// 0` (reset from `X-RateLimit-Reset`) or a `Retry-After` (seconds from
/// now). `None` when the response is an ordinary error.
fn rate_limit_reset(headers: &reqwest::header::HeaderMap) -> Option<i64> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
    };
    let remaining_zero = header("X-RateLimit-Remaining").is_some_and(|v| v == "0");
    let retry_after = header("Retry-After");
    if !remaining_zero && retry_after.is_none() {
        return None;
    }
    if let Some(reset) = header("X-RateLimit-Reset").and_then(|v| v.parse::<i64>().ok()) {
        return Some(reset);
    }
    if let Some(secs) = retry_after.and_then(|v| v.parse::<i64>().ok()) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        return Some(now + secs);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Some(now)
}

/// The `rel="next"` URL from a `Link` header, but only when it is on the
/// same origin (scheme, host, port) as `base`. A cross-origin next link
/// ends the walk (`None`) instead of being followed.
fn parse_next_link(link: Option<&reqwest::header::HeaderValue>, base: &url::Url) -> Option<String> {
    let link = link?.to_str().ok()?;
    for part in link.split(',') {
        let part = part.trim();
        let (url, params) = part.split_once(';')?;
        if !params.trim().contains("rel=\"next\"") && !params.trim().contains("rel=next") {
            continue;
        }
        let raw = url.trim().trim_start_matches('<').trim_end_matches('>');
        let next = base.join(raw).ok()?;
        if next.scheme() == base.scheme()
            && next.host_str() == base.host_str()
            && next.port_or_known_default() == base.port_or_known_default()
        {
            return Some(next.to_string());
        }
        return None;
    }
    None
}

pub mod importer;

#[cfg(test)]
mod tests;
