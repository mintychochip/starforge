//! Authenticated upload client for session uploads (C6).
//!
//! Wire conventions (M1c-chosen; the server must accept them):
//!
//! - `PUT /api/v1/repos/{owner}/{repo}/sessions/{ulid}` with a `SessionMeta`
//!   JSON body (200/201 ok).
//! - `PUT .../sessions/{ulid}/segments/{n}` with the exact compressed spool
//!   bytes and an `X-Starforge-Blake3: <hex of the request body>` header.
//!   `200` is success; `409` carrying our own hash is an idempotent success
//!   (the bytes are already stored); `409` with different content is
//!   [`UploadError::Conflict`] and is never retried blindly.
//! - `POST .../sessions/{ulid}/complete` with `{}`.
//! - `POST .../sessions/{ulid}/links` with `{"links": [<links.jsonl objects>]}`.
//!
//! Every call sends `Authorization: Bearer <token>` and times out after
//! 30 s. Only transport errors and `5xx` are retryable (see
//! [`UploadError::is_retryable`]); `401`/`403` means the token is rejected,
//! and any other `4xx` is terminal for that entry.

use std::time::Duration;

/// Authenticated client for session uploads.
pub struct UploadClient {
    pub api_url: String,
    pub token: String,
    pub client: reqwest::Client,
}

/// Upload failures.
#[derive(Debug, thiserror::Error)]
pub enum UploadError {
    /// Transport failure (connection, DNS, timeout, broken body): retryable.
    #[error("upload transport error: {0}")]
    Transport(String),
    /// `5xx` from the server: retryable.
    #[error("server error {status}: {message}")]
    Server { status: u16, message: String },
    /// Any other non-success status (except the idempotent-409 path):
    /// terminal for that entry.
    #[error("server rejected upload ({status}): {message}")]
    Rejected { status: u16, message: String },
    /// `401`/`403`: the token is rejected. Callers stop uploading and tell
    /// the user to refresh credentials.
    #[error(
        "authentication rejected for {repo}: run `starforge auth login` to refresh credentials"
    )]
    Auth { repo: String },
    /// A `409` whose stored hash differs from the request bytes: the queued
    /// entry is kept (with bumped attempts) and the run ends with exit 2.
    #[error("segment {segment} of session `{ulid}` differs from the uploaded bytes")]
    Conflict { ulid: String, segment: u64 },
    /// Local spool failure.
    #[error("spool error: {0}")]
    Spool(#[from] crate::spool::SpoolError),
    /// Local queue failure.
    #[error("queue error: {0}")]
    Queue(#[from] crate::queue::QueueError),
    /// Local I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// The injected `now` timestamp did not parse as RFC 3339.
    #[error("bad timestamp `{0}`: {1}")]
    Time(String, String),
}

impl UploadError {
    /// True for transport errors and `5xx`: the caller bumps attempts, sleeps
    /// the backoff via the injected [`Sleeper`](crate::queue::Sleeper), and
    /// retries. Everything else is terminal for the entry (or the run).
    pub fn is_retryable(&self) -> bool {
        matches!(self, UploadError::Transport(_) | UploadError::Server { .. })
    }
}

impl From<reqwest::Error> for UploadError {
    fn from(err: reqwest::Error) -> Self {
        UploadError::Transport(err.to_string())
    }
}

/// The stored-hash document a `409` carries: `{"hash": "<hex>"}`.
#[derive(serde::Deserialize)]
struct ConflictBody {
    #[serde(default)]
    hash: String,
}

impl UploadClient {
    /// Build a client for `api_url` with bearer `token` (30 s per request).
    pub fn new(api_url: String, token: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            api_url,
            token,
            client,
        }
    }

    fn session_url(&self, owner_repo: &str, ulid: &str) -> String {
        format!(
            "{}/api/v1/repos/{}/sessions/{}",
            self.api_url.trim_end_matches('/'),
            owner_repo,
            ulid
        )
    }

    /// `PUT .../sessions/{ulid}` with `SessionMeta` JSON. 200/201 ok.
    pub async fn put_meta(
        &self,
        owner_repo: &str,
        meta: &starforge_format::SessionMeta,
    ) -> Result<(), UploadError> {
        self.put_meta_status(owner_repo, meta).await.map(|_| ())
    }

    /// `PUT .../sessions/{ulid}`, reporting the created-vs-existing
    /// outcome: `Ok(true)` on `201 Created`, `Ok(false)` on `200 OK`
    /// (the session row already existed). Import derives "exists" from
    /// this rather than a separate read probe, which needs `repo:read`.
    pub async fn put_meta_status(
        &self,
        owner_repo: &str,
        meta: &starforge_format::SessionMeta,
    ) -> Result<bool, UploadError> {
        let url = self.session_url(owner_repo, &meta.id.to_string());
        let resp = self
            .client
            .put(&url)
            .bearer_auth(&self.token)
            .json(meta)
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::CREATED {
            return Ok(true);
        }
        check_status(owner_repo, resp).await?;
        Ok(false)
    }

    /// `PUT .../segments/{n}` with the exact spool bytes plus
    /// `X-Starforge-Blake3`. 200 ok; 409 carrying our own hash is an
    /// idempotent success; 409 with different content is [`UploadError::Conflict`].
    pub async fn put_segment(
        &self,
        owner_repo: &str,
        ulid: &str,
        n: u64,
        bytes: &[u8],
    ) -> Result<(), UploadError> {
        let ours = starforge_format::blake3_hex(bytes);
        let url = format!("{}/segments/{n}", self.session_url(owner_repo, ulid));
        let resp = self
            .client
            .put(&url)
            .bearer_auth(&self.token)
            .header("X-Starforge-Blake3", &ours)
            .header("content-type", "application/octet-stream")
            .body(bytes.to_vec())
            .send()
            .await?;
        if resp.status() == reqwest::StatusCode::CONFLICT {
            let body = resp.text().await.unwrap_or_default();
            let stored: ConflictBody = serde_json::from_str(&body).unwrap_or(ConflictBody {
                hash: String::new(),
            });
            if stored.hash == ours {
                return Ok(());
            }
            return Err(UploadError::Conflict {
                ulid: ulid.to_string(),
                segment: n,
            });
        }
        check_status(owner_repo, resp).await
    }

    /// `POST .../complete` with `{}`.
    pub async fn post_complete(&self, owner_repo: &str, ulid: &str) -> Result<(), UploadError> {
        let url = format!("{}/complete", self.session_url(owner_repo, ulid));
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({}))
            .send()
            .await?;
        check_status(owner_repo, resp).await
    }

    /// `POST .../links` with `{"links": [...]}`.
    pub async fn post_links(
        &self,
        owner_repo: &str,
        ulid: &str,
        links: &[serde_json::Value],
    ) -> Result<(), UploadError> {
        let url = format!("{}/links", self.session_url(owner_repo, ulid));
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "links": links }))
            .send()
            .await?;
        check_status(owner_repo, resp).await
    }
}

/// Map a non-409 response to `Ok`/`Err`: 2xx ok, 401/403 auth, 5xx retryable,
/// anything else terminal.
async fn check_status(owner_repo: &str, resp: reqwest::Response) -> Result<(), UploadError> {
    let status = resp.status();
    if status.is_success() {
        return Ok(());
    }
    let code = status.as_u16();
    // Drain the body for the message but never fail the mapping on it.
    let message = resp.text().await.unwrap_or_default();
    let message = message
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(UploadError::Auth {
            repo: owner_repo.to_string(),
        });
    }
    if status.is_server_error() {
        return Err(UploadError::Server {
            status: code,
            message,
        });
    }
    Err(UploadError::Rejected {
        status: code,
        message,
    })
}
