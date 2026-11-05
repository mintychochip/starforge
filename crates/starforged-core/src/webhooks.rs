//! Repository webhooks (spec §10.4, M2e K1): CRUD on [`Core`], fan-out into
//! the job queue, and signed delivery with the retry ladder.
//!
//! Secrets are random 32-byte hex strings, shown in plaintext exactly once at
//! creation. At rest they are ChaCha20-Poly1305 (`ring`, already in the lock
//! via `rustls`/`lettre`) under the server `webhook_key`, stored as
//! `v1:<base64(nonce‖ciphertext)>` in `webhooks.secret_encrypted` — the exact
//! shape the H1 schema comment promises. Delivery signs the exact JSON bytes
//! with HMAC-SHA256 (`ring::hmac`) as
//! `X-Starforge-Signature-256: sha256=<hex>`.
//!
//! Every delivery is `POST` with `Content-Type: application/json`,
//! `User-Agent: starforged/<version>`, `X-Starforge-Event`, and
//! `X-Starforge-Delivery` (the job id, stable across retries of one
//! delivery), and its body is the one D1 envelope: `event`, `action`,
//! `cause` (both always present, string or null), `at` (RFC 3339 UTC),
//! `repository` (`owner`, `name`, `full_name`, `url`), `sender` (the acting
//! user's `handle`, or null when system-originated), and exactly one subject
//! object under the key named by `event`.
//!
//! Delivery is SSRF-gated: the host resolves at delivery time, non-globally-
//! reachable addresses (loopback, RFC 1918, link-local incl. the metadata
//! endpoint, unique-local, multicast, …) are denied fail-closed with no
//! request and no retry, the client pins the checked address (no re-resolve,
//! no redirects), and success bodies are capped at 64 KiB under the 10 s
//! timeout. Only the test-only `allow_loopback_webhooks` flag admits
//! loopback.
//!
//! Permissions: every mutation and every read needs ≥ `Maintain` on the repo
//! (readers get `Forbidden`, never a leak-shaped `NotFound`). An archived
//! repository refuses new hooks. Fan-out ([`Core::dispatch_event`]) never
//! fails the caller: enqueue errors are logged, and delivery itself always
//! runs on a worker — never inline in the request path.

use std::time::{Duration, Instant};

use base64::Engine as _;
use ring::aead::{self, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use serde::{Deserialize, Serialize};
use starforged_db::{
    checks as db_checks, jobs as db_jobs, now, repos as db_repos, trails as db_trails,
};

use crate::accounts::User;
use crate::jobs::{Job, MAX_ATTEMPTS};
use crate::permission::Permission;
use crate::{Core, CoreError, CoreResult};

/// Events a hook may subscribe to (spec §10.4 D4). An empty subscription
/// means all of them.
pub const EVENT_TYPES: [&str; 5] = ["push", "trail", "review", "check", "session"];

/// One webhook event (spec §10.4 D1–D3). `event` is one of [`EVENT_TYPES`];
/// `subject` is the JSON for the key named by `event`.
pub struct HookEvent {
    pub event: &'static str,
    /// `opened`/`updated`/… (`trail`, `review`, `session`); always `None` for
    /// `push` and `check`.
    pub action: Option<&'static str>,
    /// Only with action `updated`: why the trail changed (D3).
    pub cause: Option<&'static str>,
    /// Acting user's handle; `None` when system-originated.
    pub sender: Option<String>,
    /// The subject JSON, filed under the key named by `event`.
    pub subject: serde_json::Value,
}

/// Keeps only [`EVENT_TYPES`], de-duplicated, order-preserving. An empty
/// input reads as empty (subscribe to all); dispatch and the DTO decide
/// what an empty result means via [`Subscription`].
pub fn normalize_events(events: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        if EVENT_TYPES.contains(&event.as_str()) && !out.contains(&event) {
            out.push(event);
        }
    }
    out
}

/// One stored subscription, classified (M2e K3 fold-in A): the single parser
/// the dispatch path and the DTO both use. `All` is a stored `[]`; `Set`
/// holds the known types (unknown names dropped, order kept); `Invalid`
/// is an unparseable cell, or a non-empty stored list with no known type.
/// Dispatch delivers on `All` and on a matching `Set`, never on `Invalid`.
pub enum Subscription {
    All,
    Set(Vec<String>),
    Invalid,
}

/// The one subscription parser: see [`Subscription`].
pub fn classify_subscription(raw: &str) -> Subscription {
    let parsed: Vec<String> = match serde_json::from_str(raw) {
        Ok(parsed) => parsed,
        Err(_) => return Subscription::Invalid,
    };
    let kept = normalize_events(parsed.clone());
    if kept.is_empty() {
        if parsed.is_empty() {
            Subscription::All
        } else {
            Subscription::Invalid
        }
    } else {
        Subscription::Set(kept)
    }
}

/// Delivery timeout per attempt (spec: 10 s).
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
/// Max response body the worker reads per delivery (spec: bodies ≤ 64 KiB).
const MAX_BODY_BYTES: usize = 64 * 1024;
/// Max response body stored per logged attempt (D5: the first 16 KiB,
/// UTF-8-lossy).
const MAX_STORED_BODY_BYTES: usize = 16 * 1024;
/// Max response headers stored per logged attempt (D5).
const MAX_STORED_HEADERS: usize = 50;
/// Max stored length of one response header value (D5: 1 KiB).
const MAX_STORED_HEADER_VALUE_BYTES: usize = 1024;

/// One webhook for API and settings-page rendering. The secret is never here:
/// creation returns it once; lists carry `has_secret` only. An invalid
/// stored subscription reads as `events: []` plus `subscription_invalid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDto {
    pub id: i64,
    pub url: String,
    pub events: Vec<String>,
    pub subscription_invalid: bool,
    pub active: bool,
    pub last_status: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: i64,
}

fn dto_of(row: &db_checks::WebhookRow) -> CoreResult<WebhookDto> {
    // Stored subscriptions pass through the one classifier: legacy names
    // (pre-0014 rows) drop out, duplicates collapse, and cells with no
    // known type (or no JSON at all) report invalid instead of looking
    // like "all".
    let (events, subscription_invalid) = match classify_subscription(&row.events) {
        Subscription::All => (Vec::new(), false),
        Subscription::Set(kept) => (kept, false),
        Subscription::Invalid => (Vec::new(), true),
    };
    Ok(WebhookDto {
        id: row.id,
        url: row.url.clone(),
        events,
        subscription_invalid,
        active: row.active != 0,
        last_status: row.last_status,
        last_error: row.last_error.clone(),
        created_at: row.created_at,
    })
}

fn check_url(url: &str) -> CoreResult<()> {
    if url.is_empty() || url.len() > 2000 {
        return Err(CoreError::Invalid(
            "webhook url must be 1–2000 characters".into(),
        ));
    }
    let parsed = url::Url::parse(url)
        .map_err(|_| CoreError::Invalid(format!("invalid webhook url {url:?}")))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" => {
            // Plain HTTP only for loopback receivers (tests and local dev).
            // `host_str` keeps IPv6 brackets (`[::1]`), so strip them first.
            let host = parsed.host_str().unwrap_or("");
            let bare = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host);
            if matches!(bare, "localhost" | "127.0.0.1" | "::1") {
                Ok(())
            } else {
                Err(CoreError::Invalid(
                    "webhook url must be https (http is only allowed for localhost)".into(),
                ))
            }
        }
        _ => Err(CoreError::Invalid("webhook url must be http(s)".into())),
    }
}

/// Every event must be one of [`EVENT_TYPES`]; an empty list subscribes to
/// all. De-duplicated, order-preserving.
fn check_events(events: &[String]) -> CoreResult<Vec<String>> {
    let mut out = Vec::with_capacity(events.len());
    for event in events {
        if !EVENT_TYPES.contains(&event.as_str()) {
            return Err(CoreError::Invalid(format!(
                "unknown webhook event '{event}' (expected one of: {})",
                EVENT_TYPES.join(", ")
            )));
        }
        if !out.contains(event) {
            out.push(event.clone());
        }
    }
    Ok(out)
}

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ` (Howard Hinnant's civil-from-days;
/// no new dependency for one envelope field).
fn rfc3339_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

struct OneNonce([u8; 12]);

impl NonceSequence for OneNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.0))
    }
}

fn unbound(key: &[u8; 32]) -> Result<UnboundKey, CoreError> {
    UnboundKey::new(&aead::CHACHA20_POLY1305, key)
        .map_err(|_| CoreError::Internal("invalid webhook key length".into()))
}

/// `v1:<base64(nonce‖ciphertext)>` with a fresh 12-byte nonce per seal.
fn seal_secret(key: &[u8; 32], plaintext: &str) -> CoreResult<String> {
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce)
        .map_err(|e| CoreError::Internal(format!("randomness failed: {e}")))?;
    let mut sealing = SealingKey::new(unbound(key)?, OneNonce(nonce));
    let mut buf = plaintext.as_bytes().to_vec();
    sealing
        .seal_in_place_append_tag(aead::Aad::empty(), &mut buf)
        .map_err(|_| CoreError::Internal("sealing the webhook secret failed".into()))?;
    let mut packed = nonce.to_vec();
    packed.extend_from_slice(&buf);
    Ok(format!(
        "v1:{}",
        base64::engine::general_purpose::STANDARD.encode(&packed)
    ))
}

fn open_secret(key: &[u8; 32], sealed: &str) -> CoreResult<String> {
    let b64 = sealed
        .strip_prefix("v1:")
        .ok_or_else(|| CoreError::Invalid("unknown webhook secret format".into()))?;
    let packed = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| CoreError::Invalid("corrupt webhook secret".into()))?;
    if packed.len() < 12 + 16 {
        return Err(CoreError::Invalid("corrupt webhook secret".into()));
    }
    let (nonce, ciphertext) = packed.split_at(12);
    let mut opening = OpeningKey::new(
        unbound(key)?,
        OneNonce(
            nonce
                .try_into()
                .map_err(|_| CoreError::Invalid("corrupt webhook secret".into()))?,
        ),
    );
    let mut buf = ciphertext.to_vec();
    let plain = opening
        .open_in_place(aead::Aad::empty(), &mut buf)
        .map_err(|_| CoreError::Invalid("cannot decrypt the webhook secret".into()))?;
    String::from_utf8(plain.to_vec())
        .map_err(|_| CoreError::Invalid("corrupt webhook secret".into()))
}

/// HMAC-SHA256 over `msg`, hex-encoded, via `ring` (keyed
/// `Algorithm::HMAC_SHA256` over the exact body bytes).
pub fn hmac_sha256_hex(key: &str, msg: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key.as_bytes());
    hex::encode(ring::hmac::sign(&key, msg))
}

fn webhook_target(owner: &str, repo: &str, id: i64) -> String {
    format!("webhook:{owner}/{repo}#{id}")
}

impl Core {
    /// Creates a hook (≥ `Maintain`): validates, seals the fresh secret,
    /// audits `webhook.created`, and returns the DTO plus the plaintext
    /// secret — the only time it is ever exposed.
    pub async fn create_webhook(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        url: &str,
        events: &[String],
    ) -> CoreResult<(WebhookDto, String)> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        check_url(url)?;
        let events = check_events(events)?;
        let secret = crate::crypto::random_hex(32);
        let sealed = seal_secret(&self.config().webhook_key.0, &secret)?;
        let row = db_checks::insert_webhook(
            self.db(),
            access.repo.id,
            url,
            &sealed,
            &serde_json::to_string(&events).map_err(|e| CoreError::Internal(e.to_string()))?,
            now(),
        )
        .await?;
        let payload = serde_json::json!({"id": row.id, "url": url}).to_string();
        db_trails::insert_timeline(
            self.db(),
            access.repo.id,
            None,
            "webhook.created",
            Some(user.id),
            &payload,
            now(),
        )
        .await?;
        self.audit(
            Some(user.id),
            "webhook.created",
            &webhook_target(owner, repo, row.id),
            &payload,
        )
        .await?;
        Ok((dto_of(&row)?, secret))
    }

    /// Hooks of the repo in insert order (≥ `Maintain`; readers get
    /// `Forbidden`). Never contains secrets.
    pub async fn list_webhooks(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Vec<WebhookDto>> {
        let access = self.repo_for(viewer, owner, repo).await?;
        if access.permission < Permission::Maintain {
            return Err(CoreError::Forbidden);
        }
        let mut out = Vec::new();
        for row in db_checks::webhooks_of_repo(self.db(), access.repo.id).await? {
            out.push(dto_of(&row)?);
        }
        Ok(out)
    }

    /// Deletes a hook (≥ `Maintain`); missing ids are `NotFound`. Audits
    /// `webhook.deleted`.
    pub async fn delete_webhook(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        id: i64,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        if !db_checks::delete_webhook(self.db(), id, access.repo.id).await? {
            return Err(CoreError::NotFound);
        }
        let payload = serde_json::json!({"id": id}).to_string();
        db_trails::insert_timeline(
            self.db(),
            access.repo.id,
            None,
            "webhook.deleted",
            Some(user.id),
            &payload,
            now(),
        )
        .await?;
        self.audit(
            Some(user.id),
            "webhook.deleted",
            &webhook_target(owner, repo, id),
            &payload,
        )
        .await?;
        Ok(())
    }

    /// Flips a hook's `active` flag (≥ `Maintain`); missing ids are `NotFound`.
    pub async fn set_webhook_active(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        id: i64,
        active: bool,
    ) -> CoreResult<WebhookDto> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        let row = db_checks::webhooks_of_repo(self.db(), access.repo.id)
            .await?
            .into_iter()
            .find(|row| row.id == id)
            .ok_or(CoreError::NotFound)?;
        if (row.active != 0) != active {
            db_checks::set_webhook_active(self.db(), id, active).await?;
        }
        let row = db_checks::webhook_by_id(self.db(), id)
            .await?
            .ok_or(CoreError::Internal("webhook vanished".into()))?;
        dto_of(&row)
    }

    /// Fan-out: builds the D1 envelope (action, cause, `at`, `repository`,
    /// `sender`, the subject under its key) and enqueues one
    /// `WebhookDelivery` job per active hook subscribed to `ev.event`
    /// (empty subscription = all). Delivery itself always runs on a worker.
    /// Never fails the caller: every error is logged and swallowed.
    pub async fn dispatch_event(&self, repo_id: i64, ev: HookEvent) {
        if let Err(err) = self.dispatch_event_inner(repo_id, &ev).await {
            tracing::warn!(repo = repo_id, event = ev.event, error = %err, "webhook fan-out failed");
        }
    }

    async fn dispatch_event_inner(&self, repo_id: i64, ev: &HookEvent) -> CoreResult<()> {
        if !EVENT_TYPES.contains(&ev.event) {
            return Err(CoreError::Invalid(format!(
                "unknown webhook event '{}'",
                ev.event
            )));
        }
        let repo = db_repos::by_id(self.db(), repo_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let base = self.config().base_url.trim_end_matches('/');
        let body = serde_json::json!({
            "event": ev.event,
            "action": ev.action,
            "cause": ev.cause,
            "at": rfc3339_utc(now()),
            "repository": {
                "owner": repo.owner_handle,
                "name": repo.name,
                "full_name": format!("{}/{}", repo.owner_handle, repo.name),
                "url": format!("{base}/{}/{}", repo.owner_handle, repo.name),
            },
            "sender": ev.sender.as_ref().map(|handle| serde_json::json!({"handle": handle})),
            ev.event: ev.subject,
        });
        let payload =
            serde_json::to_string(&body).map_err(|e| CoreError::Internal(e.to_string()))?;
        for hook in db_checks::webhooks_of_repo(self.db(), repo_id).await? {
            if hook.active == 0 {
                continue;
            }
            match classify_subscription(&hook.events) {
                Subscription::Invalid => {
                    tracing::warn!(
                        hook = hook.id,
                        "webhook has an invalid subscription; skipping"
                    );
                    continue;
                }
                Subscription::All => {}
                Subscription::Set(subscribed) => {
                    if !subscribed.iter().any(|e| e == ev.event) {
                        continue;
                    }
                }
            }
            if let Err(err) = self
                .enqueue(&Job::WebhookDelivery {
                    webhook_id: hook.id,
                    event: ev.event.to_owned(),
                    payload: payload.clone(),
                    redelivery: false,
                })
                .await
            {
                tracing::warn!(hook = hook.id, event = ev.event, error = %err, "webhook enqueue failed");
            }
        }
        Ok(())
    }

    /// Convenience fan-out for every `trail` event (D3): looks up the repo
    /// and trail, builds the trail subject (plus `change` when one caused
    /// the event), and dispatches. Never fails the caller: lookup failures
    /// only warn.
    pub async fn dispatch_trail_event(
        &self,
        repo_id: i64,
        sender: Option<String>,
        action: Option<&'static str>,
        cause: Option<&'static str>,
        trail_number: i64,
        change: Option<serde_json::Value>,
    ) {
        let subject = match self.trail_subject(repo_id, trail_number, change).await {
            Ok(subject) => subject,
            Err(err) => {
                tracing::warn!(repo = repo_id, trail = trail_number, error = %err, "webhook trail subject failed; skipping fan-out");
                return;
            }
        };
        self.dispatch_event(
            repo_id,
            HookEvent {
                event: "trail",
                action,
                cause,
                sender,
                subject,
            },
        )
        .await;
    }

    /// The D2 `trail` subject: number, title, state, ready, author, and the
    /// absolute web URL, plus `change` (`k`, `revision`) when one caused it.
    async fn trail_subject(
        &self,
        repo_id: i64,
        trail_number: i64,
        change: Option<serde_json::Value>,
    ) -> CoreResult<serde_json::Value> {
        let repo = db_repos::by_id(self.db(), repo_id)
            .await?
            .ok_or_else(|| CoreError::Internal("trail webhook has no repo".into()))?;
        let Some(trail) = db_trails::trail_by_number(self.db(), repo_id, trail_number).await?
        else {
            return Err(CoreError::Internal("trail webhook has no trail".into()));
        };
        let author = match trail.author_id {
            None => "deleted user".to_owned(),
            Some(id) => self
                .user_by_id(id)
                .await?
                .map(|user| user.handle)
                .unwrap_or_else(|| "deleted user".to_owned()),
        };
        let base = self.config().base_url.trim_end_matches('/');
        let mut subject = serde_json::json!({
            "number": trail.number,
            "title": trail.title,
            "state": trail.state,
            "ready": trail.ready != 0,
            "author": author,
            "url": format!("{base}/{}/{}/trails/{}", repo.owner_handle, repo.name, trail.number),
        });
        if let Some(change) = change {
            subject["change"] = change;
        }
        Ok(subject)
    }

    /// Convenience fan-out for every `session` event (D2): looks up the
    /// session by ULID, builds the identifier-and-state subject (never
    /// titles, reasons, prompts, or transcripts — §6.4), and dispatches.
    /// Never fails the caller: lookup failures only warn.
    pub async fn dispatch_session_event(
        &self,
        repo_id: i64,
        sender: Option<String>,
        action: &'static str,
        ulid: &str,
    ) {
        let subject = match self.session_subject(repo_id, ulid).await {
            Ok(subject) => subject,
            Err(err) => {
                tracing::warn!(repo = repo_id, ulid, error = %err, "webhook session subject failed; skipping fan-out");
                return;
            }
        };
        self.dispatch_event(
            repo_id,
            HookEvent {
                event: "session",
                action: Some(action),
                cause: None,
                sender,
                subject,
            },
        )
        .await;
    }

    /// The D2 `session` subject: identifiers and state only (`ulid`,
    /// `uploader`, `agent`, `lifecycle_state`, `quarantine_state`,
    /// `visibility`). Anything richer would leak §6.4-restricted reads
    /// to an external URL.
    async fn session_subject(&self, repo_id: i64, ulid: &str) -> CoreResult<serde_json::Value> {
        let Some(session) =
            starforged_db::sessions::session_by_ulid(self.db(), repo_id, ulid).await?
        else {
            return Err(CoreError::Internal("session webhook has no session".into()));
        };
        let uploader = match self.user_by_id(session.uploader_id).await? {
            Some(user) => user.handle,
            None => "deleted user".to_owned(),
        };
        Ok(serde_json::json!({
            "ulid": session.ulid,
            "uploader": uploader,
            "agent": session.agent_name,
            "lifecycle_state": session.lifecycle,
            "quarantine_state": session.quarantine,
            "visibility": session.visibility,
        }))
    }

    /// The acting user's handle, or `None` when the account is gone (or the
    /// lookup fails): those senders read as system-originated.
    pub(crate) async fn sender_of(&self, user_id: i64) -> Option<String> {
        self.user_by_id(user_id)
            .await
            .ok()
            .flatten()
            .map(|user| user.handle)
    }

    /// Worker: POSTs `payload` to the hook with the `X-Starforge-*` headers,
    /// and writes exactly one delivery-log row for the attempt — success,
    /// HTTP error, transport error, SSRF denial, and corrupt secret alike —
    /// then applies the retry ladder. Missing or disabled hooks complete
    /// silently (no row, no retry). A corrupt secret, an SSRF denial, or an
    /// exhausted ladder is terminal: the failure is recorded and the job
    /// completes, so a dead endpoint never wedges the queue. Every attempt
    /// refreshes the hook's `last_status`/`last_error`; only terminal
    /// failures write `webhook.failed` timeline and audit rows.
    pub(crate) async fn deliver_webhook(
        &self,
        job_id: i64,
        webhook_id: i64,
        event: &str,
        payload: &str,
        redelivery: bool,
    ) -> CoreResult<()> {
        let delivery_id = job_id.to_string();
        // The claim already bumped `attempts`, so it is the 1-based number
        // of this attempt; a vanished job row still logs as attempt 1.
        let attempt_no = db_jobs::by_id(self.db(), job_id)
            .await?
            .map(|row| row.attempts)
            .unwrap_or(1)
            .max(1);
        let action = envelope_action(payload);
        let started = Instant::now();
        let Some(hook) = db_checks::webhook_by_id(self.db(), webhook_id).await? else {
            return Ok(());
        };
        if hook.active == 0 {
            return Ok(());
        }
        let secret = match open_secret(&self.config().webhook_key.0, &hook.secret_encrypted) {
            Ok(secret) => secret,
            Err(err) => {
                // No signature without a secret: store the headers the
                // attempt would have sent, minus the signature.
                let request_headers = request_headers_json(event, &delivery_id, None);
                let error = format!("cannot decrypt the webhook secret: {err}");
                self.record_terminal_attempt(
                    &hook,
                    &delivery_id,
                    attempt_no,
                    event,
                    action.as_deref(),
                    &request_headers,
                    payload,
                    None,
                    None,
                    None,
                    &error,
                    started.elapsed(),
                    redelivery,
                )
                .await?;
                return Ok(());
            }
        };
        let signature = format!("sha256={}", hmac_sha256_hex(&secret, payload.as_bytes()));
        let request_headers = request_headers_json(event, &delivery_id, Some(&signature));
        // Resolve and classify before touching the network: denials
        // (unresolvable or non-global hosts) are deterministic, so they are
        // terminal — fail-closed, with no request and no retry. The denied
        // attempt stores the request it would have sent, the error, and a
        // null status.
        let parsed = url::Url::parse(&hook.url)
            .map_err(|_| CoreError::Internal("stored webhook url is invalid".into()))?;
        let (pinned, target) =
            match resolve_target(&parsed, self.config().allow_loopback_webhooks).await {
                Ok(resolved) => resolved,
                Err(err) => {
                    self.record_terminal_attempt(
                        &hook,
                        &delivery_id,
                        attempt_no,
                        event,
                        action.as_deref(),
                        &request_headers,
                        payload,
                        None,
                        None,
                        None,
                        &err,
                        started.elapsed(),
                        redelivery,
                    )
                    .await?;
                    return Ok(());
                }
            };
        let send_started = Instant::now();
        match post_hook(
            &hook.url,
            pinned.as_deref(),
            target,
            &request_headers,
            payload,
        )
        .await
        {
            Ok(response) if (200..300).contains(&response.status) => {
                self.record_attempt(
                    &hook,
                    &delivery_id,
                    attempt_no,
                    event,
                    action.as_deref(),
                    &request_headers,
                    payload,
                    Some(response.status),
                    Some(&response.headers_json),
                    Some(&response.stored_body()),
                    None,
                    send_started.elapsed(),
                    redelivery,
                )
                .await?;
                Ok(())
            }
            Ok(response) => {
                let error = format!("webhook returned HTTP {}", response.status);
                self.fail_attempt(
                    job_id,
                    &hook,
                    &delivery_id,
                    attempt_no,
                    event,
                    action.as_deref(),
                    &request_headers,
                    payload,
                    Some(response.status),
                    Some(&response.headers_json),
                    Some(&response.stored_body()),
                    &error,
                    send_started.elapsed(),
                    redelivery,
                )
                .await
            }
            Err(err) => {
                self.fail_attempt(
                    job_id,
                    &hook,
                    &delivery_id,
                    attempt_no,
                    event,
                    action.as_deref(),
                    &request_headers,
                    payload,
                    None,
                    None,
                    None,
                    &err,
                    send_started.elapsed(),
                    redelivery,
                )
                .await
            }
        }
    }

    /// Writes one delivery-log row and refreshes the hook's last-result
    /// fields to this attempt's outcome.
    #[allow(clippy::too_many_arguments)]
    async fn record_attempt(
        &self,
        hook: &db_checks::WebhookRow,
        delivery_id: &str,
        attempt_no: i64,
        event: &str,
        action: Option<&str>,
        request_headers: &str,
        payload: &str,
        status: Option<i64>,
        response_headers: Option<&str>,
        response_body: Option<&str>,
        error: Option<&str>,
        elapsed: Duration,
        redelivery: bool,
    ) -> CoreResult<()> {
        db_checks::insert_delivery(
            self.db(),
            &db_checks::DeliveryAttempt {
                webhook_id: hook.id,
                delivery_id,
                attempt: attempt_no,
                event,
                action,
                request_headers,
                payload,
                status_code: status,
                response_headers,
                response_body,
                error,
                duration_ms: elapsed.as_millis().min(i64::MAX as u128) as i64,
                redelivery,
                now: now(),
            },
        )
        .await?;
        db_checks::set_webhook_result(self.db(), hook.id, status, error).await?;
        Ok(())
    }

    /// A failed attempt: terminal (this was the last rung) records the
    /// `webhook.failed` timeline and audit rows; anything earlier returns
    /// `Err` so the queue retries it. Either way the attempt is logged.
    #[allow(clippy::too_many_arguments)]
    async fn fail_attempt(
        &self,
        job_id: i64,
        hook: &db_checks::WebhookRow,
        delivery_id: &str,
        attempt_no: i64,
        event: &str,
        action: Option<&str>,
        request_headers: &str,
        payload: &str,
        status: Option<i64>,
        response_headers: Option<&str>,
        response_body: Option<&str>,
        error: &str,
        elapsed: Duration,
        redelivery: bool,
    ) -> CoreResult<()> {
        self.record_attempt(
            hook,
            delivery_id,
            attempt_no,
            event,
            action,
            request_headers,
            payload,
            status,
            response_headers,
            response_body,
            Some(error),
            elapsed,
            redelivery,
        )
        .await?;
        let terminal = db_jobs::by_id(self.db(), job_id)
            .await?
            .is_none_or(|row| row.attempts >= MAX_ATTEMPTS);
        if terminal {
            self.record_terminal_signal(hook, event, error).await?;
            Ok(())
        } else {
            Err(CoreError::Internal(format!(
                "webhook delivery failed: {error}"
            )))
        }
    }

    /// Records a terminal outcome that never reached the network (corrupt
    /// secret, SSRF denial): the logged attempt plus the `webhook.failed`
    /// timeline and audit rows.
    #[allow(clippy::too_many_arguments)]
    async fn record_terminal_attempt(
        &self,
        hook: &db_checks::WebhookRow,
        delivery_id: &str,
        attempt_no: i64,
        event: &str,
        action: Option<&str>,
        request_headers: &str,
        payload: &str,
        status: Option<i64>,
        response_headers: Option<&str>,
        response_body: Option<&str>,
        error: &str,
        elapsed: Duration,
        redelivery: bool,
    ) -> CoreResult<()> {
        self.record_attempt(
            hook,
            delivery_id,
            attempt_no,
            event,
            action,
            request_headers,
            payload,
            status,
            response_headers,
            response_body,
            Some(error),
            elapsed,
            redelivery,
        )
        .await?;
        self.record_terminal_signal(hook, event, error).await?;
        Ok(())
    }

    /// The terminal signal: one repo-scoped `webhook.failed` timeline row
    /// plus one audit row. Non-terminal attempts write only their log row.
    async fn record_terminal_signal(
        &self,
        hook: &db_checks::WebhookRow,
        event: &str,
        error: &str,
    ) -> CoreResult<()> {
        let detail = serde_json::json!({"id": hook.id, "event": event, "error": error}).to_string();
        db_trails::insert_timeline(
            self.db(),
            hook.repo_id,
            None,
            "webhook.failed",
            None,
            &detail,
            now(),
        )
        .await?;
        self.audit(
            None,
            "webhook.failed",
            &format!("webhook#{}", hook.id),
            &detail,
        )
        .await?;
        Ok(())
    }

    /// Logged attempts of one hook (≥ `Maintain`), newest first; at most
    /// `limit` (which clamps to 1–100, default 20). Readers get
    /// `Forbidden`; a missing hook (or one from another repo) is `NotFound`.
    pub async fn list_deliveries(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        hook_id: i64,
        limit: Option<i64>,
    ) -> CoreResult<Vec<DeliverySummary>> {
        let hook = self.hook_in_repo(user, owner, repo, hook_id).await?;
        let limit = limit.unwrap_or(20).clamp(1, 100);
        let mut out = Vec::new();
        for row in db_checks::recent_deliveries(self.db(), hook.id, limit).await? {
            out.push(DeliverySummary::of(&row));
        }
        Ok(out)
    }

    /// One logged attempt of this hook in full (≥ `Maintain`): the summary
    /// plus the stored request and response. A row from another hook (or a
    /// missing one) is `NotFound`.
    pub async fn get_delivery(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        hook_id: i64,
        delivery_row: i64,
    ) -> CoreResult<DeliveryDetail> {
        let hook = self.hook_in_repo(user, owner, repo, hook_id).await?;
        let Some(row) = db_checks::delivery_by_id(self.db(), delivery_row).await? else {
            return Err(CoreError::NotFound);
        };
        if row.webhook_id != hook.id {
            return Err(CoreError::NotFound);
        }
        Ok(DeliveryDetail::of(&row))
    }

    /// Replays a logged attempt as a NEW delivery (D6): the stored request
    /// body is re-sent under a new delivery id, re-signed with the hook's
    /// current secret, through the same SSRF gate and retry ladder. The
    /// new attempts carry `redelivery = 1`. Needs ≥ `Maintain` on a
    /// non-archived repo and an active hook (else `Invalid`); writes one
    /// repo-scoped `webhook.redelivered` timeline row and one audit row.
    /// Returns the new delivery id.
    pub async fn redeliver(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        hook_id: i64,
        delivery_row: i64,
    ) -> CoreResult<String> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        let Some(hook) = db_checks::webhook_by_id(self.db(), hook_id).await? else {
            return Err(CoreError::NotFound);
        };
        if hook.repo_id != access.repo.id {
            return Err(CoreError::NotFound);
        }
        if hook.active == 0 {
            return Err(CoreError::Invalid("webhook is inactive".into()));
        }
        let Some(logged) = db_checks::delivery_by_id(self.db(), delivery_row).await? else {
            return Err(CoreError::NotFound);
        };
        if logged.webhook_id != hook.id {
            return Err(CoreError::NotFound);
        }
        let job = Job::WebhookDelivery {
            webhook_id: hook.id,
            event: logged.event.clone(),
            payload: logged.payload.clone(),
            redelivery: true,
        };
        let delivery_id = self.enqueue_returning(&job).await?.to_string();
        let detail = serde_json::json!({
            "hook": hook.id,
            "row": logged.id,
            "delivery_id": delivery_id,
        })
        .to_string();
        db_trails::insert_timeline(
            self.db(),
            access.repo.id,
            None,
            "webhook.redelivered",
            Some(user.id),
            &detail,
            now(),
        )
        .await?;
        self.audit(
            Some(user.id),
            "webhook.redelivered",
            &webhook_target(owner, repo, hook.id),
            &detail,
        )
        .await?;
        Ok(delivery_id)
    }

    /// The hook when it belongs to this repo (≥ `Maintain`), else
    /// `Forbidden`/`NotFound`.
    async fn hook_in_repo(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        hook_id: i64,
    ) -> CoreResult<db_checks::WebhookRow> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        let Some(hook) = db_checks::webhook_by_id(self.db(), hook_id).await? else {
            return Err(CoreError::NotFound);
        };
        if hook.repo_id != access.repo.id {
            return Err(CoreError::NotFound);
        }
        Ok(hook)
    }
}

/// One logged delivery attempt, newest first (D5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverySummary {
    pub id: i64,
    pub delivery_id: String,
    pub attempt: i64,
    pub event: String,
    pub action: Option<String>,
    pub status_code: Option<i64>,
    pub error: Option<String>,
    pub duration_ms: i64,
    pub redelivery: bool,
    pub delivered_at: i64,
}

/// One logged attempt in full: the summary plus the stored request and
/// response. Request headers always hold exactly the headers sent (the
/// signature included, never the secret); the response body is the first
/// 16 KiB, UTF-8-lossy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryDetail {
    #[serde(flatten)]
    pub summary: DeliverySummary,
    pub request_headers: String,
    pub request_body: String,
    pub response_headers: Option<String>,
    pub response_body: Option<String>,
}

impl DeliverySummary {
    fn of(row: &db_checks::WebhookDeliveryRow) -> DeliverySummary {
        DeliverySummary {
            id: row.id,
            delivery_id: row.delivery_id.clone().unwrap_or_default(),
            attempt: row.attempt.unwrap_or(0),
            event: row.event.clone(),
            action: row.action.clone(),
            status_code: row.status_code,
            error: row.error.clone(),
            duration_ms: row.duration_ms.unwrap_or(0),
            redelivery: row.redelivery != 0,
            delivered_at: row.delivered_at,
        }
    }
}

impl DeliveryDetail {
    fn of(row: &db_checks::WebhookDeliveryRow) -> DeliveryDetail {
        DeliveryDetail {
            summary: DeliverySummary::of(row),
            request_headers: row.request_headers.clone().unwrap_or_else(|| "{}".into()),
            request_body: row.payload.clone(),
            response_headers: row.response_headers.clone(),
            response_body: row.response_body.clone(),
        }
    }
}

/// The `action` filed in the delivery envelope, if it parses and is a
/// string (D1 always sends it, null or otherwise).
fn envelope_action(payload: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()?
        .get("action")?
        .as_str()
        .map(str::to_owned)
}

/// Exactly the headers one attempt sends, as a JSON object: content type,
/// user agent, event, delivery id, and the signature when the secret
/// opened (never the secret itself).
fn request_headers_json(event: &str, delivery_id: &str, signature: Option<&str>) -> String {
    let mut headers = serde_json::Map::with_capacity(5);
    headers.insert(
        "content-type".into(),
        serde_json::Value::String("application/json".into()),
    );
    headers.insert(
        "user-agent".into(),
        serde_json::Value::String(format!("starforged/{}", env!("CARGO_PKG_VERSION"))),
    );
    headers.insert(
        "x-starforge-event".into(),
        serde_json::Value::String(event.to_owned()),
    );
    headers.insert(
        "x-starforge-delivery".into(),
        serde_json::Value::String(delivery_id.to_owned()),
    );
    if let Some(signature) = signature {
        headers.insert(
            "x-starforge-signature-256".into(),
            serde_json::Value::String(signature.to_owned()),
        );
    }
    serde_json::Value::Object(headers).to_string()
}

/// Delivery-time SSRF gate: literal IPs and every resolved address are
/// classified; anything that is not globally reachable is denied, with
/// loopback additionally gated behind the test-only `allow_loopback` escape
/// hatch. Denied: loopback (unless flagged), private (RFC 1918), shared
/// (100.64/10), link-local (169.254/16 — including the 169.254.169.254
/// metadata endpoint — and fe80::/10), unique-local (fc00::/7),
/// unspecified, broadcast, multicast, documentation, benchmarking, and
/// reserved ranges, in either address family — IPv4-mapped IPv6 forms
/// (`::ffff:a.b.c.d`) unwrap to their inner IPv4 address first. The coarser
/// checks use stable predicates, the rest explicit prefix matches.
fn host_allowed(ip: std::net::IpAddr, allow_loopback: bool) -> bool {
    if ip.is_loopback() {
        return allow_loopback;
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            // Stable predicates cover unspecified, private (RFC 1918),
            // link-local (169.254/16, incl. the 169.254.169.254 metadata
            // endpoint), broadcast, and multicast; the rest are octet
            // checks (this toolchain gates the finer predicates).
            if v4.is_unspecified()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
            {
                return false;
            }
            let o = v4.octets();
            if o[0] == 0 || o[0] >= 240 {
                return false; // 0/8 software-scope, 240/4 reserved.
            }
            if o[0] == 100 && (o[1] & 0b1100_0000) == 0b0100_0000 {
                return false; // 100.64/10 shared.
            }
            if o[0] == 192 && o[1] == 0 && o[2] == 2 {
                return false; // 192.0.2/24 documentation.
            }
            if o[0] == 198 && o[1] == 51 && o[2] == 100 {
                return false; // 198.51.100/24 documentation.
            }
            if o[0] == 203 && o[1] == 0 && o[2] == 113 {
                return false; // 203.0.113/24 documentation.
            }
            if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
                return false; // 198.18/15 benchmarking.
            }
            true
        }
        std::net::IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is the same host as its
            // inner IPv4 address: unwrap and classify as IPv4, or private
            // and loopback ranges slip through the V6 checks below.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return host_allowed(std::net::IpAddr::V4(v4), allow_loopback);
            }
            // (fe80::/10), and unique-local (fc00::/7); documentation is a
            // prefix check.
            if v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6.is_unique_local()
            {
                return false;
            }
            !matches!(v6.segments(), [0x2001, 0x0db8, ..])
        }
    }
}

/// Resolves the hook URL to one pinned socket address. Literal IPs classify
/// directly (no DNS); hostnames resolve and keep only allowed addresses, and
/// the first allowed one is pinned — the client below connects to exactly
/// the address checked here, never re-resolving. Unresolvable hosts and
/// hosts with no allowed address are denied (fail-closed).
async fn resolve_target(
    parsed: &url::Url,
    allow_loopback: bool,
) -> Result<(Option<String>, std::net::SocketAddr), String> {
    let host = parsed
        .host_str()
        .ok_or_else(|| "webhook url has no host".to_owned())?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "webhook url has no port".to_owned())?;
    // `host_str` keeps IPv6 brackets; strip them before parsing.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        if !host_allowed(ip, allow_loopback) {
            return Err(format!("webhook host {host} is not allowed"));
        }
        // IP literals never consult DNS: nothing to pin.
        return Ok((None, std::net::SocketAddr::new(ip, port)));
    }
    let mut allowed: Option<std::net::SocketAddr> = None;
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("webhook host {host} does not resolve: {e}"))?;
    for addr in addrs {
        if allowed.is_none() && host_allowed(addr.ip(), allow_loopback) {
            allowed = Some(addr);
        }
    }
    allowed
        .map(|addr| (Some(host.to_owned()), addr))
        .ok_or_else(|| format!("webhook host {host} resolves to no allowed address"))
}

/// One attempt's HTTP response: the status, the stored response headers
/// (JSON object), and the full body read (capped at [`MAX_BODY_BYTES`]).
struct PostResponse {
    status: i64,
    headers_json: String,
    body: Vec<u8>,
}

impl PostResponse {
    /// The first [`MAX_STORED_BODY_BYTES`], UTF-8-lossy, for the log row.
    fn stored_body(&self) -> String {
        let end = self.body.len().min(MAX_STORED_BODY_BYTES);
        String::from_utf8_lossy(&self.body[..end]).into_owned()
    }
}

/// POSTs the exact `payload` bytes with the stored `request_headers` (parsed
/// back, so the row holds exactly the headers sent) to the pinned `target`
/// (no re-resolve, no redirects). Returns the status with the response
/// headers and body — success and error bodies alike, read up to the 64 KiB
/// cap. Transport failures (including the 10 s timeout) and over-cap bodies
/// are `Err`. The error text never contains the secret or the signature.
async fn post_hook(
    url: &str,
    pinned: Option<&str>,
    target: std::net::SocketAddr,
    request_headers: &str,
    payload: &str,
) -> Result<PostResponse, String> {
    let stored: serde_json::Map<String, serde_json::Value> = serde_json::from_str(request_headers)
        .map_err(|_| "stored webhook request headers are invalid".to_owned())?;
    let mut builder = reqwest::Client::builder()
        .timeout(DELIVERY_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(domain) = pinned {
        // Pin the checked address: no re-resolve between check and connect.
        builder = builder.resolve(domain, target);
    }
    let client = builder
        .build()
        .map_err(|e| format!("building the webhook client failed: {e}"))?;
    let mut request = client.post(url).body(payload.to_owned());
    for (name, value) in &stored {
        let value = value.as_str().unwrap_or("");
        request = request.header(name.as_str(), value);
    }
    let mut response = request.send().await.map_err(|e| {
        if e.is_timeout() {
            "webhook delivery timed out after 10s".to_owned()
        } else {
            format!("webhook delivery failed: {e}")
        }
    })?;
    let status = i64::from(response.status().as_u16());
    let headers_json = response_headers_json(response.headers());
    // Bound the body read chunk by chunk: never more than 64 KiB, for
    // success and error responses alike.
    let mut body = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|e| format!("webhook delivery failed: {e}"))?;
        let Some(bytes) = chunk else { break };
        if body.len() + bytes.len() > MAX_BODY_BYTES {
            return Err("webhook response body exceeds the 64 KiB cap".to_owned());
        }
        body.extend_from_slice(&bytes);
    }
    Ok(PostResponse {
        status,
        headers_json,
        body,
    })
}

/// The response headers for the log row: a JSON object of at most
/// [`MAX_STORED_HEADERS`] headers, each value truncated to
/// [`MAX_STORED_HEADER_VALUE_BYTES`] bytes, repeated names joined with
/// ", ". Nothing from the receiver is trusted beyond this capped preview.
fn response_headers_json(headers: &reqwest::header::HeaderMap) -> String {
    let mut out = serde_json::Map::with_capacity(headers.keys_len().min(MAX_STORED_HEADERS));
    for name in headers.keys().take(MAX_STORED_HEADERS) {
        let mut values = Vec::new();
        for value in headers.get_all(name) {
            let text = String::from_utf8_lossy(value.as_bytes());
            let end = floor_char_boundary(&text, MAX_STORED_HEADER_VALUE_BYTES);
            values.push(text[..end].to_owned());
        }
        out.insert(
            name.as_str().to_owned(),
            serde_json::Value::String(values.join(", ")),
        );
    }
    serde_json::Value::Object(out).to_string()
}

/// The longest prefix of `text` that fits in `max` bytes and ends on a
/// UTF-8 boundary.
fn floor_char_boundary(text: &str, max: usize) -> usize {
    let mut end = text.len().min(max);
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231_vector() {
        // RFC 4231 test case 2.
        assert_eq!(
            hmac_sha256_hex("Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn secret_seal_round_trips() {
        let key = [9u8; 32];
        let sealed = seal_secret(&key, "topsecret").unwrap();
        assert!(sealed.starts_with("v1:"));
        assert_eq!(open_secret(&key, &sealed).unwrap(), "topsecret");
        // Nonces differ, and the wrong key refuses.
        assert_ne!(sealed, seal_secret(&key, "topsecret").unwrap());
        assert!(open_secret(&[8u8; 32], &sealed).is_err());
    }

    #[test]
    fn url_policy_allows_only_https_and_loopback() {
        assert!(check_url("https://example.com/hook").is_ok());
        assert!(check_url("http://127.0.0.1:9/hook").is_ok());
        assert!(check_url("http://localhost/hook").is_ok());
        assert!(check_url("http://[::1]/hook").is_ok());
        assert!(check_url("http://example.com/hook").is_err());
        assert!(check_url("ftp://example.com/hook").is_err());
        assert!(check_url("not a url").is_err());
    }

    #[test]
    fn ssrf_matrix_denies_everything_non_global() {
        use std::net::IpAddr;
        let denied = [
            "127.0.0.1",
            "::1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.169.254",
            "fe80::1",
            "fc00::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "192.0.2.1",
            "203.0.113.1",
            // IPv4-mapped IPv6: the same hosts in `::ffff:` form, including
            // what a hostname resolving to a mapped address yields.
            // (`::ffff:127.0.0.1` is asserted explicitly below: this
            // toolchain's `is_loopback` misses mapped forms, so the loop
            // guard cannot tell it apart from a denied address.)
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ];
        for host in denied {
            let ip: IpAddr = host.parse().unwrap();
            assert!(!host_allowed(ip, false), "{host} denied without the flag");
            if !ip.is_loopback() {
                assert!(!host_allowed(ip, true), "{host} denied even with the flag");
            }
        }
        assert!(host_allowed("127.0.0.1".parse().unwrap(), true));
        assert!(host_allowed("::1".parse::<IpAddr>().unwrap(), true));
        assert!(host_allowed(
            "::ffff:127.0.0.1".parse::<IpAddr>().unwrap(),
            true
        ));
        assert!(!host_allowed(
            "::ffff:127.0.0.1".parse::<IpAddr>().unwrap(),
            false
        ));
        assert!(!host_allowed(
            "::ffff:10.0.0.1".parse::<IpAddr>().unwrap(),
            true
        ));
        assert!(!host_allowed(
            "::ffff:169.254.169.254".parse::<IpAddr>().unwrap(),
            false
        ));
        for host in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            let ip: IpAddr = host.parse().unwrap();
            assert!(host_allowed(ip, false), "{host} allowed");
            assert!(host_allowed(ip, true), "{host} allowed");
        }
    }

    /// The sealing key never renders in `Debug`, in any format (the unit
    /// fixture key is `[7u8; 32]`, hex `0707…`).
    #[tokio::test]
    async fn debug_output_redacts_the_webhook_key() {
        let (core, _f, _) = seeded(false).await;
        let rendered = format!("{:?}", core.config());
        assert!(rendered.contains("webhook_key"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(!rendered.contains("0707"), "hex bytes leak: {rendered}");
        assert!(
            !rendered.contains("[7, 7"),
            "decimal bytes leak: {rendered}"
        );
    }
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A `Core` with `repo_id` ready, sealing hook secrets with its own key.
    async fn seeded(allow_loopback: bool) -> (Core, crate::testing::Fixture, i64) {
        let (core, fixture) = crate::testing::test_core_with(|c, _| {
            c.allow_loopback_webhooks = allow_loopback;
        })
        .await;
        let user = crate::testing::user(&core, "alice").await;
        let repo = core
            .create_repo(
                &user,
                crate::repos::CreateRepo {
                    name: "proj".into(),
                    description: String::new(),
                    visibility: crate::permission::Visibility::Private,
                    readme: false,
                },
            )
            .await
            .unwrap();
        (core, fixture, repo.id)
    }

    async fn insert_hook(core: &Core, repo_id: i64, url: &str) -> db_checks::WebhookRow {
        let sealed = seal_secret(&core.config().webhook_key.0, "s3cret").unwrap();
        db_checks::insert_webhook(core.db(), repo_id, url, &sealed, "[]", now())
            .await
            .unwrap()
    }

    /// Enqueues a real delivery job and runs the worker arm against it once.
    async fn deliver_once(core: &Core, hook_id: i64) -> CoreResult<()> {
        let payload = "{\"a\":1}".to_owned();
        core.enqueue(&Job::WebhookDelivery {
            webhook_id: hook_id,
            event: "check".into(),
            payload: payload.clone(),
            redelivery: false,
        })
        .await
        .unwrap();
        let job = db_jobs::list_recent(core.db(), 5)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.kind == "webhook_delivery")
            .unwrap();
        core.deliver_webhook(job.id, hook_id, "check", &payload, false)
            .await
    }

    /// Hand-rolled loopback HTTP server (no axum in dev-deps): records hits
    /// and answers every request with `response`.
    async fn tcp_sink(response: Vec<u8>, hits: Arc<AtomicUsize>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                hits.fetch_add(1, Ordering::SeqCst);
                let mut acc = Vec::new();
                let mut buf = [0u8; 4096];
                let _ = tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                acc.extend_from_slice(&buf[..n]);
                                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                })
                .await;
                let _ = sock.write_all(&response).await;
            }
        });
        addr
    }

    fn ok_response() -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec()
    }

    /// Denied literal-IP hosts are terminal with no request and no retry —
    /// there is no server behind these addresses in the test at all.
    #[tokio::test]
    async fn denied_hosts_record_terminal_without_request() {
        let (core, _f, repo_id) = seeded(false).await;
        for url in [
            "http://10.0.0.1/hook",
            "http://169.254.169.254/latest/meta-data/",
            "http://224.0.0.1/hook",
            "http://[fc00::1]/hook",
        ] {
            let hook = insert_hook(&core, repo_id, url).await;
            deliver_once(&core, hook.id).await.unwrap();
            let deliveries = db_checks::recent_deliveries(core.db(), hook.id, 5)
                .await
                .unwrap();
            assert_eq!(deliveries.len(), 1, "{url}");
            assert!(deliveries[0].status_code.is_none(), "{url}");
            assert!(
                deliveries[0]
                    .error
                    .as_deref()
                    .unwrap_or("")
                    .contains("not allowed")
                    || deliveries[0]
                        .error
                        .as_deref()
                        .unwrap_or("")
                        .contains("no allowed address"),
                "{url}: {:?}",
                deliveries[0].error
            );
            // Denial is terminal: `deliver_once` returned `Ok` (no retry
            // `Err`) and the outcome is already recorded above.
        }
    }

    /// Loopback is denied by default and the denial precedes any connection:
    /// the bound acceptor observes zero hits.
    #[tokio::test]
    async fn loopback_denied_by_default() {
        let (core, _f, repo_id) = seeded(false).await;
        let hits = Arc::new(AtomicUsize::new(0));
        let addr = tcp_sink(ok_response(), hits.clone()).await;
        let hook = insert_hook(&core, repo_id, &format!("http://{addr}/hook")).await;
        deliver_once(&core, hook.id).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(hits.load(Ordering::SeqCst), 0, "no request was sent");
        let deliveries = db_checks::recent_deliveries(core.db(), hook.id, 5)
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        assert!(
            deliveries[0]
                .error
                .as_deref()
                .unwrap_or("")
                .contains("not allowed")
        );
    }

    /// A hostname resolving to loopback is denied too (fail-closed when it
    /// does not resolve at all).
    #[tokio::test]
    async fn localhost_hostname_denied_by_default() {
        let (core, _f, repo_id) = seeded(false).await;
        let hook = insert_hook(&core, repo_id, "http://localhost:9/hook").await;
        deliver_once(&core, hook.id).await.unwrap();
        let deliveries = db_checks::recent_deliveries(core.db(), hook.id, 5)
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        let error = deliveries[0].error.clone().unwrap_or_default();
        assert!(
            error.contains("no allowed address") || error.contains("does not resolve"),
            "{error}"
        );
    }

    /// With the test-only flag, loopback delivers normally.
    #[tokio::test]
    async fn loopback_allowed_with_flag() {
        let (core, _f, repo_id) = seeded(true).await;
        let hits = Arc::new(AtomicUsize::new(0));
        let addr = tcp_sink(ok_response(), hits.clone()).await;
        let hook = insert_hook(&core, repo_id, &format!("http://{addr}/hook")).await;
        deliver_once(&core, hook.id).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let deliveries = db_checks::recent_deliveries(core.db(), hook.id, 5)
            .await
            .unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].status_code, Some(200));
    }

    /// A 302 is returned, never followed: the redirect target sees nothing
    /// and the attempt stays retryable.
    #[tokio::test]
    async fn redirect_is_not_followed() {
        let (core, _f, repo_id) = seeded(true).await;
        let hits_b = Arc::new(AtomicUsize::new(0));
        let addr_b = tcp_sink(ok_response(), hits_b.clone()).await;
        let hits_a = Arc::new(AtomicUsize::new(0));
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{addr_b}/hook\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let addr_a = tcp_sink(redirect, hits_a.clone()).await;
        let hook = insert_hook(&core, repo_id, &format!("http://{addr_a}/hook")).await;
        let err = deliver_once(&core, hook.id).await.unwrap_err();
        assert!(err.to_string().contains("HTTP 302"), "{err}");
        assert_eq!(hits_a.load(Ordering::SeqCst), 1);
        assert_eq!(
            hits_b.load(Ordering::SeqCst),
            0,
            "redirect target untouched"
        );
    }

    /// A 200 with a body past the cap fails the attempt.
    #[tokio::test]
    async fn body_cap_enforced() {
        let (core, _f, repo_id) = seeded(true).await;
        let big = vec![b'x'; MAX_BODY_BYTES + 1];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            big.len()
        )
        .into_bytes();
        response.extend_from_slice(&big);
        let hits = Arc::new(AtomicUsize::new(0));
        let addr = tcp_sink(response, hits.clone()).await;
        let hook = insert_hook(&core, repo_id, &format!("http://{addr}/hook")).await;
        let err = deliver_once(&core, hook.id).await.unwrap_err();
        assert!(err.to_string().contains("64 KiB"), "{err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
