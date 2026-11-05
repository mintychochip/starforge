//! `checks`, `gate_rules`, `webhooks`, `webhook_deliveries`: commit statuses,
//! merge gate rules, and webhook fan-out (spec §6.5, M2c).
//!
//! The data-access layer stays thin — no validation or permission checks here
//! (those live in `starforged-core`). `latest_checks_for_sha` returns the
//! current row per `(repo, sha, context)`; the `UNIQUE (repo_id, sha, context)`
//! constraint plus the upsert in [`insert_check`] keep it to one row per
//! context. [`combined_state`] folds a slice with error > failure > pending >
//! success precedence (empty means pending); [`combined_status`] is the same
//! fold over the rows stored for `(repo, sha)`.
//!
//! `gate_rules.required_contexts` / `allowed_methods` are TEXT holding JSON
//! arrays (no JSON operators — both engines). `webhooks.secret_encrypted`
//! holds `v1:<base64(nonce‖ciphertext)>` AEAD ciphertext; the db layer stores
//! what it is given and never encrypts — callers in `starforged-core` own the
//! seal/open. User FKs (`checks.creator_id`) are nullable
//! `ON DELETE SET NULL` so history survives account deletion; rows inside one
//! aggregate (`gate_rules`, `webhooks`, `webhook_deliveries`) cascade.

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::{Db, DbResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRow {
    pub id: i64,
    pub repo_id: i64,
    pub sha: String,
    pub context: String,
    pub state: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
    pub creator_id: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRuleRow {
    pub id: i64,
    pub repo_id: i64,
    pub pattern: Option<String>,
    pub required_approvals: i64,
    pub dismiss_on_push: i64,
    pub block_on_request_changes: i64,
    pub required_contexts: String,
    pub require_up_to_date: i64,
    pub require_threads_resolved: i64,
    pub require_session_evidence: i64,
    pub allowed_methods: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRow {
    pub id: i64,
    pub repo_id: i64,
    pub url: String,
    pub secret_encrypted: String,
    pub events: String,
    pub active: i64,
    pub last_status: Option<i64>,
    pub last_error: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDeliveryRow {
    pub id: i64,
    pub webhook_id: i64,
    pub event: String,
    pub payload: String,
    pub status_code: Option<i64>,
    pub error: Option<String>,
    pub delivered_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewCheck<'a> {
    pub repo_id: i64,
    pub sha: &'a str,
    pub context: &'a str,
    pub state: &'a str,
    pub target_url: Option<&'a str>,
    pub description: Option<&'a str>,
    pub creator: Option<i64>,
    pub now: i64,
}

#[derive(Debug, Clone)]
pub struct NewGateRule<'a> {
    pub repo_id: i64,
    pub pattern: Option<&'a str>,
    pub approvals: i64,
    pub dismiss_on_push: bool,
    pub block_rc: bool,
    pub contexts: &'a str,
    pub up_to_date: bool,
    pub threads: bool,
    pub session_ev: bool,
    pub methods: &'a str,
    pub now: i64,
}

#[derive(Debug, Clone)]
pub struct NewWebhook<'a> {
    pub repo_id: i64,
    pub url: &'a str,
    pub secret_enc: &'a str,
    pub events: &'a str,
    pub now: i64,
}

#[derive(Debug, Clone, Default)]
pub struct GateRuleUpdate<'a> {
    pub pattern: Option<Option<&'a str>>,
    pub approvals: Option<i64>,
    pub dismiss_on_push: Option<bool>,
    pub block_rc: Option<bool>,
    pub contexts: Option<&'a str>,
    pub up_to_date: Option<bool>,
    pub threads: Option<bool>,
    pub session_ev: Option<bool>,
    pub methods: Option<&'a str>,
}

macro_rules! select_check {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, sha, context, state, target_url, description, creator_id, ",
            "created_at, updated_at FROM checks ",
            $tail
        )
    };
}

macro_rules! select_gate_rule {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, pattern, required_approvals, dismiss_on_push, ",
            "block_on_request_changes, required_contexts, require_up_to_date, ",
            "require_threads_resolved, require_session_evidence, allowed_methods, ",
            "created_at, updated_at FROM gate_rules ",
            $tail
        )
    };
}

macro_rules! select_webhook {
    ($tail:literal) => {
        concat!(
            "SELECT id, repo_id, url, secret_encrypted, events, active, last_status, ",
            "last_error, created_at FROM webhooks ",
            $tail
        )
    };
}

macro_rules! select_delivery {
    ($tail:literal) => {
        concat!(
            "SELECT id, webhook_id, event, payload, status_code, error, delivered_at ",
            "FROM webhook_deliveries ",
            $tail
        )
    };
}

fn check_from_row(row: &AnyRow) -> DbResult<CheckRow> {
    Ok(CheckRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        sha: row.try_get("sha")?,
        context: row.try_get("context")?,
        state: row.try_get("state")?,
        target_url: row.try_get("target_url")?,
        description: row.try_get("description")?,
        creator_id: row.try_get("creator_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn gate_rule_from_row(row: &AnyRow) -> DbResult<GateRuleRow> {
    Ok(GateRuleRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        pattern: row.try_get("pattern")?,
        required_approvals: row.try_get("required_approvals")?,
        dismiss_on_push: row.try_get("dismiss_on_push")?,
        block_on_request_changes: row.try_get("block_on_request_changes")?,
        required_contexts: row.try_get("required_contexts")?,
        require_up_to_date: row.try_get("require_up_to_date")?,
        require_threads_resolved: row.try_get("require_threads_resolved")?,
        require_session_evidence: row.try_get("require_session_evidence")?,
        allowed_methods: row.try_get("allowed_methods")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn webhook_from_row(row: &AnyRow) -> DbResult<WebhookRow> {
    Ok(WebhookRow {
        id: row.try_get("id")?,
        repo_id: row.try_get("repo_id")?,
        url: row.try_get("url")?,
        secret_encrypted: row.try_get("secret_encrypted")?,
        events: row.try_get("events")?,
        active: row.try_get("active")?,
        last_status: row.try_get("last_status")?,
        last_error: row.try_get("last_error")?,
        created_at: row.try_get("created_at")?,
    })
}

fn delivery_from_row(row: &AnyRow) -> DbResult<WebhookDeliveryRow> {
    Ok(WebhookDeliveryRow {
        id: row.try_get("id")?,
        webhook_id: row.try_get("webhook_id")?,
        event: row.try_get("event")?,
        payload: row.try_get("payload")?,
        status_code: row.try_get("status_code")?,
        error: row.try_get("error")?,
        delivered_at: row.try_get("delivered_at")?,
    })
}

fn bool_to_int(b: bool) -> i64 {
    i64::from(b)
}

/// Inserts the check, or updates the existing row for
/// `(repo_id, sha, context)` (state/fields + `updated_at`); the returned row
/// is the current one either way.
#[allow(clippy::too_many_arguments)]
pub async fn insert_check(
    db: &Db,
    repo_id: i64,
    sha: &str,
    context: &str,
    state: &str,
    target_url: Option<&str>,
    description: Option<&str>,
    creator: Option<i64>,
    now: i64,
) -> DbResult<CheckRow> {
    insert_check_row(
        db,
        &NewCheck {
            repo_id,
            sha,
            context,
            state,
            target_url,
            description,
            creator,
            now,
        },
    )
    .await
}

async fn insert_check_row(db: &Db, n: &NewCheck<'_>) -> DbResult<CheckRow> {
    let row = sqlx::query(
        "INSERT INTO checks (repo_id, sha, context, state, target_url, description, creator_id, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8) \
         ON CONFLICT (repo_id, sha, context) DO UPDATE SET state = $4, target_url = $5, description = $6, \
         creator_id = $7, updated_at = $8 \
         RETURNING id, repo_id, sha, context, state, target_url, description, creator_id, created_at, updated_at",
    )
    .bind(n.repo_id)
    .bind(n.sha)
    .bind(n.context)
    .bind(n.state)
    .bind(n.target_url)
    .bind(n.description)
    .bind(n.creator)
    .bind(n.now)
    .fetch_one(db.pool())
    .await?;
    check_from_row(&row)
}

/// The current row per context for `(repo_id, sha)`, ordered by context.
pub async fn latest_checks_for_sha(db: &Db, repo_id: i64, sha: &str) -> DbResult<Vec<CheckRow>> {
    let rows = sqlx::query(select_check!(
        "WHERE repo_id = $1 AND sha = $2 ORDER BY context ASC"
    ))
    .bind(repo_id)
    .bind(sha)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(check_from_row).collect()
}

/// Alias for [`latest_checks_for_sha`] (H1 contract name).
pub async fn latest_statuses(db: &Db, repo_id: i64, sha: &str) -> DbResult<Vec<CheckRow>> {
    latest_checks_for_sha(db, repo_id, sha).await
}

/// Folds check states with error > failure > pending > success precedence;
/// empty means pending.
pub async fn combined_state(checks: &[CheckRow]) -> &'static str {
    if checks.iter().any(|c| c.state == "error") {
        "error"
    } else if checks.iter().any(|c| c.state == "failure") {
        "failure"
    } else if checks.iter().any(|c| c.state == "pending") || checks.is_empty() {
        "pending"
    } else {
        "success"
    }
}

/// The combined state of the rows stored for `(repo_id, sha)` (same
/// error > failure > pending > success fold; empty means pending).
pub async fn combined_status(db: &Db, repo_id: i64, sha: &str) -> DbResult<&'static str> {
    let checks = latest_checks_for_sha(db, repo_id, sha).await?;
    Ok(combined_state(&checks).await)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_gate_rule(
    db: &Db,
    repo_id: i64,
    pattern: Option<&str>,
    approvals: i64,
    dismiss_on_push: bool,
    block_rc: bool,
    contexts: &str,
    up_to_date: bool,
    threads: bool,
    session_ev: bool,
    methods: &str,
    now: i64,
) -> DbResult<GateRuleRow> {
    insert_gate_rule_row(
        db,
        &NewGateRule {
            repo_id,
            pattern,
            approvals,
            dismiss_on_push,
            block_rc,
            contexts,
            up_to_date,
            threads,
            session_ev,
            methods,
            now,
        },
    )
    .await
}

async fn insert_gate_rule_row(db: &Db, n: &NewGateRule<'_>) -> DbResult<GateRuleRow> {
    let row = sqlx::query(
        "INSERT INTO gate_rules (repo_id, pattern, required_approvals, dismiss_on_push, block_on_request_changes, \
         required_contexts, require_up_to_date, require_threads_resolved, require_session_evidence, allowed_methods, \
         created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11) \
         RETURNING id, repo_id, pattern, required_approvals, dismiss_on_push, block_on_request_changes, \
         required_contexts, require_up_to_date, require_threads_resolved, require_session_evidence, allowed_methods, \
         created_at, updated_at",
    )
    .bind(n.repo_id)
    .bind(n.pattern)
    .bind(n.approvals)
    .bind(bool_to_int(n.dismiss_on_push))
    .bind(bool_to_int(n.block_rc))
    .bind(n.contexts)
    .bind(bool_to_int(n.up_to_date))
    .bind(bool_to_int(n.threads))
    .bind(bool_to_int(n.session_ev))
    .bind(n.methods)
    .bind(n.now)
    .fetch_one(db.pool())
    .await?;
    gate_rule_from_row(&row)
}

/// Gate rules of the repo in insert order.
pub async fn gate_rules_for_repo(db: &Db, repo_id: i64) -> DbResult<Vec<GateRuleRow>> {
    let rows = sqlx::query(select_gate_rule!("WHERE repo_id = $1 ORDER BY id ASC"))
        .bind(repo_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(gate_rule_from_row).collect()
}

/// Alias for [`gate_rules_for_repo`] (H1 contract name).
pub async fn gate_rules_for(db: &Db, repo_id: i64) -> DbResult<Vec<GateRuleRow>> {
    gate_rules_for_repo(db, repo_id).await
}

/// One gate rule by id, scoped to the repo (`None` for a missing id or
/// another repo's id).
pub async fn gate_rule_by_id(db: &Db, id: i64, repo_id: i64) -> DbResult<Option<GateRuleRow>> {
    let row = sqlx::query(select_gate_rule!("WHERE id = $1 AND repo_id = $2"))
        .bind(id)
        .bind(repo_id)
        .fetch_optional(db.pool())
        .await?;
    row.map(|row| gate_rule_from_row(&row)).transpose()
}

/// Updates the rule `id` scoped to the repo (`None` for a missing id or
/// another repo's id); set fields replace the row's, unset fields stay.
pub async fn update_gate_rule(
    db: &Db,
    id: i64,
    repo_id: i64,
    update: &GateRuleUpdate<'_>,
    now: i64,
) -> DbResult<Option<GateRuleRow>> {
    let Some(mut rule) = gate_rule_by_id(db, id, repo_id).await? else {
        return Ok(None);
    };
    if let Some(p) = update.pattern {
        rule.pattern = p.map(str::to_owned);
    }
    if let Some(a) = update.approvals {
        rule.required_approvals = a;
    }
    if let Some(b) = update.dismiss_on_push {
        rule.dismiss_on_push = bool_to_int(b);
    }
    if let Some(b) = update.block_rc {
        rule.block_on_request_changes = bool_to_int(b);
    }
    if let Some(c) = update.contexts {
        rule.required_contexts = c.to_owned();
    }
    if let Some(b) = update.up_to_date {
        rule.require_up_to_date = bool_to_int(b);
    }
    if let Some(b) = update.threads {
        rule.require_threads_resolved = bool_to_int(b);
    }
    if let Some(b) = update.session_ev {
        rule.require_session_evidence = bool_to_int(b);
    }
    if let Some(m) = update.methods {
        rule.allowed_methods = m.to_owned();
    }
    sqlx::query(
        "UPDATE gate_rules SET pattern = $1, required_approvals = $2, dismiss_on_push = $3, \
         block_on_request_changes = $4, required_contexts = $5, require_up_to_date = $6, \
         require_threads_resolved = $7, require_session_evidence = $8, allowed_methods = $9, \
         updated_at = $10 WHERE id = $11",
    )
    .bind(rule.pattern.as_deref())
    .bind(rule.required_approvals)
    .bind(rule.dismiss_on_push)
    .bind(rule.block_on_request_changes)
    .bind(&rule.required_contexts)
    .bind(rule.require_up_to_date)
    .bind(rule.require_threads_resolved)
    .bind(rule.require_session_evidence)
    .bind(&rule.allowed_methods)
    .bind(now)
    .bind(rule.id)
    .execute(db.pool())
    .await?;
    rule.updated_at = now;
    Ok(Some(rule))
}

pub async fn delete_gate_rule(db: &Db, id: i64, repo_id: i64) -> DbResult<bool> {
    let done = sqlx::query("DELETE FROM gate_rules WHERE id = $1 AND repo_id = $2")
        .bind(id)
        .bind(repo_id)
        .execute(db.pool())
        .await?;
    Ok(done.rows_affected() > 0)
}

pub async fn insert_webhook(
    db: &Db,
    repo_id: i64,
    url: &str,
    secret_enc: &str,
    events: &str,
    now: i64,
) -> DbResult<WebhookRow> {
    insert_webhook_row(
        db,
        &NewWebhook {
            repo_id,
            url,
            secret_enc,
            events,
            now,
        },
    )
    .await
}

async fn insert_webhook_row(db: &Db, n: &NewWebhook<'_>) -> DbResult<WebhookRow> {
    let row = sqlx::query(
        "INSERT INTO webhooks (repo_id, url, secret_encrypted, events, active, created_at) \
         VALUES ($1, $2, $3, $4, 1, $5) \
         RETURNING id, repo_id, url, secret_encrypted, events, active, last_status, last_error, created_at",
    )
    .bind(n.repo_id)
    .bind(n.url)
    .bind(n.secret_enc)
    .bind(n.events)
    .bind(n.now)
    .fetch_one(db.pool())
    .await?;
    webhook_from_row(&row)
}

/// Webhooks of the repo in insert order.
pub async fn webhooks_for_repo(db: &Db, repo_id: i64) -> DbResult<Vec<WebhookRow>> {
    let rows = sqlx::query(select_webhook!("WHERE repo_id = $1 ORDER BY id ASC"))
        .bind(repo_id)
        .fetch_all(db.pool())
        .await?;
    rows.iter().map(webhook_from_row).collect()
}

/// Alias for [`webhooks_for_repo`] (H1 contract name).
pub async fn webhooks_of_repo(db: &Db, repo_id: i64) -> DbResult<Vec<WebhookRow>> {
    webhooks_for_repo(db, repo_id).await
}

/// One webhook by id, if it still exists.
pub async fn webhook_by_id(db: &Db, id: i64) -> DbResult<Option<WebhookRow>> {
    let row = sqlx::query(select_webhook!("WHERE id = $1"))
        .bind(id)
        .fetch_optional(db.pool())
        .await?;
    row.as_ref().map(webhook_from_row).transpose()
}

pub async fn delete_webhook(db: &Db, id: i64, repo_id: i64) -> DbResult<bool> {
    let done = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND repo_id = $2")
        .bind(id)
        .bind(repo_id)
        .execute(db.pool())
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Toggles the hook's `active` flag.
pub async fn set_webhook_active(db: &Db, id: i64, active: bool) -> DbResult<()> {
    sqlx::query("UPDATE webhooks SET active = $1 WHERE id = $2")
        .bind(bool_to_int(active))
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

pub async fn set_webhook_result(
    db: &Db,
    id: i64,
    status: Option<i64>,
    error: Option<&str>,
) -> DbResult<()> {
    sqlx::query("UPDATE webhooks SET last_status = $1, last_error = $2 WHERE id = $3")
        .bind(status)
        .bind(error)
        .bind(id)
        .execute(db.pool())
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_delivery(
    db: &Db,
    webhook_id: i64,
    event: &str,
    payload: &str,
    status: Option<i64>,
    error: Option<&str>,
    now: i64,
) -> DbResult<WebhookDeliveryRow> {
    let row = sqlx::query(
        "INSERT INTO webhook_deliveries (webhook_id, event, payload, status_code, error, delivered_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         RETURNING id, webhook_id, event, payload, status_code, error, delivered_at",
    )
    .bind(webhook_id)
    .bind(event)
    .bind(payload)
    .bind(status)
    .bind(error)
    .bind(now)
    .fetch_one(db.pool())
    .await?;
    delivery_from_row(&row)
}

/// The newest `limit` deliveries of the hook, newest first.
pub async fn recent_deliveries(
    db: &Db,
    webhook_id: i64,
    limit: i64,
) -> DbResult<Vec<WebhookDeliveryRow>> {
    let rows = sqlx::query(select_delivery!(
        "WHERE webhook_id = $1 ORDER BY id DESC LIMIT $2"
    ))
    .bind(webhook_id)
    .bind(limit)
    .fetch_all(db.pool())
    .await?;
    rows.iter().map(delivery_from_row).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::{self, NewRepo};
    use crate::testing::TestDb;
    use crate::users::{self, NewUser};

    fn user(handle: &str) -> NewUser<'_> {
        NewUser {
            handle,
            display_name: "",
            email: None,
            email_verified: false,
            password_hash: None,
            is_admin: false,
        }
    }

    fn repo(owner_id: i64, name: &str) -> NewRepo<'_> {
        NewRepo {
            owner_id,
            name,
            description: "",
            visibility: "private",
            default_branch: "main",
        }
    }

    async fn setup() -> (TestDb, i64, i64, i64) {
        let t = TestDb::new().await;
        let alice = users::insert(&t.db, &user("checks-alice")).await.unwrap();
        let bob = users::insert(&t.db, &user("checks-bob")).await.unwrap();
        // The repo belongs to bob: deleting alice (the check creator) nulls
        // the creator instead of cascading through the repo.
        let repo_id = repos::insert(&t.db, &repo(bob, "checks-demo"))
            .await
            .unwrap();
        (t, alice, bob, repo_id)
    }

    #[tokio::test]
    async fn check_upsert_same_repo_sha_context_updates_state() {
        let (t, alice, _bob, repo_id) = setup().await;
        let first = insert_check(
            &t.db,
            repo_id,
            "abc123",
            "ci/unit",
            "pending",
            None,
            None,
            Some(alice),
            1_700_000_000,
        )
        .await
        .unwrap();
        assert_eq!(first.state, "pending");
        let second = insert_check(
            &t.db,
            repo_id,
            "abc123",
            "ci/unit",
            "success",
            Some("https://ci.example/run/1"),
            Some("all green"),
            Some(alice),
            1_700_000_100,
        )
        .await
        .unwrap();
        assert_eq!(second.id, first.id);
        assert_eq!(second.state, "success");
        assert!(second.updated_at > first.updated_at);
        let latest = latest_checks_for_sha(&t.db, repo_id, "abc123")
            .await
            .unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].state, "success");
    }

    #[tokio::test]
    async fn latest_checks_returns_one_row_per_context() {
        let (t, alice, _bob, repo_id) = setup().await;
        insert_check(
            &t.db,
            repo_id,
            "sha1",
            "ci/unit",
            "success",
            None,
            None,
            Some(alice),
            1_700_000_000,
        )
        .await
        .unwrap();
        insert_check(
            &t.db,
            repo_id,
            "sha1",
            "ci/lint",
            "pending",
            None,
            None,
            Some(alice),
            1_700_000_001,
        )
        .await
        .unwrap();
        // Second post for the same context updates instead of duplicating.
        insert_check(
            &t.db,
            repo_id,
            "sha1",
            "ci/unit",
            "failure",
            None,
            Some("flaky"),
            Some(alice),
            1_700_000_002,
        )
        .await
        .unwrap();
        let latest = latest_checks_for_sha(&t.db, repo_id, "sha1").await.unwrap();
        assert_eq!(latest.len(), 2);
        let unit = latest.iter().find(|c| c.context == "ci/unit").unwrap();
        assert_eq!(unit.state, "failure");
        // Other SHAs never leak in.
        let other = latest_checks_for_sha(&t.db, repo_id, "sha2").await.unwrap();
        assert!(other.is_empty());
    }

    #[tokio::test]
    async fn combined_state_truth_table() {
        async fn states(rows: &[(&str, &str)]) -> &'static str {
            let checks: Vec<CheckRow> = rows
                .iter()
                .enumerate()
                .map(|(i, (context, state))| CheckRow {
                    id: i as i64,
                    repo_id: 1,
                    sha: "s".to_owned(),
                    context: (*context).to_owned(),
                    state: (*state).to_owned(),
                    target_url: None,
                    description: None,
                    creator_id: None,
                    created_at: 0,
                    updated_at: 0,
                })
                .collect();
            combined_state(&checks).await
        }
        assert_eq!(states(&[]).await, "pending");
        assert_eq!(states(&[("a", "success")]).await, "success");
        assert_eq!(
            states(&[("a", "success"), ("b", "success")]).await,
            "success"
        );
        assert_eq!(
            states(&[("a", "success"), ("b", "pending")]).await,
            "pending"
        );
        assert_eq!(
            states(&[("a", "success"), ("b", "failure")]).await,
            "failure"
        );
        assert_eq!(states(&[("a", "failure"), ("b", "error")]).await, "error");
        assert_eq!(states(&[("a", "pending"), ("b", "error")]).await, "error");
    }

    #[tokio::test]
    async fn combined_status_reads_stored_rows() {
        let (t, alice, _bob, repo_id) = setup().await;
        assert_eq!(
            combined_status(&t.db, repo_id, "missing").await.unwrap(),
            "pending"
        );
        insert_check(
            &t.db,
            repo_id,
            "s1",
            "ci/unit",
            "success",
            None,
            None,
            Some(alice),
            1_700_000_000,
        )
        .await
        .unwrap();
        insert_check(
            &t.db,
            repo_id,
            "s1",
            "ci/lint",
            "failure",
            None,
            None,
            Some(alice),
            1_700_000_001,
        )
        .await
        .unwrap();
        assert_eq!(
            combined_status(&t.db, repo_id, "s1").await.unwrap(),
            "failure"
        );
    }

    #[tokio::test]
    async fn gate_rule_insert_list_delete_round_trip() {
        let (t, _alice, _bob, repo_id) = setup().await;
        let rule = insert_gate_rule(
            &t.db,
            repo_id,
            Some("main"),
            2,
            true,
            true,
            r#"["ci/unit"]"#,
            true,
            false,
            true,
            r#"["merge","squash"]"#,
            1_700_000_000,
        )
        .await
        .unwrap();
        assert_eq!(rule.required_approvals, 2);
        assert_eq!(rule.dismiss_on_push, 1);
        assert_eq!(rule.required_contexts, r#"["ci/unit"]"#);
        let rules = gate_rules_for_repo(&t.db, repo_id).await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, rule.id);
        assert!(delete_gate_rule(&t.db, rule.id, repo_id).await.unwrap());
        assert!(!delete_gate_rule(&t.db, rule.id, repo_id).await.unwrap());
        assert!(
            gate_rules_for_repo(&t.db, repo_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn gate_rule_by_id_and_update_hit_miss_and_cross_repo() {
        let (t, _alice, bob, repo_id) = setup().await;
        let other_repo = repos::insert(&t.db, &repo(bob, "checks-other"))
            .await
            .unwrap();
        let rule = insert_gate_rule(
            &t.db,
            repo_id,
            Some("main"),
            1,
            false,
            true,
            "[]",
            false,
            false,
            false,
            "[]",
            1_700_000_000,
        )
        .await
        .unwrap();
        // Hit.
        let found = gate_rule_by_id(&t.db, rule.id, repo_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.pattern.as_deref(), Some("main"));
        // Miss and another repo's id are both `None`.
        assert!(
            gate_rule_by_id(&t.db, 999_999, repo_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            gate_rule_by_id(&t.db, rule.id, other_repo)
                .await
                .unwrap()
                .is_none()
        );
        // Scoped update applies set fields and touches `updated_at`.
        let updated = update_gate_rule(
            &t.db,
            rule.id,
            repo_id,
            &GateRuleUpdate {
                approvals: Some(2),
                contexts: Some(r#"["ci/unit"]"#),
                ..Default::default()
            },
            1_700_000_100,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(updated.id, rule.id);
        assert_eq!(updated.required_approvals, 2);
        assert_eq!(updated.required_contexts, r#"["ci/unit"]"#);
        assert_eq!(updated.pattern.as_deref(), Some("main"));
        assert!(updated.updated_at > rule.updated_at);
        // Miss and cross-repo updates are `None` and write nothing.
        assert!(
            update_gate_rule(
                &t.db,
                999_999,
                repo_id,
                &GateRuleUpdate {
                    approvals: Some(9),
                    ..Default::default()
                },
                1_700_000_200,
            )
            .await
            .unwrap()
            .is_none()
        );
        assert!(
            update_gate_rule(
                &t.db,
                rule.id,
                other_repo,
                &GateRuleUpdate {
                    approvals: Some(9),
                    ..Default::default()
                },
                1_700_000_200,
            )
            .await
            .unwrap()
            .is_none()
        );
        assert_eq!(
            gate_rule_by_id(&t.db, rule.id, repo_id)
                .await
                .unwrap()
                .unwrap()
                .required_approvals,
            2
        );
    }

    #[tokio::test]
    async fn webhook_crud_and_delivery_round_trip() {
        let (t, _alice, _bob, repo_id) = setup().await;
        let secret = "v1:dGVzdC1ub25jZS10ZXN0LWNpcGhlcnRleHQ=";
        let hook = insert_webhook(
            &t.db,
            repo_id,
            "https://hooks.example/starforge",
            secret,
            r#"["check","merge"]"#,
            1_700_000_000,
        )
        .await
        .unwrap();
        // Ciphertext-shaped TEXT round-trips byte-for-byte; the db layer never
        // encrypts — it stores what it is given.
        assert_eq!(hook.secret_encrypted, secret);
        assert_eq!(hook.active, 1);
        let hooks = webhooks_for_repo(&t.db, repo_id).await.unwrap();
        assert_eq!(hooks.len(), 1);
        set_webhook_active(&t.db, hook.id, false).await.unwrap();
        let hooks = webhooks_of_repo(&t.db, repo_id).await.unwrap();
        assert_eq!(hooks[0].active, 0);
        set_webhook_active(&t.db, hook.id, true).await.unwrap();
        set_webhook_result(&t.db, hook.id, Some(200), None)
            .await
            .unwrap();
        let hooks = webhooks_for_repo(&t.db, repo_id).await.unwrap();
        assert_eq!(hooks[0].last_status, Some(200));
        let delivery = insert_delivery(
            &t.db,
            hook.id,
            "check",
            r#"{"sha":"abc"}"#,
            Some(200),
            None,
            1_700_000_010,
        )
        .await
        .unwrap();
        assert_eq!(delivery.webhook_id, hook.id);
        insert_delivery(
            &t.db,
            hook.id,
            "check",
            r#"{"sha":"def"}"#,
            Some(500),
            Some("boom"),
            1_700_000_020,
        )
        .await
        .unwrap();
        let recent = recent_deliveries(&t.db, hook.id, 10).await.unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].payload, r#"{"sha":"def"}"#);
        assert!(delete_webhook(&t.db, hook.id, repo_id).await.unwrap());
        // Deliveries cascade with the hook.
        assert!(
            recent_deliveries(&t.db, hook.id, 10)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn check_creator_nulls_on_user_delete() {
        let (t, alice, _bob, repo_id) = setup().await;
        insert_check(
            &t.db,
            repo_id,
            "dead-beef",
            "ci/unit",
            "success",
            None,
            None,
            Some(alice),
            1_700_000_000,
        )
        .await
        .unwrap();
        users::delete(&t.db, alice).await.unwrap();
        let latest = latest_checks_for_sha(&t.db, repo_id, "dead-beef")
            .await
            .unwrap();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].creator_id, None);
    }
}
