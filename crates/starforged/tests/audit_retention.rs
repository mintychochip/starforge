//! Audit retention: `audit::prune_before` deletes in batches, and the daily
//! job prunes rows older than the configured retention.

mod common;

use starforged_db::audit;

/// Inserts one audit row with an explicit timestamp; returns its id.
async fn seed(db: &starforged_db::Db, created_at: i64, action: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO audit_log (actor_id, action, target, detail, ip, user_agent, created_at) \
         VALUES (NULL, $1, 'test', '', '127.0.0.1', 'test', $2) RETURNING id",
    )
    .bind(action)
    .bind(created_at)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

async fn count(db: &starforged_db::Db, action: &str) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_log WHERE action = $1")
        .bind(action)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// `prune_before` deletes every old row across several batches and leaves
/// newer rows alone. Runs on SQLite or Postgres through `TestDb`.
#[tokio::test]
async fn prune_before_spans_multiple_batches_and_keeps_newer_rows() {
    let t = starforged_db::testing::TestDb::new().await;
    let cutoff = 1_700_000_000;
    for i in 0..5 {
        seed(&t.db, cutoff - 100 - i, "test.old").await;
    }
    seed(&t.db, cutoff, "test.new").await;
    seed(&t.db, cutoff + 100, "test.new").await;

    let deleted = audit::prune_before(&t.db, cutoff, 2).await.unwrap();
    assert_eq!(deleted, 5);
    assert_eq!(count(&t.db, "test.old").await, 0);
    assert_eq!(count(&t.db, "test.new").await, 2);

    // A second pass finds nothing left to delete.
    assert_eq!(audit::prune_before(&t.db, cutoff, 2).await.unwrap(), 0);
    // A non-positive batch is a no-op rather than an infinite loop.
    assert_eq!(audit::prune_before(&t.db, cutoff, 0).await.unwrap(), 0);
}

/// The daily job honours `audit.retention_days`: with retention 0 it keeps
/// everything; with a positive retention it drops old rows.
#[tokio::test]
async fn daily_prune_respects_retention() {
    let s = common::TestServer::start_with(|c| {
        c.audit.retention_days = 1;
    })
    .await;
    let now = starforged_db::now();
    seed(s.db(), now - 2 * 86_400, "test.retention").await;
    seed(s.db(), now, "test.retention").await;

    s.core
        .enqueue(&starforged_core::jobs::Job::DailyPrune)
        .await
        .unwrap();
    s.core.run_due_jobs().await.unwrap();
    assert_eq!(count(s.db(), "test.retention").await, 1);
}

/// With retention 0 the daily job never touches the audit log.
#[tokio::test]
async fn daily_prune_with_zero_retention_keeps_everything() {
    let s = common::TestServer::start_with(|c| {
        c.audit.retention_days = 0;
    })
    .await;
    let now = starforged_db::now();
    seed(s.db(), now - 2 * 86_400, "test.keep").await;

    s.core
        .enqueue(&starforged_core::jobs::Job::DailyPrune)
        .await
        .unwrap();
    s.core.run_due_jobs().await.unwrap();
    assert_eq!(count(s.db(), "test.keep").await, 1);
}
