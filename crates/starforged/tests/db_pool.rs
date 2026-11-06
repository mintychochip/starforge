//! The SQLite reader pool (plan M5b O5, decision D7): a separate
//! `query_only` pool serves pure reads, the single writer pool serves
//! writes. The first two tests are SQLite-only (Postgres keeps one pool);
//! the third runs on either engine.

use std::time::Duration;

use starforged_db::testing::TestDb;
use starforged_db::{Backend, Db};

async fn seed_owner(db: &Db, handle: &str) {
    sqlx::query("INSERT INTO owners (kind, handle, created_at) VALUES ('user', $1, 0)")
        .bind(handle)
        .execute(db.pool())
        .await
        .unwrap();
}

/// A read transaction held open on a reader connection must not block a
/// write on the writer pool (WAL: readers never block the single writer).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_read_does_not_block_a_write() {
    let t = TestDb::new().await;
    if t.db.backend() == Backend::Postgres {
        eprintln!("SKIP: reader pool split is SQLite-only");
        return;
    }
    let db = t.db.clone();
    seed_owner(&db, "alice").await;

    // Hold a read transaction open on one reader connection.
    let mut reader = db.read_pool().acquire().await.unwrap();
    sqlx::query("BEGIN").execute(&mut *reader).await.unwrap();
    let seen: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM owners")
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    assert_eq!(seen, 1);

    // A write on the writer pool completes while the read is held.
    let writer = db.clone();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        sqlx::query("INSERT INTO owners (kind, handle, created_at) VALUES ('user', 'bob', 0)")
            .execute(writer.pool())
            .await
            .unwrap();
        let _ = done_tx.send(());
    });
    tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("write blocked by a held reader transaction")
        .unwrap();

    // The held read still sees its original snapshot.
    let seen: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM owners")
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    assert_eq!(seen, 1);
    sqlx::query("ROLLBACK").execute(&mut *reader).await.unwrap();

    // A fresh read sees the committed write.
    let seen: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM owners")
        .fetch_one(db.read_pool())
        .await
        .unwrap();
    assert_eq!(seen, 2);
}

/// Reader connections refuse writes (`PRAGMA query_only = ON`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reader_pool_refuses_writes() {
    let t = TestDb::new().await;
    if t.db.backend() == Backend::Postgres {
        eprintln!("SKIP: reader pool split is SQLite-only");
        return;
    }
    let db = &t.db;

    let query_only: i64 = sqlx::query_scalar("PRAGMA query_only")
        .fetch_one(db.read_pool())
        .await
        .unwrap();
    assert_eq!(query_only, 1);

    let err =
        sqlx::query("INSERT INTO owners (kind, handle, created_at) VALUES ('user', 'mallory', 0)")
            .execute(db.read_pool())
            .await;
    assert!(err.is_err(), "reader pool accepted a write: {err:?}");

    // The writer pool is unaffected.
    seed_owner(db, "alice").await;
}

/// A write, then an immediate read through the reader pool, sees the write
/// (WAL visibility on SQLite; the same committed row on Postgres).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_is_visible_to_an_immediate_read() {
    let t = TestDb::new().await;
    let db = &t.db;
    seed_owner(db, "alice").await;

    let owner = starforged_db::orgs::owner_by_handle(db, "alice")
        .await
        .unwrap()
        .expect("just-committed owner visible through the reader pool");
    assert_eq!(owner.kind, "user");

    // The public read helpers (reader pool) agree with the writer pool.
    let via_writer: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM owners")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(via_writer, 1);
}
