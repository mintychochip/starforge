//! Data access for starforged: one schema, two engines (SQLite, Postgres), through sqlx's `Any` driver.
//!
//! Every statement in this crate must run unchanged on both engines:
//! - placeholders are `$1, $2, …` and each number first appears in ascending order
//!   (SQLite numbers `$N` parameters by first appearance);
//! - integer columns decode as `i64` (Postgres `BIGINT`, SQLite `INTEGER`);
//! - booleans are stored as `0`/`1` integers;
//! - timestamps are unix seconds.

use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::AnyPool;
use sqlx::Executor;
use sqlx::any::AnyPoolOptions;

pub mod audit;
pub mod auth_factors;
pub mod changes;
pub mod checks;
pub mod ci;
pub mod collaborators;
pub mod doctor;
pub mod email_tokens;
pub mod github_imports;
pub mod invites;
pub mod jobs;
pub mod notifications;
pub mod oauth;
pub mod orgs;
pub mod protection;
pub mod redirects;
pub mod remotes;
pub mod repos;
pub mod sandboxes;
pub mod sessions;
pub mod sshkeys;
pub mod tokens;
pub mod trails;
pub mod users;
pub mod web_sessions;

static SQLITE_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");
static POSTGRES_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("unsupported database url (expected sqlite: or postgres:): {0}")]
    UnsupportedUrl(String),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

impl DbError {
    pub fn is_unique_violation(&self) -> bool {
        matches!(self, DbError::Sqlx(e) if e.as_database_error().is_some_and(|d| d.is_unique_violation()))
    }

    /// A foreign-key violation: a referencing row whose parent
    /// (`owners`, `users`, `repos`, …) vanished, e.g. a repo-scoped write
    /// racing an org or account deletion. Callers map this to `NotFound`
    /// (the parent is gone) instead of surfacing a 500.
    pub fn is_foreign_key_violation(&self) -> bool {
        matches!(self, DbError::Sqlx(e) if e.as_database_error().is_some_and(|d| d.is_foreign_key_violation()))
    }
}

pub type DbResult<T> = Result<T, DbError>;

#[derive(Debug, Clone)]
pub struct Db {
    pool: AnyPool,
    read_pool: AnyPool,
    backend: Backend,
}

impl Db {
    pub async fn connect(url: &str) -> DbResult<Db> {
        sqlx::any::install_default_drivers();
        let backend = if url.starts_with("sqlite:") {
            Backend::Sqlite
        } else if url.starts_with("postgres:") || url.starts_with("postgresql:") {
            Backend::Postgres
        } else {
            return Err(DbError::UnsupportedUrl(url.to_owned()));
        };
        let pool = match backend {
            // One writer connection: SQLite serializes writes anyway, and a
            // single connection avoids SQLITE_BUSY among writers.
            Backend::Sqlite => {
                AnyPoolOptions::new()
                    .max_connections(1)
                    .after_connect(|conn, _meta| {
                        Box::pin(async move {
                            conn.execute("PRAGMA foreign_keys = ON").await?;
                            conn.execute("PRAGMA journal_mode = WAL").await?;
                            conn.execute("PRAGMA busy_timeout = 5000").await?;
                            Ok(())
                        })
                    })
                    .connect(url)
                    .await?
            }
            Backend::Postgres => {
                AnyPoolOptions::new()
                    .max_connections(16)
                    .connect(url)
                    .await?
            }
        };
        // In-memory SQLite databases are named per connection by sqlx, so a
        // second pool would be a different (empty) database: share one pool.
        let in_memory = url.contains(":memory:") || url.contains("mode=memory");
        let read_pool = match backend {
            Backend::Sqlite if !in_memory => {
                AnyPoolOptions::new()
                    .max_connections(4)
                    .after_connect(|conn, _meta| {
                        Box::pin(async move {
                            conn.execute("PRAGMA foreign_keys = ON").await?;
                            conn.execute("PRAGMA journal_mode = WAL").await?;
                            conn.execute("PRAGMA busy_timeout = 5000").await?;
                            // Last: every reader connection refuses writes, so a
                            // write accidentally routed here fails loudly instead
                            // of contending with the single writer.
                            conn.execute("PRAGMA query_only = ON").await?;
                            Ok(())
                        })
                    })
                    .connect(url)
                    .await?
            }
            _ => pool.clone(),
        };
        Ok(Db {
            pool,
            read_pool,
            backend,
        })
    }

    pub async fn migrate(&self) -> DbResult<()> {
        match self.backend {
            Backend::Sqlite => SQLITE_MIGRATIONS.run(&self.pool).await?,
            Backend::Postgres => POSTGRES_MIGRATIONS.run(&self.pool).await?,
        }
        Ok(())
    }

    /// The writer pool: every write, every transaction (`pool().begin()`),
    /// and every read-then-write function.
    ///
    /// Read-your-writes rule: a function that must observe a write it just
    /// made in the same request stays on this pool. Committed writes are
    /// visible to the reader pool (WAL on SQLite, READ COMMITTED on
    /// Postgres), so a sequential "write, then read" across two functions is
    /// safe on either pool — but a read inside an open write transaction
    /// (which sees the transaction's uncommitted rows) must use this pool.
    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    /// The read-only pool: functions that only `SELECT` outside a transaction.
    /// On Postgres this is the same pool as [`Db::pool`]; on SQLite it is a
    /// separate pool of `query_only` connections, so a long read never blocks
    /// the single writer and a stray write fails instead of landing.
    pub fn read_pool(&self) -> &AnyPool {
        &self.read_pool
    }

    /// Answers `SELECT 1` (the `/readyz` database check, plan M5b D5).
    pub async fn ping(&self) -> DbResult<()> {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(self.read_pool())
            .await?;
        Ok(())
    }

    pub fn backend(&self) -> Backend {
        self.backend
    }
    /// The highest applied migration version, or `None` when the migrator has
    /// never run. Reads sqlx's own bookkeeping table, so it tracks whatever
    /// `migrate` applied on either engine.
    pub async fn latest_migration(&self) -> DbResult<Option<i64>> {
        Ok(
            sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
                .fetch_one(self.read_pool())
                .await?,
        )
    }

    /// The highest migration version this binary knows about for this
    /// backend (the newest file in the embedded migrator). `starforged
    /// doctor` compares [`Db::latest_migration`] against this to tell
    /// "migrations are up to date" from "run `starforged migrate`".
    pub fn known_migration(&self) -> i64 {
        let migrator = match self.backend {
            Backend::Sqlite => &SQLITE_MIGRATIONS,
            Backend::Postgres => &POSTGRES_MIGRATIONS,
        };
        migrator
            .iter()
            .map(|migration| migration.version)
            .max()
            .unwrap_or(0)
    }

    /// Writes a transactionally consistent copy of the SQLite database to
    /// `dest` via `VACUUM INTO` (`starforged backup`). The destination
    /// must not exist. Backups only; on Postgres this errors (use
    /// `pg_dump`).
    pub async fn vacuum_into_file(&self, dest: &std::path::Path) -> DbResult<()> {
        if self.backend != Backend::Sqlite {
            return Err(DbError::UnsupportedUrl(
                "VACUUM INTO is only available for SQLite databases".into(),
            ));
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|err| {
                DbError::UnsupportedUrl(format!(
                    "creating the backup database directory {}: {err}",
                    parent.display()
                ))
            })?;
        }
        // Single quotes in the path are doubled (SQL string-literal
        // escaping); the statement itself is fixed.
        let literal = dest.to_string_lossy().replace('\'', "''");
        // Safe: the statement is a fixed `VACUUM INTO` with one escaped
        // string literal built from a filesystem path.
        sqlx::query(sqlx::AssertSqlSafe(format!("VACUUM INTO '{literal}'")))
            .execute(self.pool())
            .await?;
        Ok(())
    }
}

/// Current time in unix seconds.
pub fn now() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after 1970")
        .as_secs();
    i64::try_from(secs).expect("unix time fits in i64")
}

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests {
    use crate::testing::TestDb;
    use crate::{Db, DbError};

    #[tokio::test]
    async fn migrations_create_every_table_and_rerun_cleanly() {
        let t = TestDb::new().await;
        t.db.migrate().await.unwrap();
        for table in [
            "owners",
            "users",
            "access_tokens",
            "web_sessions",
            "repos",
            "collaborators",
            "audit_log",
        ] {
            let sql = format!("SELECT COUNT(*) FROM {table}");
            let rows: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
                .fetch_one(t.db.pool())
                .await
                .unwrap();
            assert_eq!(rows, 0, "{table}");
        }
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let t = TestDb::new().await;
        let err =
            sqlx::query("INSERT INTO users (id, display_name, created_at) VALUES ($1, $2, $3)")
                .bind(999_i64)
                .bind("ghost")
                .bind(0_i64)
                .execute(t.db.pool())
                .await
                .unwrap_err();
        assert!(err.as_database_error().is_some(), "{err}");
    }

    #[tokio::test]
    async fn unique_violations_are_recognized() {
        let t = TestDb::new().await;
        let insert = || {
            sqlx::query("INSERT INTO owners (kind, handle, created_at) VALUES ('user', $1, $2)")
                .bind("alice")
                .bind(0_i64)
                .execute(t.db.pool())
        };
        insert().await.unwrap();
        let err = DbError::from(insert().await.unwrap_err());
        assert!(err.is_unique_violation());
    }

    #[tokio::test]
    async fn rejects_unknown_url_schemes() {
        let err = Db::connect("mysql://localhost/starforge")
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::UnsupportedUrl(_)));
    }

    /// `sqlite::memory:` must share one pool between writer and reader:
    /// sqlx names each in-memory database uniquely per connection, so a
    /// second pool would migrate and query a different, empty database.
    #[tokio::test]
    async fn in_memory_sqlite_shares_one_pool() {
        let db = Db::connect("sqlite::memory:").await.unwrap();
        db.migrate().await.unwrap();
        sqlx::query("INSERT INTO owners (kind, handle, created_at) VALUES ('user', 'alice', 0)")
            .execute(db.pool())
            .await
            .unwrap();
        let owner = crate::orgs::owner_by_handle(&db, "alice")
            .await
            .unwrap()
            .expect("row written through the writer is visible through read_pool");
        assert_eq!(owner.kind, "user");
    }
}
