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

pub mod users;

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
}

pub type DbResult<T> = Result<T, DbError>;

#[derive(Debug, Clone)]
pub struct Db {
    pool: AnyPool,
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
            // One connection: SQLite serializes writes anyway, and a single connection avoids SQLITE_BUSY.
            // The reader-pool split from spec §12 lands in M5.
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
        Ok(Db { pool, backend })
    }

    pub async fn migrate(&self) -> DbResult<()> {
        match self.backend {
            Backend::Sqlite => SQLITE_MIGRATIONS.run(&self.pool).await?,
            Backend::Postgres => POSTGRES_MIGRATIONS.run(&self.pool).await?,
        }
        Ok(())
    }

    pub fn pool(&self) -> &AnyPool {
        &self.pool
    }

    pub fn backend(&self) -> Backend {
        self.backend
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
}
