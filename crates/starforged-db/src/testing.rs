//! Throwaway databases for tests. With `STARFORGE_TEST_PG_URL` set (a Postgres URL allowed to
//! `CREATE DATABASE`), every `TestDb` is a fresh Postgres database; otherwise a SQLite file in a temp dir.

use crate::Db;

pub struct TestDb {
    pub db: Db,
    pub url: String,
    _dir: Option<tempfile::TempDir>,
}

impl TestDb {
    pub async fn new() -> TestDb {
        let (url, dir) = match std::env::var("STARFORGE_TEST_PG_URL") {
            Ok(admin_url) => (create_pg_database(&admin_url).await, None),
            Err(_) => {
                let dir = tempfile::tempdir().expect("create temp dir");
                (
                    format!("sqlite://{}?mode=rwc", dir.path().join("test.db").display()),
                    Some(dir),
                )
            }
        };
        let db = Db::connect(&url).await.expect("connect to test database");
        db.migrate().await.expect("migrate test database");
        TestDb { db, url, _dir: dir }
    }
}

async fn create_pg_database(admin_url: &str) -> String {
    let mut bytes = [0_u8; 6];
    getrandom::fill(&mut bytes).expect("OS randomness");
    let name = format!("sf_test_{}", hex::encode(bytes));
    let admin = Db::connect(admin_url)
        .await
        .expect("connect with STARFORGE_TEST_PG_URL");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(admin.pool())
        .await
        .expect("create test database");
    admin.pool().close().await;
    let mut url = url::Url::parse(admin_url).expect("STARFORGE_TEST_PG_URL is a URL");
    url.set_path(&format!("/{name}"));
    url.to_string()
}
