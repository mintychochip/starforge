//! starforged-core: domain rules and the service layer (spec §5.1). The web UI and the API call `Core`;
//! nothing else reads or writes stored state.

pub mod accounts;
pub mod audit;
pub mod content;
pub mod crypto;
pub mod error;
pub mod jobs;
pub mod permission;
pub mod repos;
pub mod sessions;
pub mod tokens;
pub mod validate;

use std::path::PathBuf;
use std::sync::Arc;

use starforged_db::Db;

pub use error::{CoreError, CoreResult};

#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Directory holding bare repositories (`<data_dir>/repos`).
    pub repos_dir: PathBuf,
    /// Program that repository hooks execute (`starforged`); tests point it at the built binary.
    pub hook_exe: PathBuf,
}

/// The service layer. Cheap to clone; share one per process.
#[derive(Debug, Clone)]
pub struct Core {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    db: Db,
    config: CoreConfig,
    /// Wakes one idle job worker when a job is queued.
    job_wakeup: tokio::sync::Notify,
}

impl Core {
    pub fn new(db: Db, config: CoreConfig) -> Core {
        Core {
            inner: Arc::new(Inner {
                db,
                config,
                job_wakeup: tokio::sync::Notify::new(),
            }),
        }
    }

    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    pub fn config(&self) -> &CoreConfig {
        &self.inner.config
    }
}

impl Core {
    /// `<repos_dir>/<id % 100, two digits>/<id>.git` (spec §5.3). Renames never move directories.
    pub fn repo_path(&self, repo_id: i64) -> PathBuf {
        self.inner
            .config
            .repos_dir
            .join(format!("{:02}", repo_id.rem_euclid(100)))
            .join(format!("{repo_id}.git"))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::accounts::{CreateUser, User};

    pub(crate) struct Fixture {
        _db: starforged_db::testing::TestDb,
        _dir: tempfile::TempDir,
    }

    pub(crate) async fn test_core() -> (Core, Fixture) {
        let db = starforged_db::testing::TestDb::new().await;
        let dir = tempfile::tempdir().unwrap();
        let config = CoreConfig {
            repos_dir: dir.path().join("repos"),
            hook_exe: PathBuf::from("/bin/false"),
        };
        (
            Core::new(db.db.clone(), config),
            Fixture { _db: db, _dir: dir },
        )
    }

    pub(crate) async fn user(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            ..Default::default()
        })
        .await
        .unwrap()
    }
}
