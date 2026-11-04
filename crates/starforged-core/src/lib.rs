//! starforged-core: domain rules and the service layer (spec §5.1). The web UI and the API call `Core`;
//! nothing else reads or writes stored state.

pub mod account;
pub mod accounts;
pub mod admin;
pub mod audit;
pub mod content;
pub mod crypto;
pub mod email_tokens;
pub mod error;
pub mod invites;
pub mod jobs;
pub mod mail;
pub mod passwords;
pub mod permission;
pub mod registration;
pub mod repos;
pub mod sessions;
pub mod tokens;
pub mod validate;
pub mod verification;

use std::path::PathBuf;
use std::sync::Arc;

use starforged_db::Db;

pub use error::{CoreError, CoreResult};

#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Directory holding bare repositories (`<data_dir>/repos`).
    pub repos_dir: PathBuf,
    /// Scratch space on the same filesystem as `repos_dir` (`<data_dir>/tmp`); purged repositories pass
    /// through it.
    pub tmp_dir: PathBuf,
    /// Program that repository hooks execute (`starforged`); tests point it at the built binary.
    pub hook_exe: PathBuf,
    /// Public URL without a trailing slash; links in emails start with it.
    pub base_url: String,
    /// `None`: this instance sends no email.
    pub mailer: Option<mail::Mailer>,
    /// Who may sign up.
    pub registration: registration::Registration,
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
    use std::path::Path;

    use super::*;
    use crate::accounts::{CreateUser, User};
    use crate::mail::Mailer;

    pub(crate) struct Fixture {
        _db: starforged_db::testing::TestDb,
        dir: tempfile::TempDir,
    }

    impl Fixture {
        /// Messages sent through [`with_file_mail`] so far, oldest first. Run queued jobs first.
        pub(crate) fn mail(&self) -> Vec<String> {
            crate::mail::testing::read_mailbox(&self.dir.path().join("mail"))
        }
    }

    pub(crate) async fn test_core() -> (Core, Fixture) {
        test_core_with(|_, _| {}).await
    }

    /// Like [`test_core`], after `configure` adjusts the configuration. The path is the fixture's
    /// temporary directory.
    pub(crate) async fn test_core_with(
        configure: impl FnOnce(&mut CoreConfig, &Path),
    ) -> (Core, Fixture) {
        let db = starforged_db::testing::TestDb::new().await;
        let dir = tempfile::tempdir().unwrap();
        let mut config = CoreConfig {
            repos_dir: dir.path().join("repos"),
            tmp_dir: dir.path().join("tmp"),
            hook_exe: PathBuf::from("/bin/false"),
            base_url: "http://forge.test".into(),
            mailer: None,
            registration: registration::Registration::default(),
        };
        configure(&mut config, dir.path());
        (Core::new(db.db.clone(), config), Fixture { _db: db, dir })
    }

    /// Sends email as `.eml` files into `<dir>/mail`; read them with [`Fixture::mail`].
    pub(crate) fn with_file_mail(config: &mut CoreConfig, dir: &Path) {
        config.mailer = Mailer::from_config(
            &format!("file://{}", dir.join("mail").display()),
            "Starforge <forge@example.test>",
        )
        .unwrap();
    }

    pub(crate) async fn user(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            ..Default::default()
        })
        .await
        .unwrap()
    }
    /// Commits one file per branch in a scratch working copy (each branch starts from the previous one) and
    /// fetches every branch into repository `repo_id`'s bare directory. Fetching runs no hooks.
    pub(crate) fn seed_branches(core: &Core, repo_id: i64, branches: &[&str]) {
        let work = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let out = std::process::Command::new("git")
                .args(["-c", "user.name=T", "-c", "user.email=t@example.com"])
                .args(args)
                .current_dir(work.path())
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        git(&["init", "-q", "-b", branches[0], "."]);
        for (i, branch) in branches.iter().enumerate() {
            if i > 0 {
                git(&["checkout", "-q", "-b", branch]);
            }
            std::fs::write(
                work.path()
                    .join(format!("{}.txt", branch.replace('/', "-"))),
                branch,
            )
            .unwrap();
            git(&["add", "-A"]);
            git(&["commit", "-q", "-m", &format!("on {branch}")]);
        }
        let bare = core.repo_path(repo_id);
        git(&[
            "--git-dir",
            bare.to_str().unwrap(),
            "fetch",
            "-q",
            work.path().to_str().unwrap(),
            "refs/heads/*:refs/heads/*",
        ]);
    }
}
