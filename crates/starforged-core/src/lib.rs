//! starforged-core: domain rules and the service layer (spec §5.1). The web UI and the API call `Core`;
//! nothing else reads or writes stored state.

pub mod account;
pub mod accounts;
pub mod admin;
pub mod audit;
pub mod blame;
pub mod changes;
pub mod checks;
pub mod content;
pub mod crypto;
pub mod email_tokens;
pub mod error;
pub mod gate_rules;
pub mod gates;
pub mod ingest;
pub mod invites;
pub mod jobs;
pub mod mail;
pub mod merge;
pub mod oauth;
pub mod passwords;
pub mod permission;
pub mod quota;
pub mod read;
pub mod registration;
pub mod repos;
pub mod rescan;
pub mod sessions;
pub mod tokens;
pub mod trails;
pub mod validate;
pub mod verification;
pub mod webhooks;

use std::path::PathBuf;
use std::sync::Arc;

use starforged_db::Db;

pub use error::{CoreError, CoreResult};

/// Default cap for one uploaded session segment body (spec §6.3).
pub const DEFAULT_MAX_SEGMENT_BYTES: u64 = 16 * 1024 * 1024;
/// Default cap for total segment bytes stored for one repository (spec §7.7).
pub const DEFAULT_MAX_REPO_BYTES: u64 = 20 * 1024 * 1024 * 1024;
/// Default cap for total segment bytes stored for one uploader (spec §7.7).
pub const DEFAULT_MAX_USER_BYTES: u64 = 5 * 1024 * 1024 * 1024;
/// Default cap for segment bytes one uploader may add per rolling hour (spec §7.7).
pub const DEFAULT_MAX_HOURLY_BYTES: u64 = 500 * 1024 * 1024;
/// Default cap for one segment's decompressed event JSONL (spec §6.3): 256 MiB
/// bounds the in-memory expansion of any accepted segment body.
pub const DEFAULT_MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
#[derive(Debug, Clone)]
pub struct CoreConfig {
    /// Directory holding bare repositories (`<data_dir>/repos`).
    pub repos_dir: PathBuf,
    /// Scratch space on the same filesystem as `repos_dir` (`<data_dir>/tmp`); purged repositories pass
    /// through it.
    pub tmp_dir: PathBuf,
    /// Content-addressed blob root (`<blob_dir>/<hash[0..2]>/<hash>`, spec §5.3).
    pub blob_dir: PathBuf,
    /// Rejects segment bodies larger than this (spec §6.3).
    pub max_segment_bytes: u64,
    /// Rejects segment uploads past this per-repository stored total (spec §7.7).
    pub max_repo_bytes: u64,
    /// Rejects segment uploads past this per-uploader stored total (spec §7.7).
    pub max_user_bytes: u64,
    /// Rejects segment uploads past this per-uploader rolling-hour volume (spec §7.7).
    pub max_hourly_bytes: u64,
    /// Rejects segment bodies whose decompressed event JSONL exceeds this (spec §6.3):
    /// the server never materializes more than `limit + 1` bytes per segment.
    pub max_decompressed_bytes: u64,
    /// Operator redact rules (`.starforge/redact.toml` grammar, `None` = unset)
    /// merged last over built-ins and repo rules, so the operator always wins.
    pub site_redact_rules: Option<String>,
    /// Content-addressed store behind segment/raw bytes; `FsBlobStore` on `blob_dir` in production.
    pub blob_store: std::sync::Arc<dyn starforged_blob::BlobStore>,
    /// Program that repository hooks execute (`starforged`); tests point it at the built binary.
    pub hook_exe: PathBuf,
    /// Public URL without a trailing slash; links in emails start with it.
    pub base_url: String,
    /// `None`: this instance sends no email.
    pub mailer: Option<mail::Mailer>,
    /// Who may sign up.
    pub registration: registration::Registration,
    /// Key sealing webhook secrets at rest (from `security.secret_key`).
    /// `Debug` is redacted like `SecurityConfig::secret_key`: the bytes
    /// never render, in any format.
    pub webhook_key: WebhookKey,
    /// Test-only escape hatch for the webhook SSRF gate: when true, delivery
    /// may target loopback addresses (the integration suite's in-process
    /// receiver). Always false in production; everything else non-global is
    /// denied regardless.
    pub allow_loopback_webhooks: bool,
}

/// The 32-byte key sealing webhook secrets at rest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WebhookKey(pub [u8; 32]);

impl std::fmt::Debug for WebhookKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebhookKey(<redacted>)")
    }
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
    /// Test seam for the merge CAS race (see [`merge::PreCasHook`]): `None`
    /// in production. Integration tests set it to move the base ref between
    /// gate evaluation and the compare-and-swap.
    merge_cas_hook: std::sync::Mutex<Option<merge::PreCasHook>>,
}

impl Core {
    pub fn new(db: Db, config: CoreConfig) -> Core {
        Core {
            inner: Arc::new(Inner {
                db,
                config,
                job_wakeup: tokio::sync::Notify::new(),
                merge_cas_hook: std::sync::Mutex::new(None),
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
        let blob_dir = dir.path().join("blobs");
        let mut config = CoreConfig {
            repos_dir: dir.path().join("repos"),
            tmp_dir: dir.path().join("tmp"),
            blob_store: std::sync::Arc::new(starforged_blob::FsBlobStore::new(blob_dir.clone())),
            blob_dir,
            max_segment_bytes: DEFAULT_MAX_SEGMENT_BYTES,
            max_repo_bytes: DEFAULT_MAX_REPO_BYTES,
            max_user_bytes: DEFAULT_MAX_USER_BYTES,
            max_hourly_bytes: DEFAULT_MAX_HOURLY_BYTES,
            max_decompressed_bytes: DEFAULT_MAX_DECOMPRESSED_BYTES,
            site_redact_rules: None,
            hook_exe: PathBuf::from("/bin/false"),
            base_url: "http://forge.test".into(),
            mailer: None,
            registration: registration::Registration::default(),
            webhook_key: WebhookKey([7u8; 32]),
            allow_loopback_webhooks: false,
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
