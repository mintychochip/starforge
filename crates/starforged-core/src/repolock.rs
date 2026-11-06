//! Cross-process repository locks (plan M5b O1, decisions D2).
//!
//! Every code path that writes inside a repository directory holds
//! [`RepoLock::shared`] for its duration; `starforged backup` copies each
//! repository under [`RepoLock::exclusive`], which blocks repository
//! writers for that repository only. Readers (upload-pack, browsing) never
//! lock, and shared locks never block each other, so writers do not
//! serialize against each other beyond blocking a backup.
//!
//! The blob GC lock ([`BlobGcLock`]) pauses blob deletion during a backup:
//! the backup holds it shared from just before the database snapshot until
//! the blob copy ends, and the GC sweep holds it exclusive, so every blob
//! referenced by the snapshot is still present when it is copied.
//!
//! Locks are `flock`-style advisory locks via [`std::fs::File::lock`] on a
//! file inside the repository (`<repo>.git/starforge.lock`, created on
//! first use) resp. the blob directory (`<blob_dir>/.gc.lock`), and are
//! released on drop; a process crash releases them through the OS.
//! Acquisition blocks with a bounded timeout ([`LOCK_TIMEOUT`]) so a
//! wedged holder fails the operation instead of hanging a request forever.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{Core, CoreError, CoreResult};

/// How long a lock acquisition waits before giving up. Backup copies take
/// seconds per repository and pushes stream for longer than that, so the
/// bound is generous: a timeout means the holder is very likely wedged.
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(120);
/// Delay between non-blocking acquisition attempts.
const POLL: Duration = Duration::from_millis(10);
/// The lock file inside each repository directory (plan decision D2).
pub const REPO_LOCK_FILE: &str = "starforge.lock";
/// The blob-GC lock file inside the blob directory (plan decision D2).
pub const GC_LOCK_FILE: &str = ".gc.lock";

/// Which side of a lock an acquisition wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockMode {
    Shared,
    Exclusive,
}

impl LockMode {
    fn name(self) -> &'static str {
        match self {
            LockMode::Shared => "shared",
            LockMode::Exclusive => "exclusive",
        }
    }
}

#[derive(Debug)]
pub enum LockError {
    Io(std::io::Error),
    Timeout { path: PathBuf, mode: LockMode },
    WouldBlock { path: PathBuf, mode: LockMode },
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::Io(err) => write!(f, "repository lock IO error: {err}"),
            LockError::Timeout { path, mode } => write!(
                f,
                "timed out after {}s waiting for the {} lock on {}",
                LOCK_TIMEOUT.as_secs(),
                mode.name(),
                path.display()
            ),
            LockError::WouldBlock { path, mode } => write!(
                f,
                "the {} lock on {} is already held",
                mode.name(),
                path.display()
            ),
        }
    }
}

impl std::error::Error for LockError {}

/// A held lock. Dropping it releases the lock; the OS releases it on a
/// process crash too.
pub struct LockGuard {
    _file: File,
    path: PathBuf,
}

impl LockGuard {
    /// The lock file this guard holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for LockGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockGuard")
            .field("path", &self.path)
            .finish()
    }
}

/// Opens (creating on first use) the lock file and acquires `mode` on it,
/// blocking with a bounded timeout. `None` timeout means [`LOCK_TIMEOUT`].
fn acquire(
    path: &Path,
    mode: LockMode,
    timeout: Duration,
    blocking: bool,
) -> Result<LockGuard, LockError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(LockError::Io)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(LockError::Io)?;
    let deadline = Instant::now() + timeout;
    loop {
        let held = match mode {
            LockMode::Shared => file.try_lock_shared(),
            LockMode::Exclusive => file.try_lock(),
        };
        match held {
            Ok(()) => {
                return Ok(LockGuard {
                    _file: file,
                    path: path.to_path_buf(),
                });
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                if !blocking {
                    return Err(LockError::WouldBlock {
                        path: path.to_path_buf(),
                        mode,
                    });
                }
                let now = Instant::now();
                if now >= deadline {
                    return Err(LockError::Timeout {
                        path: path.to_path_buf(),
                        mode,
                    });
                }
                std::thread::sleep(POLL.min(deadline - now));
            }
            Err(std::fs::TryLockError::Error(err)) => return Err(LockError::Io(err)),
        }
    }
}

/// Non-mutating probe (doctor): `Ok(true)` when the lock is free — or the
/// lock file does not exist yet — without creating anything.
fn probe(path: &Path) -> Result<bool, LockError> {
    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(err) => return Err(LockError::Io(err)),
    };
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(err)) => Err(LockError::Io(err)),
    }
}

/// Runs a blocking lock acquisition on a blocking thread so async callers
/// never stall the runtime.
async fn acquire_async(
    path: PathBuf,
    mode: LockMode,
    timeout: Duration,
) -> Result<LockGuard, LockError> {
    tokio::task::spawn_blocking(move || acquire(&path, mode, timeout, true))
        .await
        .map_err(|err| LockError::Io(std::io::Error::other(format!("lock task failed: {err}"))))?
}

/// The per-repository lock (`<repo>.git/starforge.lock`, plan decision D2).
pub struct RepoLock;

impl RepoLock {
    /// The lock file for one repository directory.
    pub fn lock_path(repo_dir: &Path) -> PathBuf {
        repo_dir.join(REPO_LOCK_FILE)
    }

    /// Takes the shared lock: repository writers (receive-pack, merges,
    /// imports, mirror fetches, maintenance, trail ref writes) hold this
    /// for their whole write.
    pub fn shared(repo_dir: &Path) -> Result<LockGuard, LockError> {
        Self::shared_timeout(repo_dir, LOCK_TIMEOUT)
    }

    /// Takes the exclusive lock: backup (and repository purge) hold this
    /// while copying/respectively removing the repository directory.
    pub fn exclusive(repo_dir: &Path) -> Result<LockGuard, LockError> {
        Self::exclusive_timeout(repo_dir, LOCK_TIMEOUT)
    }

    pub fn shared_timeout(repo_dir: &Path, timeout: Duration) -> Result<LockGuard, LockError> {
        acquire(&Self::lock_path(repo_dir), LockMode::Shared, timeout, true)
    }

    pub fn exclusive_timeout(repo_dir: &Path, timeout: Duration) -> Result<LockGuard, LockError> {
        acquire(
            &Self::lock_path(repo_dir),
            LockMode::Exclusive,
            timeout,
            true,
        )
    }

    /// Non-blocking probes (doctor): `Err(LockError::WouldBlock)` when the
    /// lock is held by another process.
    pub fn try_shared(repo_dir: &Path) -> Result<LockGuard, LockError> {
        acquire(
            &Self::lock_path(repo_dir),
            LockMode::Shared,
            Duration::ZERO,
            false,
        )
    }

    pub fn try_exclusive(repo_dir: &Path) -> Result<LockGuard, LockError> {
        acquire(
            &Self::lock_path(repo_dir),
            LockMode::Exclusive,
            Duration::ZERO,
            false,
        )
    }

    /// Non-mutating probe: `Ok(true)` when no process holds the exclusive
    /// lock (a missing lock file counts as free). For doctor.
    pub fn probe_exclusive(repo_dir: &Path) -> Result<bool, LockError> {
        probe(&Self::lock_path(repo_dir))
    }

    pub async fn shared_async(repo_dir: &Path) -> Result<LockGuard, LockError> {
        acquire_async(Self::lock_path(repo_dir), LockMode::Shared, LOCK_TIMEOUT).await
    }

    pub async fn exclusive_async(repo_dir: &Path) -> Result<LockGuard, LockError> {
        acquire_async(Self::lock_path(repo_dir), LockMode::Exclusive, LOCK_TIMEOUT).await
    }
}

/// The blob-GC lock (`<blob_dir>/.gc.lock`, plan decision D2): backup holds
/// it shared, the blob GC sweep holds it exclusive.
pub struct BlobGcLock;

impl BlobGcLock {
    /// The lock file for one blob directory.
    pub fn lock_path(blob_dir: &Path) -> PathBuf {
        blob_dir.join(GC_LOCK_FILE)
    }

    /// Backup holds this shared from just before the database snapshot
    /// until the blob copy ends.
    pub fn shared(blob_dir: &Path) -> Result<LockGuard, LockError> {
        Self::shared_timeout(blob_dir, LOCK_TIMEOUT)
    }

    /// The blob GC sweep holds this exclusive, so a running backup pauses
    /// deletion until every referenced blob has been copied.
    pub fn exclusive(blob_dir: &Path) -> Result<LockGuard, LockError> {
        Self::exclusive_timeout(blob_dir, LOCK_TIMEOUT)
    }

    pub fn shared_timeout(blob_dir: &Path, timeout: Duration) -> Result<LockGuard, LockError> {
        acquire(&Self::lock_path(blob_dir), LockMode::Shared, timeout, true)
    }

    pub fn exclusive_timeout(blob_dir: &Path, timeout: Duration) -> Result<LockGuard, LockError> {
        acquire(
            &Self::lock_path(blob_dir),
            LockMode::Exclusive,
            timeout,
            true,
        )
    }

    pub fn try_shared(blob_dir: &Path) -> Result<LockGuard, LockError> {
        acquire(
            &Self::lock_path(blob_dir),
            LockMode::Shared,
            Duration::ZERO,
            false,
        )
    }

    pub fn try_exclusive(blob_dir: &Path) -> Result<LockGuard, LockError> {
        acquire(
            &Self::lock_path(blob_dir),
            LockMode::Exclusive,
            Duration::ZERO,
            false,
        )
    }

    /// Non-mutating probe: `Ok(true)` when no process holds the exclusive
    /// lock (a missing lock file counts as free). For doctor.
    pub fn probe_exclusive(blob_dir: &Path) -> Result<bool, LockError> {
        probe(&Self::lock_path(blob_dir))
    }

    pub async fn shared_async(blob_dir: &Path) -> Result<LockGuard, LockError> {
        acquire_async(Self::lock_path(blob_dir), LockMode::Shared, LOCK_TIMEOUT).await
    }

    pub async fn exclusive_async(blob_dir: &Path) -> Result<LockGuard, LockError> {
        acquire_async(Self::lock_path(blob_dir), LockMode::Exclusive, LOCK_TIMEOUT).await
    }
}

impl Core {
    /// The shared repository lock for async writers: hold the returned
    /// guard for the whole write so a concurrent backup either sees the
    /// pre-write or the post-write state, never a torn one.
    pub async fn repo_lock_shared(&self, repo_id: i64) -> CoreResult<LockGuard> {
        Ok(RepoLock::shared_async(&self.repo_path(repo_id)).await?)
    }

    /// The exclusive repository lock for async removers (purge).
    pub async fn repo_lock_exclusive(&self, repo_id: i64) -> CoreResult<LockGuard> {
        Ok(RepoLock::exclusive_async(&self.repo_path(repo_id)).await?)
    }
}

impl From<LockError> for CoreError {
    fn from(err: LockError) -> CoreError {
        CoreError::Internal(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    fn repo_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("repo.git")).unwrap();
        dir
    }

    #[test]
    fn shared_lock_blocks_exclusive_and_vice_versa() {
        let dir = repo_dir();
        let repo = dir.path().join("repo.git");

        // A held shared lock blocks an exclusive acquisition...
        let shared = RepoLock::shared(&repo).unwrap();
        let probe_repo = repo.clone();
        let (tx, rx) = mpsc::channel();
        let contender = std::thread::spawn(move || {
            let result = RepoLock::exclusive_timeout(&probe_repo, Duration::from_millis(200));
            tx.send(result.is_err()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
        contender.join().unwrap();
        drop(shared);

        // ...and once released, the exclusive lock lands.
        let exclusive = RepoLock::exclusive_timeout(&repo, Duration::from_secs(2)).unwrap();
        // While exclusive is held, a shared acquisition times out too.
        let probe_repo = repo.clone();
        let (tx, rx) = mpsc::channel();
        let contender = std::thread::spawn(move || {
            let result = RepoLock::shared_timeout(&probe_repo, Duration::from_millis(200));
            tx.send(result.is_err()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
        contender.join().unwrap();
        drop(exclusive);
    }

    #[test]
    fn shared_locks_coexist_and_drop_releases() {
        let dir = repo_dir();
        let repo = dir.path().join("repo.git");
        let first = RepoLock::shared(&repo).unwrap();
        let second = RepoLock::shared_timeout(&repo, Duration::from_secs(2)).unwrap();
        drop(first);
        drop(second);
        // After both drops the exclusive lock is free immediately.
        let _guard = RepoLock::exclusive_timeout(&repo, Duration::from_millis(200)).unwrap();
    }

    #[test]
    fn try_variants_report_would_block() {
        let dir = repo_dir();
        let repo = dir.path().join("repo.git");
        let _held = RepoLock::exclusive(&repo).unwrap();
        assert!(matches!(
            RepoLock::try_shared(&repo),
            Err(LockError::WouldBlock { .. })
        ));
        assert!(matches!(
            RepoLock::try_exclusive(&repo),
            Err(LockError::WouldBlock { .. })
        ));
    }

    #[test]
    fn probe_is_non_mutating_and_sees_held_locks() {
        let dir = repo_dir();
        let repo = dir.path().join("repo.git");
        // No lock file yet: free, and the probe must not create one.
        assert!(RepoLock::probe_exclusive(&repo).unwrap());
        assert!(!RepoLock::lock_path(&repo).exists());
        let _held = RepoLock::exclusive(&repo).unwrap();
        assert!(!RepoLock::probe_exclusive(&repo).unwrap());
        drop(_held);
        assert!(RepoLock::probe_exclusive(&repo).unwrap());
        let blobs = dir.path().join("blobs");
        assert!(BlobGcLock::probe_exclusive(&blobs).unwrap());
        assert!(!BlobGcLock::lock_path(&blobs).exists());
    }

    #[test]
    fn blob_gc_exclusive_blocks_backup_shared() {
        let dir = tempfile::tempdir().unwrap();
        let blobs = dir.path().join("blobs");
        let _gc = BlobGcLock::exclusive(&blobs).unwrap();
        let probe = blobs.clone();
        let (tx, rx) = mpsc::channel();
        let contender = std::thread::spawn(move || {
            let result = BlobGcLock::shared_timeout(&probe, Duration::from_millis(200));
            tx.send(result.is_err()).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_secs(5)).unwrap());
        contender.join().unwrap();
    }

    #[tokio::test]
    async fn async_wrappers_acquire() {
        let dir = repo_dir();
        let repo = dir.path().join("repo.git");
        let _guard = RepoLock::shared_async(&repo).await.unwrap();
        let blobs = dir.path().join("blobs");
        let _gc = BlobGcLock::exclusive_async(&blobs).await.unwrap();
    }
}
