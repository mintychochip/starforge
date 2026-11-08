//! `starforged backup <dir>`: a transactionally consistent snapshot of the
//! data directory (plan M5b O1, spec §12).
//!
//! Layout of the snapshot:
//!
//! - `manifest.json` — format version 1, starforged version, creation
//!   time, database engine, latest applied migration, repository and blob
//!   counts;
//! - `database/` — SQLite through `VACUUM INTO`, Postgres through
//!   `pg_dump` from `PATH` (decision D4);
//! - `repos/` — every repository, copied under its exclusive repository
//!   lock (one repository at a time), in the same sharded layout;
//! - `blobs/` — the whole blob store;
//! - `config/starforged.toml` — a copy of the running config (decision
//!   D3), unless `--no-config` was passed. It contains `secret_key`: the
//!   backup directory is created `0700` and the config file `0600`.
//!
//! The search index is skipped: it is rebuildable from the database.
//!
//! Consistency: the blob-GC lock is held shared from just before the
//! database snapshot until the blob copy ends, so the GC cannot delete a
//! blob the snapshot references; each repository is copied under its
//! exclusive lock, which blocks that repository's writers (they hold the
//! shared lock) for the copy without touching other repositories. A backup
//! taken during a push therefore contains the pre-push or the post-push
//! state of each repository, never a torn one.
//!
//! The target directory must be empty or absent.

use std::path::{Path, PathBuf};
use std::process::Command as ShellCommand;
use std::time::SystemTime;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use starforged_core::repolock::{BlobGcLock, RepoLock};
use starforged_db::{Backend, Db};

use crate::config::Config;

/// Manifest format version written by this backup.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;

#[derive(Deserialize, Serialize)]
struct Manifest {
    format_version: u32,
    starforged_version: String,
    created_at: i64,
    engine: String,
    latest_migration: Option<i64>,
    repositories: u64,
    blobs: u64,
}

/// Runs the backup into `target` and prints a one-line summary.
pub async fn run(config_path: &Path, target: &Path, include_config: bool) -> anyhow::Result<()> {
    let config =
        Config::load(config_path).with_context(|| format!("loading {}", config_path.display()))?;
    run_with_config(&config, Some(config_path), target, include_config).await
}

/// Shared backup implementation for the CLI and the scheduled-backup task.
/// `config_path` supplies the config-file bytes for the copy when present;
/// without it the copy is the serialized effective config.
pub async fn run_with_config(
    config: &Config,
    config_path: Option<&Path>,
    target: &Path,
    include_config: bool,
) -> anyhow::Result<()> {
    prepare_target(target)?;

    let db = Db::connect(&config.database_url())
        .await
        .context("connecting to the database")?;
    let engine = match db.backend() {
        Backend::Sqlite => "sqlite",
        Backend::Postgres => "postgres",
    };
    let latest_migration = db
        .latest_migration()
        .await
        .context("reading the latest applied migration")?;

    // The blob-GC lock is held shared from just before the database
    // snapshot until the blob copy ends (Global Constraints).
    let _blob_gc_lock = BlobGcLock::shared_async(&config.blob_dir())
        .await
        .context("taking the blob-GC lock")?;

    // Database snapshot (transactionally consistent on both engines).
    let database_dir = target.join("database");
    make_dir(&database_dir)?;
    match db.backend() {
        Backend::Sqlite => {
            db.vacuum_into_file(&database_dir.join("starforge.db"))
                .await
                .context("writing the SQLite snapshot (VACUUM INTO)")?;
        }
        Backend::Postgres => {
            pg_dump(&config.database.url, &database_dir.join("starforge.pgdump"))
                .context("writing the Postgres snapshot (pg_dump)")?;
        }
    }

    // Repositories, one exclusive lock at a time.
    let repos_dir = target.join("repos");
    make_dir(&repos_dir)?;
    let mut repositories = 0_u64;
    for repo in repository_dirs(&config.repos_dir())? {
        let _repo_lock = RepoLock::exclusive_async(&repo)
            .await
            .with_context(|| format!("locking repository {}", repo.display()))?;
        let rel = repo
            .strip_prefix(config.repos_dir())
            .expect("repository_dirs yields paths under repos_dir");
        copy_tree(&repo, &repos_dir.join(rel), Some("starforge.lock"))?;
        repositories += 1;
    }

    // Blobs.
    let blob_dir = config.blob_dir();
    make_dir(&target.join("blobs"))?;
    let blobs = if blob_dir.is_dir() {
        copy_tree(&blob_dir, &target.join("blobs"), Some(".gc.lock"))?
    } else {
        0
    };

    drop(_blob_gc_lock);

    // Config copy (contains `secret_key`; D3).
    if include_config {
        let config_dir = target.join("config");
        make_dir(&config_dir)?;
        let text = match config_path {
            Some(path) => {
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?
            }
            None => toml::to_string_pretty(config)
                .context("serializing the config for the backup copy")?
                .into_bytes(),
        };
        let dest = config_dir.join("starforged.toml");
        write_file(&dest, &text, 0o600)?;
    }

    let manifest = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        starforged_version: env!("CARGO_PKG_VERSION").to_owned(),
        created_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        engine: engine.to_owned(),
        latest_migration,
        repositories,
        blobs,
    };
    let json = serde_json::to_string_pretty(&manifest).context("serializing the manifest")?;
    let mut out = json.into_bytes();
    out.push(b'\n');
    write_file(&target.join("manifest.json"), &out, 0o600)?;

    println!(
        "backed up {repositories} repositories and {blobs} blobs to {} (engine {engine})",
        target.display()
    );
    Ok(())
}

/// Writes one scheduled backup into `<backup.dir>/starforge-backup-<UTC YYYYMMDD-HHMMSS>`,
/// rotates old backups, and returns the new backup directory. The call
/// includes the config copy, like `starforged backup`.
pub async fn run_scheduled(config: &Config, config_path: Option<&Path>) -> anyhow::Result<PathBuf> {
    let dir = &config.backup.dir;
    if !config.backup.enabled() {
        bail!("scheduled backups are disabled");
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    set_mode(dir, 0o700)?;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let target = scheduled_target(dir, secs);
    if let Err(err) = run_with_config(config, config_path, &target, true).await {
        if let Err(remove_err) = std::fs::remove_dir_all(&target) {
            tracing::error!(
                target = %target.display(),
                error = %remove_err,
                "removing partial scheduled backup"
            );
        }
        return Err(err);
    }
    rotate(dir, config.backup.keep)?;
    Ok(target)
}

/// Creates `dir` if absent and probes that it is writable, so the server
/// can refuse to start (instead of failing every scheduled backup later)
/// when the scheduled-backup directory is unusable.
pub fn validate_backup_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating backup directory {}", dir.display()))?;
    let probe = dir.join(".starforge-backup-write-probe");
    std::fs::write(&probe, b"")
        .with_context(|| format!("backup directory {} is not writable", dir.display()))?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// The `<dir>/starforge-backup-<UTC YYYYMMDD-HHMMSS>` path for `secs`. If
/// that name already exists, `-2`, `-3`, … disambiguate it so a second
/// backup within the same second never refuses a non-empty target.
pub fn scheduled_target(dir: &Path, secs: i64) -> PathBuf {
    let base = format!("starforge-backup-{}", utc_stamp(secs));
    let mut candidate = dir.join(&base);
    let mut n = 2_u64;
    while candidate.exists() {
        candidate = dir.join(format!("{base}-{n}"));
        n += 1;
    }
    candidate
}

/// UTC `YYYYMMDD-HHMMSS` for unix seconds `secs`.
pub fn utc_stamp(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let hour = sod / 3_600;
    let minute = (sod % 3_600) / 60;
    let second = sod % 60;
    // Civil date from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}{m:02}{d:02}-{hour:02}{minute:02}{second:02}")
}

/// Reads `<dir>/manifest.json` and checks its format version.
fn read_manifest(dir: &Path) -> anyhow::Result<Manifest> {
    let text = std::fs::read_to_string(dir.join("manifest.json"))
        .with_context(|| format!("reading {}", dir.join("manifest.json").display()))?;
    let manifest: Manifest = serde_json::from_str(&text).context("parsing the backup manifest")?;
    if manifest.format_version != MANIFEST_FORMAT_VERSION {
        bail!(
            "backup manifest format version {} is not supported",
            manifest.format_version
        );
    }
    Ok(manifest)
}

/// Keeps the newest `keep` scheduled backups in `dir` and removes the
/// older ones. Only entries that are real directories (not symlinks)
/// named `starforge-backup-*` and holding a valid manifest count;
/// everything else in `dir` (a manual `starforged backup <dir>/quarterly`,
/// symlinks, plain files) is never counted or deleted. The newest
/// backup always survives: `keep` is at least 1.
pub fn rotate(dir: &Path, keep: u64) -> anyhow::Result<()> {
    let keep = usize::try_from(keep.max(1)).unwrap_or(usize::MAX);
    let mut valid: Vec<(i64, PathBuf)> = Vec::new();
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        let is_scheduled_dir = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("starforge-backup-"))
            && std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_dir());
        if is_scheduled_dir && let Ok(manifest) = read_manifest(&path) {
            valid.push((manifest.created_at, path));
        }
    }
    // Newest first; the path breaks ties so the result is deterministic.
    valid.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    for (_, path) in valid.into_iter().skip(keep) {
        std::fs::remove_dir_all(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

/// Refuses a non-empty target; creates an absent one. Either way the
/// directory is `0700` (D3): the backup holds `secret_key`.
fn prepare_target(target: &Path) -> anyhow::Result<()> {
    if target.exists() {
        if !target.is_dir() {
            bail!("backup target {} is not a directory", target.display());
        }
        let mut entries =
            std::fs::read_dir(target).with_context(|| format!("reading {}", target.display()))?;
        if entries.next().is_some() {
            bail!(
                "backup directory {} is not empty; refusing to write into it",
                target.display()
            );
        }
        set_mode(target, 0o700)?;
    } else {
        std::fs::create_dir_all(target)
            .with_context(|| format!("creating {}", target.display()))?;
        set_mode(target, 0o700)?;
    }
    Ok(())
}

/// Every `<repos>/<shard>/<id>.git` directory, sorted for a stable order.
fn repository_dirs(repos_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut repos = Vec::new();
    if !repos_dir.is_dir() {
        return Ok(repos);
    }
    let mut shards: Vec<PathBuf> = std::fs::read_dir(repos_dir)
        .with_context(|| format!("reading {}", repos_dir.display()))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()
        .with_context(|| format!("reading {}", repos_dir.display()))?;
    shards.sort();
    for shard in shards {
        if !shard.is_dir() {
            continue;
        }
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&shard)
            .with_context(|| format!("reading {}", shard.display()))?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<_, _>>()
            .with_context(|| format!("reading {}", shard.display()))?;
        entries.sort();
        for entry in entries {
            if entry.is_dir() && entry.extension().is_some_and(|ext| ext == "git") {
                repos.push(entry);
            }
        }
    }
    Ok(repos)
}

/// Recursively copies `src` to `dest` (creating `dest`), skipping the
/// root-level `skip` entry when given. Returns the number of files copied.
/// File contents and permissions are preserved. Symlinks and other
/// non-regular entries are refused (matching restore's `check_tree`):
/// a backup never reports success unless restore will accept it.
pub(crate) fn copy_tree(src: &Path, dest: &Path, skip: Option<&str>) -> anyhow::Result<u64> {
    std::fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    let mut files = 0_u64;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(src)
        .with_context(|| format!("reading {}", src.display()))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()
        .with_context(|| format!("reading {}", src.display()))?;
    entries.sort();
    for entry in entries {
        if let Some(skip) = skip
            && entry.parent() == Some(src)
            && entry.file_name().is_some_and(|name| name == skip)
        {
            continue;
        }
        let dest_entry = dest.join(entry.file_name().expect("entries have names"));
        let meta = std::fs::symlink_metadata(&entry)
            .with_context(|| format!("reading {}", entry.display()))?;
        if meta.file_type().is_symlink() {
            bail!(
                "refusing to back up {}: symlinks are not restorable; remove it and retry",
                entry.display()
            );
        } else if meta.is_dir() {
            files += copy_tree(&entry, &dest_entry, None)?;
        } else if meta.is_file() {
            std::fs::copy(&entry, &dest_entry)
                .with_context(|| format!("copying {}", entry.display()))?;
            files += 1;
        } else {
            bail!(
                "refusing to back up {}: not a regular file or directory; remove it and retry",
                entry.display()
            );
        }
    }
    Ok(files)
}

fn make_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    set_mode(path, 0o700)
}

pub(crate) fn write_file(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    set_mode(path, mode)
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting permissions on {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn set_mode(path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

/// `pg_dump --format=custom --no-owner --file <dest> <url>` (decision D4):
/// the password travels through `PGPASSWORD` in the child environment,
/// never argv, and a missing `pg_dump` fails naming the requirement.
fn pg_dump(url: &str, dest: &Path) -> anyhow::Result<()> {
    let (dump_url, password) = split_pg_password(url);
    let mut command = ShellCommand::new("pg_dump");
    command
        .arg("--format=custom")
        .arg("--no-owner")
        .arg("--file")
        .arg(dest)
        .arg(&dump_url);
    if let Some(password) = &password {
        command.env("PGPASSWORD", password);
    }
    match command.status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => bail!("pg_dump exited with {status}"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => bail!(
            "pg_dump is required for Postgres backups but was not found in PATH; \
             install the PostgreSQL client tools (postgresql-client) and retry"
        ),
        Err(err) => Err(err).context("running pg_dump"),
    }
}

/// Splits `postgres://user:password@host/db` into a password-less URL and
/// the password, so the password never appears in argv.
pub(crate) fn split_pg_password(url: &str) -> (String, Option<String>) {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            let password = parsed.password().map(percent_decode);
            if password.is_some() {
                let _ = parsed.set_password(None);
            }
            (parsed.to_string(), password)
        }
        Err(_) => (url.to_owned(), None),
    }
}

/// Decodes `%XX` escapes in a URL password (`Url::password()` is still
/// percent-encoded). Malformed escapes pass through unchanged.
fn percent_decode(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_value(bytes[i + 1]), hex_value(bytes[i + 2]))
        {
            out.push(hi * 16 + lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_split_decodes_escapes_and_strips_argv() {
        let (url, password) =
            split_pg_password("postgres://user:p%40ss%25word@127.0.0.1:55439/sf_test");
        assert_eq!(password.as_deref(), Some("p@ss%word"));
        assert!(
            !url.contains("p%40ss"),
            "the password must not reach argv: {url}"
        );
        assert_eq!(url, "postgres://user@127.0.0.1:55439/sf_test");
    }

    #[test]
    fn password_split_without_password_is_unchanged() {
        let (url, password) = split_pg_password("postgres://user@127.0.0.1:5432/db");
        assert_eq!(url, "postgres://user@127.0.0.1:5432/db");
        assert_eq!(password, None);
    }
}
