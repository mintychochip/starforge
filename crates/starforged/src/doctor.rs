//! `starforged doctor`: offline health checks for a data directory (plan
//! M5b, spec §12).
//!
//! Prints one line per check (`[OK]`, `[WARN]`, or `[FAIL]`), then exits
//! with the fail count mapped onto exit codes:
//!
//! - `0` when every check passes,
//! - `1` when any check fails,
//! - `2` when only warnings occur.
//!
//! The checks are, in order:
//!
//! 1. `git version` — the `git` binary is present and at least 2.38.
//! 2. `ssh client` — `ssh` is present when any remote in the database uses
//!    an SSH URL.
//! 3. `pg_dump` — present when Postgres is configured (WARN when missing).
//! 4. `data directory permissions` — no world-writable directory under the
//!    data directory, and the `secret_key`-bearing config is `0600`
//!    (WARN otherwise).
//! 5. `repository hooks` — every live repository directory exists and
//!    carries the expected hooks.
//! 6. `stray repository directories` — no `repos/<shard>/<id>.git`
//!    directory without a database row (WARN).
//! 7. `orphan blobs` — no blob file without a database row (WARN), and no
//!    zero-ref blob row older than the GC window (WARN).
//! 8. `search index` — the index opens and its document counts are within
//!    1% of the database counts (WARN, suggesting `index rebuild`).
//! 9. `migrations` — the applied schema is at the latest known version.
//!
//! `--fix` repairs only two things, both filesystem-side: it reinstalls
//! missing or wrong repository hooks, and it removes orphaned blob files
//! older than one hour. It never deletes database rows. When a fix fully
//! repairs a check, that check reports `[OK]` in the same run.
//!
//! Doctor runs offline: when a server holds the search-index writer, the
//! index check reports `[OK]` with a note that verification was skipped
//! rather than counting a throwaway index against the database.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command as ShellCommand;

use anyhow::Context;
use starforged_db::Db;
use starforged_db::doctor as db_doctor;
use starforged_db::repos as db_repos;
use starforged_db::repos::RepoRow;
use starforged_db::sessions as db_sessions;

use crate::admin::open_core;
use crate::config::Config;

/// Minimum supported `git` version (spec §12).
const MIN_GIT_VERSION: (u64, u64) = (2, 38);
/// Zero-ref blob rows older than this are reported (the GC sweep in the
/// jobs worker deletes zero-ref rows immediately today; the window is the
/// grace period doctor tolerates before a row reads as stale). O1 will
/// land the blob-GC lock; until then this window is doctor's own policy.
pub const BLOB_GC_WINDOW_SECS: i64 = 24 * 60 * 60;
/// `--fix` only removes orphaned blob files older than this, so a file
/// that a concurrent ingest just wrote is never deleted mid-write.
const ORPHAN_FIX_MIN_AGE_SECS: i64 = 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    fn tag(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

#[derive(Default)]
struct Report {
    statuses: Vec<Status>,
}
impl Report {
    /// Prints one line for the check and records its status.
    fn line(&mut self, status: Status, name: &str, detail: &str) {
        println!("[{}] {name}: {detail}", status.tag());
        self.statuses.push(status);
    }

    fn exit_code(&self) -> i32 {
        if self.statuses.contains(&Status::Fail) {
            1
        } else if self.statuses.contains(&Status::Warn) {
            2
        } else {
            0
        }
    }
}

/// Runs every check against the config at `config_path` and returns the
/// process exit code (`0` healthy, `1` any FAIL, `2` only WARNs).
pub async fn run(config_path: &Path, fix: bool) -> anyhow::Result<i32> {
    let config =
        Config::load(config_path).with_context(|| format!("loading {}", config_path.display()))?;
    let hook_exe = std::env::current_exe().context("locating the starforged executable")?;
    let mut report = Report::default();

    check_git_version(&mut report);
    check_pg_dump(&mut report, &config);

    // The database connection feeds checks 2 and 5-9. A failed connect
    // fails those checks with the cause instead of aborting the run, so
    // the filesystem checks above and below still report.
    let db = Db::connect(&config.database_url()).await.ok();
    let db_error = match &db {
        Some(_) => None,
        None => Some("cannot connect to the configured database".to_owned()),
    };

    check_ssh_client(&mut report, db.as_ref(), db_error.as_deref()).await;
    check_permissions(&mut report, &config, config_path);
    check_repo_hooks(
        &mut report,
        &config,
        db.as_ref(),
        &hook_exe,
        fix,
        db_error.as_deref(),
    )
    .await;
    check_stray_repos(&mut report, &config, db.as_ref(), db_error.as_deref()).await;
    check_orphan_blobs(&mut report, &config, db.as_ref(), fix, db_error.as_deref()).await;
    check_search_index(&mut report, &config, db.as_ref(), db_error.as_deref()).await;
    check_migrations(&mut report, db.as_ref(), db_error.as_deref()).await;

    Ok(report.exit_code())
}

/// `git --version` output is `git version 2.43.0`; parse the numeric core.
fn parse_git_version(output: &str) -> Option<(u64, u64)> {
    let version = output.split_whitespace().nth(2)?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn check_git_version(report: &mut Report) {
    let output = ShellCommand::new("git").arg("--version").output();
    match output {
        Err(_) => report.line(
            Status::Fail,
            "git version",
            "git was not found in PATH; git 2.38 or newer is required",
        ),
        Ok(output) if !output.status.success() => report.line(
            Status::Fail,
            "git version",
            "git --version failed; git 2.38 or newer is required",
        ),
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout);
            match parse_git_version(&text) {
                Some(found) if found >= MIN_GIT_VERSION => {
                    report.line(Status::Ok, "git version", text.trim())
                }
                Some(found) => report.line(
                    Status::Fail,
                    "git version",
                    &format!(
                        "git {}.{} is older than the required {}.{}",
                        found.0, found.1, MIN_GIT_VERSION.0, MIN_GIT_VERSION.1
                    ),
                ),
                None => report.line(
                    Status::Fail,
                    "git version",
                    &format!("could not parse `git --version` output: {}", text.trim()),
                ),
            }
        }
    }
}

/// Whether `url` needs the `ssh` client: an `ssh://` URL or scp-like
/// `user@host:path` syntax (the same shapes the remote policy accepts).
fn is_ssh_url(url: &str) -> bool {
    if url.starts_with("ssh://") {
        return true;
    }
    if url.contains("://") {
        return false;
    }
    let Some((before_colon, _)) = url.split_once(':') else {
        return false;
    };
    before_colon.contains('@') && !before_colon.contains('/')
}

async fn any_ssh_remote(db: &Db) -> anyhow::Result<bool> {
    let urls = db_doctor::remote_urls(db).await?;
    Ok(urls.iter().any(|url| is_ssh_url(url)))
}

async fn check_ssh_client(report: &mut Report, db: Option<&Db>, db_error: Option<&str>) {
    let Some(db) = db else {
        report.line(
            Status::Fail,
            "ssh client",
            db_error.unwrap_or("database unavailable"),
        );
        return;
    };
    let needs_ssh = match any_ssh_remote(db).await {
        Ok(found) => found,
        Err(err) => {
            report.line(
                Status::Fail,
                "ssh client",
                &format!("could not read remotes from the database: {err}"),
            );
            return;
        }
    };
    if !needs_ssh {
        report.line(Status::Ok, "ssh client", "no SSH remotes configured");
        return;
    }
    let ok = ShellCommand::new("ssh")
        .arg("-V")
        .output()
        .is_ok_and(|output| output.status.success());
    if ok {
        report.line(Status::Ok, "ssh client", "ssh is in PATH");
    } else {
        report.line(
            Status::Fail,
            "ssh client",
            "SSH remotes exist but `ssh` was not found in PATH",
        );
    }
}

fn check_pg_dump(report: &mut Report, config: &Config) {
    let postgres = config.database.url.starts_with("postgres:")
        || config.database.url.starts_with("postgresql:");
    if !postgres {
        report.line(Status::Ok, "pg_dump", "not needed (SQLite)");
        return;
    }
    let ok = ShellCommand::new("pg_dump")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if ok {
        report.line(Status::Ok, "pg_dump", "pg_dump is in PATH");
    } else {
        report.line(
            Status::Warn,
            "pg_dump",
            "Postgres is configured but `pg_dump` was not found in PATH; backups need it",
        );
    }
}

/// Every directory under the data directory must not be world-writable,
/// and the config file (which bears `secret_key`) must be `0600`.
fn check_permissions(report: &mut Report, config: &Config, config_path: &Path) {
    let mut findings = Vec::new();
    let data_dir = &config.storage.data_dir;
    let mut stack = vec![data_dir.clone()];
    while let Some(dir) = stack.pop() {
        match std::fs::metadata(&dir) {
            Ok(meta) if meta.is_dir() => {}
            _ => continue,
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir)
                .map(|meta| meta.permissions().mode() & 0o777)
                .unwrap_or(0);
            if mode & 0o002 != 0 {
                findings.push(format!("{} is world-writable", dir.display()));
            }
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && !path.is_symlink() {
                    stack.push(path);
                }
            }
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(config_path)
            .map(|meta| meta.permissions().mode() & 0o777)
            .unwrap_or(0);
        if mode != 0o600 {
            findings.push(format!(
                "{} is {mode:04o}, expected 0600",
                config_path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = config_path;
    if findings.is_empty() {
        report.line(
            Status::Ok,
            "data directory permissions",
            "no world-writable directories; config is 0600",
        );
    } else {
        report.line(
            Status::Warn,
            "data directory permissions",
            &findings.join("; "),
        );
    }
}

/// `repos/<id % 100, two digits>/<id>.git` (spec §5.3), mirroring
/// `Core::repo_path`.
fn repo_path(config: &Config, repo_id: i64) -> PathBuf {
    config
        .repos_dir()
        .join(format!("{:02}", repo_id.rem_euclid(100)))
        .join(format!("{repo_id}.git"))
}

async fn live_repos(db: &Db) -> anyhow::Result<Vec<RepoRow>> {
    Ok(db_repos::list_all_live(db, i64::MAX).await?)
}

async fn check_repo_hooks(
    report: &mut Report,
    config: &Config,
    db: Option<&Db>,
    hook_exe: &Path,
    fix: bool,
    db_error: Option<&str>,
) {
    let Some(db) = db else {
        report.line(
            Status::Fail,
            "repository hooks",
            db_error.unwrap_or("database unavailable"),
        );
        return;
    };
    let repos = match live_repos(db).await {
        Ok(repos) => repos,
        Err(err) => {
            report.line(
                Status::Fail,
                "repository hooks",
                &format!("could not list repositories: {err}"),
            );
            return;
        }
    };
    let mut findings = Vec::new();
    let mut repaired = Vec::new();
    for repo in &repos {
        let dir = repo_path(config, repo.id);
        if !dir.is_dir() {
            findings.push(format!("repo {} is missing its directory", repo.id));
            continue;
        }
        for name in starforged_git::init::HOOKS {
            let hook = dir.join("hooks").join(name);
            let good = std::fs::read_to_string(&hook)
                .is_ok_and(|content| starforged_git::init::is_expected_hook(&content, name))
                && is_executable(&hook);
            if good {
                continue;
            }
            if fix {
                match starforged_git::init::install_hooks(&dir, hook_exe).await {
                    Ok(()) => repaired.push(format!("repo {}", repo.id)),
                    Err(err) => findings.push(format!(
                        "repo {} (could not reinstall hooks: {err})",
                        repo.id
                    )),
                }
            } else {
                findings.push(format!("repo {} is missing hooks/{name}", repo.id));
            }
        }
    }
    if findings.is_empty() {
        if repaired.is_empty() {
            report.line(
                Status::Ok,
                "repository hooks",
                &format!("{} repositories carry the expected hooks", repos.len()),
            );
        } else {
            report.line(
                Status::Ok,
                "repository hooks",
                &format!("reinstalled hooks for {}", dedup(repaired).join(", ")),
            );
        }
    } else {
        report.line(Status::Fail, "repository hooks", &findings.join("; "));
    }
}

fn dedup(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items.dedup();
    items
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Every `repos/<shard>/<id>.git` directory must have a database row (any
/// row, including soft-deleted ones: a deleted row's directory should have
/// been purged, but it is not a stray the same way an unknown id is).
async fn check_stray_repos(
    report: &mut Report,
    config: &Config,
    db: Option<&Db>,
    db_error: Option<&str>,
) {
    let Some(db) = db else {
        report.line(
            Status::Fail,
            "stray repository directories",
            db_error.unwrap_or("database unavailable"),
        );
        return;
    };
    let known: HashSet<i64> = match db_doctor::repo_ids(db).await {
        Ok(ids) => ids.into_iter().collect(),
        Err(err) => {
            report.line(
                Status::Fail,
                "stray repository directories",
                &format!("could not list repository ids: {err}"),
            );
            return;
        }
    };
    let mut strays = Vec::new();
    let repos_dir = config.repos_dir();
    if let Ok(shards) = std::fs::read_dir(&repos_dir) {
        for shard in shards.flatten() {
            let shard_path = shard.path();
            if !shard_path.is_dir() {
                continue;
            }
            let shard_name = shard.file_name();
            let shard_name = shard_name.to_string_lossy();
            let shard_ok = shard_name.len() == 2 && shard_name.bytes().all(|b| b.is_ascii_digit());
            if !shard_ok {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(&shard_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() {
                        continue;
                    }
                    let Some(stem) = path
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .filter(|_| path.extension().is_some_and(|ext| ext == "git"))
                    else {
                        continue;
                    };
                    let Ok(id) = stem.parse::<i64>() else {
                        continue;
                    };
                    if !known.contains(&id) {
                        strays.push(path.display().to_string());
                    }
                }
            }
        }
    }
    if strays.is_empty() {
        report.line(
            Status::Ok,
            "stray repository directories",
            "every repository directory has a database row",
        );
    } else {
        report.line(
            Status::Warn,
            "stray repository directories",
            &format!(
                "{} director{} without a database row: {}",
                strays.len(),
                if strays.len() == 1 { "y" } else { "ies" },
                strays.join(", ")
            ),
        );
    }
}

/// Blob files are `<blob_dir>/<hash[0..2]>/<hash>` (spec §5.3): a file
/// whose hash has no row is orphaned; a zero-ref row older than
/// [`BLOB_GC_WINDOW_SECS`] is stale. Both are WARNs. `--fix` removes
/// orphaned files older than one hour and never touches rows.
async fn check_orphan_blobs(
    report: &mut Report,
    config: &Config,
    db: Option<&Db>,
    fix: bool,
    db_error: Option<&str>,
) {
    let Some(db) = db else {
        report.line(
            Status::Fail,
            "orphan blobs",
            db_error.unwrap_or("database unavailable"),
        );
        return;
    };
    let known: HashSet<String> = match db_doctor::blob_hashes(db).await {
        Ok(hashes) => hashes.into_iter().collect(),
        Err(err) => {
            report.line(
                Status::Fail,
                "orphan blobs",
                &format!("could not list blob hashes: {err}"),
            );
            return;
        }
    };
    let blob_dir = config.blob_dir();
    let mut orphans: Vec<PathBuf> = Vec::new();
    if let Ok(shards) = std::fs::read_dir(&blob_dir) {
        for shard in shards.flatten() {
            let shard_path = shard.path();
            if !shard_path.is_dir() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(&shard_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_file() {
                        continue;
                    }
                    let hash = path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or_default();
                    if !known.contains(hash) {
                        orphans.push(path);
                    }
                }
            }
        }
    }
    let cutoff = starforged_db::now() - BLOB_GC_WINDOW_SECS;
    let stale_rows: i64 = db_doctor::stale_zero_ref_blobs(db, cutoff)
        .await
        .unwrap_or(0);

    let mut removed = 0_usize;
    let mut remaining: Vec<&PathBuf> = Vec::new();
    for orphan in &orphans {
        // Age is how long ago the file was modified; `--fix` only
        // removes orphans at least ORPHAN_FIX_MIN_AGE_SECS old, so a
        // file a concurrent ingest just wrote survives.
        let old_enough = std::fs::metadata(orphan)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .is_some_and(|modified_at| {
                starforged_db::now() - i64::try_from(modified_at.as_secs()).unwrap_or(0)
                    >= ORPHAN_FIX_MIN_AGE_SECS
            });
        if fix && old_enough && std::fs::remove_file(orphan).is_ok() {
            removed += 1;
            continue;
        }
        remaining.push(orphan);
    }

    let total = remaining.len() + stale_rows.max(0) as usize;
    if total == 0 && removed == 0 {
        report.line(
            Status::Ok,
            "orphan blobs",
            "no orphaned blob files or stale zero-ref rows",
        );
    } else if total == 0 {
        report.line(
            Status::Ok,
            "orphan blobs",
            &format!("removed {removed} orphaned blob file(s)"),
        );
    } else {
        let mut detail = Vec::new();
        if !remaining.is_empty() {
            detail.push(format!("{} orphaned blob file(s)", remaining.len()));
        }
        if stale_rows > 0 {
            detail.push(format!(
                "{stale_rows} zero-ref blob row(s) older than {}h",
                BLOB_GC_WINDOW_SECS / 3600
            ));
        }
        if removed > 0 {
            detail.push(format!("removed {removed} orphaned blob file(s)"));
        }
        report.line(Status::Warn, "orphan blobs", &detail.join("; "));
    }
}

/// The search index opens and its document counts are within 1% of the
/// database counts. Expected event documents are counted with the same
/// row-to-document translation a rebuild uses, so a mismatch means the
/// index is stale and `index rebuild` is the fix (WARN either way when
/// it cannot be verified).
async fn check_search_index(
    report: &mut Report,
    config: &Config,
    db: Option<&Db>,
    db_error: Option<&str>,
) {
    let Some(_db) = db else {
        report.line(
            Status::Fail,
            "search index",
            db_error.unwrap_or("database unavailable"),
        );
        return;
    };
    let index_dir = config.index_dir();
    let probe = match starforged_index::SearchIndex::open_or_create_fresh(&index_dir) {
        Ok((index, fresh)) => (index, fresh),
        Err(starforged_index::IndexError::Locked(_)) => {
            report.line(
                Status::Ok,
                "search index",
                "in use by a running server; counts not verified",
            );
            return;
        }
        Err(err) => {
            report.line(
                Status::Warn,
                "search index",
                &format!("could not open the index ({err}); run `starforged index rebuild`"),
            );
            return;
        }
    };
    let (probe, fresh) = probe;
    if fresh {
        drop(probe);
        report.line(
            Status::Warn,
            "search index",
            "the index directory was missing or corrupt and has been recreated empty; run `starforged index rebuild`",
        );
        return;
    }
    let stats = probe.stats().unwrap_or(starforged_index::IndexStats {
        trails: 0,
        events: 0,
    });
    drop(probe);
    // Count the database side through a Core opened without auto-migrate,
    // so doctor never writes the schema it is checking. The probe is
    // dropped first, so the Core opens the real index, not a throwaway.
    let mut doctor_config = config.clone();
    doctor_config.database.auto_migrate = false;
    let core = match open_core(&doctor_config, std::env::current_exe().unwrap_or_default()).await {
        Ok(core) => core,
        Err(err) => {
            report.line(
                Status::Warn,
                "search index",
                &format!("could not open the database side of the index ({err}); run `starforged index rebuild`"),
            );
            return;
        }
    };
    let db_trails: i64 = db_doctor::live_trail_count(core.db()).await.unwrap_or(0);
    let db_events = expected_event_docs(&core).await.unwrap_or(0);
    let within = |index: u64, database: i64| -> bool {
        let database = database.max(0) as u64;
        if database == 0 {
            return index == 0;
        }
        let diff = index.abs_diff(database) as f64 / database as f64;
        diff <= 0.01
    };
    if within(stats.trails, db_trails) && within(stats.events, db_events) {
        report.line(
            Status::Ok,
            "search index",
            &format!(
                "{} trail document(s), {} event document(s)",
                stats.trails, stats.events
            ),
        );
    } else {
        report.line(
            Status::Warn,
            "search index",
            &format!(
                "index holds {} trail and {} event document(s) but the database holds {db_trails} trails and {db_events} indexed events; run `starforged index rebuild`",
                stats.trails, stats.events
            ),
        );
    }
}

/// Indexed event documents a rebuild would produce: one per searchable
/// item of every `complete` session in a live repository, counted with
/// [`starforged_core::search::event_docs`].
async fn expected_event_docs(core: &starforged_core::Core) -> anyhow::Result<i64> {
    let mut total = 0_i64;
    for repo in db_repos::list_all_live(core.db(), i64::MAX).await? {
        let visibility = starforged_core::search::visibility_of(&repo);
        for session in db_sessions::sessions_of_repo(core.db(), repo.id, i64::MAX).await? {
            if session.lifecycle != "complete" {
                continue;
            }
            let items = core.load_session_items(session.id).await?;
            let docs = starforged_core::search::event_docs(&session, visibility, &items, &[]);
            total += docs.len() as i64;
        }
    }
    Ok(total)
}

async fn check_migrations(report: &mut Report, db: Option<&Db>, db_error: Option<&str>) {
    let Some(db) = db else {
        report.line(
            Status::Fail,
            "migrations",
            db_error.unwrap_or("database unavailable"),
        );
        return;
    };
    let applied = db.latest_migration().await;
    let known = db.known_migration();
    match applied {
        Ok(Some(applied)) if applied >= known => report.line(
            Status::Ok,
            "migrations",
            &format!("applied version {applied} is the latest known ({known})"),
        ),
        Ok(Some(applied)) => report.line(
            Status::Fail,
            "migrations",
            &format!(
                "applied version {applied} but this binary knows version {known}; run `starforged migrate`"
            ),
        ),
        Ok(None) => report.line(
            Status::Fail,
            "migrations",
            &format!(
                "no migrations have been applied; this binary knows version {known}; run `starforged migrate`"
            ),
        ),
        Err(err) => report.line(
            Status::Fail,
            "migrations",
            &format!("could not read the applied migration version: {err}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_version_parsing() {
        assert_eq!(parse_git_version("git version 2.43.0\n"), Some((2, 43)));
        assert_eq!(parse_git_version("git version 2.30.0"), Some((2, 30)));
        assert_eq!(
            parse_git_version("git version 10.2.1.windows.1"),
            Some((10, 2))
        );
        assert_eq!(parse_git_version("nonsense"), None);
    }

    #[test]
    fn ssh_url_detection() {
        assert!(is_ssh_url("ssh://git@example.com/owner/repo.git"));
        assert!(is_ssh_url("git@example.com:owner/repo.git"));
        assert!(!is_ssh_url("https://example.com/owner/repo.git"));
        assert!(!is_ssh_url("http://example.com/owner/repo.git"));
        assert!(!is_ssh_url("file:///tmp/repo.git"));
        assert!(!is_ssh_url("/tmp/repo.git"));
    }

    #[test]
    fn exit_code_precedence() {
        let mut report = Report::default();
        assert_eq!(report.exit_code(), 0);
        report.line(Status::Warn, "a", "b");
        assert_eq!(report.exit_code(), 2);
        report.line(Status::Fail, "a", "b");
        assert_eq!(report.exit_code(), 1);
    }
}
