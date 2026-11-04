//! Clap command surface (C2 wires real `auth` handlers; C3–C7 follow).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::CliPaths;

/// Developer CLI for Starforge sessions.
#[derive(Debug, Parser)]
#[command(name = "starforge", version, about = "Starforge developer CLI")]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub cmd: Cmd,
    /// Enable debug logging.
    #[arg(long, global = true)]
    pub verbose: bool,
    /// Print planned actions without writing anything.
    #[arg(long, global = true)]
    pub dry_run: bool,
}

/// All subcommands (§10.3 surface + hidden git-hook entry points).
#[derive(Debug, Subcommand)]
pub enum Cmd {
    /// Authenticate with the server (device flow).
    Auth {
        #[command(subcommand)]
        cmd: AuthCmd,
    },
    /// Install git hooks and repo config.
    Enable,
    /// Remove git hooks installed by `enable`.
    Disable,
    /// Show repo/session/upload status.
    Status,
    /// Check environment, config, and connectivity.
    Doctor,
    /// Upload queued sessions.
    Sync,
    /// Manage local sessions.
    Sessions {
        #[command(subcommand)]
        cmd: SessionsCmd,
    },
    /// Export a session bundle.
    Export,
    /// Import a session bundle.
    Import,
    /// Show the session trail.
    Trail,
    /// Git `prepare-commit-msg` hook entry point (invoked by installed hooks).
    #[command(hide = true, name = "_hook-prepare-commit-msg")]
    HookPrepare {
        /// Path to the commit message file.
        msg_file: PathBuf,
    },
    /// Git `post-commit` hook entry point (invoked by installed hooks).
    #[command(hide = true, name = "_hook-post-commit")]
    HookPostCommit,
    /// Git `pre-push` hook entry point (invoked by installed hooks).
    #[command(hide = true, name = "_hook-pre-push")]
    HookPrePush,
}

/// `auth` subcommands.
#[derive(Debug, Subcommand)]
pub enum AuthCmd {
    /// Log in via device flow.
    Login {
        /// Server host or URL (e.g. `example.com`).
        server: String,
    },
    /// Log out (delete stored credentials).
    Logout {
        /// Server host or URL. Defaults to the single stored host.
        server: Option<String>,
    },
    /// Show auth status.
    Status,
}

/// `sessions` subcommands: `list`/`show`/`link`/`unlink` are real (C4/C7);
/// `publish`/`unpublish`/`delete` remain stubs (out of scope for M1c).
#[derive(Debug, Subcommand)]
pub enum SessionsCmd {
    /// List local sessions.
    List,
    /// Show a session's metadata.
    Show {
        /// Session ULID (unambiguous prefix also works).
        ulid: String,
    },
    /// Explicitly link a session to a commit (default: HEAD).
    Link {
        /// Session ULID (unambiguous prefix also works).
        ulid: String,
        /// Commit SHA to link. Defaults to HEAD.
        #[arg(long)]
        commit: Option<String>,
    },
    /// Remove a session's link to a commit.
    Unlink {
        /// Session ULID (unambiguous prefix also works).
        ulid: String,
        /// Commit SHA to unlink.
        #[arg(long)]
        commit: String,
    },
    /// Publish a session (not in M1c).
    Publish {
        /// Session ULID.
        ulid: String,
    },
    /// Unpublish a session (not in M1c).
    Unpublish {
        /// Session ULID.
        ulid: String,
    },
    /// Delete a session (not in M1c).
    Delete {
        /// Session ULID.
        ulid: String,
    },
}
/// CLI errors. Every non-root cause maps to an exit code (0/1/2).
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Handler not implemented yet (C3–C7 replace these stubs).
    #[error("{0} is not yet implemented")]
    Unimplemented(&'static str),
    /// Auth failure.
    #[error(transparent)]
    Auth(#[from] crate::auth::AuthError),
}

impl CliError {
    /// Exit code: 0 success; 1 operational error; 2 items still queued.
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Unimplemented(_) | CliError::Auth(_) => 1,
        }
    }
}

/// Dispatch `cli` to its handler. Auth handlers are real (C2); the rest are
/// stubs until C3–C7.
///
/// Must not be called from inside a Tokio runtime (it blocks on one for the
/// async device flow); async contexts use [`run_async`] instead.
pub fn run(cli: Cli, paths: CliPaths) -> std::process::ExitCode {
    if let Cmd::Auth { .. } | Cmd::Status | Cmd::Sync | Cmd::Doctor | Cmd::HookPrePush = &cli.cmd {
        // fall through to async dispatch below
    } else {
        return sync_stub(cli, paths);
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("error: cannot start runtime: {err}");
            return std::process::ExitCode::from(1);
        }
    };
    runtime.block_on(run_async(cli, paths))
}

fn sync_stub(cli: Cli, paths: CliPaths) -> std::process::ExitCode {
    let dry_run = cli.dry_run;
    match cli.cmd {
        Cmd::Auth { .. } => unreachable!("auth dispatches via run_async"),
        Cmd::Status => unreachable!("status dispatches via run_async"),
        Cmd::Doctor => unreachable!("doctor dispatches via run_async"),
        Cmd::Enable => run_enable(paths, dry_run),
        Cmd::Disable => run_disable(paths, dry_run),
        Cmd::Sessions { cmd } => run_sessions(cmd, dry_run),
        Cmd::HookPrepare { msg_file } => run_hook_prepare(paths, msg_file),
        Cmd::HookPostCommit => run_hook_post_commit(paths),
        Cmd::HookPrePush => unreachable!("pre-push dispatches via run_async"),
        Cmd::Sync => unreachable!("sync dispatches via run_async"),
        Cmd::Export => stub_err(CliError::Unimplemented("export")),
        Cmd::Import => stub_err(CliError::Unimplemented("import")),
        Cmd::Trail => stub_err(CliError::Unimplemented("trail")),
    }
}

/// Current directory as the repo root, or `None` after reporting the error.
fn cwd_repo() -> Option<std::path::PathBuf> {
    match std::env::current_dir() {
        Ok(dir) => Some(dir),
        Err(err) => {
            eprintln!("error: cannot determine current directory: {err}");
            None
        }
    }
}

/// `enable`: install dispatchers + agent hooks, print every file changed.
fn run_enable(paths: CliPaths, dry_run: bool) -> std::process::ExitCode {
    let Some(repo) = cwd_repo() else {
        return std::process::ExitCode::from(1);
    };
    let (out, code) = crate::commands::hooks::enable(&repo, &paths, dry_run);
    if code == 0 {
        if !out.is_empty() {
            println!("{out}");
        }
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("{out}");
        std::process::ExitCode::from(code)
    }
}

/// `disable`: remove dispatchers + agent hooks, restore originals.
fn run_disable(paths: CliPaths, dry_run: bool) -> std::process::ExitCode {
    let Some(repo) = cwd_repo() else {
        return std::process::ExitCode::from(1);
    };
    let (out, code) = crate::commands::hooks::disable(&repo, &paths, dry_run);
    if code == 0 {
        if !out.is_empty() {
            println!("{out}");
        }
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("{out}");
        std::process::ExitCode::from(code)
    }
}

/// Hidden `_hook-prepare-commit-msg`: never fails the commit.
fn run_hook_prepare(paths: CliPaths, msg_file: std::path::PathBuf) -> std::process::ExitCode {
    let Some(repo) = cwd_repo() else {
        return std::process::ExitCode::SUCCESS;
    };
    std::process::ExitCode::from(crate::commands::hooks::hook_prepare(
        &repo, &msg_file, &paths,
    ))
}

/// Hidden `_hook-post-commit`: records trailer links, never fails.
fn run_hook_post_commit(paths: CliPaths) -> std::process::ExitCode {
    let Some(repo) = cwd_repo() else {
        return std::process::ExitCode::SUCCESS;
    };
    std::process::ExitCode::from(crate::commands::hooks::hook_post_commit(&repo, &paths))
}

/// Hidden `_hook-pre-push`: enqueue + best-effort upload, never fails the push.
async fn run_hook_pre_push_async(paths: CliPaths) -> std::process::ExitCode {
    let Some(repo) = cwd_repo() else {
        return std::process::ExitCode::SUCCESS;
    };
    let code =
        crate::commands::hooks::hook_pre_push_full(&repo, &paths, |key| std::env::var(key).ok())
            .await;
    std::process::ExitCode::from(code)
}

/// `sessions` subcommands: list/show/link/unlink are real; the rest are stubs.
fn run_sessions(cmd: SessionsCmd, dry_run: bool) -> std::process::ExitCode {
    let repo = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: cannot determine current directory: {err}");
            return std::process::ExitCode::from(1);
        }
    };
    let (out, code) = match cmd {
        SessionsCmd::List => crate::commands::sessions::list(&repo, dry_run),
        SessionsCmd::Show { ulid } => crate::commands::sessions::show(&repo, &ulid, dry_run),
        SessionsCmd::Link { ulid, commit } => {
            crate::commands::sessions::link(&repo, &ulid, commit.as_deref(), dry_run)
        }
        SessionsCmd::Unlink { ulid, commit } => {
            crate::commands::sessions::unlink(&repo, &ulid, &commit, dry_run)
        }
        SessionsCmd::Publish { .. } => {
            return stub_err(CliError::Unimplemented("sessions publish"));
        }
        SessionsCmd::Unpublish { .. } => {
            return stub_err(CliError::Unimplemented("sessions unpublish"));
        }
        SessionsCmd::Delete { .. } => {
            return stub_err(CliError::Unimplemented("sessions delete"));
        }
    };
    if code == 0 {
        println!("{out}");
    } else {
        eprintln!("{out}");
    }
    std::process::ExitCode::from(code)
}

/// Async dispatch (auth/status/sync/doctor/pre-push live here; the rest are
/// sync or stubs).
pub async fn run_async(cli: Cli, paths: CliPaths) -> std::process::ExitCode {
    let dry_run = cli.dry_run;
    match cli.cmd {
        Cmd::Auth { cmd } => run_auth(cmd, paths, dry_run).await,
        Cmd::Enable => run_enable(paths, dry_run),
        Cmd::Disable => run_disable(paths, dry_run),
        Cmd::Status => run_status(paths, dry_run).await,
        Cmd::Doctor => run_doctor(paths, dry_run).await,
        Cmd::Sync => run_sync(paths, dry_run).await,
        Cmd::Sessions { cmd } => run_sessions(cmd, dry_run),
        Cmd::Export => stub_err(CliError::Unimplemented("export")),
        Cmd::Import => stub_err(CliError::Unimplemented("import")),
        Cmd::Trail => stub_err(CliError::Unimplemented("trail")),
        Cmd::HookPrepare { msg_file } => run_hook_prepare(paths, msg_file),
        Cmd::HookPostCommit => run_hook_post_commit(paths),
        Cmd::HookPrePush => run_hook_pre_push_async(paths).await,
    }
}

/// `doctor`: environment, config, and connectivity checks.
async fn run_doctor(paths: CliPaths, dry_run: bool) -> std::process::ExitCode {
    let repo = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: cannot determine current directory: {err}");
            return std::process::ExitCode::from(1);
        }
    };
    let (out, code) = crate::commands::doctor::doctor(&repo, &paths, dry_run).await;
    if code == 0 {
        println!("{out}");
    } else {
        eprintln!("{out}");
    }
    std::process::ExitCode::from(code)
}
async fn run_auth(cmd: AuthCmd, paths: CliPaths, dry_run: bool) -> std::process::ExitCode {
    match cmd {
        AuthCmd::Login { server } => {
            let sleeper = crate::queue::TokioSleeper;
            let now = time::OffsetDateTime::now_utc();
            match crate::commands::auth::login(&paths, &server, &sleeper, now, dry_run).await {
                Ok(msg) => {
                    println!("{msg}");
                    std::process::ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    std::process::ExitCode::from(1)
                }
            }
        }
        AuthCmd::Logout { server } => {
            match crate::commands::auth::logout(&paths, server.as_deref(), dry_run) {
                Ok(msg) => {
                    println!("{msg}");
                    std::process::ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    std::process::ExitCode::from(1)
                }
            }
        }
        AuthCmd::Status => {
            let (out, code) = crate::commands::auth::status(&paths);
            println!("{out}");
            std::process::ExitCode::from(code)
        }
    }
}

/// `status`: resolve the server for the current directory and print it.
async fn run_status(paths: CliPaths, dry_run: bool) -> std::process::ExitCode {
    let repo = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: cannot determine current directory: {err}");
            return std::process::ExitCode::from(1);
        }
    };
    let (out, code) = crate::commands::status::status(&repo, &paths, dry_run).await;
    if code == 0 {
        println!("{out}");
    } else {
        eprintln!("{out}");
    }
    std::process::ExitCode::from(code)
}

/// Host key for credential lookup from a server `api_url`: lowercased host
/// plus an explicit port when present (mirrors [`crate::auth::normalize_server`]).
pub(crate) fn sync_host_key(api_url: &str) -> Option<String> {
    let url = url::Url::parse(api_url).ok()?;
    let host = url.host_str()?.to_lowercase();
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

/// `sync`: drain due queue entries to the resolved server. Exit 0 drained,
/// 2 remainder, 1 operational error (including auth). `--dry-run` prints the
/// plan without any HTTP or writes.
async fn run_sync(paths: CliPaths, dry_run: bool) -> std::process::ExitCode {
    let repo = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            eprintln!("error: cannot determine current directory: {err}");
            return std::process::ExitCode::from(1);
        }
    };
    let common = match crate::git::common_dir(&repo) {
        Ok(common) => common,
        Err(err) => {
            eprintln!("error: not a git repo: {err}");
            return std::process::ExitCode::from(1);
        }
    };
    let spool = crate::spool::Spool::open(&common);
    if dry_run {
        return run_sync_dry_run(&spool);
    }
    // Ingest before draining so `sync` uploads fresh native sessions even when
    // nothing was ever queued; an ingest failure surfaces as exit 1.
    {
        let roots = crate::commands::hooks::adapter_roots(&paths, &repo);
        match crate::ingest::ingest(&spool, &roots, &repo, time::OffsetDateTime::now_utc()) {
            Ok(stats) => tracing::debug!(
                "sync ingest: {} session(s), {} new event(s)",
                stats.sessions,
                stats.new_events
            ),
            Err(err) => {
                eprintln!("error: ingest failed: {err}");
                return std::process::ExitCode::from(1);
            }
        }
    }
    let (server, owner_repo, _chosen) =
        match crate::commands::status::resolve_server(&repo, &paths).await {
            Ok(resolved) => resolved,
            Err(err) => {
                eprintln!("error: {err}");
                return std::process::ExitCode::from(1);
            }
        };
    let Some(host) = sync_host_key(&server.api_url) else {
        eprintln!("error: cannot parse server api_url {:?}", server.api_url);
        return std::process::ExitCode::from(1);
    };
    let token = match crate::auth::resolve_token(&paths, &host, |key| std::env::var(key).ok()) {
        Ok(resolved) => resolved.token().to_string(),
        Err(err) => {
            eprintln!("error: {err}");
            return std::process::ExitCode::from(1);
        }
    };
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let sleeper = crate::queue::TokioSleeper;
    match crate::commands::sync::sync(&spool, &server, &owner_repo, &token, &sleeper, &now, false)
        .await
    {
        Ok(summary) => {
            println!(
                "sync: {} uploaded, {} skipped, {} remaining",
                summary.uploaded, summary.skipped, summary.remaining
            );
            std::process::ExitCode::from(summary.exit_code())
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::ExitCode::from(1)
        }
    }
}

/// `sync --dry-run`: print every due op, write nothing, exit 0. No server or
/// token resolution, so no network happens.
fn run_sync_dry_run(spool: &crate::spool::Spool) -> std::process::ExitCode {
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    match crate::commands::sync::dry_run_plan(spool, &now) {
        Ok(planned) => {
            for line in &planned {
                println!("would {line}");
            }
            std::process::ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::ExitCode::from(1)
        }
    }
}

fn stub_err(err: CliError) -> std::process::ExitCode {
    eprintln!("error: {err} (not implemented yet)");
    std::process::ExitCode::from(err.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn cli_help_lists_core_surface() {
        let mut cmd = Cli::command();
        let mut help = Vec::new();
        cmd.write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();
        for sub in ["enable", "sync", "sessions", "auth"] {
            assert!(help.contains(sub), "help missing {sub}:\n{help}");
        }
    }

    #[test]
    fn cli_version_flag_succeeds() {
        let err = Cli::try_parse_from(["starforge", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn cli_auth_help_succeeds() {
        let cli = Cli::try_parse_from(["starforge", "auth", "--help"]);
        let err = cli.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn cli_unknown_subcommand_fails() {
        let err = Cli::try_parse_from(["starforge", "frobnicate"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn cli_globals_parse() {
        let cli = Cli::try_parse_from(["starforge", "--verbose", "--dry-run", "status"]).unwrap();
        assert!(cli.verbose);
        assert!(cli.dry_run);
    }

    #[test]
    fn cli_stub_returns_exit_1() {
        let cli = Cli::try_parse_from(["starforge", "status"]).unwrap();
        let paths = CliPaths::from_home(PathBuf::from("/tmp/cli-test"));
        assert_eq!(run(cli, paths), std::process::ExitCode::from(1));
    }

    #[test]
    fn cli_auth_login_parses_server() {
        let cli = Cli::try_parse_from(["starforge", "auth", "login", "example.com"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Auth {
                cmd: AuthCmd::Login { .. },
            }
        ));
    }
}
