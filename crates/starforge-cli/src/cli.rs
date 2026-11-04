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

/// `sessions` subcommands (full set lands C5/C7).
#[derive(Debug, Subcommand)]
pub enum SessionsCmd {
    /// List local sessions.
    List,
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
    if let Cmd::Auth { .. } | Cmd::Status = &cli.cmd {
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

fn sync_stub(cli: Cli, _paths: CliPaths) -> std::process::ExitCode {
    let result: Result<(), CliError> = match cli.cmd {
        Cmd::Auth { .. } => unreachable!("auth dispatches via run_async"),
        Cmd::Status => unreachable!("status dispatches via run_async"),
        Cmd::Enable => Err(CliError::Unimplemented("enable")),
        Cmd::Disable => Err(CliError::Unimplemented("disable")),
        Cmd::Doctor => Err(CliError::Unimplemented("doctor")),
        Cmd::Sync => Err(CliError::Unimplemented("sync")),
        Cmd::Sessions { .. } => Err(CliError::Unimplemented("sessions")),
        Cmd::Export => Err(CliError::Unimplemented("export")),
        Cmd::Import => Err(CliError::Unimplemented("import")),
        Cmd::Trail => Err(CliError::Unimplemented("trail")),
        Cmd::HookPrepare { .. } => Err(CliError::Unimplemented("_hook-prepare-commit-msg")),
        Cmd::HookPostCommit => Err(CliError::Unimplemented("_hook-post-commit")),
        Cmd::HookPrePush => Err(CliError::Unimplemented("_hook-pre-push")),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err} (not implemented yet)");
            std::process::ExitCode::from(err.exit_code())
        }
    }
}

/// Async dispatch (auth handlers live here; other commands stay stubs).
pub async fn run_async(cli: Cli, paths: CliPaths) -> std::process::ExitCode {
    let dry_run = cli.dry_run;
    match cli.cmd {
        Cmd::Auth { cmd } => run_auth(cmd, paths, dry_run).await,
        Cmd::Enable => stub_err(CliError::Unimplemented("enable")),
        Cmd::Disable => stub_err(CliError::Unimplemented("disable")),
        Cmd::Status => run_status(paths, dry_run).await,
        Cmd::Doctor => stub_err(CliError::Unimplemented("doctor")),
        Cmd::Sync => stub_err(CliError::Unimplemented("sync")),
        Cmd::Sessions { .. } => stub_err(CliError::Unimplemented("sessions")),
        Cmd::Export => stub_err(CliError::Unimplemented("export")),
        Cmd::Import => stub_err(CliError::Unimplemented("import")),
        Cmd::Trail => stub_err(CliError::Unimplemented("trail")),
        Cmd::HookPrepare { .. } => stub_err(CliError::Unimplemented("_hook-prepare-commit-msg")),
        Cmd::HookPostCommit => stub_err(CliError::Unimplemented("_hook-post-commit")),
        Cmd::HookPrePush => stub_err(CliError::Unimplemented("_hook-pre-push")),
    }
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
