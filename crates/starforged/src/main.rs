use std::path::PathBuf;

use clap::{Parser, Subcommand};
use starforged::admin::{self, NewUserArgs};
use starforged::config::Config;

#[derive(Parser)]
#[command(name = "starforged", version, about = "Starforge server")]
struct Cli {
    /// Path to starforged.toml. Optional so that `restore` can run
    /// without one (it then uses the backup's config); every other
    /// subcommand defaults to `starforged.toml` in the working
    /// directory, exactly as before.
    #[arg(long, env = "STARFORGE_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write a new config file and data directory.
    Init {
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:3000")]
        base_url: String,
        #[arg(long, default_value = "127.0.0.1:3000")]
        http_addr: String,
    },
    /// Create or update the database schema.
    Migrate,
    /// Run the server.
    Serve,
    /// Administrative tasks.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Search index administration.
    Index {
        #[command(subcommand)]
        command: IndexCommand,
    },
    /// Check the data directory, database, and search index for problems.
    /// Exits 0 when healthy, 1 on any failure, and 2 when only warnings occur.
    Doctor {
        /// Reinstall missing repository hooks and remove orphaned blob files
        /// older than one hour. Never deletes database rows.
        #[arg(long)]
        fix: bool,
    },
    /// Write a consistent snapshot of the data directory. The target must
    /// be empty or absent. Contains `secret_key` (see `backup --help`).
    Backup {
        /// The (empty or absent) directory to write the snapshot into.
        dir: PathBuf,
        /// Omit the config copy (which contains `secret_key`).
        #[arg(long)]
        no_config: bool,
    },
    /// Restore a backup snapshot into the target config's data
    /// directory and database, which must be empty. Without
    /// `--config`, the backup's config copy is used with
    /// `storage.data_dir` taken from `--data-dir`.
    Restore {
        /// The backup snapshot directory to restore from.
        dir: PathBuf,
        /// The target data directory (required when `--config` is absent).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Entry points for git hooks in hosted repositories.
    #[command(hide = true)]
    Hook {
        #[command(subcommand)]
        hook: HookCommand,
    },
}

#[derive(Subcommand)]
enum IndexCommand {
    /// Wipe and rebuild the search index from the database and blobs. The
    /// server must be stopped (or use the site-admin rebuild action).
    Rebuild,
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Manage users.
    User {
        #[command(subcommand)]
        command: AdminUserCommand,
    },
    /// Manage personal access tokens.
    Token {
        #[command(subcommand)]
        command: AdminTokenCommand,
    },
    /// Email.
    Mail {
        #[command(subcommand)]
        command: AdminMailCommand,
    },
}

#[derive(Subcommand)]
enum AdminUserCommand {
    /// Create a local user.
    Create {
        #[arg(long)]
        handle: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        display_name: Option<String>,
        /// Make the user a site administrator.
        #[arg(long)]
        admin: bool,
        /// Read the password from standard input.
        #[arg(long)]
        password_stdin: bool,
    },
}

#[derive(Subcommand)]
enum AdminTokenCommand {
    /// Create a personal access token and print it once.
    Create {
        #[arg(long)]
        user: String,
        #[arg(long)]
        name: String,
        /// Comma-separated scopes.
        #[arg(long, default_value = "repo:read,repo:write")]
        scopes: String,
        #[arg(long, default_value_t = 30)]
        expires_days: u32,
    },
}

#[derive(Subcommand)]
enum AdminMailCommand {
    /// Send a test message directly (not through the job queue) to check the [mail] settings.
    Test {
        #[arg(long)]
        to: String,
    },
}

#[derive(Subcommand)]
enum HookCommand {
    /// Checks pushed refs (`<old> <new> <ref>` lines on stdin).
    PreReceive,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // `restore` may run without `--config` (it then uses the backup's
    // config); every other subcommand defaults to `starforged.toml`.
    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(|| PathBuf::from("starforged.toml"));
    match cli.command {
        Command::Init {
            data_dir,
            base_url,
            http_addr,
        } => {
            let config = starforged::init::run(&starforged::init::InitOptions {
                config_path: &config_path,
                data_dir: &data_dir,
                base_url: &base_url,
                http_addr: &http_addr,
            })?;
            println!(
                "wrote {} (data directory {})",
                config_path.display(),
                config.storage.data_dir.display()
            );
        }
        Command::Migrate => {
            admin::migrate(&Config::load(&config_path)?).await?;
            println!("database schema is up to date");
        }
        Command::Serve => {
            let config = Config::load(&config_path)?;
            init_tracing(&config);
            starforged::serve::run(config).await?;
        }
        Command::Admin { command } => {
            let config = Config::load(&config_path)?;
            match command {
                AdminCommand::User {
                    command:
                        AdminUserCommand::Create {
                            handle,
                            email,
                            display_name,
                            admin: is_admin,
                            password_stdin,
                        },
                } => {
                    let args = NewUserArgs {
                        handle,
                        email,
                        display_name,
                        admin: is_admin,
                        password_stdin,
                    };
                    let user = admin::create_user(&config, args).await?;
                    println!("created user {} (id {})", user.handle, user.id);
                }
                AdminCommand::Token {
                    command:
                        AdminTokenCommand::Create {
                            user,
                            name,
                            scopes,
                            expires_days,
                        },
                } => {
                    println!(
                        "{}",
                        admin::create_token(&config, &user, &name, &scopes, expires_days).await?
                    );
                }
                AdminCommand::Mail {
                    command: AdminMailCommand::Test { to },
                } => {
                    admin::mail_test(&config, &to).await?;
                    println!("sent a test email to {to}");
                }
            }
        }
        Command::Index {
            command: IndexCommand::Rebuild,
        } => {
            starforged::index_cmd::rebuild(&Config::load(&config_path)?).await?;
        }
        Command::Doctor { fix } => {
            std::process::exit(starforged::doctor::run(&config_path, fix).await?);
        }
        Command::Backup { dir, no_config } => {
            starforged::backup::run(&config_path, &dir, !no_config).await?;
        }
        Command::Restore { dir, data_dir } => {
            starforged::restore::run(&dir, cli.config.as_deref(), data_dir.as_deref()).await?;
        }
        Command::Hook {
            hook: HookCommand::PreReceive,
        } => {
            std::process::exit(starforged::hook::pre_receive(
                std::io::stdin().lock(),
                std::io::stderr(),
            ));
        }
    }
    Ok(())
}

/// Initializes tracing from the config (plan M5b D1): `log.format` picks
/// text or JSON output, `log.level` is the `EnvFilter` string. A
/// `RUST_LOG` environment override still wins, matching the old behavior.
/// Text output is colored only on a terminal (and never under `NO_COLOR`),
/// so container, journald, and file logs carry no ANSI escapes.
fn init_tracing(config: &Config) {
    use std::io::IsTerminal as _;
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(config.log.level.clone()));
    let ansi = std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(ansi);
    if config.log.format == "json" {
        builder.json().init();
    } else {
        builder.init();
    }
}
