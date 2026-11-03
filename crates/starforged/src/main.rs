use std::path::PathBuf;

use clap::{Parser, Subcommand};
use starforged::admin::{self, NewUserArgs};
use starforged::config::Config;

#[derive(Parser)]
#[command(name = "starforged", version, about = "Starforge server")]
struct Cli {
    /// Path to starforged.toml.
    #[arg(
        long,
        env = "STARFORGE_CONFIG",
        default_value = "starforged.toml",
        global = true
    )]
    config: PathBuf,
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
    /// Administrative tasks.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            data_dir,
            base_url,
            http_addr,
        } => {
            let config = starforged::init::run(&starforged::init::InitOptions {
                config_path: &cli.config,
                data_dir: &data_dir,
                base_url: &base_url,
                http_addr: &http_addr,
            })?;
            println!(
                "wrote {} (data directory {})",
                cli.config.display(),
                config.storage.data_dir.display()
            );
        }
        Command::Migrate => {
            admin::migrate(&Config::load(&cli.config)?).await?;
            println!("database schema is up to date");
        }
        Command::Admin { command } => {
            let config = Config::load(&cli.config)?;
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
            }
        }
    }
    Ok(())
}
