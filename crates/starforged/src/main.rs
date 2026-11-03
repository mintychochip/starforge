use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
}

fn main() -> anyhow::Result<()> {
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
    }
    Ok(())
}
