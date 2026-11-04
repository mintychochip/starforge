//! `starforge` binary: parse args, set up tracing, dispatch.

use clap::Parser;
use starforge_cli::cli::{Cli, run};
use starforge_cli::config::CliPaths;

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                if cli.verbose {
                    "debug".into()
                } else {
                    "info".into()
                }
            }),
        )
        .with_writer(std::io::stderr)
        .init();
    let paths = CliPaths::resolve();
    run(cli, paths)
}
