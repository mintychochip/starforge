//! `starforge-runner` standalone binary: claim jobs and execute them in
//! sandboxes (plan M6d D4). `starforge runner` runs the same executor.

use std::sync::atomic::AtomicBool;

use clap::Parser;
use starforge_runner::{Executor, HttpSandboxProvider, RunnerArgs, RunnerConfig};

#[derive(Debug, Parser)]
#[command(name = "starforge-runner", version, about = "Starforge CI runner")]
struct Args {
    #[command(flatten)]
    args: RunnerArgs,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Args::parse();
    let config = RunnerConfig::from(&cli.args);
    if config.token.is_empty() {
        eprintln!("error: runner token is empty (pass --token or STARFORGE_RUNNER_TOKEN)");
        return std::process::ExitCode::from(2);
    }
    println!("{}", config.plan_text());
    let provider = HttpSandboxProvider::new(&config.server_url);
    let executor = Executor::new(config, provider);
    let stop = AtomicBool::new(false);
    match executor.run_until_idle(&stop).await {
        Ok(n) => {
            println!("runner idle: {n} job(s) executed");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: runner: {e}");
            std::process::ExitCode::from(1)
        }
    }
}
