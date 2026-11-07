//! `starforge runner` subcommand: run the CI runner executor.
//!
//! `--dry-run` prints the execution plan with no network access.

use starforge_runner::{Executor, HttpSandboxProvider, RunnerArgs, RunnerConfig};

/// Build the plan text for `--dry-run` (no network).
pub fn plan(args: &RunnerArgs) -> String {
    RunnerConfig::from(args).plan_text()
}

/// Run the runner loop. `dry_run` prints the plan and returns 0 without
/// any network access.
pub async fn run(args: RunnerArgs, dry_run: bool) -> u8 {
    if dry_run {
        println!("{}\n(dry run: no network access)", plan(&args));
        return 0;
    }
    let config = RunnerConfig::from(&args);
    if config.token.is_empty() {
        eprintln!("error: runner token is empty (pass --token or STARFORGE_RUNNER_TOKEN)");
        return 2;
    }
    let provider = HttpSandboxProvider::new(&config.server_url);
    let executor = Executor::new(config, provider);
    let stop = std::sync::atomic::AtomicBool::new(false);
    match executor.run_until_idle(&stop).await {
        Ok(n) => {
            println!("runner idle: {n} job(s) executed");
            0
        }
        Err(e) => {
            eprintln!("error: runner: {e}");
            1
        }
    }
}
