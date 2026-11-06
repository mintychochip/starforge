//! Smoke test pinning the §10.3 command surface from day one.

use clap::CommandFactory;
use starforge_cli::cli::Cli;

#[test]
fn starforge_help_lists_core_surface() {
    let mut cmd = Cli::command();
    let mut help = Vec::new();
    cmd.write_long_help(&mut help).unwrap();
    let help = String::from_utf8(help).unwrap();
    for sub in ["enable", "sync", "sessions", "auth", "hook"] {
        assert!(help.contains(sub), "help missing {sub}:\n{help}");
    }
}
