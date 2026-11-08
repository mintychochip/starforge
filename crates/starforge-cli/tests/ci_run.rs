//! `starforge ci run` parses the working tree's spec without a daemon.

use std::process::Command;

fn run(dir: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_starforge"))
        .args(["ci", "run", "--dry-run"])
        .current_dir(dir)
        .output()
        .unwrap()
}

#[test]
fn ci_run_dry_run_lists_expanded_jobs_and_rejects_bad_specs() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".starforge")).unwrap();
    std::fs::write(
        dir.path().join(".starforge/ci.toml"),
        r#"
version = 1
[triggers]
push = ["main"]
[[job]]
name = "test"
image = "rust:1.85"
commands = ["true"]
[job.matrix]
os = ["linux", "mac"]
"#,
    )
    .unwrap();
    let out = run(dir.path());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("test-0-os-linux"), "{stdout}");
    assert!(stdout.contains("test-1-os-mac"), "{stdout}");

    std::fs::write(dir.path().join(".starforge/ci.toml"), "version = 2\n").unwrap();
    let out = run(dir.path());
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("version"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
