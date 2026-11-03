use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(config: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_starforged"))
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn admin_creates_users_and_tokens() {
    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("starforged.toml");
    let data = tmp.path().join("data");
    assert!(
        run(
            &config,
            &["init", "--data-dir", data.to_str().unwrap()],
            None
        )
        .status
        .success()
    );

    let created = run(
        &config,
        &[
            "admin",
            "user",
            "create",
            "--handle",
            "Alice",
            "--email",
            "alice@example.com",
            "--admin",
            "--password-stdin",
        ],
        Some("correct horse battery\n"),
    );
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(String::from_utf8_lossy(&created.stdout).starts_with("created user alice (id "));

    let token = run(
        &config,
        &[
            "admin",
            "token",
            "create",
            "--user",
            "alice",
            "--name",
            "ci",
            "--scopes",
            "repo:read",
        ],
        None,
    );
    assert!(
        token.status.success(),
        "{}",
        String::from_utf8_lossy(&token.stderr)
    );
    let secret = String::from_utf8(token.stdout).unwrap().trim().to_owned();
    assert!(secret.starts_with("sfp_") && secret.len() == 68, "{secret}");

    let duplicate = run(
        &config,
        &["admin", "user", "create", "--handle", "alice"],
        None,
    );
    assert!(!duplicate.status.success());
    assert!(String::from_utf8_lossy(&duplicate.stderr).contains("already taken"));

    let migrate = run(&config, &["migrate"], None);
    assert!(migrate.status.success());
}
