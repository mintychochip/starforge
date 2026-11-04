use std::io::Write;
use std::process::{Command, Stdio};

fn hook_with(input: &str, env: &[(&str, &str)]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_starforged"))
        .args(["hook", "pre-receive"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(env.iter().copied())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn hook(input: &str) -> std::process::Output {
    hook_with(input, &[])
}

/// The RPC layer's write tier: writers pushing branches or tags.
fn write_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("STARFORGE_PERMISSION", "write"),
        ("STARFORGE_SCOPE_WRITE", "1"),
    ]
}

#[test]
fn the_binary_runs_the_pre_receive_policy() {
    // Branches pass for the write tier …
    assert!(
        hook_with("0 1 refs/heads/main\n", &write_env())
            .status
            .success()
    );
    // … and are rejected without write permission or scope.
    let denied = hook("0 1 refs/heads/main\n");
    assert_eq!(denied.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&denied.stderr).contains("need write permission")
            || String::from_utf8_lossy(&denied.stderr).contains("repo:write scope")
    );
    let rejected = hook("0 1 refs/entire/checkpoints/ab/x\n");
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("refs/entire/checkpoints/ab/x is not allowed")
    );
}
