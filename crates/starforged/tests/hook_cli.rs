use std::io::Write;
use std::process::{Command, Stdio};

fn hook(input: &str) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_starforged"))
        .args(["hook", "pre-receive"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

#[test]
fn the_binary_runs_the_pre_receive_policy() {
    assert!(hook("0 1 refs/heads/main\n").status.success());
    let rejected = hook("0 1 refs/entire/checkpoints/ab/x\n");
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("refs/entire/checkpoints/ab/x is not allowed")
    );
}
