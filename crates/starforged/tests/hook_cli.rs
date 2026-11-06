use std::io::Write;
use std::process::{Command, Stdio};

/// An empty protection snapshot: no branch rules, so branch and tag pushes
/// follow the pre-protection policy.
const EMPTY_SNAPSHOT: &str = r#"{"v":1,"branches":[],"tags":[],"tag_ok":true,"namespaces":[]}"#;

fn hook_with(input: &str, env: &[(&str, &str)]) -> std::process::Output {
    hook_with_owned(
        input,
        &env.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<Vec<_>>(),
    )
}

fn hook_with_owned(input: &str, env: &[(String, String)]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_starforged"))
        .args(["hook", "pre-receive"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
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

/// A bare repo with a `main` branch, so the hook's branch listing resolves it.
fn repo_with_main() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo.git");
    let repo_str = repo.to_str().unwrap().to_owned();
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["init", "-b", "main", &repo_str]);
    run(&["-C", &repo_str, "commit", "--allow-empty", "-m", "init"]);
    (dir, repo_str)
}

fn hook(input: &str) -> std::process::Output {
    hook_with(input, &[])
}

/// The RPC layer's write tier: writers pushing branches or tags.
fn write_env() -> Vec<(&'static str, &'static str)> {
    vec![
        ("STARFORGE_PERMISSION", "write"),
        ("STARFORGE_SCOPE_WRITE", "1"),
        ("STARFORGE_PROTECTION", EMPTY_SNAPSHOT),
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

/// Without a snapshot the hook fails closed: every branch and tag push is
/// refused, while `refs/for` keeps working.
#[test]
fn missing_or_malformed_snapshot_fails_closed_for_branches_and_tags() {
    let base = vec![
        ("STARFORGE_PERMISSION", "write"),
        ("STARFORGE_SCOPE_WRITE", "1"),
    ];
    for snapshot in [None, Some("not json")] {
        let mut extra = base.clone();
        if let Some(raw) = snapshot {
            extra.push(("STARFORGE_PROTECTION", raw));
        }
        for line in ["0 1 refs/heads/main\n", "0 1 refs/tags/v1\n"] {
            let out = hook_with(line, &extra);
            assert_eq!(out.status.code(), Some(1), "{line} with {snapshot:?}");
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("protection snapshot"),
                "fail-closed message names the snapshot: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
    // `refs/for` is unaffected by the snapshot state. The hook resolves the
    // base against the repository's branch list, so point it at a temp repo
    // that has a `main` branch.
    let (_dir, git_dir) = repo_with_main();
    let out = hook_with_owned(
        "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/for/main/feat\n",
        &[
            ("STARFORGE_PERMISSION".to_owned(), "write".to_owned()),
            ("STARFORGE_SCOPE_WRITE".to_owned(), "1".to_owned()),
            ("STARFORGE_USER_ID".to_owned(), "7".to_owned()),
            ("STARFORGE_USER_HANDLE".to_owned(), "bob".to_owned()),
            ("GIT_DIR".to_owned(), git_dir),
        ],
    );
    assert_eq!(out.status.code(), Some(0));
}

/// A snapshot rule blocking direct pushes refuses the branch, naming the
/// ref and the pattern; an exempt snapshot lets it through.
#[test]
fn snapshot_direct_push_block_names_ref_and_pattern() {
    let blocked = r#"{"v":1,"branches":[{"pattern":"main","direct":true,"force":false,"delete":false,"exempt":false}],"tags":[],"tag_ok":true,"namespaces":[]}"#;
    let out = hook_with(
        "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main\n",
        &[
            ("STARFORGE_PERMISSION", "write"),
            ("STARFORGE_SCOPE_WRITE", "1"),
            ("STARFORGE_PROTECTION", blocked),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("refs/heads/main"), "{err}");
    assert!(err.contains("main"), "{err}");
    let exempt = r#"{"v":1,"branches":[{"pattern":"main","direct":true,"force":false,"delete":false,"exempt":true}],"tags":[],"tag_ok":true,"namespaces":[]}"#;
    let out = hook_with(
        "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/heads/main\n",
        &[
            ("STARFORGE_PERMISSION", "write"),
            ("STARFORGE_SCOPE_WRITE", "1"),
            ("STARFORGE_PROTECTION", exempt),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "exempt snapshot passes");
}

/// Tag protection: a matching pattern needs `tag_ok`; non-matching tags
/// follow the write tier, and refusals name the ref and the pattern.
#[test]
fn tag_protection_needs_maintain_for_matching_tags() {
    fn snapshot(tags: &str, tag_ok: bool) -> String {
        format!(
            "{{\"v\":1,\"branches\":[],\"tags\":[{tags}],\"tag_ok\":{tag_ok},\"namespaces\":[]}}"
        )
    }
    let line = "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/tags/v1\n";
    let base = vec![
        ("STARFORGE_PERMISSION", "write"),
        ("STARFORGE_SCOPE_WRITE", "1"),
    ];
    // A matching pattern without `tag_ok` refuses, naming the ref and pattern.
    let mut env = base.clone();
    let guarded = snapshot(r#""v*""#, false);
    env.push(("STARFORGE_PROTECTION", guarded.as_str()));
    let out = hook_with(line, &env);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("refs/tags/v1"), "{err}");
    assert!(err.contains("v*"), "{err}");
    // A maintainer snapshot lets the same push through.
    let mut env = base.clone();
    let open = snapshot(r#""v*""#, true);
    env.push(("STARFORGE_PROTECTION", open.as_str()));
    assert!(hook_with(line, &env).status.success());
    // A non-matching tag sails through without `tag_ok`.
    let other = "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/tags/release-1\n";
    let mut env = base.clone();
    let guarded = snapshot(r#""v*""#, false);
    env.push(("STARFORGE_PROTECTION", guarded.as_str()));
    assert!(hook_with(other, &env).status.success());
    // Deleting a protected tag needs `tag_ok` too.
    let delete = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0000000000000000000000000000000000000000 refs/tags/v1\n";
    assert!(!hook_with(delete, &env).status.success());
}

/// Allow-listed namespaces push like branches; everything else stays refused.
#[test]
fn allow_listed_namespaces_push_like_branches() {
    let line = "0000000000000000000000000000000000000000 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa refs/notes/commits\n";
    let listed = r#"{"v":1,"branches":[],"tags":[],"tag_ok":false,"namespaces":["refs/notes/"]}"#;
    let out = hook_with(
        line,
        &[
            ("STARFORGE_PERMISSION", "write"),
            ("STARFORGE_SCOPE_WRITE", "1"),
            ("STARFORGE_PROTECTION", listed),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "allow-listed notes push passes");
    // Without the allow-list the same push is refused.
    let out = hook_with(line, &write_env());
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(err.contains("refs/notes/commits"), "{err}");
    // Readers stay refused inside the allow-list.
    let out = hook_with(
        line,
        &[
            ("STARFORGE_PERMISSION", "read"),
            ("STARFORGE_SCOPE_WRITE", "1"),
            ("STARFORGE_PROTECTION", listed),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
}
