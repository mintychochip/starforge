//! Entry points that git runs inside hosted repositories (see `starforged_git::init::HOOKS`).
//! Anything written to stderr reaches the pusher as `remote: …`.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use starforged_git::{pushsidecar, read, refpolicy};

/// Snapshot of the push the RPC layer took at spawn: the hook process never
/// opens the database, it only enforces this snapshot.
#[derive(Debug, Clone)]
pub struct HookCtx {
    pub repo_id: i64,
    pub user_id: Option<i64>,
    pub handle: String,
    pub permission: Option<String>,
    pub is_member: bool,
    /// The token granted `repo:write` scope. Branch/tag pushes need it on top
    /// of a write-level permission; the RPC admits readers for `refs/for`.
    pub scope_write: bool,
    pub refs_for: String,
    pub git_dir: PathBuf,
    pub branches: Vec<String>,
    pub nonce: String,
    /// `None` when `GIT_PUSH_OPTION_COUNT` is absent (no `-o` flags).
    pub options: Option<Vec<String>>,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl HookCtx {
    /// Builds the context from the hook process environment. Missing identity
    /// means anonymous; missing `STARFORGE_REFS_FOR` defaults to the
    /// permissive mode (the column default); an invalid nonce is replaced.
    /// Branch listing failures degrade to an empty list (refs/for pushes then
    /// fail with `unknown base branch`, branches/tags are unaffected).
    pub fn from_env() -> Self {
        let git_dir = env("GIT_DIR")
            .map(PathBuf::from)
            .unwrap_or(PathBuf::from("."));
        let branches = read::branches(&git_dir).unwrap_or_default();
        let count = env("GIT_PUSH_OPTION_COUNT");
        let options = count.map(|c| {
            let n: usize = c.parse().unwrap_or(0);
            (0..n)
                .map(|i| env(&format!("GIT_PUSH_OPTION_{i}")).unwrap_or_default())
                .collect()
        });
        let nonce = env("STARFORGE_PUSH_NONCE").filter(|n| pushsidecar::valid_nonce(n));
        HookCtx {
            repo_id: env("STARFORGE_REPO_ID")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            user_id: env("STARFORGE_USER_ID").and_then(|v| v.parse().ok()),
            handle: env("STARFORGE_USER_HANDLE").unwrap_or_default(),
            permission: env("STARFORGE_PERMISSION"),
            is_member: env("STARFORGE_IS_MEMBER").is_some_and(|v| v == "1"),
            scope_write: env("STARFORGE_SCOPE_WRITE").is_some_and(|v| v == "1"),
            refs_for: env("STARFORGE_REFS_FOR").unwrap_or_else(|| "anyone_with_read".to_owned()),
            git_dir,
            branches,
            nonce: nonce.unwrap_or_else(pushsidecar::new_nonce),
            options,
        }
    }
}

/// `starforged hook pre-receive`: checks every pushed ref; returns the process exit code.
pub fn pre_receive(input: impl BufRead, err: impl Write) -> i32 {
    pre_receive_with(input, err, &HookCtx::from_env())
}

/// Same as [`pre_receive`] with an explicit context (tests inject branches,
/// options, and a temp git dir instead of the live process environment).
pub fn pre_receive_with(input: impl BufRead, mut err: impl Write, ctx: &HookCtx) -> i32 {
    // Orphaned sidecars (a push that never got scanned) must not accumulate.
    pushsidecar::reap(&ctx.git_dir, pushsidecar::MAX_AGE_SECS);
    let permission = ctx.permission.as_deref();
    let mut code = 0;
    let mut accepted: Vec<(String, String, String, String, String)> = Vec::new();
    for line in input.lines() {
        let Ok(line) = line else { return 1 };
        if line.trim().is_empty() {
            continue;
        }
        let Some(update) = refpolicy::parse_line(&line) else {
            let _ = writeln!(err, "starforge: malformed pre-receive input");
            return 1;
        };
        match refpolicy::check_allowed(&update.name, permission, ctx.is_member, &ctx.refs_for) {
            Err(message) => {
                let _ = writeln!(err, "starforge: {message}");
                code = 1;
            }
            Ok(refpolicy::RefKind::For(_)) if refpolicy::is_zero_oid(&update.new) => {
                let _ = writeln!(
                    err,
                    "starforge: cannot delete {}: refs/for is not stored",
                    update.name
                );
                code = 1;
            }
            Ok(refpolicy::RefKind::For(_)) => {
                if !refpolicy::is_oid(&update.new) {
                    let _ = writeln!(err, "starforge: malformed pre-receive input");
                    code = 1;
                    continue;
                }
                let remainder = update.name.strip_prefix("refs/for/").unwrap_or_default();
                match refpolicy::split_for(
                    remainder,
                    &ctx.branches,
                    &refpolicy::default_topic(&ctx.handle),
                ) {
                    Err(message) => {
                        let _ = writeln!(
                            err,
                            "starforge: pushing to {} is not allowed: {message}",
                            update.name
                        );
                        code = 1;
                    }
                    Ok((base, topic)) => {
                        accepted.push((update.name, base, topic, update.old, update.new));
                    }
                }
            }
            Ok(refpolicy::RefKind::Branch) | Ok(refpolicy::RefKind::Tag) => {
                // The RPC admits readers for `refs/for`, so branches and tags
                // enforce the write half here: write-level permission plus a
                // write-scoped token.
                if let Err(message) =
                    refpolicy::check_branch_push(ctx.permission.as_deref(), ctx.scope_write)
                {
                    let _ = writeln!(
                        err,
                        "starforge: pushing to {} is not allowed: {message}",
                        update.name
                    );
                    code = 1;
                }
            }
        }
    }
    let options = match &ctx.options {
        None => refpolicy::PushOptions::default(),
        Some(vars) => {
            let n = vars.len().to_string();
            match refpolicy::parse_push_options(Some(&n), |i| vars.get(i).cloned()) {
                Ok(opts) => opts,
                Err(message) => {
                    let _ = writeln!(err, "{message}");
                    return 1;
                }
            }
        }
    };
    if ctx.options.as_ref().is_some_and(|v| !v.is_empty()) && accepted.is_empty() {
        let _ = writeln!(
            err,
            "starforge: push options given but no refs/for ref pushed"
        );
        return 1;
    }
    for (refname, base, topic, old, new) in &accepted {
        let sidecar = pushsidecar::Sidecar {
            repo_id: ctx.repo_id,
            user_id: ctx.user_id,
            base: base.clone(),
            topic: topic.clone(),
            trail: options.trail,
            title: options.title.clone(),
            refname: refname.clone(),
            old: old.clone(),
            new: new.clone(),
            nonce: ctx.nonce.clone(),
        };
        if let Err(message) =
            pushsidecar::write_sidecar(&ctx.git_dir, &ctx.nonce, refname, &sidecar)
        {
            let _ = writeln!(err, "starforge: {message}");
            code = 1;
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(git_dir: PathBuf) -> HookCtx {
        HookCtx {
            repo_id: 9,
            user_id: Some(42),
            handle: "Alice".to_owned(),
            permission: Some("read".to_owned()),
            is_member: false,
            scope_write: true,
            refs_for: "anyone_with_read".to_owned(),
            git_dir,
            branches: vec!["main".to_owned(), "release/1.x".to_owned()],
            nonce: "testnonce".to_owned(),
            options: None,
        }
    }

    fn run(input: &str, ctx: &HookCtx) -> (i32, String) {
        let mut err = Vec::new();
        let code = pre_receive_with(input.as_bytes(), &mut err, ctx);
        (code, String::from_utf8(err).unwrap())
    }

    fn sha(c: char) -> String {
        c.to_string().repeat(40)
    }

    #[test]
    fn accepts_branches_and_tags_for_writers() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = ctx(tmp.path().to_owned());
        c.permission = Some("write".to_owned());
        assert_eq!(
            run("0 1 refs/heads/main\n0 2 refs/tags/v1\n\n", &c),
            (0, String::new())
        );
    }

    #[test]
    fn branch_and_tag_pushes_need_write_permission_and_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let c = ctx(tmp.path().to_owned());
        // Reader permission with a write-scoped token: rejected on permission.
        let (code, err) = run("0 1 refs/heads/main\n", &c);
        assert_eq!(code, 1);
        assert!(err.contains("need write permission"), "{err}");
        // Write permission with a read-scoped token: rejected on scope.
        let mut scoped = ctx(tmp.path().to_owned());
        scoped.permission = Some("write".to_owned());
        scoped.scope_write = false;
        let (code, err) = run("0 2 refs/tags/v1\n", &scoped);
        assert_eq!(code, 1);
        assert!(err.contains("repo:write scope"), "{err}");
    }

    #[test]
    fn rejects_other_namespaces_and_reports_each() {
        let tmp = tempfile::tempdir().unwrap();
        let c = ctx(tmp.path().to_owned());
        let (code, err) = run(
            "0 1 refs/heads/main\n0 2 refs/notes/x\n0 3 refs/entire/y\n",
            &c,
        );
        assert_eq!(code, 1);
        assert!(
            err.contains("starforge: pushing to refs/notes/x is not allowed"),
            "{err}"
        );
        assert!(err.contains("refs/entire/y"), "{err}");
    }

    #[test]
    fn rejects_malformed_input() {
        let tmp = tempfile::tempdir().unwrap();
        let c = ctx(tmp.path().to_owned());
        assert_eq!(run("garbage\n", &c).0, 1);
    }

    #[test]
    fn reader_push_to_for_writes_a_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let c = ctx(tmp.path().to_owned());
        let new = sha('a');
        let (code, err) = run(&format!("{} {new} refs/for/main/feat\n", sha('0')), &c);
        assert_eq!((code, err.as_str()), (0, ""));
        let found = pushsidecar::find_for_ref(tmp.path(), "refs/for/main/feat");
        assert_eq!(found.len(), 1);
        let s = pushsidecar::read_sidecar(&found[0]).unwrap();
        assert_eq!(s.base, "main");
        assert_eq!(s.topic, "feat");
        assert_eq!(
            (s.repo_id, s.user_id, s.new.as_str()),
            (9, Some(42), new.as_str())
        );
        assert_eq!((s.trail, s.title), (None, None));
    }

    #[test]
    fn for_push_without_topic_uses_the_pusher_default() {
        let tmp = tempfile::tempdir().unwrap();
        let c = ctx(tmp.path().to_owned());
        let (code, err) = run(
            &format!("{} {} refs/for/release/1.x\n", sha('0'), sha('b')),
            &c,
        );
        assert_eq!((code, err.as_str()), (0, ""));
        let found = pushsidecar::find_for_ref(tmp.path(), "refs/for/release/1.x");
        let s = pushsidecar::read_sidecar(&found[0]).unwrap();
        assert_eq!(
            (s.base.as_str(), s.topic.as_str()),
            ("release/1.x", "alice")
        );
    }

    #[test]
    fn anonymous_for_push_is_rejected_without_a_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = ctx(tmp.path().to_owned());
        c.user_id = None;
        c.permission = None;
        let (code, err) = run(
            &format!("{} {} refs/for/main/feat\n", sha('0'), sha('a')),
            &c,
        );
        assert_eq!(code, 1);
        assert!(err.contains("require authentication"), "{err}");
        assert!(pushsidecar::find_for_ref(tmp.path(), "refs/for/main/feat").is_empty());
    }

    #[test]
    fn members_mode_needs_an_explicit_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = ctx(tmp.path().to_owned());
        c.refs_for = "members".to_owned();
        let line = format!("{} {} refs/for/main/feat\n", sha('0'), sha('a'));
        assert_eq!(run(&line, &c).0, 1, "non-member reader is rejected");
        c.is_member = true;
        assert_eq!(run(&line, &c), (0, String::new()));
    }

    #[test]
    fn unknown_base_and_deletion_and_trails_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let c = ctx(tmp.path().to_owned());
        let (code, err) = run(&format!("{} {} refs/for/nope/t\n", sha('0'), sha('a')), &c);
        assert_eq!(code, 1);
        assert!(err.contains("unknown base branch"), "{err}");
        let (code, err) = run(
            &format!("{} {} refs/for/main/feat\n", sha('a'), sha('0')),
            &c,
        );
        assert_eq!(
            code, 1,
            "refs/for refs are not stored and cannot be deleted"
        );
        assert!(err.contains("cannot delete"), "{err}");
        let (code, err) = run(
            &format!("{} {} refs/trails/1/changes/1/head\n", sha('0'), sha('a')),
            &c,
        );
        assert_eq!(code, 1);
        assert!(err.contains("server-only"), "{err}");
        assert!(pushsidecar::find_for_ref(tmp.path(), "refs/for/main/feat").is_empty());
    }

    #[test]
    fn bad_push_options_reject_the_whole_push() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = ctx(tmp.path().to_owned());
        c.options = Some(vec!["bogus=1".to_owned()]);
        let (code, err) = run(
            &format!("{} {} refs/for/main/feat\n", sha('0'), sha('a')),
            &c,
        );
        assert_eq!(code, 1);
        assert!(err.contains("bad push option"), "{err}");
        assert!(pushsidecar::find_for_ref(tmp.path(), "refs/for/main/feat").is_empty());
    }

    #[test]
    fn options_without_a_for_line_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = ctx(tmp.path().to_owned());
        c.options = Some(vec!["trail=2".to_owned()]);
        let (code, err) = run("0 1 refs/heads/main\n", &c);
        assert_eq!(code, 1);
        assert!(err.contains("no refs/for ref pushed"), "{err}");
    }

    #[test]
    fn options_land_in_the_sidecar() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = ctx(tmp.path().to_owned());
        c.options = Some(vec!["trail=2".to_owned(), "title=Fix it".to_owned()]);
        let (code, err) = run(
            &format!("{} {} refs/for/main/feat\n", sha('0'), sha('a')),
            &c,
        );
        assert_eq!((code, err.as_str()), (0, ""));
        let found = pushsidecar::find_for_ref(tmp.path(), "refs/for/main/feat");
        let s = pushsidecar::read_sidecar(&found[0]).unwrap();
        assert_eq!(s.trail, Some(2));
        assert_eq!(s.title.as_deref(), Some("Fix it"));
    }

    #[test]
    fn concurrent_pushes_of_the_same_sha_get_distinct_sidecars() {
        // Two pushes of the SAME commit under different topics (different
        // push nonces) must produce two sidecars and, downstream, two changes.
        let tmp = tempfile::tempdir().unwrap();
        let new = sha('a');
        let mut c1 = ctx(tmp.path().to_owned());
        c1.nonce = "nonce-one".to_owned();
        let mut c2 = ctx(tmp.path().to_owned());
        c2.nonce = "nonce-two".to_owned();
        assert_eq!(
            run(&format!("{} {new} refs/for/main/alpha\n", sha('0')), &c1).0,
            0
        );
        assert_eq!(
            run(&format!("{} {new} refs/for/main/beta\n", sha('0')), &c2).0,
            0
        );
        let a = pushsidecar::find_for_ref(tmp.path(), "refs/for/main/alpha");
        let b = pushsidecar::find_for_ref(tmp.path(), "refs/for/main/beta");
        assert_eq!(a.len(), 1);
        assert_eq!(b.len(), 1);
        assert_ne!(a[0], b[0], "distinct sidecar files, not one sha-keyed file");
        assert_eq!(pushsidecar::read_sidecar(&a[0]).unwrap().topic, "alpha");
        assert_eq!(pushsidecar::read_sidecar(&b[0]).unwrap().topic, "beta");
        assert_eq!(pushsidecar::read_sidecar(&a[0]).unwrap().new, new);
        assert_eq!(pushsidecar::read_sidecar(&b[0]).unwrap().new, new);
    }
}
