//! Entry points that git runs inside hosted repositories (see `starforged_git::init::HOOKS`).
//! Anything written to stderr reaches the pusher as `remote: …`.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use starforged_git::{merge, pushsidecar, read, refpolicy};

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
    /// The parsed `STARFORGE_PROTECTION` snapshot; `Err` (missing or
    /// malformed) fails closed for branch and tag pushes, while `refs/for`
    /// keeps working.
    pub protection: Result<refpolicy::Protection, String>,
    pub git_dir: PathBuf,
    pub branches: Vec<String>,
    pub nonce: String,
    /// `None` when `GIT_PUSH_OPTION_COUNT` is absent (no `-o` flags).
    pub options: Option<Vec<String>>,
    /// M5a `refs/for` rate-limit snapshot: `None` when the limit is disabled
    /// or absent (no budget enforced), otherwise the pusher's remaining
    /// hourly new-change budget.
    pub refs_for_budget: Option<i64>,
    /// The pusher's own open agit topics in this repository as
    /// `base/topic` lines (`STARFORGE_REFS_FOR_TOPICS`); a pushed pair not
    /// in this list opens a NEW change and counts against the budget.
    pub refs_for_topics: Vec<String>,
    /// M4b: a one-time import is pending/running on this repository; every
    /// ref update is refused ("import in progress").
    pub import_in_progress: bool,
    /// M4b: the repository is an enabled pull mirror; every branch/tag
    /// push is refused ("this repository is a pull mirror"), while
    /// `refs/for` stays open for discussion.
    pub mirror: bool,
    /// Repository-size limit in bytes (`STARFORGE_MAX_REPO_BYTES`); `0`
    /// disables the limit.
    pub max_repo_bytes: u64,
    /// Quarantined incoming objects for this push (`GIT_QUARANTINE_PATH`):
    /// git stages the incoming pack under
    /// `$GIT_DIR/objects/tmp_objdir-incoming-*` and points this variable at
    /// it before running the hook, so the repository-size check below can
    /// measure existing objects plus the incoming ones. `None` outside a
    /// real receive-pack run (tests inject it or rely on the glob scan).
    pub quarantine_path: Option<PathBuf>,
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
        let protection = match env("STARFORGE_PROTECTION") {
            Some(raw) => refpolicy::parse_protection(&raw),
            None => Err("missing protection snapshot".to_owned()),
        };
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
            protection,
            git_dir,
            branches,
            nonce: nonce.unwrap_or_else(pushsidecar::new_nonce),
            options,
            refs_for_budget: env("STARFORGE_REFS_FOR_BUDGET").and_then(|v| v.parse().ok()),
            refs_for_topics: env("STARFORGE_REFS_FOR_TOPICS")
                .map(|raw| {
                    raw.lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            import_in_progress: env("STARFORGE_IMPORT_IN_PROGRESS").is_some_and(|v| v == "1"),
            mirror: env("STARFORGE_MIRROR").is_some_and(|v| v == "1"),
            max_repo_bytes: env("STARFORGE_MAX_REPO_BYTES")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            quarantine_path: env("GIT_QUARANTINE_PATH").map(PathBuf::from),
        }
    }
}

/// Sum of the file sizes under `root`, not descending into any path in
/// `skip`. A missing root measures as zero (an empty repository has no
/// objects directory to speak of); any other read failure is an error so
/// the caller can fail open with a warning instead of a wrong total.
fn dir_size(root: &std::path::Path, skip: &[PathBuf]) -> Result<u64, String> {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        if skip.contains(&path) {
            continue;
        }
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("measuring {}: {err}", path.display())),
        };
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
            continue;
        }
        if !metadata.is_dir() {
            continue;
        }
        let entries = std::fs::read_dir(&path)
            .map_err(|err| format!("measuring {}: {err}", path.display()))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("measuring {}: {err}", path.display()))?;
            stack.push(entry.path());
        }
    }
    Ok(total)
}

/// Total object storage for the size limit: everything under
/// `$GIT_DIR/objects` plus the quarantined incoming objects. The
/// quarantine directory (git's `$GIT_DIR/objects/tmp_objdir-incoming-*`,
/// named by `GIT_QUARANTINE_PATH`) lives inside `objects`, so it is
/// excluded from the first walk and added back explicitly — never counted
/// twice, never missed. Without the environment variable the incoming
/// directories are found by the same name glob git uses.
fn repo_size_at_hook_time(ctx: &HookCtx) -> Result<u64, String> {
    let objects = ctx.git_dir.join("objects");
    let mut quarantine: Vec<PathBuf> = match &ctx.quarantine_path {
        Some(path) => vec![path.clone()],
        None => {
            let mut found = Vec::new();
            if let Ok(entries) = std::fs::read_dir(&objects) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    if name.to_string_lossy().starts_with("tmp_objdir-incoming-") {
                        found.push(entry.path());
                    }
                }
            }
            found
        }
    };
    // The explicit path may not sit directly in `objects`; the skip list
    // only ever matches exact paths, so an outside path skips nothing.
    quarantine.sort();
    quarantine.dedup();
    let mut total = dir_size(&objects, &quarantine)?;
    for path in &quarantine {
        total = total.saturating_add(dir_size(path, &[])?);
    }
    Ok(total)
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
    // M4b: while a one-time import is pending or running, pushes are
    // refused outright — no ref (branch, tag, refs/for, or namespace) moves.
    if ctx.import_in_progress {
        let _ = writeln!(
            err,
            "starforge: repository import in progress; pushes are refused"
        );
        return 1;
    }
    // Repository-size limit, measured now — at hook time, so the incoming
    // objects quarantined by receive-pack count towards the total and a
    // single push can never land the repository above the limit. Refused
    // objects are discarded by git with the push. A measurement failure
    // fails open with a warning (the pusher sees it as `remote: …`).
    if ctx.max_repo_bytes > 0 {
        match repo_size_at_hook_time(ctx) {
            Ok(total) if total >= ctx.max_repo_bytes => {
                let _ = writeln!(
                    err,
                    "starforge: repository size limit reached ({} MiB of {} MiB); pushes are refused",
                    total / (1024 * 1024),
                    ctx.max_repo_bytes / (1024 * 1024)
                );
                return 1;
            }
            Ok(_) => {}
            Err(measure_err) => {
                let _ = writeln!(
                    err,
                    "starforge: warning: repository size measurement failed ({measure_err}); allowing push"
                );
            }
        }
    }
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
        // M4b pull mirror: branches, tags, and namespaces never move by
        // push; `refs/for` stays open (Trails can be opened for discussion).
        if ctx.mirror && !update.name.starts_with("refs/for/") {
            let _ = writeln!(
                err,
                "starforge: pushing to {} is not allowed: this repository is a pull mirror",
                update.name
            );
            code = 1;
            continue;
        }
        let namespaces: &[String] = ctx
            .protection
            .as_ref()
            .map(|protection| protection.namespaces.as_slice())
            .unwrap_or(&[]);
        // `refs/for` needs an author: deploy keys push with permission but no
        // user (M3c D5), so they are refused here like anonymous pushes.
        match refpolicy::check_allowed(
            &update.name,
            ctx.user_id.and(permission),
            ctx.is_member,
            &ctx.refs_for,
            namespaces,
        ) {
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
            Ok(refpolicy::RefKind::Branch) => {
                // The RPC admits readers for `refs/for`, so branches
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
                    continue;
                }
                // Then the protection snapshot. A missing or malformed
                // snapshot fails closed; ancestry runs with the hook's
                // environment so quarantined objects stay visible.
                match &ctx.protection {
                    Err(reason) => {
                        let _ = writeln!(
                            err,
                            "starforge: pushing to {} is not allowed: protection snapshot {reason}",
                            update.name
                        );
                        code = 1;
                    }
                    Ok(protection) => {
                        let git_dir = ctx.git_dir.clone();
                        if let Err(message) =
                            refpolicy::check_protected_update(protection, &update, |old, new| {
                                merge::is_ancestor_inherit_env(&git_dir, old, new).unwrap_or(false)
                            })
                        {
                            let _ = writeln!(err, "starforge: {message}");
                            code = 1;
                        }
                    }
                }
            }
            Ok(refpolicy::RefKind::Tag) => {
                // Tags need the write tier too; then the snapshot's tag
                // globs: a matching pattern needs `tag_ok` (maintain+)
                // to create, move, or delete. A missing or malformed
                // snapshot fails closed.
                if let Err(message) =
                    refpolicy::check_branch_push(ctx.permission.as_deref(), ctx.scope_write)
                {
                    let _ = writeln!(
                        err,
                        "starforge: pushing to {} is not allowed: {message}",
                        update.name
                    );
                    code = 1;
                    continue;
                }
                match &ctx.protection {
                    Err(reason) => {
                        let _ = writeln!(
                            err,
                            "starforge: pushing to {} is not allowed: protection snapshot {reason}",
                            update.name
                        );
                        code = 1;
                    }
                    Ok(protection) => {
                        if let Err(message) = refpolicy::check_tag_update(protection, &update) {
                            let _ = writeln!(err, "starforge: {message}");
                            code = 1;
                        }
                    }
                }
            }
            Ok(refpolicy::RefKind::Namespace) => {
                // Allow-listed namespaces need the write tier like branches,
                // but are never subject to branch protection. A missing or
                // malformed snapshot still fails closed.
                if let Err(message) =
                    refpolicy::check_branch_push(ctx.permission.as_deref(), ctx.scope_write)
                {
                    let _ = writeln!(
                        err,
                        "starforge: pushing to {} is not allowed: {message}",
                        update.name
                    );
                    code = 1;
                    continue;
                }
                if let Err(reason) = &ctx.protection {
                    let _ = writeln!(
                        err,
                        "starforge: pushing to {} is not allowed: protection snapshot {reason}",
                        update.name
                    );
                    code = 1;
                }
            }
        }
    }
    // M5a `refs/for` rate limit: refuse the NEW changes past the pusher's
    // hourly budget; updates to the pusher's own open topics are free.
    if let Some(budget) = ctx.refs_for_budget {
        let mut spent = 0;
        accepted.retain(|(refname, base, topic, _, _)| {
            if !refpolicy::is_new_for_topic(&ctx.refs_for_topics, base, topic) {
                return true;
            }
            if spent < budget {
                spent += 1;
                true
            } else {
                let _ = writeln!(
                    err,
                    "starforge: pushing to {refname} is not allowed: refs/for new-change hourly limit exceeded"
                );
                code = 1;
                false
            }
        });
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
            protection: Ok(refpolicy::Protection {
                branches: vec![],
                tags: vec![],
                tag_ok: true,
                namespaces: vec![],
            }),
            git_dir,
            branches: vec!["main".to_owned(), "release/1.x".to_owned()],
            nonce: "testnonce".to_owned(),
            options: None,
            refs_for_budget: None,
            refs_for_topics: Vec::new(),
            import_in_progress: false,
            mirror: false,
            max_repo_bytes: 0,
            quarantine_path: None,
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

    fn write_sized(path: &std::path::Path, bytes: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn refuses_pushes_at_repository_size_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let git_dir = tmp.path().to_owned();
        // Existing object storage: 1024 bytes under objects/pack.
        write_sized(&git_dir.join("objects/pack/pack-existing"), 1024);
        // Quarantined incoming objects: 2048 bytes — found by the
        // tmp_objdir-incoming-* glob when GIT_QUARANTINE_PATH is absent.
        write_sized(
            &git_dir.join("objects/tmp_objdir-incoming-abc/pack/pack-incoming"),
            2048,
        );
        let mut c = ctx(git_dir.clone());
        c.permission = Some("write".to_owned());
        // 1024 existing + 2048 incoming = 3072: at/above a 3072 limit the
        // push is refused with the size message (and not double-counted).
        c.max_repo_bytes = 3072;
        let (code, err) = run("0 1 refs/heads/main\n", &c);
        assert_eq!(code, 1);
        assert!(err.contains("repository size limit reached"), "{err}");
        // Below the limit the same total is accepted.
        c.max_repo_bytes = 4096;
        assert_eq!(run("0 1 refs/heads/main\n", &c), (0, String::new()));
        // An explicit quarantine path outside objects counts too.
        let incoming = tmp.path().join("elsewhere-incoming");
        write_sized(&incoming.join("pack-incoming"), 2048);
        c.quarantine_path = Some(incoming);
        c.max_repo_bytes = 3072;
        let (code, err) = run("0 1 refs/heads/main\n", &c);
        assert_eq!(code, 1);
        assert!(err.contains("repository size limit reached"), "{err}");
        // Disabled: any size accepted, and no measurement happens.
        c.max_repo_bytes = 0;
        assert_eq!(run("0 1 refs/heads/main\n", &c), (0, String::new()));
    }

    #[test]
    fn size_measurement_failure_fails_open_with_a_warning() {
        let tmp = tempfile::tempdir().unwrap();
        // A file where the git dir should be: walking objects under it
        // fails, so the push is allowed with a warning, never refused.
        let not_a_dir = tmp.path().join("not-a-dir");
        std::fs::write(&not_a_dir, b"not a git dir").unwrap();
        let mut c = ctx(not_a_dir);
        c.permission = Some("write".to_owned());
        c.max_repo_bytes = 1;
        let (code, err) = run("0 1 refs/heads/main\n", &c);
        assert_eq!(code, 0);
        assert!(err.contains("measurement failed"), "{err}");
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
    #[test]
    fn missing_snapshot_fails_closed_for_branches_and_tags() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = ctx(tmp.path().to_owned());
        c.permission = Some("write".to_owned());
        c.protection = Err("missing protection snapshot".to_owned());
        for line in ["0 1 refs/heads/main\n", "0 2 refs/tags/v1\n"] {
            let (code, err) = run(line, &c);
            assert_eq!(code, 1, "{line}");
            assert!(err.contains("protection snapshot"), "{err}");
        }
        // `refs/for` keeps working without a snapshot.
        let (code, err) = run(
            &format!("{} {} refs/for/main/feat\n", sha('0'), sha('a')),
            &c,
        );
        assert_eq!((code, err.as_str()), (0, ""));
    }

    #[test]
    fn protected_direct_push_refuses_with_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let mut c = ctx(tmp.path().to_owned());
        c.permission = Some("write".to_owned());
        c.protection = refpolicy::parse_protection(
            r#"{"v":1,"branches":[{"pattern":"main","direct":true,"force":false,"delete":false,"exempt":false}],"tags":[],"tag_ok":true,"namespaces":[]}"#,
        );
        let (code, err) = run(&format!("{} {} refs/heads/main\n", sha('0'), sha('a')), &c);
        assert_eq!(code, 1);
        assert!(err.contains("refs/heads/main"), "{err}");
        assert!(err.contains("'main'"), "{err}");
    }
}
