//! Which refs clients may push (spec §8.2). M0 accepts branches and tags only; `refs/for/*` (M2) and
//! branch protection (M3) extend this through the server socket.

/// One line of `pre-receive` input: `<old-oid> <new-oid> <refname>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub name: String,
}

pub fn parse_line(line: &str) -> Option<RefUpdate> {
    let mut parts = line.split_whitespace();
    let (old, new, name) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    Some(RefUpdate {
        old: old.to_owned(),
        new: new.to_owned(),
        name: name.to_owned(),
    })
}

pub fn check(update: &RefUpdate) -> Result<(), String> {
    if update.name.starts_with("refs/heads/") || update.name.starts_with("refs/tags/") {
        Ok(())
    } else {
        Err(format!(
            "pushing to {} is not allowed; only branches and tags are accepted",
            update.name
        ))
    }
}

/// True for a 40- or 64-char lowercase-hex object id. All-zero markers (create/delete)
/// are NOT oids; callers check those separately.
pub fn is_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64)
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && s.bytes().any(|b| b != b'0')
}

/// True when `s` is all ASCII `0` (a create/delete marker of either hash width).
pub fn is_zero_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b == b'0')
}

/// Strict single-component check shared by bases and topics (spec §8.2, `git
/// check-ref-format`-style): 1–100 bytes, `[A-Za-z0-9-_.]` only, no leading `-`,
/// no leading/trailing `.`, no `..`. The charset alone already excludes spaces,
/// control chars, `~^:?*[\`, and `@{`.
pub fn valid_component(s: &str) -> bool {
    if s.is_empty() || s.len() > 100 {
        return false;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return false;
    }
    if s.starts_with('-') || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    if s.contains("..") {
        return false;
    }
    if s.ends_with(".lock") {
        return false;
    }
    true
}

/// A validated `refs/for/<base>[/<topic>]` target. An empty `topic` means the
/// ref named no topic and the caller must substitute the pusher default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForRef {
    pub base: String,
    pub topic: String,
}

/// Syntax-checks `name` as `refs/for/<base>[/<topic>]` (base may contain `/`).
/// Returns `None` for other namespaces and for any shape violating
/// [`valid_component`]. Base existence is NOT checked here; resolve it with
/// [`split_for`] against the repository's branch list.
pub fn parse_for_ref(name: &str) -> Option<ForRef> {
    let remainder = name.strip_prefix("refs/for/")?;
    if remainder.is_empty() {
        return None;
    }
    if !remainder.split('/').all(valid_component) {
        return None;
    }
    match remainder.rfind('/') {
        Some(i) => Some(ForRef {
            base: remainder[..i].to_owned(),
            topic: remainder[i + 1..].to_owned(),
        }),
        None => Some(ForRef {
            base: remainder.to_owned(),
            topic: String::new(),
        }),
    }
}

/// Deterministic base/topic split needing the branch list: when the whole
/// remainder names an existing branch it is the base and the topic defaults;
/// otherwise the base is all-but-the-last segment (which must name an existing
/// branch) and the topic is the last segment. Anything else is
/// `Err("unknown base branch …")`. This longest-match rule is the only split
/// that accepts both `refs/for/main/foo` and `refs/for/release/1.x/foo`.
pub fn split_for(
    remainder: &str,
    branches: &[String],
    default_topic: &str,
) -> Result<(String, String), String> {
    if branches.iter().any(|b| b == remainder) {
        return Ok((remainder.to_owned(), default_topic.to_owned()));
    }
    let Some((base, topic)) = remainder.rsplit_once('/') else {
        return Err(format!("unknown base branch {remainder:?}: no such branch"));
    };
    if !valid_component(topic) {
        return Err(format!("invalid topic {topic:?} for base {base:?}"));
    }
    if branches.iter().any(|b| b == base) {
        return Ok((base.to_owned(), topic.to_owned()));
    }
    Err(format!("unknown base branch {base:?}: no such branch"))
}

/// Stable per-pusher default topic: the handle lowercased with every char
/// outside `[a-z0-9-_.]` replaced by `-`, trimmed of edge dots/dashes,
/// truncated to 63 chars, never empty (`"topic"`). Re-pushes from the same
/// user land on the same topic, so updates match the same change.
pub fn default_topic(handle: &str) -> String {
    let mut topic: String = handle
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    // Bound by chars first (never split a char), then by bytes.
    if topic.len() > 63 {
        topic.truncate(63);
        while !topic.is_char_boundary(topic.len()) {
            topic.pop();
        }
    }
    let trimmed = topic.trim_matches(['.', '-']).to_owned();
    if trimmed.is_empty() || !valid_component(&trimmed) {
        return "topic".to_owned();
    }
    trimmed
}

/// Parsed `-o` push options (spec §8.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PushOptions {
    pub trail: Option<i64>,
    pub title: Option<String>,
}

/// Reads `GIT_PUSH_OPTION_COUNT` (`None` = no options) and
/// `GIT_PUSH_OPTION_<i>` via `get`. Unknown keys, missing `=`, duplicates,
/// `trail=0`/non-numeric, and empty/overlong/multiline `title=` reject the
/// WHOLE push with `Err("starforge: bad push option …")`.
pub fn parse_push_options(
    count: Option<&str>,
    get: impl Fn(usize) -> Option<String>,
) -> Result<PushOptions, String> {
    let Some(count) = count else {
        return Ok(PushOptions::default());
    };
    let count: usize = count
        .parse()
        .map_err(|_| format!("starforge: bad push option count {count:?}"))?;
    let mut opts = PushOptions::default();
    for i in 0..count {
        let raw = get(i).ok_or_else(|| {
            format!("starforge: bad push option #{i}: missing GIT_PUSH_OPTION_{i}")
        })?;
        let Some((key, value)) = raw.split_once('=') else {
            return Err(format!(
                "starforge: bad push option #{i}: {raw:?} has no '='"
            ));
        };
        match key {
            "trail" => {
                if opts.trail.is_some() {
                    return Err("starforge: bad push option: duplicate trail=".to_owned());
                }
                if value.len() > 19
                    || value.is_empty()
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(format!(
                        "starforge: bad push option: trail={value:?} is not a positive integer"
                    ));
                }
                let n: i64 = value.parse().map_err(|_| {
                    format!("starforge: bad push option: trail={value:?} is not a positive integer")
                })?;
                if n < 1 {
                    return Err(format!(
                        "starforge: bad push option: trail={value:?} is not a positive integer"
                    ));
                }
                opts.trail = Some(n);
            }
            "title" => {
                if opts.title.is_some() {
                    return Err("starforge: bad push option: duplicate title=".to_owned());
                }
                let title = value.trim().to_owned();
                if title.is_empty() || title.chars().count() > 200 || title.contains(['\n', '\r']) {
                    return Err(
                        "starforge: bad push option: title= must be 1-200 chars on one line"
                            .to_owned(),
                    );
                }
                opts.title = Some(title);
            }
            _ => return Err(format!("starforge: bad push option: unknown key {key:?}")),
        }
    }
    Ok(opts)
}

/// How a refname classified by [`check_allowed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefKind {
    Branch,
    Tag,
    For(ForRef),
}

/// Pure push policy (spec §8.2). Branches/tags need no identity at hook level
/// (the RPC layer owns the write gate, so readers stay accepted here);
/// `refs/for` needs an authenticated user with ≥ Read AND (`anyone_with_read`
/// or explicit membership); `refs/trails/*` and everything else fail closed.
pub fn check_allowed(
    name: &str,
    permission: Option<&str>,
    is_member: bool,
    refs_for: &str,
) -> Result<RefKind, String> {
    if name.starts_with("refs/heads/") {
        return Ok(RefKind::Branch);
    }
    if name.starts_with("refs/tags/") {
        return Ok(RefKind::Tag);
    }
    if name.starts_with("refs/for/") {
        let target = parse_for_ref(name).ok_or_else(|| {
            format!("pushing to {name} is not allowed: malformed refs/for target")
        })?;
        let level = permission
            .filter(|p| permission_at_least_read(p))
            .ok_or_else(|| {
                format!("pushing to {name} is not allowed: refs/for pushes require authentication")
            })?;
        let _ = level;
        match refs_for {
            "anyone_with_read" => Ok(RefKind::For(target)),
            "members" if is_member => Ok(RefKind::For(target)),
            "members" => Err(format!(
                "pushing to {name} is not allowed: repository restricts refs/for to members"
            )),
            other => Err(format!(
                "pushing to {name} is not allowed: unknown refs/for access {other:?}"
            )),
        }
    } else if name.starts_with("refs/trails/") {
        Err(format!(
            "pushing to {name} is not allowed: refs/trails/* is server-only"
        ))
    } else {
        Err(format!(
            "pushing to {name} is not allowed; only branches and tags are accepted"
        ))
    }
}

/// True for any known permission level (`read|triage|write|maintain|admin`);
/// every known level grants at least read.
fn permission_at_least_read(permission: &str) -> bool {
    matches!(
        permission,
        "read" | "triage" | "write" | "maintain" | "admin"
    )
}

/// Branch/tag pushes need a write-level permission AND a write-scoped token.
/// The RPC gate admits readers (for `refs/for` only), so the hook owns this
/// half of the split; unknown or lower permissions fail closed.
pub fn check_branch_push(permission: Option<&str>, scope_write: bool) -> Result<(), String> {
    if !matches!(permission, Some("write" | "maintain" | "admin")) {
        return Err("branch and tag pushes need write permission".to_owned());
    }
    if !scope_write {
        return Err("branch and tag pushes need a token with repo:write scope".to_owned());
    }
    Ok(())
}

/// One branch rule inside the hook's protection snapshot: the glob pattern
/// (`None` matches all branches), the three blocks, and whether the pusher
/// is exempt from the direct-push block (a user or team allow-list entry).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct BranchRule {
    #[serde(default)]
    pub pattern: Option<String>,
    pub direct: bool,
    pub force: bool,
    pub delete: bool,
    pub exempt: bool,
}

/// The parsed `STARFORGE_PROTECTION` snapshot: only `branches` is enforced
/// here (tags and namespaces arrive with B2). Unknown fields are ignored so
/// newer snapshots stay readable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    pub branches: Vec<BranchRule>,
}

/// Parses the hook's protection snapshot. Anything missing or malformed —
/// bad JSON, a wrong version, a missing `branches` array, or a rule without
/// its block kinds — is `Err`: the hook fails closed on it.
pub fn parse_protection(raw: &str) -> Result<Protection, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("invalid protection snapshot: {e}"))?;
    let version = value
        .get("v")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "invalid protection snapshot: missing version".to_owned())?;
    if version != 1 {
        return Err(format!(
            "invalid protection snapshot: unsupported version {version}"
        ));
    }
    let branches = value
        .get("branches")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "invalid protection snapshot: missing branches".to_owned())?;
    let mut rules = Vec::with_capacity(branches.len());
    for entry in branches {
        let rule: BranchRule = serde_json::from_value(entry.clone())
            .map_err(|e| format!("invalid protection snapshot: bad branch rule: {e}"))?;
        rules.push(rule);
    }
    Ok(Protection { branches: rules })
}

/// Minimal glob: `*` matches any (possibly empty) run, `?` matches exactly
/// one character, everything else matches literally. Case-sensitive. This is
/// the single implementation: `starforged-core` gates, merges, and the change
/// scan all call it — `None` and `""` match all branches.
pub fn pattern_matches(pattern: Option<&str>, branch: &str) -> bool {
    let pat = match pattern {
        None | Some("") => return true,
        Some(p) => p,
    };
    glob_match(pat.as_bytes(), branch.as_bytes())
}

fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    let (mut px, mut tx) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while tx < text.len() {
        if px < pat.len() && (pat[px] == b'?' || pat[px] == text[tx]) {
            px += 1;
            tx += 1;
        } else if px < pat.len() && pat[px] == b'*' {
            star = Some(px);
            mark = tx;
            px += 1;
        } else if let Some(s) = star {
            px = s + 1;
            mark += 1;
            tx = mark;
        } else {
            return false;
        }
    }
    while px < pat.len() && pat[px] == b'*' {
        px += 1;
    }
    px == pat.len()
}

fn rule_label(pattern: &Option<String>) -> String {
    pattern.clone().unwrap_or_else(|| "all branches".to_owned())
}

/// Enforces the snapshot on one branch push. Every matching rule applies; a
/// push is refused when ANY matching rule blocks it: deletions with the new
/// value at the zero oid and a `delete` block, force pushes (both oids set,
/// old not an ancestor of new) with a `force` block, and any other update
/// with a `direct` block unless the pusher is exempt on THAT rule. The
/// exemption never covers force pushes or deletions. Non-branch refs pass:
/// tags and namespaces are enforced elsewhere. Refusals name the ref and
/// the rule pattern.
pub fn check_protected_update(
    protection: &Protection,
    update: &RefUpdate,
    is_ancestor: impl Fn(&str, &str) -> bool,
) -> Result<(), String> {
    let Some(branch) = update.name.strip_prefix("refs/heads/") else {
        return Ok(());
    };
    let deleting = is_zero_oid(&update.new);
    let creating = is_zero_oid(&update.old);
    for rule in &protection.branches {
        if !pattern_matches(rule.pattern.as_deref(), branch) {
            continue;
        }
        let label = rule_label(&rule.pattern);
        if deleting {
            if rule.delete {
                return Err(format!(
                    "pushing to {} is not allowed: branch protection rule '{label}' blocks deletion",
                    update.name
                ));
            }
            continue;
        }
        let forced =
            !creating && update.old != update.new && !is_ancestor(&update.old, &update.new);
        if forced && rule.force {
            return Err(format!(
                "pushing to {} is not allowed: branch protection rule '{label}' blocks force pushes",
                update.name
            ));
        }
        if rule.direct && !rule.exempt {
            return Err(format!(
                "pushing to {} is not allowed: branch protection rule '{label}' blocks direct pushes (open a trail instead)",
                update.name
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(name: &str) -> RefUpdate {
        RefUpdate {
            old: "0".repeat(40),
            new: "1".repeat(40),
            name: name.into(),
        }
    }

    #[test]
    fn parses_hook_lines() {
        assert_eq!(
            parse_line("aaa bbb refs/heads/main"),
            Some(RefUpdate {
                old: "aaa".into(),
                new: "bbb".into(),
                name: "refs/heads/main".into()
            })
        );
        assert_eq!(parse_line("aaa bbb"), None);
        assert_eq!(parse_line("aaa bbb refs/heads/main extra"), None);
    }

    #[test]
    fn only_branches_and_tags_are_accepted() {
        assert!(check(&update("refs/heads/main")).is_ok());
        assert!(check(&update("refs/heads/feature/x")).is_ok());
        assert!(check(&update("refs/tags/v1.0")).is_ok());
        for rejected in [
            "refs/notes/commits",
            "refs/entire/checkpoints/ab/x",
            "refs/trails/1/changes/1/head",
            "refs/for/main",
            "HEAD",
        ] {
            let err = check(&update(rejected)).unwrap_err();
            assert!(err.contains(rejected), "{err}");
        }
    }

    #[test]
    fn for_ref_grammar_accepts_bases_with_slashes() {
        // (refname, expected base, expected topic; empty topic = pusher default)
        for (name, base, topic) in [
            ("refs/for/main", "main", ""),
            ("refs/for/main/my-topic", "main", "my-topic"),
            ("refs/for/release/1.x/feat", "release/1.x", "feat"),
            ("refs/for/a/b/c/t", "a/b/c", "t"),
            ("refs/for/main/v1.0_rc-1", "main", "v1.0_rc-1"),
        ] {
            let parsed = parse_for_ref(name).unwrap_or_else(|| panic!("accept {name}"));
            assert_eq!(
                (parsed.base.as_str(), parsed.topic.as_str()),
                (base, topic),
                "{name}"
            );
        }
    }

    #[test]
    fn for_ref_grammar_rejects_bad_shapes() {
        let long = "x".repeat(101);
        let cases = [
            "refs/for/",
            "refs/for//t",
            "refs/for/main//t",
            "refs/for/main/",
            "refs/for/../etc",
            "refs/for/main/..",
            "refs/for/-main/t",
            "refs/for/main/-t",
            "refs/for/main/.t",
            "refs/for/main/t.",
            "refs/for/ma in/t",
            "refs/for/main/t itle",
            "refs/for/main/t~1",
            "refs/for/main/t^2",
            "refs/for/main/t:v",
            "refs/for/main/t?v",
            "refs/for/main/t*v",
            "refs/for/main/t[v",
            "refs/for/main/t\\v",
            "refs/for/main/t@{1}",
            "refs/for/main/.lock",
            "refs/heads/main",
            "refs/for/main/t/extra/../x",
        ];
        for name in cases {
            assert!(parse_for_ref(name).is_none(), "reject {name}");
        }
        assert!(
            parse_for_ref(&format!("refs/for/main/{long}")).is_none(),
            "reject long topic"
        );
        assert!(
            parse_for_ref(&format!("refs/for/{long}/t")).is_none(),
            "reject long segment"
        );
        assert!(
            parse_for_ref("refs/for/main/\u{7}").is_none(),
            "reject control char"
        );
    }

    #[test]
    fn split_for_prefers_the_longest_existing_branch() {
        let branches = [
            "main".to_owned(),
            "release/1.x".to_owned(),
            "a/b".to_owned(),
            "a".to_owned(),
        ];
        let has = |v: &[String]| v.to_vec();
        assert_eq!(
            split_for("main", &has(&branches), "d").unwrap(),
            ("main".to_owned(), "d".to_owned())
        );
        // Whole remainder names a branch: topic defaults even when a shorter prefix is also a branch.
        assert_eq!(
            split_for("a/b", &has(&branches), "d").unwrap(),
            ("a/b".to_owned(), "d".to_owned())
        );
        assert_eq!(
            split_for("release/1.x/feat", &has(&branches), "d").unwrap(),
            ("release/1.x".to_owned(), "feat".to_owned())
        );
        assert_eq!(
            split_for("a/b/c", &has(&branches), "d").unwrap(),
            ("a/b".to_owned(), "c".to_owned())
        );
        assert!(
            split_for("nope", &has(&branches), "d")
                .unwrap_err()
                .contains("unknown base branch")
        );
        assert!(
            split_for("nope/t", &has(&branches), "d")
                .unwrap_err()
                .contains("unknown base branch")
        );
        // Known base but bad topic still fails closed.
        assert!(split_for("main/-t", &has(&branches), "d").is_err());
    }

    #[test]
    fn default_topic_is_stable_and_always_valid() {
        assert_eq!(default_topic("Alice"), "alice");
        assert_eq!(default_topic("Bob Smith!"), "bob-smith");
        assert_eq!(default_topic(""), "topic");
        assert_eq!(default_topic("!!!"), "topic");
        assert_eq!(default_topic("A_B.C-D"), "a_b.c-d");
        assert!(default_topic("x".repeat(200).as_str()).len() <= 63);
        for handle in [
            "Ada",
            "x-y_z.9",
            "UPPER lower",
            "a/b\\c",
            "@@@",
            ".dots.",
            "--dash--",
            "münchen",
        ] {
            let topic = default_topic(handle);
            assert!(
                valid_component(&topic),
                "default_topic({handle:?}) = {topic:?}"
            );
        }
    }

    #[test]
    fn push_options_parse_trail_and_title() {
        let none = |_: usize| None;
        assert_eq!(
            parse_push_options(None, none).unwrap(),
            PushOptions {
                trail: None,
                title: None
            }
        );
        let get = |vars: Vec<String>| move |i: usize| vars.get(i).cloned();
        let opts = parse_push_options(
            Some("2"),
            get(vec!["trail=4".into(), "title=Fix it".into()]),
        )
        .unwrap();
        assert_eq!(
            opts,
            PushOptions {
                trail: Some(4),
                title: Some("Fix it".into())
            }
        );
        // Unknown keys, missing '=', duplicates, and bad values reject the whole push.
        for vars in [
            vec!["bogus=1"],
            vec!["trail"],
            vec!["trail=1", "trail=2"],
            vec!["title=a", "title=b"],
            vec!["trail=0"],
            vec!["trail=-3"],
            vec!["trail=abc"],
            vec!["trail="],
            vec!["trail=12345678901234567890"],
            vec!["title="],
            vec!["title=   "],
            vec!["title=a\nb"],
            vec!["title=a\rb"],
        ] {
            let n = vars.len().to_string();
            assert!(
                parse_push_options(Some(&n), get(vars.into_iter().map(String::from).collect()))
                    .is_err()
            );
        }
        assert!(
            parse_push_options(Some("1"), none).is_err(),
            "missing var is an error"
        );
        assert!(parse_push_options(Some("many"), none).is_err());
        let long = "t".repeat(201);
        assert!(parse_push_options(Some("1"), get(vec![format!("title={long}")])).is_err());
    }

    #[test]
    fn check_allowed_matrix() {
        // Branches and tags never need an identity at hook level (the RPC layer owns the write gate).
        assert!(check_allowed("refs/heads/main", None, false, "anyone_with_read").is_ok());
        assert!(check_allowed("refs/tags/v1", None, false, "members").is_ok());
        // Readers may push reviews where the repo allows it; anonymous never may.
        assert!(check_allowed("refs/for/main/t", Some("read"), false, "anyone_with_read").is_ok());
        assert!(check_allowed("refs/for/main", Some("triage"), false, "anyone_with_read").is_ok());
        assert!(check_allowed("refs/for/main/t", None, false, "anyone_with_read").is_err());
        assert!(check_allowed("refs/for/main/t", None, true, "anyone_with_read").is_err());
        // members-only repos need an explicit grant; read collaborators count.
        assert!(check_allowed("refs/for/main/t", Some("read"), true, "members").is_ok());
        assert!(check_allowed("refs/for/main/t", Some("read"), false, "members").is_err());
        assert!(check_allowed("refs/for/main/t", Some("write"), false, "members").is_err());
        // Malformed refs and unknown modes fail closed.
        assert!(
            check_allowed("refs/for/main/..", Some("write"), true, "anyone_with_read").is_err()
        );
        assert!(check_allowed("refs/for/main/t", Some("write"), true, "everyone").is_err());
        assert!(
            check_allowed(
                "refs/for/main/t",
                Some("superuser"),
                true,
                "anyone_with_read"
            )
            .is_err()
        );
        // refs/trails/* stays server-only even for writers.
        assert!(
            check_allowed(
                "refs/trails/1/changes/1/head",
                Some("admin"),
                true,
                "anyone_with_read"
            )
            .is_err()
        );
        assert!(
            check_allowed(
                "refs/trails/1/changes/1/head",
                None,
                false,
                "anyone_with_read"
            )
            .is_err()
        );
        assert!(check_allowed("refs/notes/x", Some("admin"), true, "anyone_with_read").is_err());
    }

    #[test]
    fn protection_blocks_each_kind() {
        let pushing = |old: &str, new: &str| RefUpdate {
            old: old.into(),
            new: new.into(),
            name: "refs/heads/main".into(),
        };
        let create = pushing(&"0".repeat(40), &"a".repeat(40));
        let ff = pushing(&"a".repeat(40), &"b".repeat(40));
        let delete = pushing(&"a".repeat(40), &"0".repeat(40));
        // Direct-push block: creates and fast-forwards refuse, naming the pattern.
        let direct = parse_protection(
            r#"{"v":1,"branches":[{"pattern":"main","direct":true,"force":false,"delete":false,"exempt":false}],"tags":[],"tag_ok":true,"namespaces":[]}"#,
        )
        .unwrap();
        for update in [&create, &ff] {
            let err = check_protected_update(&direct, update, |_, _| true).unwrap_err();
            assert!(err.contains("refs/heads/main"), "{err}");
            assert!(err.contains("main"), "{err}");
        }
        assert!(check_protected_update(&direct, &delete, |_, _| true).is_ok());
        // Force-push block: a non-ancestor move refuses, an ancestor move passes.
        let force = parse_protection(
            r#"{"v":1,"branches":[{"pattern":"main","direct":false,"force":true,"delete":false,"exempt":false}],"tags":[],"tag_ok":true,"namespaces":[]}"#,
        )
        .unwrap();
        assert!(check_protected_update(&force, &ff, |_, _| true).is_ok());
        let err = check_protected_update(&force, &ff, |_, _| false).unwrap_err();
        assert!(err.contains("refs/heads/main"), "{err}");
        assert!(err.contains("main"), "{err}");
        assert!(check_protected_update(&force, &create, |_, _| false).is_ok());
        assert!(check_protected_update(&force, &delete, |_, _| false).is_ok());
        // Deletion block.
        let del = parse_protection(
            r#"{"v":1,"branches":[{"pattern":"main","direct":false,"force":false,"delete":true,"exempt":false}],"tags":[],"tag_ok":true,"namespaces":[]}"#,
        )
        .unwrap();
        let err = check_protected_update(&del, &delete, |_, _| true).unwrap_err();
        assert!(err.contains("refs/heads/main"), "{err}");
        assert!(err.contains("main"), "{err}");
        assert!(check_protected_update(&del, &create, |_, _| true).is_ok());
        assert!(check_protected_update(&del, &ff, |_, _| true).is_ok());
    }

    #[test]
    fn protection_applies_every_matching_rule() {
        let update = RefUpdate {
            old: "0".repeat(40),
            new: "a".repeat(40),
            name: "refs/heads/main".into(),
        };
        // Two rules match `main`; either one blocks.
        let both = parse_protection(
            r#"{"v":1,"branches":[{"pattern":"*","direct":false,"force":false,"delete":false,"exempt":false},{"pattern":"main","direct":true,"force":false,"delete":false,"exempt":false}],"tags":[],"tag_ok":true,"namespaces":[]}"#,
        )
        .unwrap();
        assert!(check_protected_update(&both, &update, |_, _| true).is_err());
        // A null pattern matches all branches; other branches are unaffected.
        let all = parse_protection(
            r#"{"v":1,"branches":[{"pattern":null,"direct":true,"force":false,"delete":false,"exempt":false}],"tags":[],"tag_ok":true,"namespaces":[]}"#,
        )
        .unwrap();
        assert!(check_protected_update(&all, &update, |_, _| true).is_err());
        let other = RefUpdate {
            name: "refs/heads/feature".into(),
            ..update.clone()
        };
        let scoped = parse_protection(
            r#"{"v":1,"branches":[{"pattern":"main","direct":true,"force":false,"delete":false,"exempt":false}],"tags":[],"tag_ok":true,"namespaces":[]}"#,
        )
        .unwrap();
        assert!(check_protected_update(&scoped, &other, |_, _| true).is_ok());
        // Non-branch refs are not subject to branch protection.
        let tag = RefUpdate {
            name: "refs/tags/v1".into(),
            ..update.clone()
        };
        assert!(check_protected_update(&all, &tag, |_, _| true).is_ok());
    }

    #[test]
    fn protection_allowlist_exempts_only_the_direct_push_block() {
        let create = RefUpdate {
            old: "0".repeat(40),
            new: "a".repeat(40),
            name: "refs/heads/main".into(),
        };
        let force = RefUpdate {
            old: "a".repeat(40),
            new: "b".repeat(40),
            ..create.clone()
        };
        let delete = RefUpdate {
            old: "a".repeat(40),
            new: "0".repeat(40),
            ..create.clone()
        };
        let exempt = parse_protection(
            r#"{"v":1,"branches":[{"pattern":"main","direct":true,"force":true,"delete":true,"exempt":true}],"tags":[],"tag_ok":true,"namespaces":[]}"#,
        )
        .unwrap();
        assert!(check_protected_update(&exempt, &create, |_, _| false).is_ok());
        assert!(check_protected_update(&exempt, &force, |_, _| true).is_ok());
        // Exemption never covers force pushes or deletions.
        assert!(check_protected_update(&exempt, &force, |_, _| false).is_err());
        assert!(check_protected_update(&exempt, &delete, |_, _| true).is_err());
        // A non-exempt rule still blocks even when another rule exempts.
        let mixed = parse_protection(
            r#"{"v":1,"branches":[{"pattern":"main","direct":true,"force":false,"delete":false,"exempt":true},{"pattern":"*","direct":true,"force":false,"delete":false,"exempt":false}],"tags":[],"tag_ok":true,"namespaces":[]}"#,
        )
        .unwrap();
        assert!(check_protected_update(&mixed, &create, |_, _| true).is_err());
    }

    #[test]
    fn protection_snapshot_must_parse() {
        for bad in [
            "",
            "not json",
            "{}",
            r#"{"v":2,"branches":[]}"#,
            r#"{"v":1}"#,
            r#"{"v":1,"branches":[{}]}"#,
        ] {
            assert!(parse_protection(bad).is_err(), "{bad:?} must fail closed");
        }
        // Unknown top-level fields are tolerated for forward compatibility.
        let ok = parse_protection(
            r#"{"v":1,"branches":[],"tags":["v*"],"tag_ok":false,"namespaces":[],"future":1}"#,
        )
        .unwrap();
        assert!(ok.branches.is_empty());
    }

    #[test]
    fn oid_shapes() {
        assert!(is_oid(&"a".repeat(40)));
        assert!(is_oid(&"f".repeat(64)));
        assert!(!is_oid(&"a".repeat(39)));
        assert!(!is_oid("xyz"));
        assert!(
            !is_oid(&"0".repeat(40)),
            "all-zero is a deletion marker, not an oid"
        );
    }
}
