//! Task A5: org permission sweep (M3a).
//!
//! Matrix over grant source (org owner; base read/write; team
//! read/triage/write/maintain/admin with all-repos or a selected set;
//! collaborator; none) × visibility (public, internal, private) × surface:
//!
//! - web repository page;
//! - API repository read;
//! - `git clone`;
//! - `git push` to a branch (Write threshold; below it the push fails);
//! - `refs/for` push with `refs_for_access = members` (member threshold,
//!   through the read-tier token path);
//! - gate approval counting (only authors holding Write count);
//! - §6.4: an unpublished session on a public repository through the
//!   session page, the Trail Sessions tab, `has_sessions`, timeline rows,
//!   and the commit panel.
//!
//! Expected: the effective level and member status match D4. Non-readers
//! get 404 on web/API; below-threshold actors get 403 on the API and a
//! rejected push over git. Revocation (member removal, team deletion, base
//! lowering, transfer away) is immediate on every surface. Every user-only
//! path (D1) refuses an org handle. The XSS helpers mirror
//! `web_discovery_security.rs`.

mod common;

use std::collections::HashMap;
use std::path::PathBuf;

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::User;
use starforged_core::gate_rules::GateRuleInput;
use starforged_core::orgs::{NewOrgInput, NewTeamInput, OrgPatch, OrgRole};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::CreateRepo;
use starforged_core::tokens::Scope;

const FULL: &[Scope] = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];
const READ: &[Scope] = &[Scope::RepoRead];

/// Executable markup must never reach the page (mirrors
/// `web_discovery_security.rs`): org templates carry no legitimate
/// executable markup, so any of these tokens is attacker markup rendered
/// live. Escaped text (`&#60;img …`) passes — it is inert — as does a bare
/// URL in escaped text; only live tags and links can execute.
fn assert_no_live_markup(page: &str, surface: &str) {
    let lower = page.to_lowercase();
    for raw in [
        "<script",
        "<img",
        "<svg",
        "<iframe",
        "<object",
        "<embed",
        "<a href=\"javascript",
        "<a href=\"data:",
    ] {
        assert!(!lower.contains(raw), "{raw} live on {surface}");
    }
    assert!(!has_live_handler(&lower), "live event handler on {surface}");
}

/// True when a real (unescaped) tag carries an `on*=` handler attribute.
fn has_live_handler(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] != b'>' {
            j += 1;
        }
        if has_handler_attr(&lower[i..j.min(bytes.len())]) {
            return true;
        }
        i = j + 1;
    }
    false
}

fn has_handler_attr(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    let mut i = 0;
    while i + 3 < bytes.len() {
        if bytes[i] == b' '
            && bytes[i + 1] == b'o'
            && bytes[i + 2] == b'n'
            && bytes[i + 3].is_ascii_alphabetic()
        {
            let mut j = i + 4;
            while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            let mut k = j;
            while k < bytes.len() && bytes[k] == b' ' {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b'=' {
                return true;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

/// Mirror of askama's `Html` escaper (mirrors `web_discovery_security.rs`).
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("&#34;"),
            '&' => out.push_str("&#38;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&#60;"),
            '>' => out.push_str("&#62;"),
            _ => out.push(ch),
        }
    }
    out
}

struct Ctx {
    s: TestServer,
    alice: User,
    uread: User,
    utriage: User,
    uwrite: User,
    umaintain: User,
    uadmin: User,
    usel: User,
    ubase: User,
    ucoll: User,
    uout: User,
    full: HashMap<String, String>,
    read: HashMap<String, String>,
    seed: PathBuf,
    main_sha: String,
    _tmp: tempfile::TempDir,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let uread = s.user("uread").await;
        let utriage = s.user("utriage").await;
        let uwrite = s.user("uwrite").await;
        let umaintain = s.user("umaintain").await;
        let uadmin = s.user("uadmin").await;
        let usel = s.user("usel").await;
        let ubase = s.user("ubase").await;
        let ucoll = s.user("ucoll").await;
        let uout = s.user("uout").await;
        s.core
            .create_org(
                &alice,
                NewOrgInput {
                    handle: "acme".into(),
                    display_name: "Acme".into(),
                    description: String::new(),
                },
            )
            .await
            .unwrap();
        for h in [
            "uread",
            "utriage",
            "uwrite",
            "umaintain",
            "uadmin",
            "usel",
            "ubase",
        ] {
            s.core
                .set_org_member(&alice, "acme", h, OrgRole::Member)
                .await
                .unwrap();
        }
        for (team, perm, member) in [
            ("readers", "read", "uread"),
            ("triage", "triage", "utriage"),
            ("writers", "write", "uwrite"),
            ("keepers", "maintain", "umaintain"),
            ("chiefs", "admin", "uadmin"),
        ] {
            s.core
                .create_team(
                    &alice,
                    "acme",
                    NewTeamInput {
                        name: team.into(),
                        description: String::new(),
                        permission: perm.into(),
                        all_repos: true,
                    },
                )
                .await
                .unwrap();
            s.core
                .set_team_member(&alice, "acme", team, member)
                .await
                .unwrap();
        }
        for (repo, visibility) in [
            ("open", Visibility::Public),
            ("innie", Visibility::Internal),
            ("shut", Visibility::Private),
        ] {
            s.core
                .create_repo(
                    &alice,
                    "acme",
                    CreateRepo {
                        name: repo.into(),
                        description: String::new(),
                        visibility,
                        readme: false,
                    },
                )
                .await
                .unwrap();
        }
        // The selected-set team covers only the public repository.
        s.core
            .create_team(
                &alice,
                "acme",
                NewTeamInput {
                    name: "select".into(),
                    description: String::new(),
                    permission: "read".into(),
                    all_repos: false,
                },
            )
            .await
            .unwrap();
        s.core
            .set_team_member(&alice, "acme", "select", "usel")
            .await
            .unwrap();
        s.core
            .add_team_repo(&alice, "acme", "select", "open")
            .await
            .unwrap();
        // A non-member collaborator with Write on every org repository.
        for repo in ["open", "innie", "shut"] {
            s.core
                .set_collaborator(&alice, "acme", repo, "ucoll", Permission::Write)
                .await
                .unwrap();
            s.core
                .set_refs_for_access(&alice, "acme", repo, "members")
                .await
                .unwrap();
        }
        // Land `main` plus one sweep commit, so clones, branch pushes, and
        // refs/for pushes all have a base.
        let tmp = tempfile::tempdir().unwrap();
        let seed = work_repo(tmp.path(), "seed", &[("README.md", "# sweep\n")]).await;
        let alice_full = s.token(&alice, FULL).await;
        for repo in ["open", "innie", "shut"] {
            git_ok(
                &seed,
                &[
                    "push",
                    "-q",
                    &s.git_url("acme", repo, Some(&alice_full)),
                    "main",
                ],
            )
            .await;
        }
        let main_sha = git_ok(&seed, &["rev-parse", "HEAD"])
            .await
            .trim()
            .to_owned();
        commit_files(&seed, &[("sweep.txt", b"sweep\n")], "sweep base").await;
        let mut full = HashMap::new();
        let mut read = HashMap::new();
        for u in [
            &alice, &uread, &utriage, &uwrite, &umaintain, &uadmin, &usel, &ubase, &ucoll, &uout,
        ] {
            full.insert(u.handle.clone(), s.token(u, FULL).await);
            read.insert(u.handle.clone(), s.token(u, READ).await);
        }
        Ctx {
            s,
            alice,
            uread,
            utriage,
            uwrite,
            umaintain,
            uadmin,
            usel,
            ubase,
            ucoll,
            uout,
            full,
            read,
            seed,
            main_sha,
            _tmp: tmp,
        }
    }

    fn user(&self, handle: &str) -> &User {
        match handle {
            "alice" => &self.alice,
            "uread" => &self.uread,
            "utriage" => &self.utriage,
            "uwrite" => &self.uwrite,
            "umaintain" => &self.umaintain,
            "uadmin" => &self.uadmin,
            "usel" => &self.usel,
            "ubase" => &self.ubase,
            "ucoll" => &self.ucoll,
            "uout" => &self.uout,
            _ => panic!("unknown handle {handle}"),
        }
    }

    fn api_repo(&self, repo: &str) -> String {
        self.s.url(&format!("/api/v1/repos/acme/{repo}"))
    }

    fn web_repo(&self, repo: &str) -> String {
        self.s.url(&format!("/acme/{repo}"))
    }

    async fn set_base(&self, base: &str) {
        self.s
            .core
            .update_org(
                &self.alice,
                "acme",
                OrgPatch {
                    display_name: None,
                    description: None,
                    base_permission: Some(base.into()),
                },
            )
            .await
            .unwrap();
    }
}

/// Expected effective level and member status (D4) for `handle` on `repo`
/// with the org base permission at `base`.
fn expected(handle: &str, repo: &str, base: &str) -> (Option<Permission>, bool) {
    let base_grant = match base {
        "read" => Some(Permission::Read),
        "write" => Some(Permission::Write),
        _ => None,
    };
    // Team members also hold the base grant: the effective level is the max
    // (D4), and the team grant always makes them members.
    let with_base = |team: Permission| (Some(base_grant.map_or(team, |b| team.max(b))), true);
    match handle {
        "alice" => (Some(Permission::Admin), true),
        "uread" => with_base(Permission::Read),
        "utriage" => with_base(Permission::Triage),
        "uwrite" => with_base(Permission::Write),
        "umaintain" => with_base(Permission::Maintain),
        "uadmin" => with_base(Permission::Admin),
        "ucoll" => (Some(Permission::Write), true),
        "usel" if repo == "open" => with_base(Permission::Read),
        "usel" | "ubase" => {
            let implicit = match repo {
                "shut" => None,
                _ => Some(Permission::Read),
            };
            let level = match (base_grant, implicit) {
                (Some(b), Some(i)) => Some(b.max(i)),
                (Some(b), None) => Some(b),
                (None, i) => i,
            };
            (level, base_grant.is_some())
        }
        // A signed-in stranger: implicit read on public and internal, never
        // a member.
        "uout" => match repo {
            "shut" => (None, false),
            _ => (Some(Permission::Read), false),
        },
        _ => panic!("unknown handle {handle}"),
    }
}

async fn web_status(client: &reqwest::Client, url: &str) -> u16 {
    client.get(url).send().await.unwrap().status().as_u16()
}

impl Ctx {
    /// The full surface check for one matrix cell: resolver facts, web page,
    /// API read, clone, branch push, and refs/for push.
    async fn check_cell(
        &self,
        client: &reqwest::Client,
        browsers: &HashMap<String, reqwest::Client>,
        clones: &std::path::Path,
        handle: &str,
        repo: &str,
        base: &str,
    ) {
        let (level, member) = expected(handle, repo, base);
        let user = self.user(handle);
        let cell = format!("{handle} on {repo} (base={base})");
        // The one resolver is the source of truth.
        let access = self.s.core.repo_for(Some(user), "acme", repo).await;
        match level {
            Some(want) => {
                let got = access.unwrap_or_else(|e| panic!("{cell}: repo_for failed: {e:?}"));
                assert_eq!(got.permission, want, "{cell}: effective level");
                let repo_id = got.repo.id;
                assert_eq!(
                    self.s.core.is_repo_member(repo_id, user.id).await.unwrap(),
                    member,
                    "{cell}: member"
                );
            }
            None => assert!(access.is_err(), "{cell}: expected no read"),
        }
        let readable = level.is_some();
        let writable = level.is_some_and(|p| p >= Permission::Write);
        // Web repository page: readers 200, non-readers 404.
        assert_eq!(
            web_status(&browsers[handle], &self.web_repo(repo)).await,
            if readable { 200 } else { 404 },
            "{cell}: web page"
        );
        // API repository read: readers 200, non-readers 404.
        let res = client
            .get(self.api_repo(repo))
            .bearer_auth(&self.full[handle])
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status().as_u16(),
            if readable { 200 } else { 404 },
            "{cell}: api read"
        );
        // `git clone`: readers succeed, non-readers fail.
        let dir = clones.join(format!("{handle}-{repo}"));
        let out = git(
            clones,
            &[
                "clone",
                "-q",
                &self.s.git_url("acme", repo, Some(&self.full[handle])),
                dir.to_str().unwrap(),
            ],
        )
        .await;
        assert_eq!(out.status.success(), readable, "{cell}: clone");
        // `git push` to a branch: Write and above succeed, below fails.
        let branch = format!("sweep/{handle}-{repo}");
        let out = git(
            &self.seed,
            &[
                "push",
                "-q",
                &self.s.git_url("acme", repo, Some(&self.full[handle])),
                &format!("HEAD:refs/heads/{branch}"),
            ],
        )
        .await;
        assert_eq!(out.status.success(), writable, "{cell}: branch push");
        // `refs/for` with `members`: members are admitted, non-members fail,
        // through the read-tier token path.
        let out = git(
            &self.seed,
            &[
                "push",
                "-q",
                &self.s.git_url("acme", repo, Some(&self.read[handle])),
                &format!("HEAD:refs/for/main/{handle}-{repo}"),
            ],
        )
        .await;
        assert_eq!(out.status.success(), member, "{cell}: refs/for push");
    }
}

const HANDLES: &[&str] = &[
    "alice",
    "uread",
    "utriage",
    "uwrite",
    "umaintain",
    "uadmin",
    "usel",
    "ubase",
    "ucoll",
    "uout",
];
const REPOS: &[&str] = &["open", "innie", "shut"];

/// The matrix: every grant source × visibility × surface, with the base
/// permission at `none` (team, collaborator, owner, and stranger grants
/// isolated).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_with_base_none() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let mut browsers = HashMap::new();
    for &h in HANDLES {
        browsers.insert(h.to_string(), c.s.login(h).await.0);
    }
    let anon = c.s.browser();
    let clones = tempfile::tempdir().unwrap();
    for &repo in REPOS {
        for &h in HANDLES {
            c.check_cell(&client, &browsers, clones.path(), h, repo, "none")
                .await;
        }
        // Anonymous: implicit read on the public repository only.
        let readable = repo == "open";
        let access = c.s.core.repo_for(None, "acme", repo).await;
        assert_eq!(access.is_ok(), readable, "anon on {repo}: resolver");
        assert_eq!(
            web_status(&anon, &c.web_repo(repo)).await,
            if readable { 200 } else { 404 },
            "anon on {repo}: web page"
        );
        let res = client.get(c.api_repo(repo)).send().await.unwrap();
        assert_eq!(
            res.status().as_u16(),
            if readable { 200 } else { 404 },
            "anon on {repo}: api read"
        );
        let out = git(
            clones.path(),
            &[
                "clone",
                "-q",
                &c.s.git_url("acme", repo, None),
                clones.path().join(format!("anon-{repo}")).to_str().unwrap(),
            ],
        )
        .await;
        assert_eq!(out.status.success(), readable, "anon on {repo}: clone");
        // Anonymous pushes always fail (no credentials at all).
        let out = git(
            &c.seed,
            &[
                "push",
                "-q",
                &c.s.git_url("acme", repo, None),
                "HEAD:refs/heads/sweep/anon",
            ],
        )
        .await;
        assert!(!out.status.success(), "anon on {repo}: push must fail");
    }
    // At least one admitted refs/for push landed end to end as an agit
    // change (the exit codes above pin admission; this pins ingestion).
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "acme", "open")
            .await
            .unwrap()
            .repo
            .id;
    let start = std::time::Instant::now();
    loop {
        let found = starforged_db::changes::open_agit_change(
            c.s.core.db(),
            repo_id,
            c.uwrite.id,
            "main",
            "uwrite-open",
            None,
        )
        .await
        .unwrap();
        if found.is_some() {
            break;
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(20),
            "refs/for change never ingested"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    // Below-threshold actors get 403, not 404: gate rules need Maintain and
    // collaborator management needs Admin.
    let res = client
        .post(c.s.url("/api/v1/repos/acme/shut/gate-rules"))
        .bearer_auth(&c.full["uwrite"])
        .json(&json!({"required_approvals": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 403, "writer creating a gate rule");
    let res = client
        .put(c.s.url("/api/v1/repos/acme/shut/collaborators/uout"))
        .bearer_auth(&c.full["uwrite"])
        .json(&json!({"permission": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 403, "writer adding a collaborator");
}

/// The matrix with the base permission at `read`, then `write`: resolver
/// facts for every cell, full surfaces for the base-only member.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_with_base_read_then_write() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let mut browsers = HashMap::new();
    for &h in HANDLES {
        browsers.insert(h.to_string(), c.s.login(h).await.0);
    }
    for base in ["read", "write"] {
        c.set_base(base).await;
        let clones = tempfile::tempdir().unwrap();
        for &repo in REPOS {
            // Resolver facts for every grant source.
            for &h in HANDLES {
                let (level, member) = expected(h, repo, base);
                let user = c.user(h);
                let access = c.s.core.repo_for(Some(user), "acme", repo).await;
                match level {
                    Some(want) => {
                        let got =
                            access.unwrap_or_else(|e| panic!("{h} on {repo} (base={base}): {e:?}"));
                        assert_eq!(got.permission, want, "{h} on {repo} (base={base})");
                        assert_eq!(
                            c.s.core.is_repo_member(got.repo.id, user.id).await.unwrap(),
                            member,
                            "{h} on {repo} (base={base}): member"
                        );
                    }
                    None => assert!(access.is_err(), "{h} on {repo} (base={base}): no read"),
                }
            }
            // Full surfaces for the base-only member.
            c.check_cell(&client, &browsers, clones.path(), "ubase", repo, base)
                .await;
        }
    }
}

/// Gate approval counting: only authors holding at least Write on the
/// repository count (the rule feeds on the one resolver).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_approvals_count_write_holders() {
    let c = Ctx::start().await;
    c.s.core
        .create_gate_rule(
            &c.alice,
            "acme",
            "shut",
            &GateRuleInput {
                required_approvals: Some(Some(1)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let alice_full = c.s.token(&c.alice, FULL).await;
    // (approver, counts toward the gate).
    let cases = [
        ("alice", true),
        ("uread", false),
        ("utriage", false),
        ("uwrite", true),
        ("umaintain", true),
        ("uadmin", true),
        ("ucoll", true),
    ];
    for (h, counts) in cases {
        let branch = format!("gate/{h}");
        git_ok(
            &c.seed,
            &[
                "push",
                "-q",
                &c.s.git_url("acme", "shut", Some(&alice_full)),
                &format!("HEAD:refs/heads/{branch}"),
            ],
        )
        .await;
        let trail =
            c.s.core
                .create_trail(c.user(h), "acme", "shut", "gate sweep", "intent")
                .await;
        if !counts {
            // Read-only approvers cannot even reach the change when they
            // cannot read the repository; when they can read, their review
            // submits but never counts.
            if c.s
                .core
                .repo_for(Some(c.user(h)), "acme", "shut")
                .await
                .is_err()
            {
                assert!(trail.is_err(), "{h}: trail creation must fail without read");
                continue;
            }
        }
        let n = trail.unwrap().number;
        c.s.core
            .create_branch_change(&c.alice, "acme", "shut", n, &branch, "main")
            .await
            .unwrap();
        c.s.core
            .submit_review(
                c.user(h),
                "acme",
                "shut",
                n,
                1,
                None,
                "approve",
                "lgtm",
                None,
                &[],
            )
            .await
            .unwrap();
        let report =
            c.s.core
                .evaluate_gates(Some(&c.alice), "acme", "shut", n, 1)
                .await
                .unwrap();
        assert_eq!(report.passed, counts, "{h}: gate counts");
    }
    // Approvers without read cannot submit at all.
    for h in ["usel", "ubase", "uout"] {
        let err =
            c.s.core
                .submit_review(
                    c.user(h),
                    "acme",
                    "shut",
                    1,
                    1,
                    None,
                    "approve",
                    "lgtm",
                    None,
                    &[],
                )
                .await;
        assert!(err.is_err(), "{h}: review without read must fail");
    }
}

const ULID_SWEEP: &str = "01ARZ3NDEKTSV4RRFFQ69G5FA9";

fn meta_body(ulid: &str, title: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "0.1.0"},
        "models": ["m1"],
        "title": title,
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 0, "cache_write": 0, "reasoning": 0},
        "files_touched": [],
        "redaction": {"fingerprint": "fp-1", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

/// §6.4 over every M2f session surface under org grants: an unpublished
/// session on a public repository is visible to members (org owner, team
/// grant, base permission, collaborator) on the session page, the Trail
/// Sessions tab, `has_sessions` (its SQL binds member and admin facts from
/// the resolver-fed `is_repo_member`), timeline rows, and the commit panel —
/// and hidden from strangers and anonymous viewers on all five.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn section_64_session_surfaces_under_org_grants() {
    let c = Ctx::start().await;
    c.set_base("read").await;
    let client = reqwest::Client::new();
    let head = c.main_sha.clone();
    let n =
        c.s.core
            .create_trail(&c.alice, "acme", "open", "session sweep", "intent")
            .await
            .unwrap()
            .number;
    let upload = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let put = client
        .put(c.s.url(&format!("/api/v1/repos/acme/open/sessions/{ULID_SWEEP}")))
        .bearer_auth(&upload)
        .json(&meta_body(ULID_SWEEP, "sweep session seven"))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "upload: {}", put.status());
    let claim = client
        .post(c.s.url(&format!(
            "/api/v1/repos/acme/open/sessions/{ULID_SWEEP}/links"
        )))
        .bearer_auth(&upload)
        .json(&json!({"links": [{"sha": head, "confidence": "exact"}]}))
        .send()
        .await
        .unwrap();
    assert!(claim.status().is_success(), "claim: {}", claim.status());
    c.s.core
        .link_trail_session(&c.alice, "acme", "open", n, ULID_SWEEP)
        .await
        .unwrap();
    // Sanity: the uploader-side facts come from the resolver-fed helper.
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "acme", "open")
            .await
            .unwrap()
            .repo
            .id;
    assert!(c.s.core.is_repo_member(repo_id, c.uwrite.id).await.unwrap());
    assert!(!c.s.core.is_repo_member(repo_id, c.uout.id).await.unwrap());

    // (viewer, sees the unpublished session).
    let cases = [
        ("alice", true),
        ("uwrite", true),
        ("ubase", true),
        ("ucoll", true),
        ("uout", false),
    ];
    let mut browsers = HashMap::new();
    for (h, _) in cases {
        browsers.insert(h.to_string(), c.s.login(h).await.0);
    }
    let anon = c.s.browser();
    for (h, sees) in cases {
        let tag = format!("{h} (member={sees})");
        // The session page: members read, others 404.
        assert_eq!(
            web_status(
                &browsers[h],
                &c.s.url(&format!("/acme/open/sessions/{ULID_SWEEP}"))
            )
            .await,
            if sees { 200 } else { 404 },
            "{tag}: session page"
        );
        // The Trail Sessions API: 200 for every reader of the public repo,
        // with the session listed only for members.
        let res = client
            .get(c.s.url(&format!("/api/v1/repos/acme/open/trails/{n}/sessions")))
            .bearer_auth(&c.full[h])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200, "{tag}: sessions api");
        let body: Value = res.json().await.unwrap();
        assert_eq!(
            body.to_string().contains(ULID_SWEEP),
            sees,
            "{tag}: sessions api body"
        );
        // `has_sessions`: the SQL predicate follows the same member rule.
        let res = client
            .get(c.s.url("/api/v1/repos/acme/open/trails?has_sessions=true"))
            .bearer_auth(&c.full[h])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 200, "{tag}: has_sessions");
        let listed: Vec<i64> = res.json::<Value>().await.unwrap()["trails"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["number"].as_i64().unwrap())
            .collect();
        assert_eq!(listed.contains(&n), sees, "{tag}: has_sessions list");
        // The Trail Sessions tab: no title or ULID leak for non-members.
        let tab = get_text(
            &browsers[h],
            &c.s.url(&format!("/acme/open/trails/{n}/sessions")),
        )
        .await;
        assert_eq!(
            tab.contains(ULID_SWEEP) || tab.contains("sweep session seven"),
            sees,
            "{tag}: sessions tab"
        );
        // Timeline rows and the commit panel obey the same rule.
        let trail_page = get_text(&browsers[h], &c.s.url(&format!("/acme/open/trails/{n}"))).await;
        assert_eq!(trail_page.contains(ULID_SWEEP), sees, "{tag}: timeline");
        let commit_page =
            get_text(&browsers[h], &c.s.url(&format!("/acme/open/commit/{head}"))).await;
        assert_eq!(
            commit_page.contains(ULID_SWEEP),
            sees,
            "{tag}: commit panel"
        );
    }
    // Anonymous and stranger-API views hide everything unpublished.
    let anon_page = get_text(&anon, &c.s.url(&format!("/acme/open/trails/{n}"))).await;
    assert!(!anon_page.contains(ULID_SWEEP), "anon: timeline");
    let anon_commit = get_text(&anon, &c.s.url(&format!("/acme/open/commit/{head}"))).await;
    assert!(!anon_commit.contains(ULID_SWEEP), "anon: commit panel");
    let res = client
        .get(c.s.url("/api/v1/repos/acme/open/trails?has_sessions=true"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200, "anon: has_sessions");
    let listed: Vec<i64> = res.json::<Value>().await.unwrap()["trails"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["number"].as_i64().unwrap())
        .collect();
    assert!(!listed.contains(&n), "anon: has_sessions list");
}

/// Revocation is immediate on every surface: member removal, team deletion,
/// base lowering, and transfer away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_is_immediate_on_every_surface() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    c.set_base("read").await;
    let extra = ["rm", "lb"];
    for h in extra {
        let u = c.s.user(h).await;
        c.s.core
            .set_org_member(&c.alice, "acme", &u.handle, OrgRole::Member)
            .await
            .unwrap();
    }
    let rm = c.s.core.user_by_handle("rm").await.unwrap().unwrap();
    let lb = c.s.core.user_by_handle("lb").await.unwrap().unwrap();
    // A team of its own for the deletion cell.
    c.s.core
        .create_team(
            &c.alice,
            "acme",
            NewTeamInput {
                name: "goners".into(),
                description: String::new(),
                permission: "write".into(),
                all_repos: true,
            },
        )
        .await
        .unwrap();
    c.s.core
        .set_team_member(&c.alice, "acme", "goners", "lb")
        .await
        .unwrap();
    let rm_browser = c.s.login("rm").await.0;
    let lb_browser = c.s.login("lb").await.0;
    let tmp = tempfile::tempdir().unwrap();
    let rm_full = c.s.token(&rm, FULL).await;
    let rm_read = c.s.token(&rm, READ).await;
    let lb_full = c.s.token(&lb, FULL).await;

    // Removing the member drops the base grant on every surface.
    assert_eq!(
        c.s.core
            .repo_for(Some(&rm), "acme", "shut")
            .await
            .unwrap()
            .permission,
        Permission::Read
    );
    c.s.core
        .remove_org_member(&c.alice, "acme", "rm")
        .await
        .unwrap();
    assert!(c.s.core.repo_for(Some(&rm), "acme", "shut").await.is_err());
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "acme", "shut")
            .await
            .unwrap()
            .repo
            .id;
    assert!(!c.s.core.is_repo_member(repo_id, rm.id).await.unwrap());
    assert_eq!(
        web_status(&rm_browser, &c.web_repo("shut")).await,
        404,
        "rm: web"
    );
    let res = client
        .get(c.api_repo("shut"))
        .bearer_auth(&rm_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404, "rm: api");
    let out = git(
        tmp.path(),
        &[
            "clone",
            "-q",
            &c.s.git_url("acme", "shut", Some(&rm_full)),
            tmp.path().join("rm-shut").to_str().unwrap(),
        ],
    )
    .await;
    assert!(!out.status.success(), "rm: clone");
    let out = git(
        &c.seed,
        &[
            "push",
            "-q",
            &c.s.git_url("acme", "shut", Some(&rm_read)),
            "HEAD:refs/for/main/rm-shut",
        ],
    )
    .await;
    assert!(!out.status.success(), "rm: refs/for");

    // Deleting the team drops its grant (base is `none` now, so the team
    // grant is the only one left).
    c.set_base("none").await;
    assert_eq!(
        c.s.core
            .repo_for(Some(&lb), "acme", "shut")
            .await
            .unwrap()
            .permission,
        Permission::Write
    );
    c.s.core
        .delete_team(&c.alice, "acme", "goners")
        .await
        .unwrap();
    assert!(c.s.core.repo_for(Some(&lb), "acme", "shut").await.is_err());
    assert!(!c.s.core.is_repo_member(repo_id, lb.id).await.unwrap());
    assert_eq!(
        web_status(&lb_browser, &c.web_repo("shut")).await,
        404,
        "lb: web"
    );
    let res = client
        .get(c.api_repo("shut"))
        .bearer_auth(&lb_full)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 404, "lb: api");
    let out = git(
        tmp.path(),
        &[
            "clone",
            "-q",
            &c.s.git_url("acme", "shut", Some(&lb_full)),
            tmp.path().join("lb-shut").to_str().unwrap(),
        ],
    )
    .await;
    assert!(!out.status.success(), "lb: clone");

    // Lowering the base permission drops it (lb is base-only again now that
    // the team is gone).
    c.set_base("write").await;
    assert_eq!(
        c.s.core
            .repo_for(Some(&lb), "acme", "shut")
            .await
            .unwrap()
            .permission,
        Permission::Write
    );
    let out = git(
        &c.seed,
        &[
            "push",
            "-q",
            &c.s.git_url("acme", "shut", Some(&lb_full)),
            "HEAD:refs/heads/sweep/lb-before",
        ],
    )
    .await;
    assert!(out.status.success(), "lb: push while base=write");
    c.set_base("none").await;
    assert!(c.s.core.repo_for(Some(&lb), "acme", "shut").await.is_err());
    assert_eq!(
        web_status(&lb_browser, &c.web_repo("shut")).await,
        404,
        "lb: web after lower"
    );
    let out = git(
        &c.seed,
        &[
            "push",
            "-q",
            &c.s.git_url("acme", "shut", Some(&lb_full)),
            "HEAD:refs/heads/sweep/lb-after",
        ],
    )
    .await;
    assert!(!out.status.success(), "lb: push after lower");

    // Transferring the repository away drops every org grant: the old path
    // redirects, the new path answers, and org grants are gone there.
    let res = client
        .post(c.s.url("/api/v1/repos/acme/shut/transfer"))
        .bearer_auth(&c.full["alice"])
        .json(&json!({"new_owner": "alice"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200, "transfer shut to alice");
    // Redirects serve readers (like renames): ask as the owner, who can read
    // the repository at its new path.
    let alice_browser = c.s.login("alice").await.0;
    assert_eq!(
        web_status(&alice_browser, &c.web_repo("shut")).await,
        301,
        "old web path redirects"
    );
    // The plain client follows redirects: use a no-redirect client and pin
    // the target, exactly like the rename sweep does.
    let noredir = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let res = noredir
        .get(c.api_repo("shut"))
        .bearer_auth(&c.full["alice"])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 301, "old api path redirects");
    assert_eq!(res.headers()["location"], "/api/v1/repos/alice/shut");
    let res = client
        .get(c.s.url("/api/v1/repos/alice/shut"))
        .bearer_auth(&c.full["alice"])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 200, "new path answers");
    for (h, tok) in [("uwrite", &c.full["uwrite"]), ("ubase", &c.full["ubase"])] {
        let res = client
            .get(c.s.url("/api/v1/repos/alice/shut"))
            .bearer_auth(tok)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 404, "{h}: no grant after transfer");
    }
    // The repositories left behind are unaffected.
    assert_eq!(
        c.s.core
            .repo_for(Some(&c.alice), "acme", "open")
            .await
            .unwrap()
            .permission,
        Permission::Admin
    );
}

/// Every user-only path (D1) refuses an org handle; hostile org and team
/// descriptions render escaped (there is no mentions feature to refuse).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_only_paths_and_rendering() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    // An org cannot be a collaborator.
    let res = client
        .put(c.s.url("/api/v1/repos/acme/open/collaborators/acme"))
        .bearer_auth(&c.full["alice"])
        .json(&json!({"permission": "read"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 422, "org as collaborator");
    // An org cannot be an assignee or a review request.
    let n =
        c.s.core
            .create_trail(&c.alice, "acme", "open", "d1 trail", "intent")
            .await
            .unwrap()
            .number;
    let res = client
        .post(c.s.url(&format!("/api/v1/repos/acme/open/trails/{n}/assignees")))
        .bearer_auth(&c.full["alice"])
        .json(&json!({"user": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 422, "org as assignee");
    let res = client
        .post(c.s.url(&format!(
            "/api/v1/repos/acme/open/trails/{n}/review-requests"
        )))
        .bearer_auth(&c.full["alice"])
        .json(&json!({"user": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 422, "org as review request");
    // An org cannot join a team: it is not a user.
    let err =
        c.s.core
            .set_team_member(&c.alice, "acme", "readers", "acme")
            .await;
    assert!(err.is_err(), "org as team member");
    // An org is not a user row at all: no token can be minted for it, and it
    // cannot sign in.
    assert!(c.s.core.user_by_handle("acme").await.unwrap().is_none());
    let (_, response) = c.s.try_login("acme", PASSWORD).await;
    assert_ne!(response.status().as_u16(), 303, "org cannot sign in");

    // Hostile descriptions render escaped on the org profile and team page.
    let hostile = "<script>alert(1)</script><img src=x onerror=alert(1)>https://attacker.example/x";
    c.s.core
        .create_org(
            &c.alice,
            NewOrgInput {
                handle: "evil".into(),
                display_name: hostile.into(),
                description: hostile.into(),
            },
        )
        .await
        .unwrap();
    c.s.core
        .set_org_member(&c.alice, "evil", "uout", OrgRole::Member)
        .await
        .unwrap();
    c.s.core
        .create_team(
            &c.alice,
            "evil",
            NewTeamInput {
                name: "red".into(),
                description: hostile.into(),
                permission: "read".into(),
                all_repos: true,
            },
        )
        .await
        .unwrap();
    // A hostile team *name* is rejected by validation, not rendered.
    let bad =
        c.s.core
            .create_team(
                &c.alice,
                "evil",
                NewTeamInput {
                    name: "<script>".into(),
                    description: String::new(),
                    permission: "read".into(),
                    all_repos: true,
                },
            )
            .await;
    assert!(bad.is_err(), "hostile team name rejected");
    let (browser, _) = c.s.login("uout").await;
    for (url, surface) in [
        (c.s.url("/evil"), "org profile"),
        (c.s.url("/orgs/evil/teams/red"), "team page"),
    ] {
        let page = get_text(&browser, &url).await;
        assert_no_live_markup(&page, surface);
        assert!(
            page.contains(&escape_html(hostile)),
            "{surface}: hostile text escaped"
        );
        assert!(!page.contains(hostile), "{surface}: hostile text raw");
    }
}
