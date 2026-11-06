//! S5: the search access matrix (§13) — viewer roles × repository
//! visibility × surface (Trail search, session search, code search; API
//! and web) × state (private, revoked grant, deleted, archived,
//! quarantined, unpublished, transferred).
//!
//! The pin is three-way and deterministic: for every viewer, the Trail
//! search set equals the Trail list access (`repo_for`/`list_trails`),
//! the session search set equals the session API set
//! (`GET .../sessions`, which runs `authorize_session_read`), and both
//! equal an independently re-derived §6.4 truth table below. Code
//! search follows repository read access (200 + match, or 404).
//! Revocation is immediate through the per-hit re-check: each state
//! change is also asserted *without* draining index jobs.
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::{CreateUser, User};
use starforged_core::ingest::IngestAuth;
use starforged_core::orgs::{NewOrgInput, NewTeamInput, OrgPatch, OrgRole};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::CreateRepo;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const READ: &[Scope] = &[Scope::RepoRead];
const REPOS: [&str; 3] = ["open", "innie", "shut"];
fn visibility(repo: &str) -> Visibility {
    match repo {
        "open" => Visibility::Public,
        "innie" => Visibility::Internal,
        _ => Visibility::Private,
    }
}

/// 26-char Crockford ULIDs, distinct per index.
fn ulid(n: u32) -> String {
    format!("01ARZ3NDEKTSV4RRFFQ69G5{n:03}")
}

fn meta_body(id: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": id,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1"],
        "title": "search fixture",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 1, "output": 2, "cache_read": 0, "cache_write": 0, "reasoning": 0},
        "files_touched": ["src/plumbline.rs"],
        "redaction": {"fingerprint": "fp-1", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

async fn drain(s: &TestServer) {
    s.core.run_due_jobs().await.unwrap();
}

async fn upload_completed(
    s: &TestServer,
    alice: &User,
    owner: &str,
    repo: &str,
    id: &str,
    text: &str,
) -> IngestAuth {
    let secret = s.token(alice, &[Scope::SessionUpload]).await;
    let token = s.core.authenticate_token(&secret).await.unwrap();
    let auth: IngestAuth = s.core.authorize_upload(&token, owner, repo).await.unwrap();
    s.core
        .upsert_session_meta(&auth, id, &meta_body(id))
        .await
        .unwrap();
    let line = json!({"v": 1, "seq": 0, "ts": "2026-11-04T00:00:00Z", "kind": "user_message", "text": text}).to_string();
    let bytes = starforge_format::compress(format!("{line}\n").as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    s.core
        .put_segment(&auth, id, 0, &bytes, Some(hash))
        .await
        .unwrap();
    s.core.complete_session(&auth, id).await.unwrap();
    auth
}

async fn publish(s: &TestServer, alice: &User, owner: &str, repo: &str, id: &str) {
    let access = s
        .core
        .require_repo(Some(alice), owner, repo, Permission::Maintain)
        .await
        .unwrap();
    s.core.publish_session(alice, &access, id).await.unwrap();
}

async fn search_api(
    client: &reqwest::Client,
    s: &TestServer,
    kind: &str,
    qs: &str,
    token: Option<&str>,
) -> (u16, Value) {
    let mut request = client.get(s.url(&format!("/api/v1/search/{kind}?{qs}")));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let res = request.send().await.unwrap();
    let status = res.status().as_u16();
    let body = res.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

fn api_trail_repos(body: &Value) -> BTreeSet<String> {
    body["results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .map(|r| r["repo"].as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn api_session_repos(body: &Value) -> BTreeSet<String> {
    body["results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .map(|r| {
                    format!(
                        "{}:{}",
                        r["repo"].as_str().unwrap_or(""),
                        r["session"].as_str().unwrap_or("")
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The `q=sessionneedle` session search result set, as `repo:ulid`.
async fn session_search_set(
    client: &reqwest::Client,
    s: &TestServer,
    token: Option<&str>,
) -> BTreeSet<String> {
    let (_, body) = search_api(client, s, "sessions", "q=sessionneedle", token).await;
    api_session_repos(&body)
}

/// `GET /api/v1/repos/{owner}/{repo}/sessions` ULIDs (the §6.4 API set),
/// or an empty set when the repository is unreadable (404).
async fn api_list_sessions(
    client: &reqwest::Client,
    s: &TestServer,
    owner: &str,
    repo: &str,
    token: Option<&str>,
) -> BTreeSet<String> {
    let mut request = client.get(s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions")));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let res = request.send().await.unwrap();
    if res.status().as_u16() != 200 {
        return BTreeSet::new();
    }
    let body = res.json::<Value>().await.unwrap();
    body["sessions"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|r| r["ulid"].as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

async fn code_api(
    client: &reqwest::Client,
    s: &TestServer,
    owner: &str,
    repo: &str,
    token: Option<&str>,
) -> (u16, Value) {
    let mut request = client.get(s.url(&format!(
        "/api/v1/repos/{owner}/{repo}/search/code?q=codeneedle"
    )));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let res = request.send().await.unwrap();
    let status = res.status().as_u16();
    let body = res.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

async fn wait_for_tip(s: &TestServer, owner: &str, repo: &str, branch: &str) -> String {
    for _ in 0..100 {
        let row = starforged_db::repos::by_owner_and_name(s.core.db(), owner, repo)
            .await
            .ok()
            .flatten();
        if let Some(row) = row {
            let path = s.core.repo_path(row.id);
            let branch_ref = format!("refs/heads/{branch}");
            let out = tokio::task::spawn_blocking(move || {
                std::process::Command::new("git")
                    .args([
                        "-C",
                        path.to_str().unwrap(),
                        "rev-parse",
                        "--verify",
                        "-q",
                        &branch_ref,
                    ])
                    .output()
            })
            .await
            .ok()
            .and_then(|out| out.ok());
            if let Some(out) = out
                && out.status.success()
            {
                return String::from_utf8_lossy(&out.stdout).trim().to_owned();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for tip of {branch}");
}

/// One session's search-relevant state, captured from the database at
/// setup so the truth table below never assumes it.
struct SessionCase {
    repo: String,
    id: String,
    published: bool,
    quarantined: bool,
}

struct Ctx {
    s: TestServer,
    users: BTreeMap<String, User>,
    tokens: BTreeMap<String, String>,
    sessions: Vec<SessionCase>,
    _seed: PathBuf,
    _tmp: tempfile::TempDir,
}

impl Ctx {
    fn user(&self, handle: &str) -> &User {
        &self.users[handle]
    }
    fn token(&self, handle: &str) -> Option<&str> {
        self.tokens.get(handle).map(String::as_str)
    }
    async fn set_base(&self, base: &str) {
        self.s
            .core
            .update_org(
                &self.users["alice"],
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

/// Builds the org matrix: team grants read/triage/write/maintain/admin
/// (all-repos), a selected-set team (open only), a collaborator, a plain
/// org member (base-grant subject), a signed-in outsider, the org owner,
/// and a site admin — over public/internal/private repositories, each
/// with a search-needle Trail, four search-needle sessions (published,
/// unpublished, quarantined, released), and pushed code.
async fn setup() -> Ctx {
    let s = TestServer::start().await;
    let mut users = BTreeMap::new();
    let insert = |handle: &str, user: User, users: &mut BTreeMap<String, User>| {
        users.insert(handle.to_owned(), user);
    };
    let alice = s.user("alice").await;
    insert("alice", alice, &mut users);
    for h in [
        "uread",
        "utriage",
        "uwrite",
        "umaintain",
        "uadmin",
        "usel",
        "ubase",
        "ucoll",
        "uout",
    ] {
        let u = s.user(h).await;
        insert(h, u, &mut users);
    }
    let root = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    insert("root", root, &mut users);

    let alice = users["alice"].clone();
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
    // Selected-set team: read on `open` only.
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
    for repo in REPOS {
        s.core
            .create_repo(
                &alice,
                "acme",
                CreateRepo {
                    name: repo.into(),
                    description: String::new(),
                    visibility: visibility(repo),
                    readme: false,
                },
            )
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "acme", repo, "ucoll", Permission::Write)
            .await
            .unwrap();
        s.core
            .create_trail(
                &alice,
                "acme",
                repo,
                &format!("Trailsweep {repo}"),
                "trailsweep intent",
            )
            .await
            .unwrap();
    }
    // The selected-set team covers only the public repository (added
    // after the repositories exist).
    s.core
        .add_team_repo(&alice, "acme", "select", "open")
        .await
        .unwrap();
    // Pushed code carrying the code needle on all three repositories.
    let tmp = tempfile::tempdir().unwrap();
    let seed = work_repo(tmp.path(), "seed", &[("sweep.txt", "codeneedle here\n")]).await;
    let alice_full = s
        .token(
            &alice,
            &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite],
        )
        .await;
    for repo in REPOS {
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
        wait_for_tip(&s, "acme", repo, "main").await;
    }

    // Sessions: per repository — published (public only; elsewhere the
    // inherit state), unpublished, quarantined, released. All carry the
    // same needle so one query covers every cell.
    let mut sessions = Vec::new();
    let mut n = 0u32;
    for repo in REPOS {
        let ids = [ulid(n), ulid(n + 1), ulid(n + 2), ulid(n + 3)];
        n += 4;
        let published_id = ids[0].clone();
        upload_completed(
            &s,
            &alice,
            "acme",
            repo,
            &published_id,
            "sessionneedle hello",
        )
        .await;
        if repo == "open" {
            publish(&s, &alice, "acme", repo, &published_id).await;
        }
        let unpublished_id = ids[1].clone();
        upload_completed(
            &s,
            &alice,
            "acme",
            repo,
            &unpublished_id,
            "sessionneedle hello",
        )
        .await;
        let quarantined_id = ids[2].clone();
        upload_completed(
            &s,
            &alice,
            "acme",
            repo,
            &quarantined_id,
            "sessionneedle hello",
        )
        .await;
        if repo == "open" {
            publish(&s, &alice, "acme", repo, &quarantined_id).await;
        }
        let released_id = ids[3].clone();
        upload_completed(
            &s,
            &alice,
            "acme",
            repo,
            &released_id,
            "sessionneedle hello",
        )
        .await;
        // Quarantine in the database, then release the fourth through the
        // real path (audited, enqueues the index job).
        let repo_id = starforged_db::repos::by_owner_and_name(s.db(), "acme", repo)
            .await
            .unwrap()
            .unwrap()
            .id;
        let quarantined_row = db_sessions::session_by_ulid(s.db(), repo_id, &quarantined_id)
            .await
            .unwrap()
            .unwrap();
        db_sessions::set_quarantine(s.db(), quarantined_row.id, "quarantined", "test", "test")
            .await
            .unwrap();
        let released_row = db_sessions::session_by_ulid(s.db(), repo_id, &released_id)
            .await
            .unwrap()
            .unwrap();
        db_sessions::set_quarantine(s.db(), released_row.id, "quarantined", "test", "test")
            .await
            .unwrap();
        let access = s
            .core
            .require_repo(Some(&alice), "acme", repo, Permission::Maintain)
            .await
            .unwrap();
        s.core
            .release_session(&alice, &access, &released_id)
            .await
            .unwrap();
        for id in ids {
            let row = db_sessions::session_by_ulid(s.db(), repo_id, &id)
                .await
                .unwrap()
                .unwrap();
            sessions.push(SessionCase {
                repo: repo.to_owned(),
                published: row.visibility == "published",
                quarantined: row.quarantine == "quarantined",
                id,
            });
        }
    }
    drain(&s).await;

    let mut tokens = BTreeMap::new();
    for (handle, user) in &users {
        tokens.insert(handle.clone(), s.token(user, READ).await);
    }
    Ctx {
        s,
        users,
        tokens,
        sessions,
        _seed: seed,
        _tmp: tmp,
    }
}

/// Expected effective level and membership (D4), mirroring
/// `org_security.rs::expected`, extended with anonymous and site admin.
fn expected(handle: &str, repo: &str, base: &str) -> (Option<Permission>, bool) {
    match handle {
        // Implicit read (permission.rs): public → everyone, internal →
        // signed-in users only, private → nobody.
        "anon" => (
            match repo {
                "open" => Some(Permission::Read),
                _ => None,
            },
            false,
        ),
        "root" => (Some(Permission::Admin), false),
        _ => {
            let base_grant = match base {
                "read" => Some(Permission::Read),
                "write" => Some(Permission::Write),
                _ => None,
            };
            let with_base =
                |team: Permission| (Some(base_grant.map_or(team, |b| team.max(b))), true);
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
                "uout" => match repo {
                    "shut" => (None, false),
                    _ => (Some(Permission::Read), false),
                },
                _ => panic!("unknown handle {handle}"),
            }
        }
    }
}

fn repo_readable(signed_in: bool, vis: Visibility, member: bool) -> bool {
    if member {
        return true;
    }
    match vis {
        Visibility::Public => true,
        Visibility::Internal => signed_in,
        Visibility::Private => false,
    }
}

/// The §6.4 truth table, re-derived from the spec rows (§6.4) for the
/// matrix: site admins read everything; quarantined is uploader or repo
/// admin; owners read the rest; published and non-public-unpublished
/// follow repository read; public-unpublished needs explicit membership.
#[allow(clippy::too_many_arguments)]
fn spec_can_read_session(
    handle: &str,
    repo: &str,
    base: &str,
    published: bool,
    quarantined: bool,
) -> bool {
    if handle == "root" {
        return true;
    }
    let (level, member) = expected(handle, repo, base);
    let Some(level) = level else { return false };
    if quarantined {
        return handle == "alice" || level >= Permission::Admin;
    }
    if handle == "alice" {
        return true;
    }
    let signed_in = handle != "anon";
    if published {
        return repo_readable(signed_in, visibility(repo), member);
    }
    if repo != "open" {
        return repo_readable(signed_in, visibility(repo), member);
    }
    member
}

const VIEWERS: [&str; 12] = [
    "anon",
    "uout",
    "uread",
    "utriage",
    "uwrite",
    "umaintain",
    "uadmin",
    "usel",
    "ubase",
    "ucoll",
    "alice",
    "root",
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trail_search_matches_trail_list_across_roles_and_visibilities() {
    let c = setup().await;
    let client = reqwest::Client::new();
    for base in ["none", "read", "write"] {
        c.set_base(base).await;
        for handle in VIEWERS {
            let token = c.token(handle);
            let viewer = (handle != "anon").then(|| c.user(handle));
            let (status, body) = search_api(&client, &c.s, "trails", "q=trailsweep", token).await;
            assert_eq!(status, 200, "{handle} trail search (base={base})");
            let got = api_trail_repos(&body);
            let mut want = BTreeSet::new();
            for repo in REPOS {
                let (level, _) = expected(handle, repo, base);
                if level.is_some() {
                    // Oracle: the Trail list access itself.
                    let listed =
                        c.s.core
                            .list_trails(
                                viewer,
                                "acme",
                                repo,
                                &starforged_core::trails::TrailFilterInput::default(),
                            )
                            .await;
                    assert!(
                        listed.is_ok(),
                        "{handle} on {repo}: list_trails oracle (base={base})"
                    );
                    assert!(
                        !listed.unwrap().trails.is_empty(),
                        "{handle} on {repo}: oracle lists the needle trail (base={base})"
                    );
                    want.insert(format!("acme/{repo}"));
                } else {
                    assert!(
                        c.s.core.repo_for(viewer, "acme", repo).await.is_err(),
                        "{handle} on {repo}: oracle says no read (base={base})"
                    );
                }
            }
            assert_eq!(got, want, "{handle} trail search set (base={base})");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_search_matches_session_api_across_states() {
    let c = setup().await;
    let client = reqwest::Client::new();
    for base in ["none", "read", "write"] {
        c.set_base(base).await;
        for handle in VIEWERS {
            let token = c.token(handle);
            let viewer = (handle != "anon").then(|| c.user(handle));
            let (status, body) =
                search_api(&client, &c.s, "sessions", "q=sessionneedle", token).await;
            assert_eq!(status, 200, "{handle} session search (base={base}): {body}");
            let got = api_session_repos(&body);
            // Oracle 1: the session list API, per repository (an
            // unreadable repository lists nothing).
            let mut api_set = BTreeSet::new();
            for repo in REPOS {
                for ulid in api_list_sessions(&client, &c.s, "acme", repo, token).await {
                    api_set.insert(format!("acme/{repo}:{ulid}"));
                }
            }
            assert_eq!(
                got, api_set,
                "{handle} session search == session list API (base={base})"
            );
            // Oracle 2: the §6.4 truth table, plus the Core check itself.
            let mut want = BTreeSet::new();
            for case in &c.sessions {
                if spec_can_read_session(handle, &case.repo, base, case.published, case.quarantined)
                {
                    want.insert(format!("acme/{}:{}", case.repo, case.id));
                }
                let core_ok =
                    c.s.core
                        .authorize_session_read_by_ulid(viewer, "acme", &case.repo, &case.id)
                        .await
                        .is_ok();
                assert_eq!(
                    core_ok,
                    spec_can_read_session(
                        handle,
                        &case.repo,
                        base,
                        case.published,
                        case.quarantined
                    ),
                    "{handle} on {}:{} core vs spec (base={base})",
                    case.repo,
                    case.id
                );
            }
            assert_eq!(
                got, want,
                "{handle} session search == spec table (base={base})"
            );
        }
    }
    // The sessions-only table pins the interesting cells directly:
    // unpublished-public needs membership (anon/uout absent, every
    // team/base member present), quarantined needs uploader or repo
    // admin (alice/uadmin/root present, plain readers absent), and
    // released behaves like an ordinary unpublished session.
    let open_unpublished: String = c
        .sessions
        .iter()
        .find(|case| case.repo == "open" && !case.published && !case.quarantined)
        .map(|case| format!("acme/open:{}", case.id))
        .unwrap();
    let open_quarantined: String = c
        .sessions
        .iter()
        .find(|case| case.repo == "open" && case.quarantined)
        .map(|case| format!("acme/open:{}", case.id))
        .unwrap();
    assert!(
        !session_search_set(&client, &c.s, c.token("anon"))
            .await
            .contains(&open_unpublished),
        "anonymous cannot find unpublished public sessions"
    );
    assert!(
        !session_search_set(&client, &c.s, c.token("uout"))
            .await
            .contains(&open_unpublished),
        "a non-member cannot find unpublished public sessions"
    );
    assert!(
        session_search_set(&client, &c.s, c.token("uread"))
            .await
            .contains(&open_unpublished),
        "a team member finds unpublished public sessions"
    );
    assert!(
        !session_search_set(&client, &c.s, c.token("uread"))
            .await
            .contains(&open_quarantined),
        "a plain reader cannot find quarantined sessions"
    );
    assert!(
        session_search_set(&client, &c.s, c.token("alice"))
            .await
            .contains(&open_quarantined),
        "the uploader finds her quarantined session"
    );
    assert!(
        session_search_set(&client, &c.s, c.token("uadmin"))
            .await
            .contains(&open_quarantined),
        "a repo admin finds quarantined sessions"
    );
    assert!(
        session_search_set(&client, &c.s, c.token("root"))
            .await
            .contains(&open_quarantined),
        "a site admin finds quarantined sessions"
    );
    // Site admins read everything (§6.4 row 12), including unpublished
    // public sessions they are not members of.
    assert!(
        session_search_set(&client, &c.s, c.token("root"))
            .await
            .contains(&open_unpublished),
        "a site admin finds unpublished public sessions"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn code_search_follows_repo_read_api_and_web() {
    let c = setup().await;
    let client = reqwest::Client::new();
    for base in ["none", "read"] {
        c.set_base(base).await;
        for handle in VIEWERS {
            let token = c.token(handle);
            for repo in REPOS {
                let (level, _) = expected(handle, repo, base);
                let readable = level.is_some();
                let (status, body) = code_api(&client, &c.s, "acme", repo, token).await;
                if readable {
                    assert_eq!(
                        status, 200,
                        "{handle} code search on {repo} (base={base}): {body}"
                    );
                    assert_eq!(
                        body["matches"].as_array().unwrap().len(),
                        1,
                        "{handle} on {repo} (base={base})"
                    );
                    assert_eq!(
                        body["matches"][0]["text"], "codeneedle here",
                        "{handle} on {repo} (base={base})"
                    );
                } else {
                    assert_eq!(
                        status, 404,
                        "{handle} code search on {repo} must 404 (base={base})"
                    );
                }
            }
        }
    }
    // Web parity: sampled viewers, both directions.
    // The web loop checks the base="none" expectations below.
    c.set_base("none").await;
    for (handle, browser) in [
        ("anon", c.s.browser()),
        ("uout", c.s.login("uout").await.0),
        ("uread", c.s.login("uread").await.0),
        ("usel", c.s.login("usel").await.0),
    ] {
        for repo in REPOS {
            let (level, _) = expected(handle, repo, "none");
            let res = browser
                .get(c.s.url(&format!("/acme/{repo}/search?q=codeneedle")))
                .send()
                .await
                .unwrap();
            assert_eq!(
                res.status().as_u16(),
                if level.is_some() { 200 } else { 404 },
                "{handle} web code search on {repo}"
            );
            if level.is_some() {
                let page = res.text().await.unwrap();
                assert!(
                    page.contains("codeneedle"),
                    "{handle} web code search on {repo} shows the match"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn web_search_matches_api_search() {
    let c = setup().await;
    let client = reqwest::Client::new();
    // Trails tab: the page shows exactly the repositories the API
    // search returned for the sampled viewer.
    for handle in ["anon", "uout", "uread", "usel", "alice", "root"] {
        let token = c.token(handle);
        let (_, body) = search_api(&client, &c.s, "trails", "q=trailsweep", token).await;
        let api = api_trail_repos(&body);
        let browser = if handle == "anon" {
            c.s.browser()
        } else {
            c.s.login(handle).await.0
        };
        let page = get_text(&browser, &c.s.url("/search?q=trailsweep")).await;
        for repo in REPOS {
            assert_eq!(
                page.contains(&format!("Trailsweep {repo}")),
                api.contains(&format!("acme/{repo}")),
                "{handle} web vs API trail search on {repo}"
            );
        }
    }
    // Sessions tab: ULID-level parity, and every session search page
    // is noindex (spec §11.1), web and API alike.
    for handle in ["anon", "uread", "uadmin", "root"] {
        let token = c.token(handle);
        let (_, body) = search_api(&client, &c.s, "sessions", "q=sessionneedle", token).await;
        let api = api_session_repos(&body);
        let browser = if handle == "anon" {
            c.s.browser()
        } else {
            c.s.login(handle).await.0
        };
        let res = browser
            .get(c.s.url("/search?tab=sessions&q=sessionneedle"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.headers()
                .get("x-robots-tag")
                .and_then(|v| v.to_str().ok()),
            Some("noindex"),
            "{handle} web session search is noindex"
        );
        let page = res.text().await.unwrap();
        for case in &c.sessions {
            assert_eq!(
                page.contains(&case.id),
                api.contains(&format!("acme/{}:{}", case.repo, case.id)),
                "{handle} web vs API session search on {}:{}",
                case.repo,
                case.id
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_deleted_archived_transferred_states() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .create_trail(&alice, "alice", "proj", "Statesweep", "statesweep intent")
        .await
        .unwrap();
    let id = ulid(900);
    upload_completed(&s, &alice, "alice", "proj", &id, "sessionneedle hello").await;
    // Pushed code with the code needle.
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("sweep.txt", "codeneedle here\n")]).await;
    let alice_write = s.token(&alice, &[Scope::RepoWrite]).await;
    let url = s.git_url("alice", "proj", Some(&alice_write));
    git_ok(&work, &["remote", "add", "origin", &url]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    wait_for_tip(&s, "alice", "proj", "main").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    drain(&s).await;
    let client = reqwest::Client::new();
    let bob_read = s.token(&bob, READ).await;
    let alice_read = s.token(&alice, READ).await;

    async fn visible(
        s: &TestServer,
        client: &reqwest::Client,
        token: Option<&str>,
    ) -> (bool, bool, bool) {
        let (_, trails) = search_api(client, s, "trails", "q=statesweep", token).await;
        let (_, sessions) = search_api(client, s, "sessions", "q=sessionneedle", token).await;
        let (code_status, _) = code_api(client, s, "alice", "proj", token).await;
        (
            !api_trail_repos(&trails).is_empty(),
            !api_session_repos(&sessions).is_empty(),
            code_status == 200,
        )
    }

    assert_eq!(
        visible(&s, &client, Some(&bob_read)).await,
        (true, true, true),
        "the collaborator sees all three surfaces"
    );
    // Revoked grant: immediate through the re-check, no job run.
    s.core
        .remove_collaborator(&alice, "alice", "proj", "bob")
        .await
        .unwrap();
    assert_eq!(
        visible(&s, &client, Some(&bob_read)).await,
        (false, false, false),
        "a revoked grant hides every surface at once"
    );
    assert_eq!(
        visible(&s, &client, Some(&alice_read)).await,
        (true, true, true),
        "the owner still sees everything"
    );
    // Archived repositories stay readable and searchable (only pushes
    // refuse them), still without a job run.
    s.core.archive_repo(&alice, "alice", "proj").await.unwrap();
    assert_eq!(
        visible(&s, &client, Some(&alice_read)).await,
        (true, true, true),
        "an archived repository stays searchable"
    );
    s.core
        .unarchive_repo(&alice, "alice", "proj")
        .await
        .unwrap();
    // Deleted repositories hide every surface at once.
    s.core
        .delete_repo(&alice, "alice", "proj", "alice/proj")
        .await
        .unwrap();
    assert_eq!(
        visible(&s, &client, Some(&alice_read)).await,
        (false, false, false),
        "a deleted repository hides every surface"
    );
    s.core.restore_repo(&alice, repo.id).await.unwrap();
    drain(&s).await;
    assert_eq!(
        visible(&s, &client, Some(&alice_read)).await,
        (true, true, true),
        "a restored repository is searchable again"
    );
    // Quarantine in the database without a job run: the re-check hides
    // it from a plain reader at once; the uploader keeps it.
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    assert_eq!(
        visible(&s, &client, Some(&bob_read)).await,
        (true, true, true)
    );
    let row = db_sessions::session_by_ulid(s.db(), repo.id, &id)
        .await
        .unwrap()
        .unwrap();
    db_sessions::set_quarantine(s.db(), row.id, "quarantined", "test", "test")
        .await
        .unwrap();
    assert_eq!(
        visible(&s, &client, Some(&bob_read)).await,
        (true, false, true),
        "stale quarantine hides the session from a reader"
    );
    assert_eq!(
        visible(&s, &client, Some(&alice_read)).await,
        (true, true, true),
        "the uploader keeps the quarantined session"
    );
    // Release through the real path, then drain: the reader sees it again.
    let access = s
        .core
        .require_repo(Some(&alice), "alice", "proj", Permission::Maintain)
        .await
        .unwrap();
    s.core.release_session(&alice, &access, &id).await.unwrap();
    drain(&s).await;
    assert_eq!(
        visible(&s, &client, Some(&bob_read)).await,
        (true, true, true),
        "a released session is readable again"
    );
    // Transfer to an org the actor owns: ids are stable, collaborators
    // stay, and search follows the new path.
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
    s.core
        .transfer_repo(&alice, "alice", "proj", "acme")
        .await
        .unwrap();
    drain(&s).await;
    let (_, trails) = search_api(&client, &s, "trails", "q=statesweep", Some(&bob_read)).await;
    assert_eq!(
        api_trail_repos(&trails),
        BTreeSet::from(["acme/proj".to_owned()]),
        "the transferred repository is found at its new path"
    );
    let (_, sessions) =
        search_api(&client, &s, "sessions", "q=sessionneedle", Some(&bob_read)).await;
    assert_eq!(
        api_session_repos(&sessions),
        BTreeSet::from([format!("acme/proj:{id}")]),
        "the transferred session is found at its new path"
    );
    let (code_status, _) = code_api(&client, &s, "acme", "proj", Some(&bob_read)).await;
    assert_eq!(code_status, 200, "code search follows the transfer");
    // The old path 301-redirects to the new path for a reader
    // (transfer, like rename, keeps the old path working) — `moved_repo`
    // + the API `redirect_renamed` middleware.
    let no_follow = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let res = no_follow
        .get(s.url("/api/v1/repos/alice/proj/search/code?q=codeneedle"))
        .bearer_auth(&bob_read)
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status().as_u16(),
        301,
        "the old path 301-redirects after transfer"
    );
    assert_eq!(
        res.headers().get("location").and_then(|v| v.to_str().ok()),
        Some("/api/v1/repos/acme/proj/search/code?q=codeneedle"),
        "the redirect points at the new path"
    );
}
