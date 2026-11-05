//! M2b G6: changes/reviews/threads security sweep + end-to-end flow.
//!
//! The permission matrix (action × role × surface), the hostile-input
//! corpus, CSRF on every change-page POST, and one real-git journey from
//! `refs/for` push to close. Follows `web_trails_security.rs` conventions;
//! every assertion pins real behavior (rows, refs, status codes, bytes).
mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::User;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use tokio::time::sleep;

const FULL: &[Scope] = &[Scope::RepoRead, Scope::TrailWrite];
const SCAN_TIMEOUT: Duration = Duration::from_secs(20);
/// Mergeability polls: a server worker may claim the job first and fail it
/// transiently under test contention, which backs off 60s before retry.
const MERGE_TIMEOUT: Duration = Duration::from_secs(75);

const PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    "<svg onload=\"alert(1)\">",
    "<details ontoggle=\"alert(1)\">x</details>",
    "[evil](javascript:alert(1))",
    "[data](data:text/html,<script>alert(1)</script>)",
    "\"><script>alert(1)</script>",
    "[redacted:<script>]",
    "\u{202E}reversed",
];

/// Executable markup must never reach the page: these elements and URL
/// schemes are absent from every legitimate change/trail template, so any
/// occurrence is attacker markup rendered live. Escaped attacker text (e.g.
/// `&lt;img … onerror=…` in a file path) passes — it is inert.
fn assert_no_live_markup(page: &str, surface: &str) {
    let lower = page.to_lowercase();
    for raw in [
        "<script",
        "<img",
        "<svg",
        "<iframe",
        "<object",
        "<embed",
        "javascript:",
        "data:text/html",
        "attacker.example",
    ] {
        assert!(!lower.contains(raw), "{raw} live on {surface}");
    }
}

/// The escaped form must be present: proves the surface went through the
/// escaper instead of being dropped or rendered raw.
fn assert_escaped(page: &str, encoded: &str, surface: &str) {
    assert!(
        page.contains(encoded),
        "{encoded} missing on {surface}: surface not escaped"
    );
}

struct Ctx {
    s: TestServer,
    alice: User,
    bob: User,
    carol: User,
    wendy: User,
    adam: User,
    root: User,
    dave: User,
    sam: User,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let wendy = s.user("wendy").await;
        let adam = s.user("adam").await;
        let dave = s.user("dave").await;
        let sam = s.user("sam").await;
        s.core
            .create_user(starforged_core::accounts::CreateUser {
                handle: "root".into(),
                password: Some(PASSWORD.into()),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let root = s.core.user_by_handle("root").await.unwrap().unwrap();
        s.repo(&alice, "proj", Visibility::Private).await;
        s.repo(&alice, "open", Visibility::Public).await;
        for (handle, perm) in [
            ("bob", Permission::Triage),
            ("carol", Permission::Read),
            ("wendy", Permission::Write),
            ("adam", Permission::Admin),
            ("sam", Permission::Read),
        ] {
            s.core
                .set_collaborator(&alice, "alice", "proj", handle, perm)
                .await
                .unwrap();
        }
        let sam_id = sam.id;
        s.core.suspend_user(&root, sam_id).await.unwrap();
        Ctx {
            s,
            alice,
            bob,
            carol,
            wendy,
            adam,
            root,
            dave,
            sam,
        }
    }

    async fn token(&self, user: &User) -> String {
        self.s.token(user, FULL).await
    }

    async fn login(&self, handle: &str) -> reqwest::Client {
        let (client, _) = self.s.login(handle).await;
        client
    }

    fn web(&self, n: i64, k: i64) -> String {
        self.s.url(&format!("/alice/proj/trails/{n}/changes/{k}"))
    }

    fn api(&self, n: i64, k: i64) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes/{k}"))
    }

    fn api_list(&self, n: i64) -> String {
        self.s
            .url(&format!("/api/v1/repos/alice/proj/trails/{n}/changes"))
    }

    /// Work repo with `main` pushed (owner token); returns repo id, work dir, push url.
    async fn pushed_repo(&self) -> (i64, PathBuf, String) {
        let token = self.s.token(&self.alice, &[Scope::RepoWrite]).await;
        let url = self.s.git_url("alice", "proj", Some(&token));
        let tmp = tempfile::tempdir().unwrap();
        let tmp_path = tmp.path().to_path_buf();
        std::mem::forget(tmp);
        let work = work_repo(&tmp_path, "work", &[("README.md", "# proj\n")]).await;
        git_ok(&work, &["push", "-q", &url, "main"]).await;
        let repo_id = self
            .s
            .core
            .repo_for(Some(&self.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
        (repo_id, work, url)
    }

    /// Pushes `feature/x` (text edits) with an owner token for branch changes.
    async fn push_feature_branch(&self, work: &Path, url: &str) {
        git_ok(work, &["checkout", "-q", "-b", "feature/x"]).await;
        commit_files(work, &[("a.txt", b"one\ntwo\n")], "add two").await;
        commit_files(work, &[("b.txt", b"bee\n")], "add bee").await;
        git_ok(work, &["push", "-q", url, "main", "feature/x"]).await;
        for alt in ["feature/y", "feature/z", "feature/w"] {
            git_ok(work, &["branch", alt, "feature/x"]).await;
            git_ok(work, &["push", "-q", url, alt]).await;
        }
    }

    async fn trail(&self, token: &str) -> i64 {
        let client = reqwest::Client::new();
        let res = client
            .post(self.s.url("/api/v1/repos/alice/proj/trails"))
            .bearer_auth(token)
            .json(&json!({"title": "sweep trail", "intent": "sweep"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        res.json::<Value>().await.unwrap()["number"]
            .as_i64()
            .unwrap()
    }

    async fn branch_change(&self, n: i64, token: &str) -> Value {
        self.branch_change_on(n, token, "feature/x").await
    }

    async fn branch_change_on(&self, n: i64, token: &str, head: &str) -> Value {
        let client = reqwest::Client::new();
        let res = client
            .post(self.api_list(n))
            .bearer_auth(token)
            .json(&json!({"kind": "branch", "head_branch": head, "base_branch": "main"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "create branch change");
        res.json::<Value>().await.unwrap()
    }
}

async fn wait_for_open_change(s: &TestServer, repo_id: i64, user_id: i64, topic: &str) {
    let start = std::time::Instant::now();
    loop {
        let found = starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            user_id,
            "main",
            topic,
            None,
        )
        .await
        .unwrap();
        if found.is_some() {
            return;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "timed out waiting for open change main/{topic}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_revisions(s: &TestServer, change_id: i64, expected: usize) {
    let start = std::time::Instant::now();
    loop {
        let revs = starforged_db::changes::revisions_of_change(s.core.db(), change_id)
            .await
            .unwrap();
        // The revision row lands before the change's current-revision pointer
        // moves, so a bare count can render the stale revision. Wait for the
        // pointer too.
        if revs.len() == expected
            && current_revision_number(s, change_id).await == Some(expected as i64)
        {
            return;
        }
        assert!(
            start.elapsed() < SCAN_TIMEOUT,
            "timed out waiting for {expected} revisions (have {})",
            revs.len()
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn current_revision_number(s: &TestServer, change_id: i64) -> Option<i64> {
    let change = starforged_db::changes::change_by_id(s.core.db(), change_id)
        .await
        .unwrap()?;
    let current = change.current_revision_id?;
    starforged_db::changes::revision_by_id(s.core.db(), current)
        .await
        .unwrap()
        .map(|r| r.number)
}

async fn change_id(s: &TestServer, repo_id: i64, user_id: i64, topic: &str) -> i64 {
    starforged_db::changes::open_agit_change(s.core.db(), repo_id, user_id, "main", topic, None)
        .await
        .unwrap()
        .expect("change exists")
        .id
}

async fn push_for(work: &Path, url: &str, target: &str, opts: &[&str]) {
    let mut owned = vec!["push".to_owned(), "-q".to_owned()];
    for o in opts {
        owned.push("-o".to_owned());
        owned.push(o.to_string());
    }
    owned.push(url.to_owned());
    owned.push(format!("HEAD:refs/for/{target}"));
    let args: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
    git_ok(work, &args).await;
}

async fn csrf(client: &reqwest::Client, url: &str) -> String {
    extract_input(&get_text(client, url).await, "_csrf")
}

fn timeline_kinds(detail: &Value) -> Vec<String> {
    detail["timeline"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap_or("").to_owned())
        .collect()
}

/// Private-repo reads: members and the site admin read; strangers 404,
/// anonymous 404s, suspended 401s, wrong-scope 403s — web and API alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_reads() {
    let c = Ctx::start().await;
    let alice_tok = c.token(&c.alice).await;
    let (_, work, url) = c.pushed_repo().await;
    c.push_feature_branch(&work, &url).await;
    let n = c.trail(&alice_tok).await;
    c.branch_change(n, &c.token(&c.bob).await).await;
    let client = reqwest::Client::new();

    let web = c.web(n, 1);
    let api_urls = [
        c.api(n, 1),
        format!("{}/diff", c.api(n, 1)),
        format!("{}/revisions", c.api(n, 1)),
        format!("{}/revisions/1", c.api(n, 1)),
        format!("{}/reviews", c.api(n, 1)),
        format!("{}/threads", c.api(n, 1)),
        c.api_list(n),
    ];

    for user in [&c.alice, &c.bob, &c.carol, &c.wendy, &c.adam, &c.root] {
        let t = c.token(user).await;
        let res = client.get(&web).bearer_auth(&t).send().await;
        // Web auth is cookie-based; bearer tokens are ignored there.
        let _ = res;
        let browser = c.login(&user.handle).await;
        assert_eq!(
            browser.get(&web).send().await.unwrap().status(),
            200,
            "{} reads the change page",
            user.handle
        );
        for u in &api_urls {
            assert_eq!(
                client.get(u).bearer_auth(&t).send().await.unwrap().status(),
                200,
                "{} reads {u}",
                user.handle
            );
        }
    }
    // Read-scoped member token still reads.
    let read_only = c.s.token(&c.carol, &[Scope::RepoRead]).await;
    assert_eq!(
        client
            .get(c.api(n, 1))
            .bearer_auth(read_only)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // Trail-write-only token lacks repo:read: 403 on every read.
    let trail_only = c.s.token(&c.alice, &[Scope::TrailWrite]).await;
    for u in &api_urls {
        assert_eq!(
            client
                .get(u)
                .bearer_auth(&trail_only)
                .send()
                .await
                .unwrap()
                .status(),
            403,
            "trail-only token reads {u}"
        );
    }
    // The CLI's session:upload-only token is refused on every route.
    let upload_only = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    for u in &api_urls {
        assert_eq!(
            client
                .get(u)
                .bearer_auth(&upload_only)
                .send()
                .await
                .unwrap()
                .status(),
            403,
            "upload-only token reads {u}"
        );
    }
    let denied = client
        .post(format!("{}/reviews", c.api(n, 1)))
        .bearer_auth(&upload_only)
        .json(&json!({"verdict": "comment", "body": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    // Stranger with full scopes: 404 on reads and mutations alike, never 403.
    let stranger = c.token(&c.dave).await;
    for u in &api_urls {
        assert_eq!(
            client
                .get(u)
                .bearer_auth(&stranger)
                .send()
                .await
                .unwrap()
                .status(),
            404,
            "stranger reads {u}"
        );
    }
    // Suspended member token: 401.
    let sam_tok = c.token(&c.sam).await;
    assert_eq!(
        client
            .get(c.api(n, 1))
            .bearer_auth(sam_tok)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // Anonymous: 404 on reads, 401 on mutations.
    assert_eq!(client.get(c.api(n, 1)).send().await.unwrap().status(), 404);
    assert_eq!(
        client
            .post(format!("{}/reviews", c.api(n, 1)))
            .json(&json!({"verdict": "comment", "body": "x"}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // Web twins: strangers 404, anonymous 404, suspended cannot sign in.
    let anon = c.s.browser();
    assert_eq!(anon.get(&web).send().await.unwrap().status(), 404);
    let dave = c.login("dave").await;
    assert_eq!(dave.get(&web).send().await.unwrap().status(), 404);
    let diff_web = format!("{web}?rev=1");
    assert_eq!(dave.get(&diff_web).send().await.unwrap().status(), 404);
    let (_, bad) = c.s.try_login("sam", PASSWORD).await;
    assert!(!bad.status().is_redirection(), "suspended login must fail");

    // One public case: the stranger and the anonymous browser read.
    let open_n =
        c.s.core
            .create_trail(&c.alice, "alice", "open", "public", "intent")
            .await
            .unwrap()
            .number;
    let pub_web = c.s.url(&format!("/alice/open/trails/{open_n}"));
    let pub_api = c.s.url("/api/v1/repos/alice/open/trails");
    assert_eq!(
        client
            .get(&pub_api)
            .bearer_auth(&stranger)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(client.get(&pub_api).send().await.unwrap().status(), 200);
    assert_eq!(anon.get(&pub_web).send().await.unwrap().status(), 200);
}

/// API mutations: create needs triage, review/thread/comment need read,
/// dismiss needs triage, resolve needs author-or-triage, close needs
/// creator-or-triage; `merged` is refused everywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_mutations_api() {
    let c = Ctx::start().await;
    let alice_tok = c.token(&c.alice).await;
    let bob_tok = c.token(&c.bob).await;
    let carol_tok = c.token(&c.carol).await;
    let wendy_tok = c.token(&c.wendy).await;
    let adam_tok = c.token(&c.adam).await;
    let dave_tok = c.token(&c.dave).await;
    let (_, work, url) = c.pushed_repo().await;
    c.push_feature_branch(&work, &url).await;
    let n = c.trail(&alice_tok).await;
    let client = reqwest::Client::new();
    let body = json!({"kind": "branch", "head_branch": "feature/w", "base_branch": "main"});

    // Branch-change creation is triage+: writers and admins pass, readers 403.
    for (tok, head, want) in [
        (&bob_tok, "feature/x", 201),
        (&wendy_tok, "feature/y", 201),
        (&adam_tok, "feature/z", 201),
        (&carol_tok, "feature/w", 403),
    ] {
        let res = client
            .post(c.api_list(n))
            .bearer_auth(tok)
            .json(&json!({"kind": "branch", "head_branch": head, "base_branch": "main"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), want, "create branch change");
    }
    // Stranger 404, anonymous 401, wrong scope 403, upload-only 403.
    assert_eq!(
        client
            .post(c.api_list(n))
            .bearer_auth(&dave_tok)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .post(c.api_list(n))
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // A trail:write-only token legitimately creates: mutations need the
    // trail:write scope, and Core enforces the repo permission (same as trails).
    let trail_only = c.s.token(&c.alice, &[Scope::TrailWrite]).await;
    assert_eq!(
        client
            .post(c.api_list(n))
            .bearer_auth(&trail_only)
            .json(&json!({"kind": "branch", "head_branch": "feature/w", "base_branch": "main"}))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    // A read-scoped token names the missing scope.
    let read_only = c.s.token(&c.carol, &[Scope::RepoRead]).await;
    let denied = client
        .post(c.api_list(n))
        .bearer_auth(read_only)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert!(
        denied.json::<Value>().await.unwrap()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("trail:write")
    );
    let upload_only = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    assert_eq!(
        client
            .post(c.api_list(n))
            .bearer_auth(&upload_only)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    let reviews = format!("{}/reviews", c.api(n, 1));
    let threads = format!("{}/threads", c.api(n, 1));
    // Any reader may submit any verdict.
    for verdict in ["approve", "request_changes", "comment"] {
        let res = client
            .post(&reviews)
            .bearer_auth(&carol_tok)
            .json(&json!({"verdict": verdict, "body": format!("{verdict} ok")}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "{verdict}");
    }
    // Stranger 404, anonymous 401 on review submit.
    assert_eq!(
        client
            .post(&reviews)
            .bearer_auth(&dave_tok)
            .json(&json!({"verdict": "comment", "body": "x"}))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .post(&reviews)
            .json(&json!({"verdict": "comment", "body": "x"}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // Dismiss needs triage even for the review author.
    let list: Value = client
        .get(&reviews)
        .bearer_auth(&carol_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = list["reviews"][0]["id"].as_i64().unwrap();
    assert_eq!(
        client
            .post(format!("{reviews}/{id}/dismiss"))
            .bearer_auth(&carol_tok)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(format!("{reviews}/{id}/dismiss"))
            .bearer_auth(&bob_tok)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // Thread create/comment need read; stranger 404, anonymous 401.
    let opened: Value = client
        .post(&threads)
        .bearer_auth(&carol_tok)
        .json(&json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 2, "body": "nit"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tid = opened["id"].as_i64().unwrap();
    assert_eq!(
        client
            .post(&threads)
            .bearer_auth(&dave_tok)
            .json(&json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 1, "body": "x"}))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // Resolve needs the thread author or triage: another reader gets 403.
    let erin = c.s.user("erin").await;
    c.s.core
        .set_collaborator(&c.alice, "alice", "proj", "erin", Permission::Read)
        .await
        .unwrap();
    let erin_tok = c.token(&erin).await;
    assert_eq!(
        client
            .post(format!("{threads}/{tid}/resolve"))
            .bearer_auth(&erin_tok)
            .json(&json!({"resolved": true}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(format!("{threads}/{tid}/resolve"))
            .bearer_auth(&carol_tok)
            .json(&json!({"resolved": true}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(format!("{threads}/{tid}/comments"))
            .bearer_auth(&erin_tok)
            .json(&json!({"body": "second"}))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    // Close/reopen: non-creator reader 403, stranger 404, anonymous 401.
    assert_eq!(
        client
            .patch(c.api(n, 1))
            .bearer_auth(&carol_tok)
            .json(&json!({"state": "closed"}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .patch(c.api(n, 1))
            .bearer_auth(&dave_tok)
            .json(&json!({"state": "closed"}))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .patch(c.api(n, 1))
            .json(&json!({"state": "closed"}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // `merged` is refused for everyone, including triage.
    assert_eq!(
        client
            .patch(c.api(n, 1))
            .bearer_auth(&bob_tok)
            .json(&json!({"state": "merged"}))
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    // Triage closes and reopens.
    assert_eq!(
        client
            .patch(c.api(n, 1))
            .bearer_auth(&bob_tok)
            .json(&json!({"state": "closed"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(format!("{}/state", c.api(n, 1)))
            .bearer_auth(&bob_tok)
            .json(&json!({"state": "open"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
}

/// Web twins: role-gated controls, 403 below threshold, 404 for strangers,
/// login redirect for anonymous POSTs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_mutations_web() {
    let c = Ctx::start().await;
    let alice_tok = c.token(&c.alice).await;
    let (_, work, url) = c.pushed_repo().await;
    c.push_feature_branch(&work, &url).await;
    let n = c.trail(&alice_tok).await;
    c.branch_change(n, &c.token(&c.bob).await).await;
    let page = c.web(n, 1);

    // The non-creator reader sees discussion forms but no curation controls.
    let carol = c.login("carol").await;
    let detail = get_text(&carol, &page).await;
    assert!(detail.contains("add-review"), "reader sees the review form");
    assert!(detail.contains("new-thread"), "reader sees the thread form");
    for control in ["close-change", "reopen-change", "Dismiss"] {
        assert!(!detail.contains(control), "reader must not see {control}");
    }
    // Triage+ sees every control.
    for handle in ["bob", "wendy", "adam", "root"] {
        let browser = c.login(handle).await;
        let body = get_text(&browser, &page).await;
        for control in ["add-review", "new-thread", "close-change", "Dismiss"] {
            assert!(body.contains(control), "{handle} must see {control}");
        }
    }
    // Anonymous on the public repo gets no forms at all.
    let open_n =
        c.s.core
            .create_trail(&c.alice, "alice", "open", "pub", "intent")
            .await
            .unwrap()
            .number;
    let anon = c.s.browser();
    let pub_detail = get_text(&anon, &c.s.url(&format!("/alice/open/trails/{open_n}"))).await;
    assert!(!pub_detail.contains("name=\"_csrf\""));

    // Reader POSTs below threshold: 403 with no state change.
    let token = csrf(&carol, &page).await;
    let res = carol
        .post(page.clone() + "/state")
        .form(&[("_csrf", token.as_str()), ("state", "closed")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let state =
        c.s.core
            .get_change(Some(&c.carol), "alice", "proj", n, 1, None)
            .await
            .unwrap()
            .change
            .state;
    assert_eq!(state, "open");

    // Stranger POSTs 404 like the GET; anonymous POSTs redirect to login.
    let dave = c.login("dave").await;
    let res = dave
        .post(page.clone() + "/reviews")
        .form(&[("_csrf", "x"), ("verdict", "comment"), ("body", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);
    let anon_post = anon
        .post(page.clone() + "/reviews")
        .form(&[("verdict", "comment"), ("body", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(anon_post.status(), 303, "anonymous POST redirects to login");
    assert!(
        anon_post.headers()["location"]
            .to_str()
            .unwrap()
            .contains("login")
    );
    let reviews =
        c.s.core
            .list_reviews(Some(&c.carol), "alice", "proj", n, 1, None)
            .await
            .unwrap();
    assert!(reviews.is_empty(), "forged posts write nothing");
}

/// Hostile input through every rendered surface: review bodies, thread
/// comments, trail titles, branch names, file paths, diff lines, and the
/// mergeability conflict list. No raw handlers, no `<img>`, no attacker
/// host — while benign Markdown still renders.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xss_corpus() {
    let c = Ctx::start().await;
    let alice_tok = c.token(&c.alice).await;
    let (repo_id, work, url) = c.pushed_repo().await;

    // Hostile trail title via `-o title=` (kept under the 200-char cap;
    // the full corpus rides in review/thread bodies); hostile file + diff lines.
    let title = PAYLOADS[..3].join(" ");
    commit_files(
        &work,
        &[
            (
                "<img src=x onerror=alert(1)>.txt",
                b"<script>alert(1)</script>\n",
            ),
            ("a.txt", b"hello\n"),
        ],
        "first",
    )
    .await;
    push_for(&work, &url, "main/xss", &[&format!("title={title}")]).await;
    wait_for_open_change(&c.s, repo_id, c.alice.id, "xss").await;
    let id = change_id(&c.s, repo_id, c.alice.id, "xss").await;
    wait_for_revisions(&c.s, id, 1).await;

    // Hostile branch names push fine and track as changes (201): the page
    // must escape them. `a&b` covers entity-escaping of a resolvable name.
    let evil_n = c.trail(&alice_tok).await;
    let client = reqwest::Client::new();
    for branch in ["evil<script>alert(1)</script>", "evil\"q\"y", "a&b"] {
        git_ok(&work, &["branch", branch, "main"]).await;
        git_ok(&work, &["push", "-q", &url, branch]).await;
        let res = client
            .post(c.api_list(evil_n))
            .bearer_auth(&alice_tok)
            .json(&json!({"kind": "branch", "head_branch": branch, "base_branch": "main"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201, "hostile branch {branch}");
    }

    // Hostile review body, thread comment, and reply — plus benign Markdown.
    let (alice, _) = c.s.login("alice").await;
    let page = c.web(1, 1);
    let token = csrf(&alice, &page).await;
    let hostile = format!(
        "{}\n\n**bold** and [text](https://example.com/)\n\n![phonehome](https://attacker.example/t.svg)",
        PAYLOADS.join("\n\n")
    );
    let res = alice
        .post(page.clone() + "/reviews")
        .form(&[
            ("_csrf", token.as_str()),
            ("verdict", "comment"),
            ("body", hostile.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let res = alice
        .post(page.clone() + "/threads")
        .form(&[
            ("_csrf", token.as_str()),
            ("path", "<img src=x onerror=alert(1)>.txt"),
            ("side", "head"),
            ("start", "1"),
            ("end", "1"),
            ("body", hostile.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let threads =
        c.s.core
            .list_threads(Some(&c.alice), "alice", "proj", 1, 1, None)
            .await
            .unwrap();
    let tid = threads[0].id;
    let res = alice
        .post(format!("{page}/threads/{tid}/comments"))
        .form(&[("_csrf", token.as_str()), ("body", hostile.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);

    // A conflicting commit on main exercises the conflict-path list.
    git_ok(&work, &["checkout", "-q", "main"]).await;
    git_ok(&work, &["reset", "-q", "--hard", "HEAD~1"]).await;
    commit_files(
        &work,
        &[("<img src=x onerror=alert(1)>.txt", b"conflict\n")],
        "conflict",
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let start = std::time::Instant::now();
    loop {
        // Tests drive the job queue themselves (push_changes.rs convention):
        // the server workers may be idle in-process.
        c.s.core.run_due_jobs().await.unwrap();
        let detail =
            c.s.core
                .get_change(Some(&c.alice), "alice", "proj", 1, 1, None)
                .await
                .unwrap();
        if detail.change.mergeability == "conflict" {
            break;
        }
        assert!(
            start.elapsed() < MERGE_TIMEOUT,
            "mergeability never flipped to conflict"
        );
        sleep(Duration::from_millis(50)).await;
    }

    for (n, k_max) in [(1, 1), (evil_n, 3)] {
        for k in 1..=k_max {
            let rendered = get_text(&alice, &c.web(n, k)).await;
            assert_no_live_markup(&rendered, &format!("trail {n} change {k}"));
        }
    }
    // Every hostile surface renders escaped rather than dropped or live:
    // askama escapes paths/branch names/diff lines (`&#60;`), the Markdown
    // sanitizer strips live markup but keeps the text (`alert(1)` stays).
    let change_page = get_text(&alice, &page).await;
    assert!(
        change_page.contains("conflicting paths"),
        "conflict list renders"
    );
    for encoded in ["&#60;script", "&#60;img"] {
        assert_escaped(&change_page, encoded, "change page");
    }
    assert!(
        change_page.contains("alert(1)") && change_page.contains("onerror"),
        "sanitized text still visible"
    );
    assert!(
        change_page.contains("<strong>bold</strong>"),
        "benign markdown renders"
    );
    assert!(
        change_page.contains("https://example.com/"),
        "benign link renders"
    );
    // The trail page carries the hostile `-o title=` the same way.
    let trail_page = get_text(&alice, &c.s.url("/alice/proj/trails/1")).await;
    assert_no_live_markup(&trail_page, "trail page");
    assert_escaped(&trail_page, "&#60;script", "trail page");
}

/// Every change-page POST rejects a missing or foreign CSRF token with 403
/// and writes nothing — including the triage-only and author-only routes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_matrix() {
    let c = Ctx::start().await;
    let alice_tok = c.token(&c.alice).await;
    let (_, work, url) = c.pushed_repo().await;
    c.push_feature_branch(&work, &url).await;
    let n = c.trail(&alice_tok).await;
    c.branch_change(n, &c.token(&c.bob).await).await;
    let page = c.web(n, 1);

    // Seed one review and one thread as alice so dismiss/resolve/comment
    // routes have targets.
    let (alice, _) = c.s.login("alice").await;
    let token = csrf(&alice, &page).await;
    alice
        .post(page.clone() + "/reviews")
        .form(&[
            ("_csrf", token.as_str()),
            ("verdict", "comment"),
            ("body", "seed"),
        ])
        .send()
        .await
        .unwrap();
    alice
        .post(page.clone() + "/threads")
        .form(&[
            ("_csrf", token.as_str()),
            ("path", "a.txt"),
            ("side", "head"),
            ("start", "1"),
            ("end", "2"),
            ("body", "seed"),
        ])
        .send()
        .await
        .unwrap();
    let review_id =
        c.s.core
            .list_reviews(Some(&c.alice), "alice", "proj", n, 1, None)
            .await
            .unwrap()[0]
            .id;
    let thread_id =
        c.s.core
            .list_threads(Some(&c.alice), "alice", "proj", n, 1, None)
            .await
            .unwrap()[0]
            .id;

    // A foreign session's token: fetch it from another login.
    let (bob, _) = c.s.login("bob").await;
    let foreign = csrf(&bob, &page).await;

    let routes: Vec<(String, Vec<(&str, &str)>)> = vec![
        (
            format!("{page}/reviews"),
            vec![("verdict", "approve"), ("body", "forged")],
        ),
        (format!("{page}/reviews/{review_id}/dismiss"), vec![]),
        (
            format!("{page}/threads"),
            vec![
                ("path", "a.txt"),
                ("side", "head"),
                ("start", "1"),
                ("end", "1"),
                ("body", "forged"),
            ],
        ),
        (
            format!("{page}/threads/{thread_id}/resolve"),
            vec![("action", "resolve")],
        ),
        (
            format!("{page}/threads/{thread_id}/comments"),
            vec![("body", "forged")],
        ),
        (format!("{page}/state"), vec![("state", "closed")]),
        (
            c.s.url(&format!("/alice/proj/trails/{n}/changes/new")),
            vec![("head", "feature/x"), ("base", "main")],
        ),
    ];
    for (route, fields) in &routes {
        for csrf_value in [None, Some(foreign.as_str())] {
            let mut form: Vec<(&str, &str)> = Vec::new();
            if let Some(t) = csrf_value {
                form.push(("_csrf", t));
            }
            form.extend(fields.iter().copied());
            let res = alice.post(route.clone()).form(&form).send().await.unwrap();
            let label = if csrf_value.is_some() {
                "foreign"
            } else {
                "missing"
            };
            assert_eq!(res.status(), 403, "{label} token POST {route}");
        }
    }
    // Nothing was written: one review, one thread, still open, still one change.
    assert_eq!(
        c.s.core
            .list_reviews(Some(&c.alice), "alice", "proj", n, 1, None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        c.s.core
            .list_threads(Some(&c.alice), "alice", "proj", n, 1, None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        c.s.core
            .get_change(Some(&c.alice), "alice", "proj", n, 1, None)
            .await
            .unwrap()
            .change
            .state,
        "open"
    );
    assert_eq!(
        c.s.core
            .list_changes(Some(&c.alice), "alice", "proj", n, None)
            .await
            .unwrap()
            .len(),
        1
    );
}

/// The whole journey over real git: a read user's `refs/for` push becomes a
/// change with r1 and clean mergeability; a second push becomes r2; a
/// conflicting main move flips mergeability to `conflict` with paths; an
/// approval, a request-changes, a resolved thread, and a close each land in
/// the trail timeline and read back through the API.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_push_review_thread_close() {
    let c = Ctx::start().await;
    let (repo_id, work, _url) = c.pushed_repo().await;
    // Carol the reader pushes over HTTP with a read-scoped token.
    let carol_git = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.carol, &[Scope::RepoRead]).await),
    );
    commit_files(&work, &[("a.txt", b"a\n")], "feature one").await;
    git_ok(
        &work,
        &["push", "-q", &carol_git, "HEAD:refs/for/main/feat"],
    )
    .await;
    wait_for_open_change(&c.s, repo_id, c.carol.id, "feat").await;
    let id = change_id(&c.s, repo_id, c.carol.id, "feat").await;
    wait_for_revisions(&c.s, id, 1).await;

    let client = reqwest::Client::new();
    let carol_tok = c.token(&c.carol).await;
    let detail: Value = client
        .get(c.api(1, 1))
        .bearer_auth(&carol_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["change"]["current_revision"], 1);
    assert_eq!(detail["change"]["creator"], "carol");
    let start = std::time::Instant::now();
    loop {
        c.s.core.run_due_jobs().await.unwrap();
        let d: Value = client
            .get(c.api(1, 1))
            .bearer_auth(&carol_tok)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if d["change"]["mergeability"] == "clean" {
            break;
        }
        assert!(
            start.elapsed() < MERGE_TIMEOUT,
            "mergeability never went clean"
        );
        sleep(Duration::from_millis(50)).await;
    }

    let base_sha = git_ok(&work, &["rev-parse", "main"])
        .await
        .trim()
        .to_owned();
    // Second push to the same topic: r2.
    commit_files(&work, &[("a.txt", b"a\nb\n")], "feature two").await;
    git_ok(
        &work,
        &["push", "-q", &carol_git, "HEAD:refs/for/main/feat"],
    )
    .await;
    wait_for_revisions(&c.s, id, 2).await;

    // A conflicting main move flips mergeability to conflict with paths.
    git_ok(&work, &["checkout", "-q", "main"]).await;
    git_ok(&work, &["reset", "-q", "--hard", &base_sha]).await;
    commit_files(&work, &[("a.txt", b"clash\n")], "clash on main").await;
    let owner_git = c.s.git_url(
        "alice",
        "proj",
        Some(&c.s.token(&c.alice, &[Scope::RepoWrite]).await),
    );
    git_ok(&work, &["push", "-q", &owner_git, "main"]).await;
    let start = std::time::Instant::now();
    let conflict: Value = loop {
        c.s.core.run_due_jobs().await.unwrap();
        let d: Value = client
            .get(c.api(1, 1))
            .bearer_auth(&carol_tok)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if d["change"]["mergeability"] == "conflict" {
            break d;
        }
        assert!(
            start.elapsed() < MERGE_TIMEOUT,
            "mergeability never flipped to conflict"
        );
        sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(conflict["change"]["conflict_paths"], json!(["a.txt"]));

    // An approval and a request-changes both record; only write+ counts,
    // so the approval comes from wendy (write) while bob stays triage.
    let wendy_tok = c.token(&c.wendy).await;
    for (tok, verdict) in [(&wendy_tok, "approve"), (&carol_tok, "request_changes")] {
        let res = client
            .post(format!("{}/reviews", c.api(1, 1)))
            .bearer_auth(tok)
            .json(&json!({"verdict": verdict, "body": format!("{verdict} from test")}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
    }
    let detail: Value = client
        .get(c.api(1, 1))
        .bearer_auth(&carol_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["reviews"].as_array().unwrap().len(), 2);
    assert_eq!(detail["reviews"][0]["verdict"], "approve");
    assert_eq!(detail["reviews"][1]["verdict"], "request_changes");

    // Thread opened on r2's head, resolved, then the change closed.
    let threads = format!("{}/threads", c.api(1, 1));
    let opened: Value = client
        .post(&threads)
        .bearer_auth(&carol_tok)
        .json(&json!({"path": "a.txt", "side": "head", "start_line": 1, "end_line": 2, "body": "nit"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tid = opened["id"].as_i64().unwrap();
    assert_eq!(
        client
            .post(format!("{threads}/{tid}/resolve"))
            .bearer_auth(&carol_tok)
            .json(&json!({"resolved": true}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // The creator (read, but author) closes her own change.
    assert_eq!(
        client
            .patch(c.api(1, 1))
            .bearer_auth(&carol_tok)
            .json(&json!({"state": "closed"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // The change page and the trail timeline reflect every step.
    let (carol_browser, _) = c.s.login("carol").await;
    let page = get_text(&carol_browser, &c.web(1, 1)).await;
    assert!(page.contains("counts toward merge"), "approval counts");
    assert!(
        page.contains("does not count toward merge"),
        "read review does not count"
    );
    assert!(page.contains("closed"), "page shows the closed state");
    assert!(page.contains("conflict"), "page shows mergeability");
    assert!(page.contains("a.txt"), "page shows the conflict path");
    let trail: Value = client
        .get(c.s.url("/api/v1/repos/alice/proj/trails/1"))
        .bearer_auth(&carol_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let kinds = timeline_kinds(&trail);
    for want in [
        "change.open",
        "change.revision",
        "change.mergeability",
        "review.submitted",
        "thread.open",
        "thread.resolved",
        "change.state",
    ] {
        assert!(
            kinds.contains(&want.to_owned()),
            "timeline has {want}: {kinds:?}"
        );
    }
    let final_detail: Value = client
        .get(c.api(1, 1))
        .bearer_auth(&carol_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(final_detail["change"]["state"], "closed");
    assert_eq!(final_detail["change"]["current_revision"], 2);
    assert_eq!(final_detail["threads"][0]["resolved"], true);
}
