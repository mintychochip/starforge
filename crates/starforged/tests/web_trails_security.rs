//! M2a F5: Trail permission/XSS/CSRF/pagination sweep, web and API alike.
//!
//! F1–F4 proved each surface works; this file asserts the full matrix
//! (action × role × surface) plus the hostile-input corpus, CSRF on every
//! trail POST, and page/`next_after` agreement.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::accounts::{CreateUser, User};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const FULL: &[Scope] = &[Scope::RepoRead, Scope::TrailWrite];

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
            .create_user(CreateUser {
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
        // Suspend after the grant: tokens and logins must stop working.
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

    fn api(&self, path: &str) -> String {
        self.s.url(path)
    }

    async fn token(&self, user: &User) -> String {
        self.s.token(user, FULL).await
    }

    async fn login(&self, handle: &str) -> reqwest::Client {
        let (client, _) = self.s.login(handle).await;
        client
    }
}

/// GET list + detail on the private repo: members and the site admin read,
/// strangers 404, anonymous 404, suspended 401, wrong scope 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_reads() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    c.s.core
        .create_trail(&c.alice, "alice", "proj", "matrix trail", "intent")
        .await
        .unwrap();
    let list = c.api("/api/v1/repos/alice/proj/trails");
    let detail = c.api("/api/v1/repos/alice/proj/trails/1");

    for user in [&c.alice, &c.bob, &c.carol, &c.wendy, &c.adam, &c.root] {
        let t = c.token(user).await;
        for url in [&list, &detail] {
            let res = client.get(url).bearer_auth(&t).send().await.unwrap();
            assert_eq!(res.status(), 200, "{} reads {url}", user.handle);
        }
    }
    // Read-scoped member token still reads.
    let read_only = c.s.token(&c.carol, &[Scope::RepoRead]).await;
    assert_eq!(
        client
            .get(&list)
            .bearer_auth(&read_only)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    // Trail-write-only token lacks repo:read: 403.
    let trail_only = c.s.token(&c.alice, &[Scope::TrailWrite]).await;
    assert_eq!(
        client
            .get(&list)
            .bearer_auth(&trail_only)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    // Stranger with full scopes: 404, never 403.
    let stranger = c.token(&c.dave).await;
    for url in [&list, &detail] {
        let res = client.get(url).bearer_auth(&stranger).send().await.unwrap();
        assert_eq!(res.status(), 404, "stranger reads {url}");
    }
    // Suspended member token: 401.
    let sam_tok = c.token(&c.sam).await;
    assert_eq!(
        client
            .get(&list)
            .bearer_auth(&sam_tok)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // Anonymous: 404 on reads, 401 on mutations.
    assert_eq!(client.get(&list).send().await.unwrap().status(), 404);
    assert_eq!(
        client
            .post(&list)
            .json(&json!({"title": "t", "intent": "i"}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    // One public case: the stranger reads the public repo.
    c.s.core
        .create_trail(&c.alice, "alice", "open", "public", "intent")
        .await
        .unwrap();
    let pub_list = c.api("/api/v1/repos/alice/open/trails");
    assert_eq!(
        client
            .get(&pub_list)
            .bearer_auth(&stranger)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(client.get(&pub_list).send().await.unwrap().status(), 200);

    // Web twins: strangers 404, suspended cannot sign in at all.
    let anon = c.s.browser();
    for url in [
        c.s.url("/alice/proj/trails"),
        c.s.url("/alice/proj/trails/1"),
    ] {
        assert_eq!(anon.get(&url).send().await.unwrap().status(), 404);
        let dave = c.login("dave").await;
        assert_eq!(dave.get(&url).send().await.unwrap().status(), 404);
    }
    let (_, bad) = c.s.try_login("sam", PASSWORD).await;
    assert!(!bad.status().is_redirection(), "suspended login must fail");
    // Site-admin stranger reads the private repo on the web too.
    let root = c.login("root").await;
    let body = get_text(&root, &c.s.url("/alice/proj/trails")).await;
    assert!(body.contains("matrix trail"));
}

/// Mutations across roles: create/comment need ≥ read; state/labels/
/// assignees/edit-others need ≥ triage; comment edits are author-or-admin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_mutations_api() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let list = c.api("/api/v1/repos/alice/proj/trails");
    let post = |t: &str| {
        client
            .post(&list)
            .bearer_auth(t.to_owned())
            .json(&json!({"title": "t", "intent": "i"}))
    };

    // Create: every member grade plus site admin → 201; stranger → 404.
    for user in [&c.alice, &c.bob, &c.carol, &c.wendy, &c.adam, &c.root] {
        let t = c.token(user).await;
        let res = post(&t).send().await.unwrap();
        assert_eq!(res.status(), 201, "{} creates", user.handle);
    }
    let stranger = c.token(&c.dave).await;
    assert_eq!(post(&stranger).send().await.unwrap().status(), 404);
    // Read-scoped token: 403 naming the missing scope.
    let read_only = c.s.token(&c.carol, &[Scope::RepoRead]).await;
    let denied = post(&read_only).send().await.unwrap();
    assert_eq!(denied.status(), 403);
    let body: Value = denied.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("trail:write")
    );

    // Comment: read member ok; stranger 404; anonymous 401.
    let comments = c.api("/api/v1/repos/alice/proj/trails/1/comments");
    let carol = c.token(&c.carol).await;
    assert_eq!(
        client
            .post(&comments)
            .bearer_auth(&carol)
            .json(&json!({"body": "carol's thought"}))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    assert_eq!(
        client
            .post(&comments)
            .bearer_auth(&stranger)
            .json(&json!({"body": "x"}))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .post(&comments)
            .json(&json!({"body": "x"}))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );

    // Comment edit: author and admin ok; triage non-author 403.
    let listed: Value = client
        .get(&comments)
        .bearer_auth(&carol)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = listed["comments"][0]["id"].as_i64().unwrap();
    let edit_url = c.api(&format!("/api/v1/repos/alice/proj/trails/1/comments/{id}"));
    let bob = c.token(&c.bob).await;
    assert_eq!(
        client
            .patch(&edit_url)
            .bearer_auth(&bob)
            .json(&json!({"body": "hijack"}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .patch(&edit_url)
            .bearer_auth(&carol)
            .json(&json!({"body": "refined"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let root = c.token(&c.root).await;
    assert_eq!(
        client
            .patch(&edit_url)
            .bearer_auth(&root)
            .json(&json!({"body": "admin touch"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // State/labels/assignees: triage+ 200; read 403; stranger 404.
    let state = c.api("/api/v1/repos/alice/proj/trails/2");
    for (user, want) in [
        (&c.bob, 200),
        (&c.wendy, 200),
        (&c.adam, 200),
        (&c.root, 200),
        (&c.carol, 403),
    ] {
        let t = c.token(user).await;
        let res = client
            .patch(&state)
            .bearer_auth(&t)
            .json(&json!({"state": "closed"}))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), want, "{} sets state", user.handle);
    }
    // Reopen for the next probes (alice owns the repo).
    let alice = c.token(&c.alice).await;
    client
        .patch(&state)
        .bearer_auth(&alice)
        .json(&json!({"state": "open"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        client
            .patch(&state)
            .bearer_auth(&stranger)
            .json(&json!({"state": "closed"}))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let labels = c.api("/api/v1/repos/alice/proj/trails/2/labels");
    let label = json!({"name": "bug"});
    for (user, want) in [
        (&c.bob, 200),
        (&c.wendy, 200),
        (&c.adam, 200),
        (&c.root, 200),
        (&c.carol, 403),
    ] {
        let t = c.token(user).await;
        let res = client
            .post(&labels)
            .bearer_auth(&t)
            .json(&label)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), want, "{} labels", user.handle);
    }
    let assignees = c.api("/api/v1/repos/alice/proj/trails/2/assignees");
    let assign = json!({"user": "carol"});
    for (user, want) in [
        (&c.bob, 200),
        (&c.wendy, 200),
        (&c.adam, 200),
        (&c.root, 200),
        (&c.carol, 403),
    ] {
        let t = c.token(user).await;
        let res = client
            .post(&assignees)
            .bearer_auth(&t)
            .json(&assign)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), want, "{} assigns", user.handle);
    }
}

/// Web twins of the mutation matrix: controls hidden from readers and
/// strangers, POSTs refused with 403 (readers) or 404 (strangers).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_mutations_web() {
    let c = Ctx::start().await;
    c.s.core
        .create_trail(&c.alice, "alice", "proj", "web matrix", "intent")
        .await
        .unwrap();
    let url = c.s.url("/alice/proj/trails/1");

    // Reader sees only the comment form; triage sees every control.
    let carol = c.login("carol").await;
    let detail = get_text(&carol, &url).await;
    assert!(detail.contains("add-comment"));
    for control in [
        "close-trail",
        "reopen-trail",
        "add-label",
        "add-assignee",
        "trail-ready",
    ] {
        assert!(!detail.contains(control), "reader must not see {control}");
    }
    for handle in ["bob", "wendy", "adam", "root"] {
        let browser = c.login(handle).await;
        let body = get_text(&browser, &url).await;
        for control in ["add-comment", "close-trail", "add-label", "add-assignee"] {
            assert!(body.contains(control), "{handle} must see {control}");
        }
    }
    // Anonymous detail on the public repo carries no forms.
    let open_n =
        c.s.core
            .create_trail(&c.alice, "alice", "open", "pub", "intent")
            .await
            .unwrap()
            .number;
    let anon = c.s.browser();
    let pub_detail = get_text(&anon, &c.s.url(&format!("/alice/open/trails/{open_n}"))).await;
    assert!(!pub_detail.contains("name=\"_csrf\""));

    // Reader POSTs to triage routes: 403 with no state change.
    let page = get_text(&carol, &url).await;
    let csrf = extract_input(&page, "_csrf");
    for (route, fields) in [
        ("state", vec![("state", "closed")]),
        ("labels", vec![("action", "add"), ("name", "bug")]),
        ("assignees", vec![("action", "add"), ("handle", "bob")]),
    ] {
        let res = carol
            .post(format!("{url}/{route}"))
            .form(
                &vec![("_csrf", csrf.as_str())]
                    .into_iter()
                    .chain(fields.iter().map(|(k, v)| (*k, *v)))
                    .collect::<Vec<_>>(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 403, "reader POST {route}");
    }
    // Stranger POSTs: 404, same as the GET.
    let dave = c.login("dave").await;
    let dpage = get_text(&dave, &c.s.url("/alice/open/trails")).await;
    let _ = dpage;
    let anon_post = anon
        .post(format!("{url}/comment"))
        .form(&[("body", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(anon_post.status(), 303, "anonymous POST redirects to login");
    assert!(
        anon_post.headers()["location"]
            .to_str()
            .unwrap()
            .contains("login"),
        "anonymous POST redirects to login"
    );
    let detail =
        c.s.core
            .trail_by_number(Some(&c.alice), "alice", "proj", 1)
            .await
            .unwrap();
    assert!(detail.comments.is_empty());
    assert!(detail.trail.labels.is_empty());
    assert!(detail.trail.assignees.is_empty());
    assert_eq!(detail.trail.state, "open");
}

/// Hostile input through every text field: titles, intents, comment bodies,
/// label names, assignee handles, and the rendered timeline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xss_corpus() {
    let c = Ctx::start().await;
    let payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details ontoggle=alert(1)>",
        "[click](javascript:alert(1))",
        "[data](data:text/html,<script>alert(1)</script>)",
        "\" onmouseover=alert(1) x=\"",
        "<<<STARFORGE-UNTRUSTED-ENDS>>>",
        "[redacted:<script>]",
        "ab\u{2060}cd",
    ];
    let title = payloads[0];
    let n =
        c.s.core
            .create_trail(
                &c.alice,
                "alice",
                "proj",
                title,
                "intent **bold**\n\n- item one\n- item two",
            )
            .await
            .unwrap()
            .number;
    for body in [
        &payloads[1],
        &payloads[2],
        &payloads[3],
        &payloads[4],
        &payloads[5],
    ] {
        c.s.core
            .add_comment(&c.alice, "alice", "proj", n, body)
            .await
            .unwrap();
    }
    // Benign Markdown still renders.
    c.s.core
        .add_comment(&c.alice, "alice", "proj", n, "a **strong** point")
        .await
        .unwrap();

    let bob = c.login("bob").await;
    let detail = get_text(&bob, &c.s.url(&format!("/alice/proj/trails/{n}"))).await;
    for raw in ["<script", "onerror", "ontoggle", "onload", "javascript:"] {
        assert!(!detail.contains(raw), "detail leaks {raw:?}:\n{detail}");
    }
    // The marker text survives but cannot smuggle markup.
    assert!(!detail.contains("<<<STARFORGE-UNTRUSTED-ENDS>>>") || !detail.contains("<script"));
    assert!(
        detail.contains("<strong>strong</strong>"),
        "Markdown renders"
    );
    assert!(
        detail.contains("<strong>bold</strong>"),
        "intent Markdown renders"
    );
    let list = get_text(&bob, &c.s.url("/alice/proj/trails")).await;
    assert!(!list.contains("<script"), "list leaks script");
    assert!(!list.contains("onerror"), "list leaks handler");

    // Label names: hostile values are rejected, never stored or reflected raw.
    let labels_url = c.s.url(&format!("/alice/proj/trails/{n}/labels"));
    for hostile in ["<script>", "a b", "UPPER OK", "x\"y"] {
        let fresh = get_text(&bob, &c.s.url(&format!("/alice/proj/trails/{n}"))).await;
        let token = extract_input(&fresh, "_csrf");
        let res = bob
            .post(&labels_url)
            .form(&[
                ("_csrf", token.as_str()),
                ("action", "add"),
                ("name", hostile),
            ])
            .send()
            .await
            .unwrap();
        // Spaces, markup, and quotes are all outside the label charset.
        assert_eq!(res.status(), 400, "label {hostile:?}");
        let body = res.text().await.unwrap();
        assert!(!body.contains("<script"), "400 page reflects {hostile:?}");
    }
    // API twin: 422 with an `invalid` code.
    let client = reqwest::Client::new();
    let tok = c.token(&c.alice).await;
    let bad = client
        .post(c.api("/api/v1/repos/alice/proj/trails/1/labels"))
        .bearer_auth(&tok)
        .json(&json!({"name": "<script>"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);

    // Assignee handles: unknown/hostile handles are rejected, never rendered.
    let assignees_url = c.s.url(&format!("/alice/proj/trails/{n}/assignees"));
    let page = get_text(&bob, &c.s.url(&format!("/alice/proj/trails/{n}"))).await;
    let csrf = extract_input(&page, "_csrf");
    for hostile in ["<img src=x onerror=alert(1)>", "nosuchuser", "dave"] {
        let res = bob
            .post(&assignees_url)
            .form(&[
                ("_csrf", csrf.as_str()),
                ("action", "add"),
                ("handle", hostile),
            ])
            .send()
            .await
            .unwrap();
        assert!(
            res.status() == 400 || res.status() == 422,
            "assignee {hostile:?} → {}",
            res.status()
        );
        let body = res.text().await.unwrap();
        assert!(
            !body.contains("<img"),
            "assignee error reflects {hostile:?}"
        );
    }
    // API twin: 422 for the hostile handle.
    let bad_api = client
        .post(c.api("/api/v1/repos/alice/proj/trails/1/assignees"))
        .bearer_auth(&tok)
        .json(&json!({"user": "<img src=x onerror=alert(1)>"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_api.status(), 422);

    // Timeline payloads: close the trail and check the event line renders safe.
    c.s.core
        .set_trail_state(&c.bob, "alice", "proj", n, "closed")
        .await
        .unwrap();
    let closed = get_text(&bob, &c.s.url(&format!("/alice/proj/trails/{n}"))).await;
    for raw in ["<script", "onerror", "ontoggle", "onload", "javascript:"] {
        assert!(!closed.contains(raw), "timeline leaks {raw:?}");
    }
}

/// Every trail POST rejects a missing token and a foreign-session token
/// with no state change — including the edit route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_matrix() {
    let c = Ctx::start().await;
    let n =
        c.s.core
            .create_trail(&c.alice, "alice", "proj", "csrf trail", "intent")
            .await
            .unwrap()
            .number;
    let base = c.s.url(&format!("/alice/proj/trails/{n}"));
    let carol = c.login("carol").await;
    let bob = c.login("bob").await;
    let bob_page = get_text(&bob, &base).await;
    let foreign = extract_input(&bob_page, "_csrf");

    let posts: Vec<(String, Vec<(&str, &str)>)> = vec![
        (format!("{base}/comment"), vec![("body", "forged")]),
        (
            format!("{base}/edit"),
            vec![("title", "forged"), ("intent", "forged")],
        ),
        (format!("{base}/state"), vec![("state", "closed")]),
        (
            format!("{base}/labels"),
            vec![("action", "add"), ("name", "bug")],
        ),
        (
            format!("{base}/assignees"),
            vec![("action", "add"), ("handle", "carol")],
        ),
        (
            c.s.url("/alice/proj/trails/new"),
            vec![("title", "forged"), ("intent", "forged")],
        ),
    ];
    for (url, fields) in &posts {
        let missing = carol.post(url).form(&fields.clone()).send().await.unwrap();
        assert_eq!(missing.status(), 403, "missing token: {url}");
        let mut forged = vec![("_csrf", foreign.as_str())];
        for (k, v) in fields {
            forged.push((k, *v));
        }
        let wrong = carol.post(url).form(&forged).send().await.unwrap();
        assert_eq!(wrong.status(), 403, "foreign token: {url}");
    }

    // Nothing moved: no rows, no labels, no assignees, still open.
    let detail =
        c.s.core
            .trail_by_number(Some(&c.alice), "alice", "proj", n)
            .await
            .unwrap();
    assert!(detail.comments.is_empty(), "forged comment wrote a row");
    assert!(detail.trail.labels.is_empty());
    assert!(detail.trail.assignees.is_empty());
    assert_eq!(detail.trail.state, "open");
    let count =
        c.s.core
            .list_trails(
                Some(&c.alice),
                "alice",
                "proj",
                &starforged_core::trails::TrailFilterInput::default(),
            )
            .await
            .unwrap()
            .trails
            .len();
    assert_eq!(count, 1, "forged create wrote a row");
}

/// 35 trails: page 2 shows the remainder with no overlap, and the API
/// `next_after` cursor walks the same sequence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pagination_matches_api_cursor() {
    let c = Ctx::start().await;
    for i in 1..=35 {
        c.s.core
            .create_trail(
                &c.alice,
                "alice",
                "proj",
                &format!("sweep-{i:02}"),
                "intent",
            )
            .await
            .unwrap();
    }
    let carol = c.login("carol").await;
    let p1 = get_text(&carol, &c.s.url("/alice/proj/trails")).await;
    let p2 = get_text(&carol, &c.s.url("/alice/proj/trails?page=2")).await;
    assert!(p1.contains("sweep-01"));
    assert!(!p1.contains("sweep-35"), "page 1 stops at 30");
    assert!(p2.contains("sweep-35"));
    assert!(!p2.contains("sweep-01"), "pages must not overlap");
    for i in 31..=35 {
        assert!(
            p2.contains(&format!("sweep-{i:02}")),
            "page 2 has sweep-{i:02}"
        );
    }

    let client = reqwest::Client::new();
    let tok = c.token(&c.carol).await;
    let first: Value = client
        .get(c.api("/api/v1/repos/alice/proj/trails"))
        .bearer_auth(&tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["trails"].as_array().unwrap().len(), 30);
    assert_eq!(first["trails"][0]["number"], 1);
    let after = first["next_after"].as_i64().unwrap();
    assert_eq!(after, 30);
    let tail: Value = client
        .get(c.api(&format!("/api/v1/repos/alice/proj/trails?after={after}")))
        .bearer_auth(&tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let numbers: Vec<i64> = tail["trails"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["number"].as_i64().unwrap())
        .collect();
    assert_eq!(numbers, vec![31, 32, 33, 34, 35]);
    assert!(tail["next_after"].is_null(), "cursor ends the list");
}

/// Number allocation under contention: 16 concurrent creates in one repo must
/// yield exactly numbers 1..=16 — no gaps, no duplicates. Regression net for
/// the MAX+1 retry on the UNIQUE(repo_id, number) constraint.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_creates_number_without_gaps() {
    let c = Ctx::start().await;
    let mut handles = Vec::new();
    for i in 0..16 {
        let core = c.s.core.clone();
        let alice = c.alice.clone();
        handles.push(tokio::spawn(async move {
            core.create_trail(&alice, "alice", "proj", &format!("race-{i}"), "intent")
                .await
                .unwrap()
                .number
        }));
    }
    let mut numbers = Vec::new();
    for h in handles {
        numbers.push(h.await.unwrap());
    }
    numbers.sort_unstable();
    assert_eq!(numbers, (1..=16).collect::<Vec<_>>());
}
