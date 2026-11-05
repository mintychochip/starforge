//! M2a F4: Trail web UI. List, new-form, detail, and mutation routes
//! through a real browser: visibility (private repos 404 for strangers),
//! role-gated controls, CSRF enforcement, XSS escaping, label rules,
//! pagination, and the state control.
mod common;

use common::*;
use starforged_core::permission::{Permission, Visibility};
struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    bob: starforged_core::accounts::User,
    carol: starforged_core::accounts::User,
}
impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let _dave = s.user("dave").await;
        s.repo(&alice, "proj", Visibility::Private).await;
        s.repo(&alice, "open", Visibility::Public).await;
        s.core
            .set_collaborator(&alice, "alice", "proj", "bob", Permission::Triage)
            .await
            .unwrap();
        s.core
            .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
            .await
            .unwrap();
        Ctx {
            s,
            alice,
            bob,
            carol,
        }
    }

    fn trails(&self) -> String {
        self.s.url("/alice/proj/trails")
    }

    fn trail(&self, n: i64) -> String {
        self.s.url(&format!("/alice/proj/trails/{n}"))
    }

    async fn create(&self, title: &str, intent: &str) -> i64 {
        self.s
            .core
            .create_trail(&self.alice, "alice", "proj", title, intent)
            .await
            .unwrap()
            .number
    }
}

async fn status(client: &reqwest::Client, method: &str, url: &str) -> u16 {
    let req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        _ => panic!("method {method}"),
    };
    req.send().await.unwrap().status().as_u16()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn visibility_and_role_gated_controls() {
    let c = Ctx::start().await;
    let n = c.create("first trail", "do the thing").await;

    // Strangers 404 on list and detail of a private repo — identical bodies
    // so numbers are not enumerable.
    let anon = c.s.browser();
    assert_eq!(status(&anon, "GET", &c.trails()).await, 404);
    assert_eq!(status(&anon, "GET", &c.trail(n)).await, 404);
    assert_eq!(
        status(&anon, "GET", &c.s.url("/alice/proj/trails/9999")).await,
        404
    );
    let (dave, _) = c.s.login("dave").await;
    assert_eq!(status(&dave, "GET", &c.trails()).await, 404);
    assert_eq!(status(&dave, "GET", &c.trail(n)).await, 404);

    // Anonymous on the public repo sees list + detail but no forms.
    let pub_list = get_text(&anon, &c.s.url("/alice/open/trails")).await;
    assert!(pub_list.contains("Trails"));
    let open_n =
        c.s.core
            .create_trail(&c.alice, "alice", "open", "public trail", "hello")
            .await
            .unwrap()
            .number;
    let pub_detail = get_text(&anon, &c.s.url(&format!("/alice/open/trails/{open_n}"))).await;
    assert!(pub_detail.contains("public trail"));
    assert!(
        !pub_detail.contains("name=\"_csrf\""),
        "anonymous detail must carry no forms"
    );

    // Read member sees list, detail, and the comment form — but no
    // close/label/assignee/ready controls.
    let (carol, _) = c.s.login("carol").await;
    let list = get_text(&carol, &c.trails()).await;
    assert!(list.contains("first trail"));
    assert!(list.contains(&format!("/alice/proj/trails/{n}")));
    assert!(list.contains("New trail"));
    let detail = get_text(&carol, &c.trail(n)).await;
    assert!(detail.contains("first trail"));
    assert!(detail.contains("do the thing"));
    assert!(
        detail.contains("add-comment"),
        "read member gets the comment form"
    );
    for control in [
        "close-trail",
        "reopen-trail",
        "add-label",
        "add-assignee",
        "trail-ready",
    ] {
        assert!(
            !detail.contains(control),
            "read member must not see {control}"
        );
    }

    // Triage sees every control.
    let (bob, _) = c.s.login("bob").await;
    let tdetail = get_text(&bob, &c.trail(n)).await;
    for control in [
        "add-comment",
        "close-trail",
        "add-label",
        "add-assignee",
        "trail-ready",
        "edit-trail",
    ] {
        assert!(tdetail.contains(control), "triage must see {control}");
    }

    // Read member cannot use triage controls: 403 each.
    let denied = [
        (c.trail(n) + "/state", vec![("state", "closed")]),
        (
            c.trail(n) + "/labels",
            vec![("action", "add"), ("name", "bug")],
        ),
        (
            c.trail(n) + "/assignees",
            vec![("action", "add"), ("handle", "bob")],
        ),
    ];
    for (url, fields) in denied {
        let page = get_text(&carol, &c.trail(n)).await;
        let csrf = extract_input(&page, "_csrf");
        let mut form = vec![("_csrf", csrf.as_str())];
        for (k, v) in &fields {
            form.push((k, *v));
        }
        let res = carol.post(&url).form(&form).send().await.unwrap();
        assert_eq!(res.status(), 403, "POST {url}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_redirects_to_new_trail() {
    let c = Ctx::start().await;
    let (carol, _) = c.s.login("carol").await;

    let form = get_text(&carol, &c.s.url("/alice/proj/trails/new")).await;
    assert!(form.contains("Markdown"));
    let csrf = extract_input(&form, "_csrf");
    let res = carol
        .post(c.s.url("/alice/proj/trails/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("title", "a new trail"),
            ("intent", "the **plan**"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(location, "/alice/proj/trails/1");
    let detail = get_text(&carol, &c.s.url(&location)).await;
    assert!(detail.contains("a new trail"));
    assert!(detail.contains("<strong>plan</strong>"));

    // Invalid create re-renders with 422 and keeps the form, writing no row.
    let bad = carol
        .post(c.s.url("/alice/proj/trails/new"))
        .form(&[("_csrf", csrf.as_str()), ("title", ""), ("intent", "x")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 422);
    assert!(bad.text().await.unwrap().contains("must not be empty"));
    let trails =
        c.s.core
            .list_trails(
                Some(&c.alice),
                "alice",
                "proj",
                &starforged_core::trails::TrailFilterInput::default(),
            )
            .await
            .unwrap();
    assert_eq!(trails.trails.len(), 1, "invalid create writes no row");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comment_appears_in_timeline_and_list() {
    let c = Ctx::start().await;
    let n = c.create("discuss me", "intent").await;
    let (carol, _) = c.s.login("carol").await;

    let page = get_text(&carol, &c.trail(n)).await;
    let csrf = extract_input(&page, "_csrf");
    let res = carol
        .post(c.trail(n) + "/comment")
        .form(&[("_csrf", csrf.as_str()), ("body", "first **comment**")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let detail = get_text(&carol, &c.trail(n)).await;
    assert!(detail.contains("first <strong>comment</strong>"));
    assert!(detail.contains("commented"));

    // Comment edits: the author and an admin succeed; triage is refused.
    let saved =
        c.s.core
            .trail_by_number(Some(&c.carol), "alice", "proj", n)
            .await
            .unwrap();
    let id = saved.comments[0].id;
    let edit_url = format!("{}/comments/{id}/edit", c.trail(n));
    let ok = carol
        .post(&edit_url)
        .form(&[("_csrf", csrf.as_str()), ("body", "edited body")])
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 303);
    assert!(get_text(&carol, &c.trail(n)).await.contains("edited body"));

    let (bob, _) = c.s.login("bob").await;
    let bob_page = get_text(&bob, &c.trail(n)).await;
    let bob_csrf = extract_input(&bob_page, "_csrf");
    let refused = bob
        .post(&edit_url)
        .form(&[("_csrf", bob_csrf.as_str()), ("body", "hijack")])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);

    let (alice, _) = c.s.login("alice").await;
    let alice_page = get_text(&alice, &c.trail(n)).await;
    let alice_csrf = extract_input(&alice_page, "_csrf");
    let admin_ok = alice
        .post(&edit_url)
        .form(&[("_csrf", alice_csrf.as_str()), ("body", "admin edit")])
        .send()
        .await
        .unwrap();
    assert_eq!(admin_ok.status(), 303);
    assert!(get_text(&carol, &c.trail(n)).await.contains("admin edit"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_failures_write_no_rows() {
    let c = Ctx::start().await;
    let n = c.create("csrf trail", "intent").await;
    let (carol, _) = c.s.login("carol").await;
    let (bob, _) = c.s.login("bob").await;

    // Missing token.
    let missing = carol
        .post(c.trail(n) + "/comment")
        .form(&[("body", "no token")])
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 403);
    // Another user's token.
    let bob_page = get_text(&bob, &c.trail(n)).await;
    let bob_csrf = extract_input(&bob_page, "_csrf");
    let wrong = carol
        .post(c.trail(n) + "/comment")
        .form(&[("_csrf", bob_csrf.as_str()), ("body", "wrong token")])
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 403);
    // Garbage token on a triage control.
    let bad_label = bob
        .post(c.trail(n) + "/labels")
        .form(&[("_csrf", "wrong"), ("action", "add"), ("name", "bug")])
        .send()
        .await
        .unwrap();
    assert_eq!(bad_label.status(), 403);

    let detail =
        c.s.core
            .trail_by_number(Some(&c.alice), "alice", "proj", n)
            .await
            .unwrap();
    assert!(detail.comments.is_empty(), "forged POSTs write no rows");
    assert!(detail.trail.labels.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xss_payloads_render_escaped() {
    let c = Ctx::start().await;
    let title = "<script>alert(1)</script>";
    let n = c.create(title, "# hello\n<script>alert(1)</script>").await;
    c.s.core
        .add_comment(&c.alice, "alice", "proj", n, "<img src=x onerror=alert(1)>")
        .await
        .unwrap();

    let anon = c.s.browser();
    let _ =
        c.s.core
            .set_collaborator(&c.alice, "alice", "open", "dave", Permission::Read)
            .await;
    let open_n =
        c.s.core
            .create_trail(&c.alice, "alice", "open", title, "intent")
            .await
            .unwrap()
            .number;
    let list = get_text(&anon, &c.s.url("/alice/open/trails")).await;
    assert!(!list.contains("<script"), "list leaks script");
    assert!(
        list.contains("&#60;script&#62;"),
        "escaped title present in list"
    );
    let detail = get_text(&anon, &c.s.url(&format!("/alice/open/trails/{open_n}"))).await;
    assert!(!detail.contains("<script"), "detail leaks script");
    assert!(detail.contains("&#60;script&#62;"));

    let (bob, _) = c.s.login("bob").await;
    let priv_detail = get_text(&bob, &c.trail(n)).await;
    assert!(!priv_detail.contains("<script"));
    assert!(!priv_detail.contains("onerror"));
    assert!(priv_detail.contains("&#60;script&#62;"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn labels_normalize_and_reject() {
    let c = Ctx::start().await;
    let n = c.create("label me", "intent").await;
    let (bob, _) = c.s.login("bob").await;
    let page = get_text(&bob, &c.trail(n)).await;
    let csrf = extract_input(&page, "_csrf");

    let added = bob
        .post(c.trail(n) + "/labels")
        .form(&[("_csrf", csrf.as_str()), ("action", "add"), ("name", "Bug")])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303);
    let detail = get_text(&bob, &c.trail(n)).await;
    assert!(detail.contains(">bug<"), "Bug normalizes to bug");

    let bad = bob
        .post(c.trail(n) + "/labels")
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "add"),
            ("name", "not a label!"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 400);

    // Assignees: a member can be added and removed; strangers are refused.
    let assigned = bob
        .post(c.trail(n) + "/assignees")
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "add"),
            ("handle", "carol"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(assigned.status(), 303);
    assert!(get_text(&bob, &c.trail(n)).await.contains("carol"));
    let unknown = bob
        .post(c.trail(n) + "/assignees")
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "add"),
            ("handle", "nobody"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pagination_and_filters() {
    let c = Ctx::start().await;
    for i in 1..=35 {
        c.create(&format!("trail-{i:02}"), "intent").await;
    }
    c.s.core
        .set_trail_state(&c.bob, "alice", "proj", 2, "closed")
        .await
        .unwrap();
    c.s.core
        .add_label(&c.bob, "alice", "proj", 3, "bug")
        .await
        .unwrap();

    let (carol, _) = c.s.login("carol").await;
    let p1 = get_text(&carol, &c.trails()).await;
    let p2 = get_text(&carol, &c.s.url("/alice/proj/trails?page=2")).await;
    assert!(p1.contains("trail-01"));
    assert!(!p1.contains("trail-35"), "page 1 stops at 30");
    assert!(p2.contains("trail-35"));
    assert!(!p2.contains("trail-01"), "pages show distinct trails");

    let closed = get_text(&carol, &c.s.url("/alice/proj/trails?state=closed")).await;
    assert!(closed.contains("trail-02"));
    assert!(!closed.contains("trail-01"));
    let bug = get_text(&carol, &c.s.url("/alice/proj/trails?label=bug")).await;
    assert!(bug.contains("trail-03"));
    assert!(!bug.contains("trail-04"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn state_control_and_ready_toggle() {
    let c = Ctx::start().await;
    let n = c.create("stateful", "intent").await;
    let (bob, _) = c.s.login("bob").await;
    let (carol, carol_csrf) = c.s.login("carol").await;

    // `merged` is never offered in the state control.
    let detail = get_text(&bob, &c.trail(n)).await;
    assert!(!detail.contains("merged"));

    // Close then reopen through the web.
    let page = get_text(&bob, &c.trail(n)).await;
    let csrf = extract_input(&page, "_csrf");
    let closed = bob
        .post(c.trail(n) + "/state")
        .form(&[("_csrf", csrf.as_str()), ("state", "closed")])
        .send()
        .await
        .unwrap();
    assert_eq!(closed.status(), 303);
    assert_eq!(
        closed.headers()["location"],
        format!("/alice/proj/trails/{n}")
    );
    let after = get_text(&bob, &c.trail(n)).await;
    assert!(after.contains("closed"));
    assert!(after.contains("reopen-trail"));

    let forged = bob
        .post(c.trail(n) + "/state")
        .form(&[("_csrf", csrf.as_str()), ("state", "merged")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 400);

    // Ready toggle is triage-only: triage succeeds, the author is refused.
    let carol_trail =
        c.s.core
            .create_trail(&c.carol, "alice", "proj", "carol's own", "mine")
            .await
            .unwrap()
            .number;
    let carol_page = get_text(&carol, &c.trail(carol_trail)).await;
    assert!(
        carol_page.contains("edit-trail"),
        "author may edit own trail"
    );
    let carol_own_csrf = extract_input(&carol_page, "_csrf");
    let edit_ok = carol
        .post(format!("{}/edit", c.trail(carol_trail)))
        .form(&[
            ("_csrf", carol_own_csrf.as_str()),
            ("title", "carol's renamed"),
            ("intent", "mine"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(edit_ok.status(), 303);
    assert!(
        get_text(&carol, &c.trail(carol_trail))
            .await
            .contains("carol&#39;s renamed")
    );
    let ready_denied = carol
        .post(format!("{}/edit", c.trail(carol_trail)))
        .form(&[
            ("_csrf", carol_csrf.as_str()),
            ("title", "carol's renamed"),
            ("intent", "mine"),
            ("ready", "true"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(ready_denied.status(), 403);
    let ready_ok = bob
        .post(format!("{}/edit", c.trail(carol_trail)))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("title", "carol's renamed"),
            ("intent", "mine"),
            ("ready", "true"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(ready_ok.status(), 303);
    assert!(
        get_text(&bob, &c.trail(carol_trail))
            .await
            .contains("ready")
    );
}

/// M2e K4: the Reviewers section round-trips through the form (303), forged
/// CSRF is 403, and a read user sees no reviewer forms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reviewers_section_round_trip() {
    let c = Ctx::start().await;
    let n = c.create("review me", "intent").await;
    let (bob, _) = c.s.login("bob").await;
    let page = get_text(&bob, &c.trail(n)).await;
    assert!(
        page.contains("add-reviewer"),
        "triage sees the request form"
    );
    let csrf = extract_input(&page, "_csrf");

    let added = bob
        .post(c.trail(n) + "/review-requests")
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "add"),
            ("handle", "carol"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303);
    let detail = get_text(&bob, &c.trail(n)).await;
    assert!(detail.contains("Reviewers"), "Reviewers section renders");
    assert!(detail.contains("requested a review from carol"));

    // A forged CSRF token is 403 and writes nothing.
    let forged = bob
        .post(c.trail(n) + "/review-requests")
        .form(&[("_csrf", "wrong"), ("action", "add"), ("handle", "bob")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);

    // Removing round-trips too.
    let removed = bob
        .post(c.trail(n) + "/review-requests")
        .form(&[
            ("_csrf", csrf.as_str()),
            ("action", "remove"),
            ("handle", "carol"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(removed.status(), 303);

    // A read user sees no reviewer forms.
    let (carol, _) = c.s.login("carol").await;
    let read_detail = get_text(&carol, &c.trail(n)).await;
    assert!(
        !read_detail.contains("add-reviewer"),
        "read user must not see the request form"
    );
}
