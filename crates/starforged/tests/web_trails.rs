//! M2a F4: Trail web UI. List, new-form, detail, and mutation routes
//! through a real browser: visibility (private repos 404 for strangers),
//! role-gated controls, CSRF enforcement, XSS escaping, label rules,
//! pagination, and the state control.
mod common;
use common::*;
use serde_json::json;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use starforged_db::checks as db_checks;
use starforged_db::sessions as db_sessions;
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
    // F4: the same strangers 404 on the tab pages.
    for tab in ["changes", "sessions"] {
        let url = c.s.url(&format!("/alice/proj/trails/{n}/{tab}"));
        assert_eq!(status(&anon, "GET", &url).await, 404, "{tab} anon");
        assert_eq!(status(&dave, "GET", &url).await, 404, "{tab} dave");
    }

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
    // F4: anonymous readers get the tab pages on the public repo.
    for tab in ["changes", "sessions"] {
        let page = get_text(
            &anon,
            &c.s.url(&format!("/alice/open/trails/{open_n}/{tab}")),
        )
        .await;
        assert!(page.contains("public trail"), "{tab} anon reads:\n{page}");
    }

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

/// M2e K5: the list form gains the `merged` state, a has-changes select, and
/// a review-requested field; all three filter the list and persist across
/// pager links.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_filters_has_changes_and_review_requested() {
    use starforged_core::tokens::Scope;
    let c = Ctx::start().await;
    for i in 1..=35 {
        c.create(&format!("trail-{i:02}"), "intent").await;
    }
    // One open change on trail 1: push the branches, then open via Core.
    let push_token = c.s.token(&c.alice, &[Scope::RepoWrite]).await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    let url = c.s.git_url("alice", "proj", Some(&push_token));
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    c.s.core
        .create_branch_change(&c.alice, "alice", "proj", 1, "feature/x", "main")
        .await
        .unwrap();
    // Pending review requests for carol on trails 1..=31 (a full pager page).
    for n in 1..=31 {
        c.s.core
            .request_review(&c.bob, "alice", "proj", n, "carol")
            .await
            .unwrap();
    }

    let (carol, _) = c.s.login("carol").await;
    let list = get_text(&carol, &c.trails()).await;
    assert!(list.contains(r#"value="merged""#), "state gains merged");
    assert!(list.contains(r#"name="has_changes""#), "has-changes select");
    assert!(
        list.contains(r#"name="review_requested""#),
        "review-requested field"
    );

    let with_changes = get_text(&carol, &c.s.url("/alice/proj/trails?has_changes=true")).await;
    assert!(with_changes.contains("trail-01"));
    assert!(!with_changes.contains("trail-02"));
    let without_changes = get_text(&carol, &c.s.url("/alice/proj/trails?has_changes=false")).await;
    assert!(!without_changes.contains("trail-01"));
    assert!(without_changes.contains("trail-02"));
    let for_carol = get_text(
        &carol,
        &c.s.url("/alice/proj/trails?review_requested=carol"),
    )
    .await;
    assert!(for_carol.contains("trail-01"));
    assert!(!for_carol.contains("trail-32"), "page 1 stops at 30");
    // (Askama escapes the `&` in pager hrefs, so check the params apart.)
    assert!(
        for_carol.contains("review_requested=carol"),
        "pager links persist the filter"
    );
    assert!(for_carol.contains("page=2"), "pager links carry the page");
    let page2 = get_text(
        &carol,
        &c.s.url("/alice/proj/trails?review_requested=carol&page=2"),
    )
    .await;
    assert!(page2.contains("trail-31"));
    assert!(!page2.contains("trail-01"));
    assert!(
        page2.contains("review_requested=carol"),
        "prev link persists the filter"
    );
    assert!(page2.contains("page=1"), "prev link carries the page");
    // Unknown handles list empty, never 404.
    let unknown = get_text(
        &carol,
        &c.s.url("/alice/proj/trails?review_requested=nosuchuser"),
    )
    .await;
    assert!(unknown.contains("No trails yet."));
}

/// M2f F2: the list gains a has-sessions select that filters and persists
/// across pager links.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_filters_has_sessions() {
    let c = Ctx::start().await;
    for i in 1..=31 {
        c.create(&format!("trail-{i:02}"), "do the thing").await;
    }

    let (carol, _) = c.s.login("carol").await;
    let list = get_text(&carol, &c.trails()).await;
    assert!(
        list.contains(r#"name="has_sessions""#),
        "has-sessions select"
    );

    // No sessions anywhere yet: true matches nothing, false matches all 31.
    let with_sessions = get_text(&carol, &c.s.url("/alice/proj/trails?has_sessions=true")).await;
    assert!(!with_sessions.contains("trail-01"));
    assert!(with_sessions.contains("No trails yet."));
    let without_sessions =
        get_text(&carol, &c.s.url("/alice/proj/trails?has_sessions=false")).await;
    assert!(without_sessions.contains("trail-01"));
    assert!(!without_sessions.contains("trail-31"), "page 1 stops at 30");
    // (Askama escapes the `&` in pager hrefs, so check the params apart.)
    assert!(
        without_sessions.contains("has_sessions=false"),
        "pager links persist the filter"
    );
    assert!(
        without_sessions.contains("page=2"),
        "pager links carry the page"
    );
    let page2 = get_text(
        &carol,
        &c.s.url("/alice/proj/trails?has_sessions=false&page=2"),
    )
    .await;
    assert!(page2.contains("trail-31"));
    assert!(!page2.contains("trail-01"));
}

/// M2f F3 helpers: push main + feature/f3, then open a branch change on the
/// trail. Returns the feature shas, oldest first. Recording is synchronous,
/// so no polling is needed afterwards.
async fn f3_push_change(c: &Ctx, repo: &str, n: i64, subjects: &[&str]) -> Vec<String> {
    let token = c.s.token(&c.alice, &[Scope::RepoWrite]).await;
    let url = c.s.git_url("alice", repo, Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/f3"]).await;
    let mut shas = Vec::new();
    for subject in subjects.iter().copied() {
        commit_files(
            &work,
            &[("a.txt", format!("{subject}\n").as_bytes())],
            subject,
        )
        .await;
        shas.push(
            git_ok(&work, &["rev-parse", "HEAD"])
                .await
                .trim()
                .to_owned(),
        );
    }
    git_ok(&work, &["push", "-q", &url, "feature/f3"]).await;
    c.s.core
        .create_branch_change(&c.alice, "alice", repo, n, "feature/f3", "main")
        .await
        .unwrap();
    shas
}

fn f3_meta(ulid: &str, title: &str, input: i64, output: i64) -> serde_json::Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1"],
        "title": title,
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "main", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": input, "output": output, "cache_read": 1, "cache_write": 2, "reasoning": 3},
        "files_touched": [],
        "redaction": {"fingerprint": "fp-f3", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

/// Uploads a session with distinctive usage numbers.
#[allow(clippy::too_many_arguments)]
async fn f3_upload(
    s: &TestServer,
    token: &str,
    owner: &str,
    repo: &str,
    ulid: &str,
    title: &str,
    input: i64,
    output: i64,
) -> i64 {
    let client = reqwest::Client::new();
    let res = client
        .put(s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions/{ulid}")))
        .bearer_auth(token)
        .json(&f3_meta(ulid, title, input, output))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "upload {ulid}");
    let viewer = s.core.user_by_handle(owner).await.unwrap().unwrap();
    let access = s.core.repo_for(Some(&viewer), owner, repo).await.unwrap();
    db_sessions::session_by_ulid(s.core.db(), access.repo.id, ulid)
        .await
        .unwrap()
        .unwrap()
        .id
}

async fn f3_claim(
    s: &TestServer,
    repo_id: i64,
    session_id: i64,
    ulid: &str,
    sha: &str,
    seq: Option<i64>,
) {
    db_sessions::upsert_claim_link(
        s.core.db(),
        repo_id,
        session_id,
        ulid,
        sha,
        "exact",
        seq,
        seq.map(|v| v + 4),
    )
    .await
    .unwrap();
}

/// Waits for the async post-receive scan to record `head` as revision 2 of
/// change `k` on trail `n` and move the current pointer to it. Recording the
/// same move explicitly would race the scan and append a duplicate revision,
/// so tests push and then wait instead.
async fn wait_for_branch_revision_2(
    s: &TestServer,
    repo_id: i64,
    trail_n: i64,
    k: i64,
    head: &str,
) {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(20);
    loop {
        let trail = starforged_db::trails::trail_by_number(s.core.db(), repo_id, trail_n)
            .await
            .unwrap()
            .unwrap();
        let change = starforged_db::changes::change_by_trail_number(s.core.db(), trail.id, k)
            .await
            .unwrap()
            .unwrap();
        let revs = starforged_db::changes::revisions_of_change(s.core.db(), change.id)
            .await
            .unwrap();
        if revs.len() == 2
            && revs[1].head_sha == head
            && change.current_revision_id == Some(revs[1].id)
        {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for revision 2 of change {k} (have {})",
            revs.len()
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

const F3_ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC8";
const F3_ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC9";
const F3_ULID_C: &str = "01ARZ3NDEKTSV4RRFFQ69G5FCA";

/// F3 tabs: Conversation, Changes, and Sessions render on all three Trail
/// pages with live counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tabs_appear_on_all_trail_pages_with_counts() {
    let c = Ctx::start().await;
    let n = c.create("tabbed trail", "do the thing").await;
    let shas = f3_push_change(&c, "proj", n, &["tabbed work"]).await;
    let token = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let sid = f3_upload(
        &c.s,
        &token,
        "alice",
        "proj",
        F3_ULID_A,
        "tab session",
        7,
        8,
    )
    .await;
    f3_claim(&c.s, repo_id, sid, F3_ULID_A, shas.last().unwrap(), Some(5)).await;
    let (alice, _) = c.s.login("alice").await;
    for path in [
        format!("/alice/proj/trails/{n}"),
        format!("/alice/proj/trails/{n}/changes"),
        format!("/alice/proj/trails/{n}/sessions"),
    ] {
        let page = get_text(&alice, &c.s.url(&path)).await;
        assert!(
            page.contains(&format!("href=\"/alice/proj/trails/{n}/changes\"")),
            "changes tab link in {path}:\n{page}"
        );
        assert!(
            page.contains(&format!("href=\"/alice/proj/trails/{n}/sessions\"")),
            "sessions tab link in {path}:\n{page}"
        );
        assert!(
            page.contains("Changes (1)"),
            "changes count in {path}:\n{page}"
        );
        assert!(
            page.contains("Sessions (1)"),
            "sessions count in {path}:\n{page}"
        );
    }
}

/// F3 changes list page: each change renders with its state and gate summary.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changes_list_shows_state_and_gate_summary() {
    let c = Ctx::start().await;
    let n = c.create("listed trail", "do the thing").await;
    f3_push_change(&c, "proj", n, &["listed work"]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    starforged_db::checks::insert_gate_rule(
        c.s.core.db(),
        repo_id,
        None,
        1,
        false,
        false,
        "[]",
        false,
        false,
        false,
        "[]",
        starforged_db::now(),
    )
    .await
    .unwrap();
    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &c.s.url(&format!("/alice/proj/trails/{n}/changes"))).await;
    assert!(page.contains("change 1"), "change row:\n{page}");
    assert!(page.contains("open"), "state badge:\n{page}");
    assert!(page.contains("Gates failing"), "gate summary:\n{page}");
    assert!(
        page.contains("needs 1 more approval"),
        "gate reason:\n{page}"
    );
    assert!(
        page.contains(&format!("/alice/proj/trails/{n}/changes/1")),
        "change link:\n{page}"
    );
}

/// F3 header gate panel: approvals have/need, required checks with states,
/// conflicts slot, session evidence, and the merge form gated by role.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_gate_panel_shows_gates_and_merge_form_by_role() {
    let c = Ctx::start().await;
    let n = c.create("gated trail", "do the thing").await;
    f3_push_change(&c, "proj", n, &["gated work"]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    starforged_db::checks::insert_gate_rule(
        c.s.core.db(),
        repo_id,
        None,
        1,
        false,
        false,
        "[\"ci/unit\"]",
        false,
        false,
        false,
        "[\"squash\"]",
        starforged_db::now(),
    )
    .await
    .unwrap();
    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &c.s.url(&format!("/alice/proj/trails/{n}/changes"))).await;
    assert!(
        page.contains("needs 1 more approval"),
        "approvals need:\n{page}"
    );
    assert!(page.contains("required context"), "check state:\n{page}");
    assert!(page.contains("ci/unit"), "check context:\n{page}");
    assert!(page.contains("Mergeability"), "mergeability:\n{page}");
    assert!(
        page.contains("Session evidence"),
        "session evidence:\n{page}"
    );
    assert!(
        page.contains(r#"<option value="squash">"#),
        "allowed method:\n{page}"
    );
    assert!(
        !page.contains(r#"<option value="merge">"#),
        "refused method:\n{page}"
    );
    // A read user sees the panel but no merge form.
    let (carol, _) = c.s.login("carol").await;
    let read_page = get_text(&carol, &c.s.url(&format!("/alice/proj/trails/{n}/changes"))).await;
    assert!(
        read_page.contains("needs 1 more approval"),
        "read panel:\n{read_page}"
    );
    assert!(
        !read_page.contains("merge-change-1"),
        "no merge form:\n{read_page}"
    );
    assert!(
        !read_page.contains(r#"<select name="method">"#,),
        "no method picker:\n{read_page}"
    );
}

/// F3: a merge posted from the header panel merges (303); a forged CSRF
/// token is refused (403).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn merge_posted_from_panel_merges_and_forged_csrf_refused() {
    let c = Ctx::start().await;
    let n = c.create("merge trail", "do the thing").await;
    f3_push_change(&c, "proj", n, &["merge work"]).await;
    let (alice, _) = c.s.login("alice").await;
    let list = get_text(&alice, &c.s.url(&format!("/alice/proj/trails/{n}/changes"))).await;
    let csrf = extract_input(&list, "_csrf");
    let merge_url = c.s.url(&format!("/alice/proj/trails/{n}/changes/1/merge"));
    let res = alice
        .post(&merge_url)
        .form(&[("_csrf", csrf.as_str()), ("method", "merge")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "merge from panel");
    // A forged token authorizes nothing, even on the now-merged change.
    let res = alice
        .post(&merge_url)
        .form(&[("_csrf", "forged"), ("method", "merge")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "forged CSRF");
}

/// F3 sessions tab: commit groups with totals and #turn- links, the
/// hand-linked group, working link/unlink forms with CSRF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_tab_groups_totals_links_and_link_unlink() {
    let c = Ctx::start().await;
    let n = c.create("session trail", "do the thing").await;
    let shas = f3_push_change(&c, "proj", n, &["first work", "second work"]).await;
    let up = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let sid_a = f3_upload(
        &c.s,
        &up,
        "alice",
        "proj",
        F3_ULID_A,
        "tabbed session",
        7000,
        800,
    )
    .await;
    f3_claim(
        &c.s,
        repo_id,
        sid_a,
        F3_ULID_A,
        shas.last().unwrap(),
        Some(5),
    )
    .await;
    let sid_b = f3_upload(
        &c.s,
        &up,
        "alice",
        "proj",
        F3_ULID_B,
        "hand session",
        100000,
        20000,
    )
    .await;
    let _ = sid_b;
    c.s.core
        .link_trail_session(&c.alice, "alice", "proj", n, F3_ULID_B)
        .await
        .unwrap();
    let sessions_url = c.s.url(&format!("/alice/proj/trails/{n}/sessions"));
    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &sessions_url).await;
    assert!(page.contains("second work"), "commit subject:\n{page}");
    assert!(page.contains("pi 2.1"), "agent:\n{page}");
    assert!(page.contains("m1"), "models:\n{page}");
    assert!(page.contains("tabbed session"), "title preview:\n{page}");
    assert!(page.contains("total 7806"), "row totals:\n{page}");
    assert!(page.contains("explicit"), "link confidence:\n{page}");
    assert!(page.contains("#turn-5"), "deep link:\n{page}");
    assert!(page.contains("Linked by hand"), "hand group:\n{page}");
    assert!(page.contains(F3_ULID_B), "hand link row:\n{page}");
    assert!(page.contains("total 127812"), "trail totals:\n{page}");
    assert!(page.contains("link-session"), "link form:\n{page}");
    assert!(page.contains("unlink"), "unlink form:\n{page}");
    // The link form links a fresh upload; the unlink form removes it.
    let sid_c = f3_upload(
        &c.s,
        &up,
        "alice",
        "proj",
        F3_ULID_C,
        "third session",
        10,
        20,
    )
    .await;
    let _ = sid_c;
    let csrf = extract_input(&page, "_csrf");
    let res = alice
        .post(&sessions_url)
        .form(&[("_csrf", csrf.as_str()), ("session", F3_ULID_C)])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "link from tab");
    let page = get_text(&alice, &sessions_url).await;
    assert!(page.contains(F3_ULID_C), "linked row:\n{page}");
    let res = alice
        .post(&sessions_url)
        .form(&[("_csrf", "forged"), ("session", F3_ULID_C)])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "forged link CSRF");
    let csrf = extract_input(&page, "_csrf");
    let res = alice
        .post(c.s.url(&format!(
            "/alice/proj/trails/{n}/sessions/{F3_ULID_C}/unlink"
        )))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303, "unlink from tab");
    let page = get_text(&alice, &sessions_url).await;
    assert!(!page.contains(F3_ULID_C), "unlinked row gone:\n{page}");
}

/// F3 §6.4: an unreadable session never appears on the Sessions tab — no
/// title, no ULID, no token totals.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_tab_hides_unreadable_session() {
    let c = Ctx::start().await;
    let n =
        c.s.core
            .create_trail(&c.alice, "alice", "open", "open trail", "do the thing")
            .await
            .unwrap()
            .number;
    let shas = f3_push_change(&c, "open", n, &["open work"]).await;
    let up = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "open")
            .await
            .unwrap()
            .repo
            .id;
    let sid = f3_upload(
        &c.s,
        &up,
        "alice",
        "open",
        F3_ULID_A,
        "secret session",
        910111,
        12131,
    )
    .await;
    f3_claim(&c.s, repo_id, sid, F3_ULID_A, shas.last().unwrap(), Some(9)).await;
    let sessions_url = c.s.url(&format!("/alice/open/trails/{n}/sessions"));
    let anon = c.s.browser();
    let page = get_text(&anon, &sessions_url).await;
    assert!(!page.contains("secret session"), "title leaked:\n{page}");
    assert!(!page.contains(F3_ULID_A), "ULID leaked:\n{page}");
    assert!(!page.contains("910111"), "totals leaked:\n{page}");
    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &sessions_url).await;
    assert!(
        page.contains("secret session"),
        "member reads title:\n{page}"
    );
    assert!(page.contains(F3_ULID_A), "member reads ULID:\n{page}");
    assert!(page.contains("910111"), "member reads totals:\n{page}");
}

/// F3 XSS: a hostile session title and commit subject render escaped on the
/// Sessions tab.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_titles_and_subjects_escape_on_sessions_tab() {
    let c = Ctx::start().await;
    let n = c.create("xss trail", "do the thing").await;
    let shas = f3_push_change(&c, "proj", n, &["<img src=x onerror=alert(2)>"]).await;
    let up = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let sid = f3_upload(
        &c.s,
        &up,
        "alice",
        "proj",
        F3_ULID_A,
        "<script>alert(1)</script>",
        1,
        2,
    )
    .await;
    f3_claim(&c.s, repo_id, sid, F3_ULID_A, shas.last().unwrap(), None).await;
    let (alice, _) = c.s.login("alice").await;
    let page = get_text(
        &alice,
        &c.s.url(&format!("/alice/proj/trails/{n}/sessions")),
    )
    .await;
    assert!(!page.contains("<script>alert(1)"), "live script:\n{page}");
    assert!(
        page.contains("&#60;script&#62;alert(1)"),
        "escaped title:\n{page}"
    );
    assert!(!page.contains("<img src=x"), "live img:\n{page}");
    assert!(page.contains("&#60;img"), "escaped subject:\n{page}");
}

/// F3 fix: every gate-panel id is unique per change — a trail page with two
/// open changes carries no duplicate `id="…"` values.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gate_panel_ids_are_unique_with_two_open_changes() {
    let c = Ctx::start().await;
    let n = c.create("two changes", "do the thing").await;
    let token = c.s.token(&c.alice, &[Scope::RepoWrite]).await;
    let url = c.s.git_url("alice", "proj", Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    for branch in ["feature/g1", "feature/g2"] {
        git_ok(&work, &["checkout", "-q", "-b", branch]).await;
        commit_files(
            &work,
            &[("a.txt", format!("{branch}\n").as_bytes())],
            branch,
        )
        .await;
        git_ok(&work, &["push", "-q", &url, branch]).await;
        git_ok(&work, &["checkout", "-q", "main"]).await;
        c.s.core
            .create_branch_change(&c.alice, "alice", "proj", n, branch, "main")
            .await
            .unwrap();
    }
    // One failing rule so both panels render the banner/list branch.
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    starforged_db::checks::insert_gate_rule(
        c.s.core.db(),
        repo_id,
        None,
        1,
        false,
        false,
        "[]",
        false,
        false,
        false,
        "[]",
        starforged_db::now(),
    )
    .await
    .unwrap();
    let (alice, _) = c.s.login("alice").await;
    for path in [
        format!("/alice/proj/trails/{n}"),
        format!("/alice/proj/trails/{n}/changes"),
        format!("/alice/proj/trails/{n}/sessions"),
    ] {
        let page = get_text(&alice, &c.s.url(&path)).await;
        assert!(
            page.contains("gates-banner-1") && page.contains("gates-banner-2"),
            "both panels render in {path}:\n{page}"
        );
        let mut seen = std::collections::HashSet::new();
        for chunk in page.split("id=\"").skip(1) {
            let id = chunk.split('"').next().unwrap();
            assert!(seen.insert(id), "duplicate id=\"{id}\" in {path}");
        }
    }
}

const F4_ULID_A: &str = "01ARZ3NDEKTSV4RRFFQ70G5FC8";
const F4_ULID_B: &str = "01ARZ3NDEKTSV4RRFFQ70G5FC9";

/// F4: the Conversation timeline merges stored events with derived session
/// and check rows, in time order, with readable sentences for reviews.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeline_merges_sessions_checks_and_reviews_in_order() {
    let c = Ctx::start().await;
    let n = c.create("timeline trail", "do the thing").await;
    // Two revisions: r1 at change creation, r2 via a branch move, so the
    // page carries both a `change.open` and a `change.revision` sentence.
    let token = c.s.token(&c.alice, &[Scope::RepoWrite]).await;
    let url = c.s.git_url("alice", "proj", Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/f4"]).await;
    commit_files(&work, &[("a.txt", b"two\n".as_slice())], "first work").await;
    git_ok(&work, &["push", "-q", &url, "feature/f4"]).await;
    c.s.core
        .create_branch_change(&c.alice, "alice", "proj", n, "feature/f4", "main")
        .await
        .unwrap();
    commit_files(&work, &[("a.txt", b"three\n".as_slice())], "second work").await;
    let r2 = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    git_ok(&work, &["push", "-q", &url, "feature/f4"]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    // The post-receive scan records the push asynchronously; wait for it to
    // make r2 the current revision instead of recording the move explicitly
    // (the explicit call races the scan and duplicates the revision).
    wait_for_branch_revision_2(&c.s, repo_id, n, 1, &r2).await;
    let up = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let sid = f3_upload(
        &c.s,
        &up,
        "alice",
        "proj",
        F3_ULID_A,
        "timeline session",
        100,
        20,
    )
    .await;
    f3_claim(&c.s, repo_id, sid, F3_ULID_A, &r2, Some(5)).await;
    c.s.core
        .submit_review(
            &c.bob,
            "alice",
            "proj",
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
    c.s.core
        .submit_status(
            &c.alice,
            "alice",
            "proj",
            &r2,
            "success",
            "ci/build",
            Some("https://ci.example.com/run/1"),
            Some("All green"),
        )
        .await
        .unwrap();
    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &c.trail(n)).await;
    for want in [
        "opened this trail",
        "opened change 1",
        "pushed revision 2 to change 1",
        "bob approved change 1 (revision 2)",
        "timeline session",
        "#turn-5",
        "ci/build",
        "All green",
    ] {
        assert!(page.contains(want), "timeline has {want:?}:\n{page}");
    }
    assert!(
        !page.contains("review.submitted"),
        "no raw review kind:\n{page}"
    );
    assert!(
        !page.contains("change.revision\""),
        "no raw change kind:\n{page}"
    );
    let pos = |s: &str| {
        page.find(s)
            .unwrap_or_else(|| panic!("missing {s:?}:\n{page}"))
    };
    let opened = pos("opened this trail");
    let change_open = pos("opened change 1");
    let revision = pos("pushed revision 2 to change 1");
    let review = pos("approved change 1 (revision 2)");
    let session = pos("timeline session");
    let check = pos("ci/build");
    assert!(
        opened < change_open
            && change_open < revision
            && revision < session
            && revision < review
            && session < check
            && review < check,
        "time order opened={opened} change_open={change_open} revision={revision} session={session} review={review} check={check}:\n{page}"
    );
}

/// F4 §6.4: a session row linked through commits is absent from the
/// Conversation timeline for a non-member on a public repo while the session
/// is unpublished.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeline_session_row_follows_section_64() {
    let c = Ctx::start().await;
    let n =
        c.s.core
            .create_trail(&c.alice, "alice", "open", "open trail", "do the thing")
            .await
            .unwrap()
            .number;
    let shas = f3_push_change(&c, "open", n, &["open work"]).await;
    let up = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "open")
            .await
            .unwrap()
            .repo
            .id;
    let sid = f3_upload(
        &c.s,
        &up,
        "alice",
        "open",
        F3_ULID_A,
        "secret session",
        910111,
        12131,
    )
    .await;
    f3_claim(&c.s, repo_id, sid, F3_ULID_A, shas.last().unwrap(), Some(9)).await;
    let url = c.s.url(&format!("/alice/open/trails/{n}"));
    let anon = c.s.browser();
    let page = get_text(&anon, &url).await;
    assert!(!page.contains("secret session"), "title leaked:\n{page}");
    assert!(!page.contains(F3_ULID_A), "ULID leaked:\n{page}");
    assert!(!page.contains("910111"), "totals leaked:\n{page}");
    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &url).await;
    assert!(
        page.contains("secret session"),
        "member reads title:\n{page}"
    );
    assert!(page.contains(F3_ULID_A), "member reads ULID:\n{page}");
    assert!(page.contains("#turn-9"), "member reads deep link:\n{page}");
}

/// F4: a hostile check context, description, and target URL render escaped;
/// a `javascript:` URL never becomes a link, while an https URL does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeline_check_xss_escapes() {
    let c = Ctx::start().await;
    let n = c.create("check xss", "do the thing").await;
    let shas = f3_push_change(&c, "proj", n, &["check work"]).await;
    let head = shas.last().unwrap().clone();
    c.s.core
        .submit_status(
            &c.alice,
            "alice",
            "proj",
            &head,
            "failure",
            "<b>ctx</b>",
            Some("https://ci.example.com/evil"),
            Some("<script>alert(2)</script>"),
        )
        .await
        .unwrap();
    // A `javascript:` target URL is rejected by Core validation, so it can
    // only arrive below it: the render layer must still neutralize it.
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    db_checks::insert_check(
        c.s.core.db(),
        repo_id,
        &head,
        "xss-link",
        "failure",
        Some("javascript:alert(3)"),
        Some("hostile"),
        Some(c.alice.id),
        starforged_db::now(),
    )
    .await
    .unwrap();
    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &c.trail(n)).await;
    assert!(!page.contains("<script>alert(2)"), "live script:\n{page}");
    assert!(
        page.contains("&#60;script&#62;alert(2)&#60;/script&#62;"),
        "escaped description:\n{page}"
    );
    assert!(!page.contains("<b>ctx</b>"), "live context:\n{page}");
    assert!(
        page.contains("&#60;b&#62;ctx&#60;/b&#62;"),
        "escaped context:\n{page}"
    );
    assert!(
        !page.contains("javascript:"),
        "javascript URL leaked:\n{page}"
    );
    assert!(
        page.contains("href=\"https://ci.example.com/evil\""),
        "https target links:\n{page}"
    );
}

/// F4 + F3-review: a stored `trail.session_linked` row shows the session ULID
/// only when the viewer can read the session — unpublished on a public repo
/// (anonymous), quarantined on a private repo (non-admin reader) — and the
/// API detail redacts the same payload the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timeline_linked_session_ulid_follows_section_64() {
    let c = Ctx::start().await;
    // Public repo, unpublished hand-linked session.
    let n =
        c.s.core
            .create_trail(&c.alice, "alice", "open", "open trail", "do the thing")
            .await
            .unwrap()
            .number;
    let up = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    f3_upload(&c.s, &up, "alice", "open", F4_ULID_A, "hand session", 7, 8).await;
    c.s.core
        .link_trail_session(&c.alice, "alice", "open", n, F4_ULID_A)
        .await
        .unwrap();
    let url = c.s.url(&format!("/alice/open/trails/{n}"));
    let anon = c.s.browser();
    let page = get_text(&anon, &url).await;
    assert!(
        page.contains("linked a session"),
        "redacted sentence:\n{page}"
    );
    assert!(!page.contains(F4_ULID_A), "ULID leaked to anon:\n{page}");
    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &url).await;
    assert!(page.contains(F4_ULID_A), "member reads ULID:\n{page}");
    // The API detail redacts the same payload for a non-member reader.
    let client = reqwest::Client::new();
    // Carol is a stranger to the public repo: a non-member reader.
    let carol_tok = c.s.token(&c.carol, &[Scope::RepoRead]).await;
    let body: serde_json::Value = client
        .get(c.s.url(&format!("/api/v1/repos/alice/open/trails/{n}")))
        .bearer_auth(&carol_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let linked = body["timeline"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "trail.session_linked")
        .expect("linked row present");
    assert!(
        linked["payload"].get("session").is_none(),
        "API payload redacted for non-member: {linked}"
    );
    let alice_tok = c.s.token(&c.alice, &[Scope::RepoRead]).await;
    let body: serde_json::Value = client
        .get(c.s.url(&format!("/api/v1/repos/alice/open/trails/{n}")))
        .bearer_auth(&alice_tok)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let linked = body["timeline"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "trail.session_linked")
        .expect("linked row present");
    assert_eq!(
        linked["payload"]["session"].as_str(),
        Some(F4_ULID_A),
        "API payload kept for member: {linked}"
    );
    // Private repo, quarantined hand-linked session: a read member sees the
    // sentence but no ULID; the admin uploader sees both.
    let m = c.create("quarantine trail", "do the thing").await;
    let sid = f3_upload(
        &c.s,
        &up,
        "alice",
        "proj",
        F4_ULID_B,
        "quarantined session",
        1,
        2,
    )
    .await;
    c.s.core
        .link_trail_session(&c.alice, "alice", "proj", m, F4_ULID_B)
        .await
        .unwrap();
    db_sessions::set_quarantine(c.s.core.db(), sid, "quarantined", "probe", "")
        .await
        .unwrap();
    let (carol, _) = c.s.login("carol").await;
    let page = get_text(&carol, &c.trail(m)).await;
    assert!(
        page.contains("linked a session"),
        "redacted sentence:\n{page}"
    );
    assert!(!page.contains(F4_ULID_B), "ULID leaked to reader:\n{page}");
    let page = get_text(&alice, &c.trail(m)).await;
    assert!(page.contains(F4_ULID_B), "admin reads ULID:\n{page}");
}

/// F4 + F3-review: the unlink forms on the Sessions tab render only for
/// viewers who may link, like the link form.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_tab_unlink_forms_follow_can_link() {
    let c = Ctx::start().await;
    let n = c.create("link forms", "do the thing").await;
    let up = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    f3_upload(&c.s, &up, "alice", "proj", F3_ULID_A, "linked", 1, 2).await;
    c.s.core
        .link_trail_session(&c.alice, "alice", "proj", n, F3_ULID_A)
        .await
        .unwrap();
    let sessions_url = c.s.url(&format!("/alice/proj/trails/{n}/sessions"));
    let (carol, _) = c.s.login("carol").await;
    let page = get_text(&carol, &sessions_url).await;
    assert!(page.contains(F3_ULID_A), "row renders:\n{page}");
    assert!(
        !page.contains("unlink-"),
        "read member sees unlink forms:\n{page}"
    );
    assert!(
        !page.contains("link-session"),
        "read member sees link form:\n{page}"
    );
    let (bob, _) = c.s.login("bob").await;
    let page = get_text(&bob, &sessions_url).await;
    assert!(page.contains("unlink-"), "triage sees unlink form:\n{page}");
    assert!(
        page.contains("link-session"),
        "triage sees link form:\n{page}"
    );
}
