//! M2b G5: change page with revisions, diff, reviews, and threads.
//! Real `refs/for` pushes through HTTP, then the HTML change page:
//! header, revision selector, diff, review summary, review/thread forms,
//! resolved/outdated thread markers, role-gated controls, CSRF, 404s for
//! non-readers, and XSS escaping.
mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::*;
use starforged_core::accounts::User;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use tokio::time::sleep;

const SCAN_TIMEOUT: Duration = Duration::from_secs(20);

struct Ctx {
    s: TestServer,
    alice: User,
    _bob: User,
    carol: User,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let _dave = s.user("dave").await;
        s.repo(&alice, "proj", Visibility::Private).await;
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
            _bob: bob,
            carol,
        }
    }

    fn change(&self, n: i64, k: i64) -> String {
        self.s.url(&format!("/alice/proj/trails/{n}/changes/{k}"))
    }
}

/// Pushes the work repo's HEAD as `refs/for/<target>`; returns the pushed SHA.
async fn push_for(work: &Path, url: &str, target: &str) -> String {
    git_ok(
        work,
        &["push", "-q", url, &format!("HEAD:refs/for/{target}")],
    )
    .await;
    git_ok(work, &["rev-parse", "HEAD"]).await.trim().to_owned()
}

async fn setup_pushed_repo(s: &TestServer, alice: &User) -> (PathBuf, String) {
    let token = s.token(alice, &[Scope::RepoWrite]).await;
    let url = s.git_url("alice", "proj", Some(&token));
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("README.md", "# proj\n")]).await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    (work, url)
}

async fn wait_for_change(s: &TestServer, repo_id: i64, user_id: i64, base: &str, topic: &str) {
    let start = Instant::now();
    loop {
        let found = starforged_db::changes::open_agit_change(
            s.core.db(),
            repo_id,
            user_id,
            base,
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
            "timed out waiting for open change {base}/{topic}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_revisions(s: &TestServer, change_id: i64, expected: usize) {
    let start = Instant::now();
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

/// Pushes one commit as `refs/for/main/<topic>` and waits for ingestion.
async fn push_revision(
    c: &Ctx,
    repo_id: i64,
    work: &Path,
    url: &str,
    topic: &str,
    files: &[(&str, &[u8])],
    message: &str,
) {
    commit_files(work, files, message).await;
    push_for(work, url, &format!("main/{topic}")).await;
    wait_for_change(&c.s, repo_id, c.alice.id, "main", topic).await;
    let id = change_id(&c.s, repo_id, c.alice.id, topic).await;
    let before = starforged_db::changes::revisions_of_change(c.s.core.db(), id)
        .await
        .unwrap()
        .len();
    wait_for_revisions(&c.s, id, before.max(1)).await;
}

async fn csrf(client: &reqwest::Client, url: &str) -> String {
    extract_input(&get_text(client, url).await, "_csrf")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_page_renders_revision_diff_and_mergeability() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(
        &c,
        repo_id,
        &work,
        &url,
        "feat",
        &[("feature.txt", b"hello feature\n")],
        "add feature",
    )
    .await;
    c.s.core.run_due_jobs().await.unwrap();

    let (alice, _) = c.s.login("alice").await;
    let page = get_text(&alice, &c.change(1, 1)).await;
    assert!(page.contains("/alice/proj/trails/1"), "trail link:\n{page}");
    assert!(page.contains("feature.txt"), "diff file:\n{page}");
    assert!(page.contains("hello feature"), "diff hunk:\n{page}");
    assert!(page.contains("name=\"rev\""), "revision selector:\n{page}");
    assert!(page.contains("clean"), "mergeability badge:\n{page}");
    // H4: no gate rules means gates pass, so the merge form is live.
    assert!(page.contains("Merge"), "merge button:\n{page}");
    assert!(
        page.contains(r#"<button type="submit">Merge</button>"#),
        "merge button live while gates pass:\n{page}"
    );
    assert!(
        page.contains(r#"name="method""#),
        "merge method select:\n{page}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revision_selector_switches_content() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(
        &c,
        repo_id,
        &work,
        &url,
        "feat",
        &[("a.txt", b"first file\n")],
        "first",
    )
    .await;
    push_revision(
        &c,
        repo_id,
        &work,
        &url,
        "feat",
        &[("b.txt", b"second file\n")],
        "second",
    )
    .await;

    let (alice, _) = c.s.login("alice").await;
    let current = get_text(&alice, &c.change(1, 1)).await;
    assert!(current.contains("b.txt"), "current shows r=2:\n{current}");
    let old = get_text(&alice, &(c.change(1, 1) + "?rev=1")).await;
    assert!(old.contains("a.txt"), "rev=1 shows r=1 diff:\n{old}");
    assert!(!old.contains("b.txt"), "rev=1 hides r=2:\n{old}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_submit_appears_and_counts_write_only() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(
        &c,
        repo_id,
        &work,
        &url,
        "feat",
        &[("a.txt", b"a\n")],
        "first",
    )
    .await;

    // A read member's approve is recorded but does not count toward gates.
    let (carol, _) = c.s.login("carol").await;
    let token = csrf(&carol, &c.change(1, 1)).await;
    let res = carol
        .post(c.change(1, 1) + "/reviews")
        .form(&[
            ("_csrf", token.as_str()),
            ("verdict", "approve"),
            ("body", "looks good"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let page = get_text(&carol, &c.change(1, 1)).await;
    assert!(page.contains("carol"), "reviewer listed:\n{page}");
    assert!(page.contains("looks good"), "review body rendered:\n{page}");
    assert!(
        page.contains("does not count"),
        "read review marked non-counting:\n{page}"
    );

    // A writer's approve counts.
    let (alice, _) = c.s.login("alice").await;
    let token = csrf(&alice, &c.change(1, 1)).await;
    let res = alice
        .post(c.change(1, 1) + "/reviews")
        .form(&[
            ("_csrf", token.as_str()),
            ("verdict", "approve"),
            ("body", "ship it"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let page = get_text(&alice, &c.change(1, 1)).await;
    assert!(page.contains("Approvals: 1"), "counting summary:\n{page}");
    assert!(
        page.contains("counts toward merge"),
        "counting badge:\n{page}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn thread_create_resolve_renders_and_outdates() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(
        &c,
        repo_id,
        &work,
        &url,
        "feat",
        &[("old.txt", b"line one\nline two\n")],
        "first",
    )
    .await;

    let (carol, _) = c.s.login("carol").await;
    let token = csrf(&carol, &c.change(1, 1)).await;
    let res = carol
        .post(c.change(1, 1) + "/threads")
        .form(&[
            ("_csrf", token.as_str()),
            ("path", "old.txt"),
            ("side", "head"),
            ("start", "1"),
            ("end", "2"),
            ("body", "why two lines?"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_owned();
    assert!(location.contains("/alice/proj/trails/1/changes/1"));
    let page = get_text(&carol, &c.change(1, 1)).await;
    assert!(page.contains("old.txt"), "thread file:\n{page}");
    assert!(page.contains("why two lines?"), "thread body:\n{page}");

    // Resolve marks the thread visually.
    let thread_id =
        c.s.core
            .list_threads(Some(&c.carol), "alice", "proj", 1, 1, None)
            .await
            .unwrap()[0]
            .id;
    let res = carol
        .post(format!("{}/threads/{thread_id}/resolve", c.change(1, 1)))
        .form(&[("_csrf", token.as_str()), ("action", "resolve")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let page = get_text(&carol, &c.change(1, 1)).await;
    assert!(page.contains("Resolved"), "resolved marker:\n{page}");

    // A second revision deleting the file outdates the r=1 thread.
    std::fs::remove_file(work.join("old.txt")).unwrap();
    commit_files(&work, &[], "drop old").await;
    push_for(&work, &url, "main/feat").await;
    let id = change_id(&c.s, repo_id, c.alice.id, "feat").await;
    wait_for_revisions(&c.s, id, 2).await;
    let page = get_text(&carol, &c.change(1, 1)).await;
    assert!(page.contains("Outdated"), "outdated marker:\n{page}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_missing_forbidden_and_nonreader_404() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(
        &c,
        repo_id,
        &work,
        &url,
        "feat",
        &[("a.txt", b"a\n")],
        "first",
    )
    .await;

    // Missing token: 403 with no state change.
    let (carol, _) = c.s.login("carol").await;
    let res = carol
        .post(c.change(1, 1) + "/reviews")
        .form(&[("verdict", "approve"), ("body", "forged")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    // Wrong token: also 403.
    let res = carol
        .post(c.change(1, 1) + "/reviews")
        .form(&[
            ("_csrf", "wrong"),
            ("verdict", "approve"),
            ("body", "forged"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let reviews =
        c.s.core
            .list_reviews(Some(&c.carol), "alice", "proj", 1, 1, None)
            .await
            .unwrap();
    assert!(reviews.is_empty(), "forged posts write nothing");

    // Strangers 404 on the change page of a private repo.
    let anon = c.s.browser();
    let res = anon.get(c.change(1, 1)).send().await.unwrap();
    assert_eq!(res.status(), 404);
    let (dave, _) = c.s.login("dave").await;
    let res = dave.get(c.change(1, 1)).send().await.unwrap();
    assert_eq!(res.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xss_payloads_render_escaped() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(
        &c,
        repo_id,
        &work,
        &url,
        "feat",
        &[("a.txt", b"a\n")],
        "first",
    )
    .await;

    let (alice, _) = c.s.login("alice").await;
    let token = csrf(&alice, &c.change(1, 1)).await;
    let res = alice
        .post(c.change(1, 1) + "/reviews")
        .form(&[
            ("_csrf", token.as_str()),
            ("verdict", "comment"),
            ("body", "nice review\n\n<script>alert(1)</script>"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let res = alice
        .post(c.change(1, 1) + "/threads")
        .form(&[
            ("_csrf", token.as_str()),
            ("path", "a.txt"),
            ("side", "head"),
            ("start", "1"),
            ("end", "1"),
            ("body", "<img src=\"x\" onerror=\"alert(1)\"> pic"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);

    let page = get_text(&alice, &c.change(1, 1)).await;
    assert!(!page.contains("<script"), "no script element:\n{page}");
    assert!(!page.contains("<img"), "no image element:\n{page}");
    assert!(page.contains("nice"), "review text survives:\n{page}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dismiss_close_and_reopen_flow() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(
        &c,
        repo_id,
        &work,
        &url,
        "feat",
        &[("a.txt", b"a\n")],
        "first",
    )
    .await;

    // Read member reviews; triage dismisses.
    let (carol, _) = c.s.login("carol").await;
    let token = csrf(&carol, &c.change(1, 1)).await;
    let res = carol
        .post(c.change(1, 1) + "/reviews")
        .form(&[
            ("_csrf", token.as_str()),
            ("verdict", "request_changes"),
            ("body", "needs work"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let review_id =
        c.s.core
            .list_reviews(Some(&c.carol), "alice", "proj", 1, 1, None)
            .await
            .unwrap()[0]
            .id;
    // Read member cannot dismiss: 403.
    let res = carol
        .post(format!("{}/reviews/{review_id}/dismiss", c.change(1, 1)))
        .form(&[("_csrf", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403);
    let (bob, _) = c.s.login("bob").await;
    let bob_token = csrf(&bob, &c.change(1, 1)).await;
    let res = bob
        .post(format!("{}/reviews/{review_id}/dismiss", c.change(1, 1)))
        .form(&[("_csrf", bob_token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let page = get_text(&bob, &c.change(1, 1)).await;
    assert!(page.contains("dismissed"), "dismissed marker:\n{page}");

    // Creator closes and reopens.
    let (alice, _) = c.s.login("alice").await;
    let alice_token = csrf(&alice, &c.change(1, 1)).await;
    let res = alice
        .post(c.change(1, 1) + "/state")
        .form(&[("_csrf", alice_token.as_str()), ("state", "closed")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let page = get_text(&alice, &c.change(1, 1)).await;
    assert!(page.contains("closed"), "closed state:\n{page}");
    let res = alice
        .post(c.change(1, 1) + "/state")
        .form(&[("_csrf", alice_token.as_str()), ("state", "open")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_page_renders_gate_panel() {
    let c = Ctx::start().await;
    let repo_id =
        c.s.core
            .repo_for(Some(&c.alice), "alice", "proj")
            .await
            .unwrap()
            .repo
            .id;
    let (work, url) = setup_pushed_repo(&c.s, &c.alice).await;
    push_revision(
        &c,
        repo_id,
        &work,
        &url,
        "feat",
        &[("feature.txt", b"hello feature\n")],
        "add feature",
    )
    .await;
    c.s.core.run_due_jobs().await.unwrap();
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
    let page = get_text(&alice, &c.change(1, 1)).await;
    assert!(page.contains("Gates"), "gate panel:\n{page}");
    assert!(page.contains("Gates failing"), "failing banner:\n{page}");
    assert!(
        page.contains("needs 1 more approval"),
        "gate reason:\n{page}"
    );

    c.s.core
        .submit_review(
            &c.alice,
            "alice",
            "proj",
            1,
            1,
            None,
            "approve",
            "lgtm",
            None,
            &[],
        )
        .await
        .unwrap();
    let page = get_text(&alice, &c.change(1, 1)).await;
    assert!(page.contains("All gates pass"), "passing banner:\n{page}");
}
