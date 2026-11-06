//! M4c integration tests: G1 (the GitHub client's wire behavior against
//! the fake API — pagination, cross-origin next links, rate limits, the
//! size cap, SSRF refusal — and placeholder-author rendering) and G2 (the
//! importer: issues/PRs → Trails/changes, review threads and verdicts,
//! author/label/assignee mapping, resumption after an injected rate limit,
//! refusal cases, and the no-webhooks/audit/token-cleanup side effects).

mod common;

use common::fake_github::FakeGithub;
use common::*;
use starforged_core::accounts::CreateUser;
use starforged_core::error::CoreError;
use starforged_core::github::{GithubClient, GithubError};
use starforged_core::permission::Visibility;
use starforged_db::changes as db_changes;
use starforged_db::github_imports as db_imports;
use starforged_db::trails as db_trails;

fn client(base: &str) -> GithubClient {
    GithubClient::new(base, "test-token", true).expect("fake api base is allowed")
}

#[tokio::test]
async fn pagination_follows_same_origin_next_link() {
    let fake = FakeGithub::start().await;
    let client = client(&fake.base);
    let page1 = client.list_issues("octo", "proj", 1).await.unwrap();
    assert_eq!(page1.items.len(), 2, "first page holds half of 3 issues");
    let next = page1.next.clone().expect("page 1 links to page 2");
    assert!(next.starts_with(&fake.base), "next {next} is same-origin");
    let page2 = client.list_issues("octo", "proj", 2).await.unwrap();
    assert_eq!(page2.items.len(), 1);
    assert_eq!(page2.next, None);
    let numbers: Vec<i64> = page1
        .items
        .iter()
        .chain(&page2.items)
        .map(|i| i.number)
        .collect();
    assert_eq!(numbers, vec![1, 2, 3]);
}

#[tokio::test]
async fn pagination_refuses_cross_origin_next_link() {
    let fake = FakeGithub::start().await;
    let client = client(&fake.base);
    // The `crossorigin` repo's listing links its next page off-origin;
    // the client must stop instead of following it.
    let page = client.list_issues("octo", "crossorigin", 1).await.unwrap();
    assert_eq!(page.items.len(), 2, "the first page still arrives");
    assert_eq!(page.next, None, "cross-origin next is refused");
}

#[tokio::test]
async fn types_decode_fixture_fields() {
    let fake = FakeGithub::start().await;
    let client = client(&fake.base);
    let repo = client.get_repository("octo", "proj").await.unwrap();
    assert_eq!(repo.full_name, "octo/proj");
    assert!(repo.clone_url.ends_with("octo/proj.git"));
    let issues = client.list_issues("octo", "proj", 1).await.unwrap();
    assert_eq!(issues.items[0].user.as_ref().unwrap().login, "octocat");
    assert_eq!(issues.items[0].labels[0].name, "bug");
    // The PR inside the issues listing is marked (D5).
    assert!(issues.items[1].pull_request.is_some());
    let pulls = client.list_pulls("octo", "proj", 1).await.unwrap();
    assert_eq!(pulls.items[0].head.name, "feature");
    assert_eq!(pulls.items[0].base.name, "main");
    assert!(pulls.items[0].merged_at.is_some());
    let comments = client
        .list_issue_comments("octo", "proj", 1, 1)
        .await
        .unwrap();
    assert_eq!(comments.items.len(), 1);
    let review_comments = client
        .list_review_comments("octo", "proj", 4, 1)
        .await
        .unwrap();
    assert_eq!(
        review_comments.items[0].path.as_deref(),
        Some("src/main.rs")
    );
    assert_eq!(review_comments.items[0].side.as_deref(), Some("RIGHT"));
    let reviews = client.list_reviews("octo", "proj", 4, 1).await.unwrap();
    assert_eq!(reviews.items[0].state, "APPROVED");
}

#[tokio::test]
async fn rate_limit_maps_to_rate_limited() {
    let fake = FakeGithub::start().await;
    let client = client(&fake.base);
    let err = client
        .list_issues("octo", "ratelimited", 1)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        GithubError::RateLimited {
            reset_at: 1893456000
        }
    );
}

#[tokio::test]
async fn response_cap_is_enforced() {
    let fake = FakeGithub::start().await;
    let client = client(&fake.base);
    let err = client.list_issues("octo", "big", 1).await.unwrap_err();
    assert!(
        matches!(&err, GithubError::Transport(m) if m.contains("10 MiB")),
        "over-cap body refused: {err}"
    );
}

#[tokio::test]
async fn ssrf_private_api_url_is_refused() {
    for url in [
        "https://10.0.0.5/",
        "https://169.254.169.254/",
        "http://192.168.0.1/",
    ] {
        assert!(
            matches!(
                GithubClient::new(url, "token", false),
                Err(GithubError::Invalid(_))
            ),
            "{url} must be refused"
        );
    }
}

#[tokio::test]
async fn placeholder_authors_render_escaped() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    // A hostile imported login: askama escapes `<`, `>`, `"` as numeric
    // entities, and the placeholder must not render as a user link.
    let hostile = "<b>octocat</b>";
    let trail = db_trails::insert_imported_trail(
        s.db(),
        repo.id,
        7,
        "Imported trail",
        "Imported body",
        "open",
        None,
        Some(hostile),
        4242,
        1_700_000_000,
    )
    .await
    .unwrap();
    db_trails::insert_imported_comment(
        s.db(),
        trail.id,
        None,
        Some("octocat"),
        4243,
        "Imported comment",
        1_700_000_100,
    )
    .await
    .unwrap();
    db_trails::insert_timeline(
        s.db(),
        repo.id,
        Some(trail.id),
        "trail.imported",
        None,
        "{}",
        1_700_000_200,
    )
    .await
    .unwrap();
    let (browser, _csrf) = s.login("alice").await;
    let list = get_text(&browser, &s.url("/alice/proj/trails")).await;
    assert!(
        list.contains("&#60;b&#62;octocat&#60;/b&#62; (imported)"),
        "list placeholder:\n{list}"
    );
    assert!(!list.contains(hostile), "hostile login escaped on the list");
    let detail = get_text(&browser, &s.url("/alice/proj/trails/7")).await;
    assert!(
        detail.contains("&#60;b&#62;octocat&#60;/b&#62; (imported)"),
        "trail placeholder:\n{detail}"
    );
    assert!(
        detail.contains("octocat (imported)"),
        "comment placeholder:\n{detail}"
    );
    assert!(
        !detail.contains(r#"<a href="/octocat""#),
        "placeholder is never a link"
    );
    assert!(
        !detail.contains(hostile),
        "hostile login escaped on the trail page"
    );
}
#[tokio::test]
async fn placeholder_votes_do_not_count_by_handle_collision() {
    use starforged_core::permission::Permission;
    use starforged_db::changes as db_changes;
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let _octocat = s.user("octocat").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    // Local `octocat` holds Write; the imported placeholder approval is
    // also by GitHub login `octocat`, so handle-based counting would
    // wrongly credit the Write user. The page is viewed by `reader`
    // (Read, no triage), who also must not resolve the placeholder thread.
    s.core
        .set_collaborator(&alice, "alice", "proj", "octocat", Permission::Write)
        .await
        .unwrap();
    s.user("reader").await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "reader", Permission::Read)
        .await
        .unwrap();
    let trail = db_trails::insert_imported_trail(
        s.db(),
        repo.id,
        1,
        "Imported PR",
        "body",
        "open",
        None,
        Some("octocat"),
        5001,
        1_700_000_000,
    )
    .await
    .unwrap();
    let change = db_changes::insert_change(
        s.db(),
        trail.id,
        "imported",
        None,
        "main",
        alice.id,
        1_700_000_100,
    )
    .await
    .unwrap();
    // Real commits for the revision: the change page diffs base..head,
    // and fake SHAs would fail the diff (500).
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[("src/main.rs", "line one\nline two\n")],
    )
    .await;
    commit_files(
        &work,
        &[("src/main.rs", b"line one\nline two\nline three\n")],
        "second",
    )
    .await;
    let bare = s.core.repo_path(repo.id);
    git_ok(
        &bare,
        &[
            "fetch",
            "-q",
            work.to_str().unwrap(),
            "refs/heads/*:refs/heads/*",
        ],
    )
    .await;
    let base_sha = git_ok(&work, &["rev-parse", "HEAD~1"]).await;
    let head_sha = git_ok(&work, &["rev-parse", "HEAD"]).await;
    let (base_sha, head_sha) = (base_sha.trim(), head_sha.trim());
    let revision =
        db_changes::insert_revision(s.db(), change.id, head_sha, base_sha, None, 1_700_000_200)
            .await
            .unwrap();
    db_changes::set_current_revision(s.db(), change.id, revision.id, 1_700_000_200)
        .await
        .unwrap();
    db_changes::insert_imported_review(
        s.db(),
        change.id,
        revision.id,
        None,
        Some("octocat"),
        6001,
        "approve",
        "Looks good",
        1_700_000_300,
    )
    .await
    .unwrap();
    let thread = db_changes::insert_thread(
        s.db(),
        change.id,
        revision.id,
        "src/main.rs",
        "head",
        1,
        1,
        1_700_000_400,
    )
    .await
    .unwrap();
    db_changes::insert_imported_thread_comment(
        s.db(),
        thread.id,
        None,
        None,
        Some("reader"),
        6002,
        "Nice",
        1_700_000_400,
    )
    .await
    .unwrap();
    let (browser, _csrf) = s.login("reader").await;
    let page = get_text(&browser, &s.url("/alice/proj/trails/1/changes/1")).await;
    assert!(
        page.contains("Approvals: 0"),
        "placeholder approval must not count:\n{page}"
    );
    assert!(
        page.contains("does not count toward merge"),
        "placeholder review marked non-counting:\n{page}"
    );
    assert!(
        !page.contains("/resolve"),
        "placeholder thread author cannot resolve by handle collision:\n{page}"
    );
}
// ---------------------------------------------------------------------------
// G2: the importer.
// ---------------------------------------------------------------------------

/// The `file://` git remote: `main` holds `src/main.rs` (5 lines), the
/// `pr4` branch changes line 4, and `refs/pull/{2,4}/head` point at real
/// commits. Returns the temp dir (keep alive), the `file://` URL, and the
/// PR-4 head SHA.
async fn pull_remote() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let work = work_repo(
        dir.path(),
        "remote",
        &[("src/main.rs", "line1\nline2\nline3\nline4\nline5\n")],
    )
    .await;
    git_ok(&work, &["checkout", "-q", "-b", "pr4"]).await;
    commit_files(
        &work,
        &[(
            "src/main.rs",
            b"line1\nline2\nline3\nline4 changed\nline5\n",
        )],
        "pr4 change",
    )
    .await;
    let head4 = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    git_ok(&work, &["update-ref", "refs/pull/4/head", &head4]).await;
    git_ok(&work, &["update-ref", "refs/pull/2/head", &head4]).await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    let url = format!("file://{}", work.display());
    (dir, url, head4)
}

async fn import_server(fake_base: String) -> TestServer {
    TestServer::start_with(move |config| {
        config.github.api_url = fake_base.clone();
        config.remotes.allow_file_urls = true;
    })
    .await
}

/// Alice, whose verified email matches the GitHub `octocat` user
/// (`octo@example.test`), and her private `proj` repository.
async fn alice_and_repo(
    s: &TestServer,
) -> (
    starforged_core::accounts::User,
    starforged_core::repos::Repo,
) {
    let alice = s
        .core
        .create_user(CreateUser {
            handle: "alice".into(),
            email: Some("octo@example.test".into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap();
    let repo = s.repo(&alice, "proj", Visibility::Private).await;
    (alice, repo)
}

#[tokio::test]
async fn importer_maps_issues_pulls_and_reviews() {
    let (_dir, file_url, head4) = pull_remote().await;
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, repo) = alice_and_repo(&s).await;
    // A hook is configured: the import must dispatch no webhooks for it.
    s.core
        .create_webhook(
            &alice,
            "alice",
            "proj",
            "https://hooks.example.test/hook",
            &["trail".into(), "review".into()],
        )
        .await
        .unwrap();
    s.core
        .start_github_import(&alice, "alice", "proj", "octo/proj", "test-token")
        .await
        .unwrap();
    s.core.run_due_jobs().await.unwrap();

    let import = db_imports::import_of_repo(s.db(), repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(import.state, "completed");
    assert_eq!(
        import.token_sealed, None,
        "the token row is cleared on finish"
    );
    assert_eq!((import.issues_count, import.pulls_count), (2, 2));
    assert_eq!(import.comments_count, 2);
    assert_eq!(import.reviews_count, 2);
    assert_eq!(import.review_comments_count, 2);
    assert!(
        import.dropped_assignees.contains("hubot"),
        "dropped: {}",
        import.dropped_assignees
    );

    // Issues 1 and 3 became Trails without changes (open, closed).
    let t1 = db_trails::trail_by_number(s.db(), repo.id, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t1.state, "open");
    assert_eq!(
        t1.author_id,
        Some(alice.id),
        "octocat matched by verified email"
    );
    assert!(
        db_changes::changes_of_trail(s.db(), t1.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        db_trails::labels_of(s.db(), t1.id).await.unwrap(),
        vec!["bug"]
    );
    let t3 = db_trails::trail_by_number(s.db(), repo.id, 3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t3.state, "closed");
    assert_eq!(t3.imported_author.as_deref(), Some("hubot"));
    assert_eq!(
        db_trails::assignees_of(s.db(), t3.id).await.unwrap(),
        vec![alice.id],
        "matched assignee applied"
    );

    // PR 2 (merged) became Trail 2 with an imported change, revision 1,
    // and the head refs present.
    let t2 = db_trails::trail_by_number(s.db(), repo.id, 2)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t2.state, "merged");
    assert_eq!(t2.imported_author.as_deref(), Some("hubot"));
    let changes2 = db_changes::changes_of_trail(s.db(), t2.id).await.unwrap();
    assert_eq!(changes2.len(), 1);
    let change2 = &changes2[0];
    assert_eq!(change2.kind, "imported");
    assert_eq!(change2.number, 1);
    assert_eq!(change2.state, "merged");
    assert_eq!(
        change2.merge_commit.as_deref(),
        Some("cccccccccccccccccccccccccccccccccccccccc")
    );
    let rev2 = db_changes::revision_by_number(s.db(), change2.id, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rev2.head_sha, head4);
    let repo_dir = s.core.repo_path(repo.id);
    for name in [
        "refs/trails/2/changes/1/head",
        "refs/trails/2/changes/1/rev/1",
    ] {
        let out = std::process::Command::new("git")
            .args(["--git-dir", repo_dir.to_str().unwrap(), "rev-parse", name])
            .output()
            .unwrap();
        assert!(out.status.success(), "ref {name} present");
        assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), head4);
    }

    // PR 4 (open): review comment on an existing line -> thread; on a
    // missing line -> quoted Trail comment. Reviews map to verdicts.
    let t4 = db_trails::trail_by_number(s.db(), repo.id, 4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(t4.state, "open");
    let change4 = db_changes::changes_of_trail(s.db(), t4.id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(change4.state, "open");
    let rev4 = db_changes::latest_revision_of_change(s.db(), change4.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rev4.number, 1);
    let threads = db_changes::threads_of_change(s.db(), change4.id)
        .await
        .unwrap();
    assert_eq!(threads.len(), 1);
    assert_eq!(threads[0].path, "src/main.rs");
    assert_eq!(threads[0].side, "head");
    assert_eq!((threads[0].start_line, threads[0].end_line), (4, 4));
    assert_eq!(threads[0].anchor_revision_id, rev4.id);
    let thread_comments = db_changes::comments_of_thread(s.db(), threads[0].id)
        .await
        .unwrap();
    assert_eq!(thread_comments.len(), 1);
    assert_eq!(thread_comments[0].body, "This line exists in revision 1.");
    assert_eq!(thread_comments[0].imported_author.as_deref(), Some("hubot"));
    let reviews = db_changes::reviews_of_change(s.db(), change4.id)
        .await
        .unwrap();
    assert_eq!(reviews.len(), 2);
    assert!(
        reviews
            .iter()
            .any(|r| r.verdict == "approve" && r.imported_author.as_deref() == Some("hubot"))
    );
    assert!(
        reviews
            .iter()
            .any(|r| r.verdict == "request_changes" && r.author_id == Some(alice.id))
    );
    let comments4 = db_trails::comments_of(s.db(), t4.id).await.unwrap();
    assert_eq!(
        comments4.len(),
        1,
        "the missing-line comment is quoted, only that one"
    );
    assert!(
        comments4[0].body.starts_with("> src/missing.rs:99"),
        "quoted: {}",
        comments4[0].body
    );
    assert!(
        comments4[0]
            .body
            .contains("https://github.com/octo/proj/pull/4#r902")
    );

    // One timeline row per imported Trail, and no webhook deliveries.
    for number in [1, 2, 3, 4] {
        let t = db_trails::trail_by_number(s.db(), repo.id, number)
            .await
            .unwrap()
            .unwrap();
        let timeline = db_trails::timeline_of_trail(s.db(), t.id).await.unwrap();
        assert_eq!(
            timeline
                .iter()
                .filter(|e| e.kind == "trail.imported")
                .count(),
            1,
            "trail {number}"
        );
    }
    let deliveries: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE kind = 'webhook_delivery'")
            .fetch_one(s.db().pool())
            .await
            .unwrap();
    assert_eq!(deliveries, 0, "the import dispatches no webhooks");

    // The audit rows were written, both against the local repository.
    for action in ["repo.github_import_started", "repo.github_import_finished"] {
        let targets: Vec<String> =
            sqlx::query_scalar("SELECT target FROM audit_log WHERE action = $1")
                .bind(action)
                .fetch_all(s.db().pool())
                .await
                .unwrap();
        assert_eq!(
            targets,
            vec!["repo:alice/proj".to_owned()],
            "audit {action}"
        );
    }
    // Imported Trails are indexed (the drained jobs indexed them):
    // searching finds the imported issue by title.
    let hits = s
        .core
        .search_trails(
            Some(&alice),
            &starforged_core::search::SearchQuery {
                q: "First issue".to_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        hits.items
            .iter()
            .any(|t| t.number == 1 && t.title == "First issue"),
        "search finds the imported issue: {:?}",
        hits.items
    );
    // (Last: this live create dispatches a webhook delivery; it runs after
    // the import-only assertions above.)
    // The next new Trail continues after the highest imported number.
    let next = s
        .core
        .create_trail(&alice, "alice", "proj", "Brand new", "")
        .await
        .unwrap();
    assert_eq!(next.number, 5);
}

#[tokio::test]
async fn importer_refuses_non_admin_and_non_empty_repos() {
    let (_dir, file_url, _head) = pull_remote().await;
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, _repo) = alice_and_repo(&s).await;
    let mallory = s.user("mallory").await;
    // A non-admin reader of a public repository gets Forbidden.
    let public = s.repo(&alice, "pub", Visibility::Public).await;
    let err = s
        .core
        .start_github_import(&mallory, "alice", "pub", "octo/proj", "test-token")
        .await
        .unwrap_err();
    assert!(
        matches!(err, CoreError::Forbidden),
        "reader: {err:?} (repo {})",
        public.id
    );
    // A non-reader of the private repository gets NotFound.
    let err = s
        .core
        .start_github_import(&mallory, "alice", "proj", "octo/proj", "test-token")
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::NotFound), "non-reader: {err:?}");
    // A repository that already has Trails refuses the import (422).
    s.core
        .create_trail(&alice, "alice", "proj", "Existing", "")
        .await
        .unwrap();
    let err = s
        .core
        .start_github_import(&alice, "alice", "proj", "octo/proj", "test-token")
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::Invalid(_)), "has trails: {err:?}");
}

#[tokio::test]
async fn importer_bad_token_fails_after_five_runs_and_clears_token() {
    let (_dir, file_url, _head) = pull_remote().await;
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, repo) = alice_and_repo(&s).await;
    let row = s
        .core
        .start_github_import(&alice, "alice", "proj", "octo/proj", "bad-token")
        .await
        .unwrap();
    assert!(row.token_sealed.is_some(), "the token is sealed at rest");
    // The fake answers 401 for `bad-token`; each run fails below the cap
    // and the fifth marks the import failed.
    for _ in 0..5 {
        let _ = s.core.run_github_import(repo.id).await;
    }
    let import = db_imports::import_of_repo(s.db(), repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(import.state, "failed");
    assert_eq!(import.failures, 5);
    assert_eq!(
        import.token_sealed, None,
        "the token row is cleared on failure"
    );
    let error = import.error.unwrap();
    assert!(
        !error.contains("bad-token"),
        "secrets never leak into errors: {error}"
    );
    assert!(
        db_trails::trails_of_repo(s.db(), repo.id, &db_trails::TrailFilter::default())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn importer_resumes_after_injected_rate_limit_without_duplicates() {
    let (_dir, file_url, _head) = pull_remote().await;
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, repo) = alice_and_repo(&s).await;
    // The GitHub slug names the fake repo `flaky`, which rate-limits its
    // third request (the first issue's comments): the run re-enqueues at
    // the reset time instead of failing.
    s.core
        .start_github_import(&alice, "alice", "proj", "octo/flaky", "test-token")
        .await
        .unwrap();
    s.core.run_github_import(repo.id).await.unwrap();
    let import = db_imports::import_of_repo(s.db(), repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(import.state, "rate_limited");
    assert_eq!(import.cursor_kind, "issues");
    assert!(
        import.token_sealed.is_some(),
        "rate limits keep the token for the resume"
    );
    // The resume completes the import without duplicating anything.
    s.core.run_github_import(repo.id).await.unwrap();
    let import = db_imports::import_of_repo(s.db(), repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(import.state, "completed");
    assert_eq!((import.issues_count, import.pulls_count), (2, 2));
    assert_eq!(import.comments_count, 2);
    let filter = db_trails::TrailFilter {
        limit: 100,
        ..Default::default()
    };
    let trails = db_trails::trails_of_repo(s.db(), repo.id, &filter)
        .await
        .unwrap();
    let numbers: Vec<i64> = trails.iter().map(|t| t.number).collect();
    assert_eq!(numbers, vec![1, 2, 3, 4], "no duplicates after the resume");
}

#[tokio::test]
async fn importer_unfetchable_pull_head_closes_change_with_note() {
    // A `file://` remote *without* any `refs/pull/*/head`: every pull
    // head is unfetchable, which closes the change with a note comment
    // rather than failing the import.
    let dir = tempfile::tempdir().unwrap();
    let work = work_repo(
        dir.path(),
        "remote",
        &[("src/main.rs", "line1\nline2\nline3\nline4\nline5\n")],
    )
    .await;
    let file_url = format!("file://{}", work.display());
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, repo) = alice_and_repo(&s).await;
    s.core
        .start_github_import(&alice, "alice", "proj", "octo/proj", "test-token")
        .await
        .unwrap();
    s.core.run_github_import(repo.id).await.unwrap();
    let import = db_imports::import_of_repo(s.db(), repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        import.state, "completed",
        "an unfetchable head is not a failure"
    );
    let t2 = db_trails::trail_by_number(s.db(), repo.id, 2)
        .await
        .unwrap()
        .unwrap();
    let change2 = db_changes::changes_of_trail(s.db(), t2.id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(change2.state, "closed");
    assert!(
        db_changes::revision_by_number(s.db(), change2.id, 1)
            .await
            .unwrap()
            .is_none()
    );
    let comments = db_trails::comments_of(s.db(), t2.id).await.unwrap();
    assert!(
        comments
            .iter()
            .any(|c| c.body.contains("no longer fetchable")),
        "the note comment: {:?}",
        comments.iter().map(|c| &c.body).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn importer_transient_pull_head_fetch_failure_retries_instead_of_closing() {
    // The `refs/pull/<n>/head` refs exist (so `ls-remote` proves them),
    // but the objects directory is temporarily moved aside: the head
    // fetch fails. That is transient, not "ref gone" — the run takes the
    // retry ladder, writes no unfetchable note, and on resume (objects
    // restored) ends with the open change + revision 1.
    let dir = tempfile::tempdir().unwrap();
    let work = work_repo(
        dir.path(),
        "remote",
        &[("src/main.rs", "line1\nline2\nline3\nline4\nline5\n")],
    )
    .await;
    git_ok(&work, &["checkout", "-q", "-b", "pr4"]).await;
    commit_files(
        &work,
        &[(
            "src/main.rs",
            b"line1\nline2\nline3\nline4 changed\nline5\n",
        )],
        "pr4 change",
    )
    .await;
    let head4 = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    git_ok(&work, &["update-ref", "refs/pull/4/head", &head4]).await;
    git_ok(&work, &["update-ref", "refs/pull/2/head", &head4]).await;
    let objects = work.join(".git/objects");
    let stashed = dir.path().join("objects-stashed");
    std::fs::rename(&objects, &stashed).unwrap();
    let file_url = format!("file://{}", work.display());
    let fake = FakeGithub::start_with_clone_url(file_url).await;
    let s = import_server(fake.base.clone()).await;
    let (alice, repo) = alice_and_repo(&s).await;
    s.core
        .start_github_import(&alice, "alice", "proj", "octo/proj", "test-token")
        .await
        .unwrap();
    // First run: the fetch fails → fatal below the cap, no note written.
    assert!(
        s.core.run_github_import(repo.id).await.is_err(),
        "a transient fetch failure must not succeed as 'unfetchable'"
    );
    let import = db_imports::import_of_repo(s.db(), repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(import.state, "running");
    assert_eq!(import.failures, 1);
    // The run died while fetching the first pull's head (PR 2): its
    // Trail and change exist, but no revision and no unfetchable note.
    let t2 = db_trails::trail_by_number(s.db(), repo.id, 2)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !db_trails::comments_of(s.db(), t2.id)
            .await
            .unwrap()
            .iter()
            .any(|c| c.body.contains("no longer fetchable")),
        "no unfetchable note for a transient failure"
    );
    let change2 = db_changes::changes_of_trail(s.db(), t2.id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(change2.state, "open");
    assert!(
        db_changes::revision_by_number(s.db(), change2.id, 1)
            .await
            .unwrap()
            .is_none()
    );
    // Restore the objects and resume: the change ends open with
    // revision 1 and the head refs.
    std::fs::rename(&stashed, &objects).unwrap();
    s.core.run_github_import(repo.id).await.unwrap();
    let import = db_imports::import_of_repo(s.db(), repo.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(import.state, "completed");
    let t4 = db_trails::trail_by_number(s.db(), repo.id, 4)
        .await
        .unwrap()
        .unwrap();
    let change4 = db_changes::changes_of_trail(s.db(), t4.id)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(change4.state, "open");
    let rev4 = db_changes::revision_by_number(s.db(), change4.id, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rev4.head_sha, head4);
    assert_eq!(change4.current_revision_id, Some(rev4.id));
    let repo_dir = s.core.repo_path(repo.id);
    let out = std::process::Command::new("git")
        .args([
            "--git-dir",
            repo_dir.to_str().unwrap(),
            "rev-parse",
            "refs/trails/4/changes/1/head",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "head ref repaired on resume");
}
