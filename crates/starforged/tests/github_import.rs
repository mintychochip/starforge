//! M4c G1 integration tests: the GitHub client's wire behavior against
//! the fake API (pagination, cross-origin next links, rate limits, the
//! size cap, SSRF refusal) and placeholder-author rendering on the trail
//! list, the trail page, and its comments.

mod common;

use common::fake_github::FakeGithub;
use common::*;
use starforged_core::github::{GithubClient, GithubError};
use starforged_core::permission::Visibility;
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
