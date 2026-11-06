//! M4a S3: the `/search` web page — tabs, filters, pagination, highlight
//! rendering, `#turn-<seq>` links, 422s, and XSS escaping.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::ingest::IngestAuth;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
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
    alice: &starforged_core::accounts::User,
    repo: &str,
    ulid: &str,
    text: &str,
) {
    let secret = s.token(alice, &[Scope::SessionUpload]).await;
    let token = s.core.authenticate_token(&secret).await.unwrap();
    let auth: IngestAuth = s
        .core
        .authorize_upload(&token, "alice", repo)
        .await
        .unwrap();
    s.core
        .upsert_session_meta(&auth, ulid, &meta_body(ulid))
        .await
        .unwrap();
    let line = json!({"v": 1, "seq": 0, "ts": "2026-11-04T00:00:00Z", "kind": "user_message", "text": text}).to_string();
    let bytes = starforge_format::compress(format!("{line}\n").as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    s.core
        .put_segment(&auth, ulid, 0, &bytes, Some(hash))
        .await
        .unwrap();
    s.core.complete_session(&auth, ulid).await.unwrap();
    let access = s
        .core
        .require_repo(
            Some(alice),
            "alice",
            repo,
            starforged_core::permission::Permission::Maintain,
        )
        .await
        .unwrap();
    s.core.publish_session(alice, &access, ulid).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_page_tabs_filters_and_highlights() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "open", Visibility::Public).await;
    s.core
        .create_trail(&alice, "alice", "open", "Zebra alpha", "plumbline intent")
        .await
        .unwrap();
    drain(&s).await;

    let client = s.browser();
    let page = get_text(&client, &s.url("/search?q=zebra")).await;
    assert!(
        page.contains("Trails") && page.contains("Sessions"),
        "both tabs render"
    );
    assert!(
        page.contains("/alice/open/trails/1"),
        "trail result links to the trail"
    );
    assert!(page.contains("Zebra alpha"), "trail title renders");
    assert!(
        page.contains("<mark>Zebra</mark>"),
        "the query word is highlighted: {page}"
    );
    assert!(
        !page.contains("<script>alert"),
        "no raw script tag from data"
    );

    // The filter form is present in the layout header (base template).
    let home = get_text(&client, &s.url("/")).await;
    assert!(
        home.contains("action=\"/search\""),
        "the header search box posts to /search"
    );

    // Repository filter narrows to nothing for an unknown repo.
    let page = get_text(&client, &s.url("/search?q=zebra&repo=alice%2Fnope")).await;
    assert!(
        !page.contains("/alice/open/trails/1"),
        "an unknown repo filter yields no results"
    );
    let page = get_text(&client, &s.url("/search?q=zebra&repo=alice%2Fopen")).await;
    assert!(
        page.contains("/alice/open/trails/1"),
        "the repo filter narrows"
    );

    // Sessions tab links to #turn-0 and is noindex.
    upload_completed(
        &s,
        &alice,
        "open",
        "01ARZ3NDEKTSV4RRFFQ69G5FCG",
        "sessionneedle hello",
    )
    .await;
    drain(&s).await;
    let res = client
        .get(s.url("/search?tab=sessions&q=sessionneedle"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.headers()
            .get("x-robots-tag")
            .and_then(|v| v.to_str().ok()),
        Some("noindex")
    );
    let page = res.text().await.unwrap();
    assert!(
        page.contains("#turn-0"),
        "session results deep-link to the turn: {page}"
    );
    assert!(
        page.contains("<mark>sessionneedle</mark>"),
        "session highlights render"
    );
    // Filters that exclude the session: agent and repo.
    let page = get_text(
        &client,
        &s.url("/search?tab=sessions&q=sessionneedle&agent=other"),
    )
    .await;
    assert!(
        !page.contains("#turn-0"),
        "the agent filter excludes the session"
    );
    let page = get_text(
        &client,
        &s.url("/search?tab=sessions&q=sessionneedle&model=m1"),
    )
    .await;
    assert!(
        page.contains("#turn-0"),
        "the model filter includes the session"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_page_pagination_and_validation() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "open", Visibility::Public).await;
    for title in ["Pager one", "Pager two", "Pager three"] {
        s.core
            .create_trail(&alice, "alice", "open", title, "intent")
            .await
            .unwrap();
    }
    drain(&s).await;
    let client = s.browser();

    let page = get_text(&client, &s.url("/search?q=pager&per_page=2")).await;
    assert!(page.contains("Next"), "more pages are offered");
    assert!(page.contains("page=2"), "the pager links to page 2");
    let page2 = get_text(&client, &s.url("/search?q=pager&per_page=2&page=2")).await;
    assert!(page2.contains("Previous"), "page 2 links back");
    assert!(!page2.contains("Next"), "page 2 is the last page");

    // Invalid input answers 422 (CoreError::Invalid maps to Unprocessable).
    for qs in [
        "per_page=51",
        "from=notadate",
        "tab=sessions&commit=xyz",
        "page=0",
    ] {
        let res = client
            .get(s.url(&format!("/search?q=pager&{qs}")))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 422, "?{qs} must be 422");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_page_escapes_hostile_text() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "open", Visibility::Public).await;
    s.core
        .create_trail(
            &alice,
            "alice",
            "open",
            "<script>alert(1)</script> zebra",
            "intent with <img src=x onerror=alert(2)>",
        )
        .await
        .unwrap();
    s.core
        .add_comment(
            &alice,
            "alice",
            "open",
            1,
            "comment with <b>boldneedle</b> text",
        )
        .await
        .unwrap();
    upload_completed(
        &s,
        &alice,
        "open",
        "01ARZ3NDEKTSV4RRFFQ69G5FCH",
        "session text with <script>alert(3)</script> sessionneedle",
    )
    .await;
    drain(&s).await;
    let client = s.browser();

    // Trail title, comment text: escaped, highlights intact.
    let page = get_text(&client, &s.url("/search?q=zebra")).await;
    assert!(
        page.contains("&#60;script&#62;alert(1)&#60;/script&#62;"),
        "the hostile title is escaped: {page}"
    );
    assert!(
        !page.contains("<script>alert(1)</script>"),
        "no raw hostile markup"
    );
    assert!(
        page.contains("<mark>zebra</mark>"),
        "highlights survive escaping"
    );

    let page = get_text(&client, &s.url("/search?q=boldneedle")).await;
    assert!(
        page.contains("&#60;b&#62;") && page.contains("<mark>boldneedle</mark>"),
        "comment text is escaped with the highlight intact: {page}"
    );
    assert!(
        !page.contains("<b>boldneedle</b>"),
        "comment markup is not rendered raw"
    );

    // Session text likewise.
    let page = get_text(&client, &s.url("/search?tab=sessions&q=sessionneedle")).await;
    assert!(
        page.contains("&#60;script&#62;alert(3)&#60;/script&#62;"),
        "session text is escaped: {page}"
    );
    assert!(
        page.contains("<mark>sessionneedle</mark>"),
        "session highlights survive escaping"
    );
    assert!(page.contains("#turn-0"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_page_respects_permissions() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "closed", Visibility::Private).await;
    s.core
        .create_trail(&alice, "alice", "closed", "Websecret title", "intent")
        .await
        .unwrap();
    drain(&s).await;

    let anon = s.browser();
    let page = get_text(&anon, &s.url("/search?q=websecret")).await;
    assert!(
        !page.contains("Websecret"),
        "anonymous search does not leak private trails"
    );

    let (alice_client, _) = s.login("alice").await;
    let page = get_text(&alice_client, &s.url("/search?q=websecret")).await;
    assert!(
        page.contains("Websecret"),
        "the owner finds her private trail"
    );
}
