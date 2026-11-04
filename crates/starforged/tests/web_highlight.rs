mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_are_highlighted_with_line_anchors_and_escaped() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    let long = format!("{}\n", "x".repeat(5_001));
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(
        tmp.path(),
        "work",
        &[
            (
                "src/main.rs",
                "fn main() {\n    let s = \"<script>alert(1)</script>\";\n}\n",
            ),
            ("long.rs", long.as_str()),
        ],
    )
    .await;
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    let client = s.browser();

    let page = get_text(&client, &s.url("/alice/proj/blob/main/src/main.rs")).await;
    assert!(
        page.contains(r##"<tr id="L1"><td class="ln"><a href="#L1">1</a></td>"##),
        "{page}"
    );
    assert!(
        page.contains(r#"<span class="hl-storage hl-type hl-function hl-rust">fn</span>"#),
        "{page}"
    );
    assert!(
        page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{page}"
    );
    assert!(!page.contains("<script>alert"), "{page}");

    let plain = get_text(&client, &s.url("/alice/proj/blob/main/long.rs")).await;
    assert!(
        !plain.contains("hl-source"),
        "a line over 5,000 characters turns highlighting off"
    );
    assert!(plain.contains(&"x".repeat(5_001)));

    let css = client
        .get(s.url("/static/highlight.css"))
        .send()
        .await
        .unwrap();
    assert_eq!(css.headers()["content-type"], "text/css; charset=utf-8");
    assert!(css.text().await.unwrap().contains(".hl-comment"));
}
