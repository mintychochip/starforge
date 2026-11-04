mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::tokens::Scope;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_repositories_can_start_with_a_readme() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    let form = get_text(&client, &s.url("/new")).await;
    assert!(form.contains(r#"name="readme""#), "{form}");
    let created = client
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "proj"),
            ("description", "A demo"),
            ("visibility", "public"),
            ("readme", "on"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 303);
    let home = get_text(&client, &s.url("/alice/proj")).await;
    assert!(home.contains("<h1>proj</h1>"), "{home}");
    assert!(home.contains("<p>A demo</p>"), "{home}");

    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let made: Value = s
        .browser()
        .post(s.url("/api/v1/user/repos"))
        .bearer_auth(&token)
        .json(&json!({"name": "api-made", "readme": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(made["full_name"], "alice/api-made");
    let tmp = tempfile::tempdir().unwrap();
    git_ok(
        tmp.path(),
        &[
            "clone",
            "-q",
            &s.git_url("alice", "api-made", Some(&token)),
            "copy",
        ],
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("copy/README.md")).unwrap(),
        "# api-made\n"
    );
    let log = git_ok(&tmp.path().join("copy"), &["log", "--format=%an <%ae>|%s"]).await;
    assert_eq!(
        log.trim(),
        "alice <alice@users.noreply.127.0.0.1>|Initial commit"
    );
}
