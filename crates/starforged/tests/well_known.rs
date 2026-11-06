//! `GET /.well-known/starforge.json` (spec §7.6): anonymous, JSON, naming the
//! server version, the API root, and the SSH clone base — and consumable by
//! the CLI's own discovery (`starforge_cli::discovery`).
mod common;

use common::*;
use serde_json::Value;
use starforge_cli::discovery::{parse_well_known, resolve_server};
use starforged_core::permission::Visibility;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn well_known_document_is_anonymous_and_cli_consumable() {
    let server = TestServer::start().await;
    let client = reqwest::Client::new();

    let response = client
        .get(server.url("/.well-known/starforge.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/json",
        "the discovery document must be JSON"
    );
    let body = response.bytes().await.unwrap();

    let parsed = parse_well_known(&body).expect("the CLI must accept the server's document");
    assert_eq!(parsed.api_url, server.base);
    assert!(
        parsed.ssh_url.starts_with("ssh://git@"),
        "ssh_url: {}",
        parsed.ssh_url
    );
    assert!(!parsed.version.is_empty());

    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["api_url"], server.base);
    assert!(json["ssh_url"].as_str().unwrap().starts_with("ssh://git@"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn well_known_resolves_for_a_repo_remote() {
    let server = TestServer::start().await;
    let owner = server.user("alice").await;
    server.repo(&owner, "widget", Visibility::Public).await;

    let scratch = tempfile::tempdir().unwrap();
    git_ok(scratch.path(), &["init", "-q", "work"]).await;
    let work = scratch.path().join("work");
    let remote = server.git_url("alice", "widget", None);
    git_ok(&work, &["remote", "add", "origin", &remote]).await;

    let client = reqwest::Client::new();
    let (info, owner_repo, chosen) = resolve_server(&client, &work)
        .await
        .expect("discovery must resolve the TestServer");
    assert_eq!(info.api_url, server.base);
    assert!(info.ssh_url.starts_with("ssh://git@"));
    assert_eq!(owner_repo, "alice/widget");
    assert_eq!(chosen, remote);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn well_known_reports_empty_ssh_url_when_ssh_is_disabled() {
    let server = TestServer::start_with(|config| {
        config.ssh.enabled = false;
    })
    .await;
    let client = reqwest::Client::new();

    let response = client
        .get(server.url("/.well-known/starforge.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let json: Value = response.json().await.unwrap();
    assert_eq!(json["api_url"], server.base);
    assert_eq!(json["ssh_url"], "");
    let parsed = parse_well_known(&serde_json::to_vec(&json).unwrap())
        .expect("the CLI must accept an SSH-disabled server");
    assert_eq!(parsed.ssh_url, "");
}
