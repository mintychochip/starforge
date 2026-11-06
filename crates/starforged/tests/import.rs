//! One-time import tests (M4b D2, D3): creation with an import body,
//! `pending → running → done`, HTTPS credentials, the SSH deploy-key flow,
//! push refusal during an import, and the scrubbed failure with retry.
mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;

async fn api_post(client: &reqwest::Client, url: &str, token: &str, body: &Value) -> (u16, Value) {
    let r = client
        .post(url)
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let text = r.text().await.unwrap();
    let v: Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, v)
}

/// Builds a source work repo with `main`, `feature`, tag `v1`, and refs
/// that must never be fetched; returns its `file://` URL.
async fn make_source(dir: &std::path::Path, name: &str) -> String {
    let work = work_repo(dir, name, &[("README.md", "# src\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature"]).await;
    commit_files(&work, &[("feature.txt", b"feature\n")], "on feature").await;
    git_ok(&work, &["checkout", "-q", "main"]).await;
    git_ok(&work, &["tag", "v1"]).await;
    git_ok(&work, &["update-ref", "refs/notes/commits", "HEAD"]).await;
    git_ok(&work, &["update-ref", "refs/pull/1/head", "HEAD"]).await;
    format!("file://{}", work.display())
}

async fn import_state(s: &TestServer, repo_id: i64) -> String {
    s.core
        .import_for(repo_id)
        .await
        .unwrap()
        .map(|v| v.state)
        .unwrap_or_else(|| "none".to_owned())
}

/// Bounded poll (10 s) on observable state: runs due jobs, then checks the
/// import state through the API.
async fn poll_import_done(s: &TestServer, token: &str, owner: &str, name: &str) -> Value {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        s.core.run_due_jobs().await.unwrap();
        let r = client
            .get(s.url(&format!("/api/v1/repos/{owner}/{name}/import")))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        let v: Value = r.json().await.unwrap();
        if v["state"] == "done" || Instant::now() > deadline {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_from_file_runs_pending_running_done() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let alice = s.user("alice").await;
    let write = s.token(&alice, &[Scope::RepoWrite]).await;
    let dir = tempfile::tempdir().unwrap();
    let url = make_source(dir.path(), "src").await;

    let client = reqwest::Client::new();
    let (status, repo) = api_post(
        &client,
        &s.url("/api/v1/user/repos"),
        &write,
        &json!({"name": "mirror", "import": {"url": url}}),
    )
    .await;
    assert_eq!(status, 201, "{repo}");
    assert_eq!(repo["import_state"], "pending");
    let repo_id = repo["id"].as_i64().unwrap();

    // Pushes are refused while pending (hook snapshot).
    let work = work_repo(dir.path(), "pusher", &[("README.md", "# x\n")]).await;
    let push = git(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "mirror", Some(&write)),
            "main",
        ],
    )
    .await;
    assert!(
        !push.status.success(),
        "push during import must fail: {}",
        String::from_utf8_lossy(&push.stderr)
    );
    let stderr = String::from_utf8_lossy(&push.stderr).to_string();
    assert!(stderr.contains("import in progress"), "{stderr}");

    let done = poll_import_done(&s, &write, "alice", "mirror").await;
    assert_eq!(done["state"], "done", "{done}");

    // Branches, tags, default branch match the source.
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "mirror")
        .await
        .unwrap();
    let branches = s.core.branches(&access).await.unwrap();
    assert!(branches.contains(&"main".to_owned()), "{branches:?}");
    assert!(branches.contains(&"feature".to_owned()), "{branches:?}");
    assert_eq!(access.repo.default_branch, "main");
    let refs = git_ok(
        &s.core.repo_path(repo_id),
        &["for-each-ref", "--format=%(refname)"],
    )
    .await;
    assert!(refs.contains("refs/tags/v1"), "{refs}");
    assert!(!refs.contains("refs/notes/"), "{refs}");
    assert!(!refs.contains("refs/pull/"), "{refs}");

    // Trails and sessions are empty (checked in the store: the list
    // endpoints envelope their pages, so a direct count is unambiguous).
    for table in ["trails", "sessions"] {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE repo_id = $1");
        // Safe: `table` is a fixed literal from this test, never user input.
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(repo_id)
            .fetch_one(s.core.db().pool())
            .await
            .unwrap();
        assert_eq!(count, 0, "{table} must be empty");
    }

    // Audit repo.import exists.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'repo.import' AND target = $1",
    )
    .bind("repo:alice/mirror")
    .fetch_one(s.core.db().pool())
    .await
    .unwrap();
    assert!(count >= 1, "repo.import audit row missing");

    // Pushes work again once done: a fresh branch from the work tree
    // (an unrelated `main` would be non-fast-forward, correctly).
    git_ok(&work, &["checkout", "-q", "-b", "after"]).await;
    let ok = git(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "mirror", Some(&write)),
            "after",
        ],
    )
    .await;
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let _ = import_state(&s, repo_id).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_over_https_with_token_and_retry() {
    let client_s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let upstream = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let alice_u = upstream.user("alice").await;
    upstream.repo(&alice_u, "proj", Visibility::Private).await;
    let token = upstream.token(&alice_u, &[Scope::RepoWrite]).await;

    let dir = tempfile::tempdir().unwrap();
    let work = work_repo(dir.path(), "work", &[("README.md", "# proj\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &upstream.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;

    let bob = client_s.user("bob").await;
    let write = client_s.token(&bob, &[Scope::RepoWrite]).await;
    let url = upstream.git_url("alice", "proj", None);
    let client = reqwest::Client::new();

    // Wrong token: fails with a scrubbed error.
    let (status, _) = api_post(
        &client,
        &client_s.url("/api/v1/user/repos"),
        &write,
        &json!({
            "name": "bad",
            "import": {"url": url, "auth": {"kind": "https", "username": "git", "password": "wrong-token-12345"}}
        }),
    )
    .await;
    assert_eq!(status, 201);
    client_s.core.run_due_jobs().await.unwrap();
    let r = client
        .get(client_s.url("/api/v1/repos/bob/bad/import"))
        .bearer_auth(&write)
        .send()
        .await
        .unwrap();
    let failed: Value = r.json().await.unwrap();
    assert_eq!(failed["state"], "failed", "{failed}");
    let msg = failed["last_error"].as_str().unwrap_or_default().to_owned();
    assert!(!msg.is_empty(), "{failed}");
    assert!(!msg.contains("wrong-token-12345"), "{msg}");

    // Retry after fixing credentials, through start with new auth.
    let st = client
        .post(client_s.url("/api/v1/repos/bob/bad/import/start"))
        .bearer_auth(&write)
        .json(&json!({"auth": {"kind": "https", "username": "git", "password": token}}))
        .send()
        .await
        .unwrap();
    assert_eq!(st.status(), 200);
    let done = poll_import_done(&client_s, &write, "bob", "bad").await;
    assert_eq!(done["state"], "done", "{done}");

    // A fresh correct import also works.
    let (status, _) = api_post(
        &client,
        &client_s.url("/api/v1/user/repos"),
        &write,
        &json!({
            "name": "good",
            "import": {"url": url, "auth": {"kind": "https", "username": "git", "password": token}}
        }),
    )
    .await;
    assert_eq!(status, 201);
    let done = poll_import_done(&client_s, &write, "bob", "good").await;
    assert_eq!(done["state"], "done", "{done}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_policy_refusal_is_422() {
    // No test flag: file:// is refused at creation.
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let write = s.token(&alice, &[Scope::RepoWrite]).await;
    let client = reqwest::Client::new();
    for url in [
        "file:///tmp/x.git",
        "/tmp/x.git",
        "ext::sh -c id",
        "https://10.0.0.1/x.git",
    ] {
        let (status, body) = api_post(
            &client,
            &s.url("/api/v1/user/repos"),
            &write,
            &json!({"name": "nope", "import": {"url": url}}),
        )
        .await;
        assert_eq!(status, 422, "{url}: {body}");
    }
    // Nothing was created for the refused names.
    let r = client
        .get(s.url("/api/v1/repos/alice/nope"))
        .bearer_auth(&write)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_over_ssh_with_generated_deploy_key() {
    let client_s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let upstream = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
        c.ssh.listen = "127.0.0.1:0".to_owned();
    })
    .await;
    let alice_u = upstream.user("alice").await;
    upstream.repo(&alice_u, "proj", Visibility::Private).await;
    let token = upstream.token(&alice_u, &[Scope::RepoWrite]).await;

    let dir = tempfile::tempdir().unwrap();
    let work = work_repo(dir.path(), "work", &[("README.md", "# proj\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &upstream.git_url("alice", "proj", Some(&token)),
            "main",
        ],
    )
    .await;

    let bob = client_s.user("bob").await;
    let write = client_s.token(&bob, &[Scope::RepoWrite]).await;
    let client = reqwest::Client::new();
    let (status, repo) = api_post(
        &client,
        &client_s.url("/api/v1/user/repos"),
        &write,
        &json!({
            "name": "sshimp",
            "import": {"url": upstream.ssh_url("alice", "proj"), "auth": {"kind": "ssh"}}
        }),
    )
    .await;
    assert_eq!(status, 201, "{repo}");
    assert_eq!(repo["import_state"], "pending");
    let public = repo["ssh_public_key"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        public.starts_with("ssh-ed25519 "),
        "public key shown: {public}"
    );

    // SSH waits in pending (no job enqueued) until start is pressed.
    client_s.core.run_due_jobs().await.unwrap();
    assert_eq!(
        import_state(&client_s, repo["id"].as_i64().unwrap()).await,
        "pending"
    );

    // Install the generated key upstream as a deploy key, then start.
    upstream
        .core
        .add_deploy_key(&alice_u, "alice", "proj", "import", &public, false)
        .await
        .unwrap();
    let st = client
        .post(client_s.url("/api/v1/repos/bob/sshimp/import/start"))
        .bearer_auth(&write)
        .send()
        .await
        .unwrap();
    assert_eq!(st.status(), 200);

    let done = poll_import_done(&client_s, &write, "bob", "sshimp").await;
    assert_eq!(done["state"], "done", "{done}");
    let access = client_s
        .core
        .repo_for(Some(&bob), "bob", "sshimp")
        .await
        .unwrap();
    let branches = client_s.core.branches(&access).await.unwrap();
    assert!(branches.contains(&"main".to_owned()), "{branches:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn import_web_form_and_banner() {
    let s = TestServer::start_with(|c| {
        c.remotes.allow_file_urls = true;
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let url = make_source(dir.path(), "src").await;
    let _ = s.user("alice").await;

    let (client, csrf) = s.login("alice").await;
    let page = get_text(&client, &s.url("/new")).await;
    assert!(page.contains("Import from URL"), "{page}");

    let r = client
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("owner", "alice"),
            ("name", "webimp"),
            ("description", ""),
            ("visibility", "private"),
            ("import_url", url.as_str()),
            ("import_auth", "none"),
            ("import_username", ""),
            ("import_password", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);

    // The banner shows the pending import with a start control.
    let home = get_text(&client, &s.url("/alice/webimp")).await;
    assert!(home.contains("Import pending"), "{home}");
    assert!(home.contains("/alice/webimp/import/start"), "{home}");
}
