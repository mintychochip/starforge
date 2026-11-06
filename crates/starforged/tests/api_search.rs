//! M4a S3: Trail and session search over the API — shapes, filters,
//! pagination, validation, and the per-hit re-check (plan D3/D6): stale
//! index documents may only hide results, never leak them.
mod common;

use common::*;
use serde_json::{Value, json};
use starforged_core::ingest::IngestAuth;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const SHA40: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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

fn event(seq: u64, text: &str) -> String {
    json!({"v": 1, "seq": seq, "ts": "2026-11-04T00:00:00Z", "kind": "user_message", "text": text})
        .to_string()
}

async fn drain(s: &TestServer) {
    s.core.run_due_jobs().await.unwrap();
}

/// Uploads one completed session with a single user message carrying `text`
/// to `alice/<repo>`; returns the ingest auth for link claims.
async fn upload_completed(
    s: &TestServer,
    alice: &starforged_core::accounts::User,
    repo: &str,
    ulid: &str,
    text: &str,
) -> IngestAuth {
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
    let bytes = starforge_format::compress(format!("{}\n", event(0, text)).as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    s.core
        .put_segment(&auth, ulid, 0, &bytes, Some(hash))
        .await
        .unwrap();
    s.core.complete_session(&auth, ulid).await.unwrap();
    auth
}

/// Publishes the session (repo `maintain` or above).
async fn publish(s: &TestServer, alice: &starforged_core::accounts::User, repo: &str, ulid: &str) {
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

async fn search(
    client: &reqwest::Client,
    s: &TestServer,
    kind: &str,
    qs: &str,
    token: Option<&str>,
) -> (u16, Value) {
    let mut request = client.get(s.url(&format!("/api/v1/search/{kind}?{qs}")));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let res = request.send().await.unwrap();
    let status = res.status().as_u16();
    let body = res.json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

fn result_repos(body: &Value) -> Vec<String> {
    body["results"]
        .as_array()
        .map(|results| {
            results
                .iter()
                .map(|r| r["repo"].as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trails_shape_filters_and_pagination() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "open", Visibility::Public).await;
    s.repo(&alice, "closed", Visibility::Private).await;
    s.core
        .create_trail(&alice, "alice", "open", "Zebra alpha", "plumbline intent")
        .await
        .unwrap();
    s.core
        .create_trail(&alice, "alice", "closed", "Zebra secret", "hidden intent")
        .await
        .unwrap();
    s.core
        .add_comment(&alice, "alice", "open", 1, "quux follow-up")
        .await
        .unwrap();
    drain(&s).await;
    let client = reqwest::Client::new();

    // Anonymous sees the public report only (D6 shape).
    let (status, body) = search(&client, &s, "trails", "q=zebra", None).await;
    assert_eq!(status, 200);
    assert_eq!(result_repos(&body), ["alice/open"]);
    let first = &body["results"][0];
    assert_eq!(first["number"], 1);
    assert_eq!(first["title"], "Zebra alpha");
    assert_eq!(first["state"], "open");
    assert!(first["updated_at"].as_str().unwrap().ends_with('Z'));
    assert_eq!(body["page"], 1);
    assert_eq!(body["per_page"], 20);
    assert_eq!(body["has_more"], false);
    let snippet_text = first["snippet"]["text"].as_str().unwrap();
    let highlights = first["snippet"]["highlights"].as_array().unwrap();
    assert!(
        !highlights.is_empty(),
        "the matched word is highlighted: {snippet_text}"
    );
    for range in highlights {
        let (start, end) = (
            range[0].as_u64().unwrap() as usize,
            range[1].as_u64().unwrap() as usize,
        );
        assert!(
            snippet_text[start..end].eq_ignore_ascii_case("zebra"),
            "ranges slice the query word"
        );
    }

    // Comment bodies are searchable.
    let (_, body) = search(&client, &s, "trails", "q=quux", None).await;
    assert_eq!(
        result_repos(&body),
        ["alice/open"],
        "comment text is indexed"
    );

    // Filters narrow: repo, author, date range.
    let (_, body) = search(&client, &s, "trails", "q=zebra&repo=alice%2Fclosed", None).await;
    assert!(
        result_repos(&body).is_empty(),
        "an unreadable repo filter yields nothing"
    );
    let (_, body) = search(&client, &s, "trails", "q=zebra&author=alice", None).await;
    assert_eq!(result_repos(&body), ["alice/open"]);
    let (_, body) = search(&client, &s, "trails", "q=zebra&author=nobody", None).await;
    assert!(
        result_repos(&body).is_empty(),
        "unknown author matches nothing"
    );
    let (_, body) = search(
        &client,
        &s,
        "trails",
        "q=zebra&from=2020-01-01&to=2020-12-31",
        None,
    )
    .await;
    assert!(
        result_repos(&body).is_empty(),
        "date range excludes the trail"
    );
    let (_, body) = search(
        &client,
        &s,
        "trails",
        "q=zebra&from=2020-01-01T00:00:00Z&to=2100-01-01",
        None,
    )
    .await;
    assert_eq!(
        result_repos(&body),
        ["alice/open"],
        "a wide date range includes it"
    );

    // A reader of the private repository sees its trail.
    let bob = s.user("bob").await;
    s.core
        .set_collaborator(&alice, "alice", "closed", "bob", Permission::Read)
        .await
        .unwrap();
    let bob_read = s.token(&bob, &[Scope::RepoRead]).await;
    drain(&s).await;
    let (_, body) = search(&client, &s, "trails", "q=zebra", Some(&bob_read)).await;
    let mut repos = result_repos(&body);
    repos.sort();
    assert_eq!(
        repos,
        ["alice/closed", "alice/open"],
        "a reader sees both repositories"
    );

    // Pagination: one result per page.
    let (_, body) = search(&client, &s, "trails", "q=zebra&per_page=1", Some(&bob_read)).await;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    assert_eq!(body["has_more"], true);
    let (_, body) = search(
        &client,
        &s,
        "trails",
        "q=zebra&per_page=1&page=2",
        Some(&bob_read),
    )
    .await;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    assert_eq!(body["page"], 2);
    assert_eq!(body["has_more"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_shape_filters_and_noindex() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "open", Visibility::Public).await;
    let ulid = "01ARZ3NDEKTSV4RRFFQ69G5FCA";
    let auth = upload_completed(&s, &alice, "open", ulid, "sessionneedle hello").await;
    s.core
        .claim_links(&auth, ulid, &[json!({"sha": SHA40, "confidence": "exact"})])
        .await
        .unwrap();
    publish(&s, &alice, "open", ulid).await;
    drain(&s).await;
    let client = reqwest::Client::new();

    let res = client
        .get(s.url("/api/v1/search/sessions?q=sessionneedle"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.headers()
            .get("x-robots-tag")
            .and_then(|v| v.to_str().ok()),
        Some("noindex"),
        "session search is noindex"
    );
    let body = res.json::<Value>().await.unwrap();
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    let first = &body["results"][0];
    assert_eq!(first["repo"], "alice/open");
    assert_eq!(first["session"], ulid);
    assert_eq!(first["agent"], "pi");
    assert_eq!(first["events"][0]["seq"], 0);
    assert_eq!(first["events"][0]["kind"], "user_message");
    let text = first["events"][0]["snippet"]["text"].as_str().unwrap();
    assert!(
        first["events"][0]["snippet"]["highlights"]
            .as_array()
            .unwrap()
            .iter()
            .any(|range| {
                let (start, end) = (
                    range[0].as_u64().unwrap() as usize,
                    range[1].as_u64().unwrap() as usize,
                );
                &text[start..end] == "sessionneedle"
            }),
        "event snippet highlights the match"
    );

    // Filters: agent, model, commit.
    let (_, body) = search(&client, &s, "sessions", "q=sessionneedle&agent=pi", None).await;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    let (_, body) = search(&client, &s, "sessions", "q=sessionneedle&agent=other", None).await;
    assert!(body["results"].as_array().unwrap().is_empty());
    let (_, body) = search(&client, &s, "sessions", "q=sessionneedle&model=m1", None).await;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    let (_, body) = search(
        &client,
        &s,
        "sessions",
        "q=sessionneedle&commit=aaaaaaa",
        None,
    )
    .await;
    assert_eq!(
        body["results"].as_array().unwrap().len(),
        1,
        "commit prefix matches"
    );
    let (_, body) = search(
        &client,
        &s,
        "sessions",
        "q=sessionneedle&commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        None,
    )
    .await;
    assert!(
        body["results"].as_array().unwrap().is_empty(),
        "other commits do not match"
    );

    // Unpublished sessions are hidden from anonymous (query filter).
    let ulid2 = "01ARZ3NDEKTSV4RRFFQ69G5FCB";
    upload_completed(&s, &alice, "open", ulid2, "sessionneedle draft").await;
    drain(&s).await;
    let (_, body) = search(&client, &s, "sessions", "q=sessionneedle", None).await;
    assert_eq!(
        body["results"].as_array().unwrap().len(),
        1,
        "only the published session matches for anonymous"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_answers_422() {
    let s = TestServer::start().await;
    let client = reqwest::Client::new();

    for (kind, qs) in [
        ("trails", "per_page=51"),
        ("trails", "per_page=0"),
        ("trails", "page=0"),
        ("trails", "from=notadate"),
        ("trails", "to=2026-13-45"),
        ("trails", "from=2026-01-01&to=2020-01-01"),
        ("trails", "repo=noslash"),
        ("sessions", "per_page=51"),
        ("sessions", "from=notadate"),
        ("sessions", "commit=xyz"),
        ("sessions", "commit=abc"),
        (
            "sessions",
            "commit=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ),
    ] {
        let (status, body) = search(&client, &s, kind, qs, None).await;
        assert_eq!(status, 422, "{kind}?{qs} must be 422: {body}");
        assert_eq!(body["error"]["code"], "invalid", "{kind}?{qs}");
    }

    // Valid edge values pass: 7-char prefix, date-only bounds.
    let (status, _) = search(&client, &s, "sessions", "commit=abcdef0", None).await;
    assert_eq!(status, 200);
    let (status, _) = search(&client, &s, "trails", "from=2026-11-04", None).await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recheck_repo_became_private() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "open", Visibility::Public).await;
    s.core
        .create_trail(&alice, "alice", "open", "Stale visibility", "intent")
        .await
        .unwrap();
    drain(&s).await;
    let client = reqwest::Client::new();
    let (_, body) = search(&client, &s, "trails", "q=stale", None).await;
    assert_eq!(
        result_repos(&body),
        ["alice/open"],
        "public trail is visible"
    );

    // Flip visibility without running the index job: the stale document
    // must not leak to a former reader.
    s.core
        .set_visibility(&alice, "alice", "open", Visibility::Private)
        .await
        .unwrap();
    let (_, body) = search(&client, &s, "trails", "q=stale", None).await;
    assert!(
        result_repos(&body).is_empty(),
        "a repository that became private is hidden without a re-index"
    );
    let alice_read = s.token(&alice, &[Scope::RepoRead]).await;
    let (_, body) = search(&client, &s, "trails", "q=stale", Some(&alice_read)).await;
    assert_eq!(
        result_repos(&body),
        ["alice/open"],
        "the owner still reads it"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recheck_revoked_grant_and_deleted_repo() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "closed", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "closed", "bob", Permission::Read)
        .await
        .unwrap();
    s.core
        .create_trail(&alice, "alice", "closed", "Grantword trail", "intent")
        .await
        .unwrap();
    drain(&s).await;
    let client = reqwest::Client::new();
    let bob_read = s.token(&bob, &[Scope::RepoRead]).await;
    let (_, body) = search(&client, &s, "trails", "q=grantword", Some(&bob_read)).await;
    assert_eq!(result_repos(&body), ["alice/closed"]);

    // Revoke without draining: the re-check hides the hit immediately.
    s.core
        .remove_collaborator(&alice, "alice", "closed", "bob")
        .await
        .unwrap();
    let (_, body) = search(&client, &s, "trails", "q=grantword", Some(&bob_read)).await;
    assert!(
        result_repos(&body).is_empty(),
        "a revoked grant hides the hit without a re-index"
    );

    // Deleted repositories hide their hits too (even for the owner).
    let alice_read = s.token(&alice, &[Scope::RepoRead]).await;
    let (_, body) = search(&client, &s, "trails", "q=grantword", Some(&alice_read)).await;
    assert_eq!(result_repos(&body), ["alice/closed"]);
    s.core
        .delete_repo(&alice, "alice", "closed", "alice/closed")
        .await
        .unwrap();
    let (_, body) = search(&client, &s, "trails", "q=grantword", Some(&alice_read)).await;
    assert!(
        result_repos(&body).is_empty(),
        "a deleted repository hides its hits without a re-index"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recheck_quarantined_and_unpublished() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "open", Visibility::Public).await;
    let ulid = "01ARZ3NDEKTSV4RRFFQ69G5FCC";
    upload_completed(&s, &alice, "open", ulid, "stalequarantine benign hello").await;
    publish(&s, &alice, "open", ulid).await;
    drain(&s).await;
    let client = reqwest::Client::new();
    let (_, body) = search(&client, &s, "sessions", "q=stalequarantine", None).await;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);

    // Quarantine in the database, without running the index job: the
    // stale published document must not leak to non-uploaders.
    let session = db_sessions::session_by_ulid(s.db(), repo.id, ulid)
        .await
        .unwrap()
        .unwrap();
    db_sessions::set_quarantine(s.db(), session.id, "quarantined", "test", "test")
        .await
        .unwrap();
    let (_, body) = search(&client, &s, "sessions", "q=stalequarantine", None).await;
    assert!(
        body["results"].as_array().unwrap().is_empty(),
        "a session quarantined after indexing is hidden"
    );
    // The uploader keeps access (§6.4 quarantine gate).
    let alice_read = s.token(&alice, &[Scope::RepoRead]).await;
    let (_, body) = search(
        &client,
        &s,
        "sessions",
        "q=stalequarantine",
        Some(&alice_read),
    )
    .await;
    assert_eq!(
        body["results"].as_array().unwrap().len(),
        1,
        "the uploader still finds the quarantined session"
    );

    // Fresh session: unpublish without draining and it disappears too.
    let ulid2 = "01ARZ3NDEKTSV4RRFFQ69G5FCD";
    upload_completed(&s, &alice, "open", ulid2, "staleunpublish benign hello").await;
    publish(&s, &alice, "open", ulid2).await;
    drain(&s).await;
    let (_, body) = search(&client, &s, "sessions", "q=staleunpublish", None).await;
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    let access = s
        .core
        .require_repo(
            Some(&alice),
            "alice",
            "open",
            starforged_core::permission::Permission::Maintain,
        )
        .await
        .unwrap();
    s.core
        .unpublish_session(&alice, &access, ulid2)
        .await
        .unwrap();
    let (_, body) = search(&client, &s, "sessions", "q=staleunpublish", None).await;
    assert!(
        body["results"].as_array().unwrap().is_empty(),
        "a session unpublished after indexing is hidden"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_without_read_scope_is_forbidden() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let upload_only = s.token(&alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let (status, _) = search(&client, &s, "trails", "q=zebra", Some(&upload_only)).await;
    assert_eq!(status, 403, "read search requires the repo:read scope");
}
