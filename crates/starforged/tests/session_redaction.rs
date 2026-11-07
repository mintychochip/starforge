//! M6c C6: CI secret value-based dynamic redaction + no-store caching.
//!
//! A CI job's sealed secret, planted in a transcript in several common
//! forms (plain, base64, URL-encoded, hex, JSON-escaped) and split across a
//! segment boundary, must never appear in any session surface (web page,
//! in-session search hits, events, raw segment, download) nor in the search
//! index, and session routes must send the no-store cache headers.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use reqwest::StatusCode;
use serde_json::{Value, json};
use starforged_core::permission::Visibility;
use starforged_core::tokens::Scope;
use starforged_db::sessions as db_sessions;

const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FD1";
const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// The job secret; it contains a quote and a backslash (so the JSON-escaped
/// form differs from the bare value) and `!`, `@`, `#` (so the URL-encoded
/// form differs too).
const SECRET: &str = "Sk-live\"9f3A\\!@#";

/// A plain searchable word that shares the event with the secret; previews of
/// search hits for it once carried the raw secret next to this marker.
const MARKER: &str = "marker-7f3a2b";

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn variants(secret: &str) -> Vec<String> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
    let url = percent_encode(secret);
    let hex: String = secret.bytes().map(|b| format!("{b:02x}")).collect();
    let json_inner = serde_json::to_string(secret)
        .unwrap()
        .trim_matches('"')
        .to_owned();
    // The double-escaped wire form (what the stored JSONL bytes hold when
    // the escaped form is planted in transcript text).
    let json_double = serde_json::to_string(&json_inner)
        .unwrap()
        .trim_matches('"')
        .to_owned();
    let hex_upper = hex.to_uppercase();
    vec![
        secret.to_owned(),
        b64,
        url,
        hex,
        hex_upper,
        json_inner,
        json_double,
    ]
}

fn assert_no_variant(haystack: &str, surface: &str) {
    for variant in variants(SECRET) {
        assert!(
            !haystack.contains(&variant),
            "{surface} leaked a CI secret form: {variant:?}"
        );
    }
}

fn meta_body(ulid: &str, title: &str) -> Value {
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
        "usage": {"input": 10, "output": 20, "cache_read": 0, "cache_write": 0, "reasoning": 0},
        "files_touched": [],
        "redaction": {"fingerprint": "fp-1", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

fn event(seq: u64, text: &str) -> String {
    json!({
        "v": 1,
        "seq": seq,
        "ts": "2026-11-04T00:00:00Z",
        "kind": "user_message",
        "text": text,
    })
    .to_string()
}

fn segment_payload(lines: &[String]) -> (Vec<u8>, String) {
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    (bytes, hash)
}

async fn upload(
    s: &TestServer,
    job_token: &str,
    owner: &str,
    repo: &str,
    ulid: &str,
    title: &str,
    segments: &[Vec<String>],
) {
    let meta_url = s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions/{ulid}"));
    let created = s
        .browser()
        .put(&meta_url)
        .bearer_auth(job_token)
        .json(&meta_body(ulid, title))
        .send()
        .await
        .unwrap();
    assert_eq!(
        created.status(),
        201,
        "meta: {}",
        created.text().await.unwrap()
    );
    for (n, lines) in segments.iter().enumerate() {
        let (bytes, hash) = segment_payload(lines);
        let put = s
            .browser()
            .put(s.url(&format!(
                "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/segments/{n}"
            )))
            .bearer_auth(job_token)
            .header("X-Starforge-Blake3", &hash)
            .body(bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(
            put.status(),
            200,
            "segment {n}: {}",
            put.text().await.unwrap()
        );
    }
}

async fn api_raw(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, reqwest::header::HeaderMap, Value) {
    let req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        _ => unreachable!(),
    };
    let req = if token.is_empty() {
        req
    } else {
        req.bearer_auth(token)
    };
    let resp = match body {
        Some(body) => req.json(&body).send().await.unwrap(),
        None => req.send().await.unwrap(),
    };
    let status = resp.status();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap();
    let value = if text.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    };
    (status, headers, value)
}

fn assert_no_store(headers: &reqwest::header::HeaderMap, surface: &str) {
    assert_eq!(
        headers
            .get(reqwest::header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap(),
        "no-store, private",
        "{surface}: Cache-Control"
    );
    assert_eq!(
        headers
            .get(reqwest::header::PRAGMA)
            .unwrap()
            .to_str()
            .unwrap(),
        "no-cache",
        "{surface}: Pragma"
    );
    let vary = headers
        .get(reqwest::header::VARY)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        vary.contains("Cookie") && vary.contains("Authorization"),
        "{surface}: Vary must cover Cookie and Authorization, got {vary}"
    );
}

/// Queues one CI job directly in the database (the trigger path is M6c).
async fn queue_job(s: &TestServer, repo_id: i64, user_id: i64) -> i64 {
    let spec = json!({
        "name": "test",
        "image": "example.test/image:1",
        "commands": ["true"],
        "runs_on": [],
    })
    .to_string();
    let now = starforged_db::now();
    starforged_db::ci::insert_ci_job(
        s.db(),
        &starforged_db::ci::NewCiJob {
            repo_id,
            trail_id: None,
            change_id: None,
            revision_id: None,
            commit_sha: SHA,
            base_sha: None,
            job_name: "test",
            spec: &spec,
            run_at: 0,
            deadline: now + 3600,
            created_by: Some(user_id),
            now,
        },
    )
    .await
    .unwrap()
    .id
}

/// Registers a runner with `pat` and returns its auth token.
async fn register_runner(s: &TestServer, pat: &str) -> String {
    let (status, _, value) = api_raw(
        &s.browser(),
        "POST",
        &s.url("/api/v1/repos/alice/proj/runners/registration-token"),
        pat,
        Some(json!({ "labels": ["linux"], "ephemeral": false })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    let (status, _, value) = api_raw(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/register"),
        "",
        Some(json!({
            "registration_token": value["token"],
            "name": "runner-1",
            "labels": ["linux"],
            "version": "test",
            "ephemeral": false,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    value["auth_token"].as_str().unwrap().to_owned()
}

async fn claim_job(s: &TestServer, runner_token: &str) -> (i64, String) {
    let (status, _, value) = api_raw(
        &s.browser(),
        "POST",
        &s.url("/api/v1/runners/jobs/request"),
        runner_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{value}");
    (
        value["job_id"].as_i64().unwrap(),
        value["job_token"].as_str().unwrap().to_owned(),
    )
}

fn walk_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ci_secret_is_redacted_on_every_session_surface() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let repo = s.repo(&alice, "proj", Visibility::Public).await;
    let pat = s.token(&alice, &[Scope::RepoWrite]).await;

    let job_id = queue_job(&s, repo.id, alice.id).await;

    // One sealed secret, registered for the job (ci_job_secrets -> ci_secrets).
    let sealed = s.core.seal_ci_secret(SECRET);
    assert_ne!(sealed, SECRET, "sealed value must differ from plaintext");
    let now = starforged_db::now();
    sqlx::query(
        "INSERT INTO ci_secrets \
         (repo_id, name, sealed_value, redact_in_sessions, created_by, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(repo.id)
    .bind("API_KEY")
    .bind(&sealed)
    .bind(1_i64)
    .bind(alice.id)
    .bind(now)
    .bind(now)
    .execute(s.db().pool())
    .await
    .unwrap();
    let secret_id: i64 = sqlx::query_scalar("SELECT id FROM ci_secrets WHERE repo_id = $1")
        .bind(repo.id)
        .fetch_one(s.db().pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO ci_job_secrets (job_id, secret_id, created_at) VALUES ($1, $2, $3)")
        .bind(job_id)
        .bind(secret_id)
        .bind(now)
        .execute(s.db().pool())
        .await
        .unwrap();
    // Resolution decrypts in memory and returns the value.
    assert_eq!(
        s.core.ci_secret_values_for_job(job_id).await,
        vec![SECRET.to_owned()]
    );

    let runner_token = register_runner(&s, &pat).await;
    let (claimed_job_id, job_token) = claim_job(&s, &runner_token).await;
    assert_eq!(claimed_job_id, job_id);

    // The transcript: every secret form in segment 0, plus a secret split
    // across the segment 0 -> 1 boundary.
    let vars = variants(SECRET);
    let split_at = SECRET.len() / 2;
    let seg0 = vec![
        event(1, &format!("{MARKER} plain: {SECRET}")),
        event(2, &format!("base64 marker b64: {}", vars[1])),
        event(3, &format!("url marker url: {}", vars[2])),
        event(4, &format!("hex marker hex: {}", vars[3])),
        event(5, &format!("json marker json: {}", vars[5])),
        event(6, &format!("split head: {}", &SECRET[..split_at])),
    ];
    let seg1 = vec![event(7, &format!("{} split tail", &SECRET[split_at..]))];
    upload(
        &s,
        &job_token,
        "alice",
        "proj",
        ULID,
        &format!("session with {SECRET} in the title"),
        &[seg0, seg1],
    )
    .await;

    let session_id = db_sessions::session_by_ulid(s.db(), repo.id, ULID)
        .await
        .unwrap()
        .unwrap()
        .id;
    // Raw reads are uploader/admin-only; enable raw storage for alice.
    sqlx::query("UPDATE sessions SET raw_enabled = 1 WHERE id = $1")
        .bind(session_id)
        .execute(s.db().pool())
        .await
        .unwrap();

    let read_token = s.token(&alice, &[Scope::RepoRead]).await;
    let (alice_client, _csrf) = s.login("alice").await;

    // 1. Web page: no secret form anywhere, no-store headers.
    let page_url = s.url(&format!("/alice/proj/sessions/{ULID}"));
    let page_resp = alice_client.get(&page_url).send().await.unwrap();
    assert_eq!(page_resp.status(), 200);
    assert_no_store(page_resp.headers(), "session page");
    let page = page_resp.text().await.unwrap();
    assert_no_variant(&page, "session page");
    assert!(
        !page.contains(&SECRET[..split_at]) || page.contains("[redacted]"),
        "split head fragment should be redacted or absent on the page"
    );

    // 2. In-session search hits: previews are redacted too.
    let search_resp = alice_client
        .get(s.url(&format!("/alice/proj/sessions/{ULID}?q={MARKER}")))
        .send()
        .await
        .unwrap();
    assert_eq!(search_resp.status(), 200);
    assert_no_store(search_resp.headers(), "session search");
    let search_page = search_resp.text().await.unwrap();
    assert_no_variant(&search_page, "session search hits");
    assert!(
        search_page.contains("[redacted]"),
        "search preview should show the redaction marker"
    );

    // 3. API events: redacted, no-store headers.
    let (status, headers, events) = api_raw(
        &s.browser(),
        "GET",
        &s.url(&format!("/api/v1/repos/alice/proj/sessions/{ULID}/events")),
        &read_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{events}");
    assert_no_store(&headers, "API events");
    assert_no_variant(&events.to_string(), "API events");

    // 3b. API meta/list/links: redacted, no-store headers. The session meta
    // carries the title, which is redacted at ingest for job-bound sessions.
    for (surface, path) in [
        (
            "API meta",
            format!("/api/v1/repos/alice/proj/sessions/{ULID}"),
        ),
        (
            "API links",
            format!("/api/v1/repos/alice/proj/sessions/{ULID}/links"),
        ),
        ("API list", "/api/v1/repos/alice/proj/sessions".to_owned()),
    ] {
        let (status, headers, value) =
            api_raw(&s.browser(), "GET", &s.url(&path), &read_token, None).await;
        assert_eq!(status, StatusCode::OK, "{surface}: {value}");
        assert_no_store(&headers, surface);
        assert_no_variant(&value.to_string(), surface);
    }

    // 3c. Web sessions list: no-store headers, redacted titles.
    let list_resp = alice_client
        .get(s.url("/alice/proj/sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.status(), 200);
    assert_no_store(list_resp.headers(), "web sessions list");
    let list_page = list_resp.text().await.unwrap();
    assert_no_variant(&list_page, "web sessions list");

    // 4. Raw segments: stored bytes are redacted (decompress and check).
    for n in [0_i64, 1] {
        let resp = s
            .browser()
            .get(s.url(&format!(
                "/api/v1/repos/alice/proj/sessions/{ULID}/segments/{n}"
            )))
            .bearer_auth(&read_token)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "segment {n}");
        assert_no_store(resp.headers(), &format!("raw segment {n}"));
        let bytes = resp.bytes().await.unwrap();
        let text = String::from_utf8(
            starforge_format::decompress(&bytes).expect("stored segment decompresses"),
        )
        .unwrap();
        assert_no_variant(&text, &format!("raw segment {n}"));
    }

    // 5. Download: redacted, no-store headers.
    let download_resp = alice_client
        .get(s.url(&format!("/alice/proj/sessions/{ULID}/download")))
        .send()
        .await
        .unwrap();
    assert_eq!(download_resp.status(), 200);
    assert_no_store(download_resp.headers(), "session download");
    let download = download_resp.text().await.unwrap();
    assert_no_variant(&download, "session download");

    // 6. The search index / global session search: no secret.
    let (status, _, hits) = api_raw(
        &s.browser(),
        "GET",
        &s.url(&format!(
            "/api/v1/search/sessions?q={}",
            percent_encode(SECRET)
        )),
        &read_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{hits}");
    assert_no_variant(&hits.to_string(), "global search");

    // 7. No secret (plain or base64) anywhere on disk: blobs, DB, index.
    let mut files = Vec::new();
    walk_files(s.data.path(), &mut files);
    assert!(!files.is_empty(), "expected data files to walk");
    for file in &files {
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        for needle in [SECRET, &vars[1]] {
            let leak = bytes
                .windows(needle.len())
                .any(|window| window == needle.as_bytes());
            assert!(!leak, "secret leaked into file {}", file.display());
        }
    }

    // 8. Core-level: the resolved values feed redaction at render too.
    let values = s.core.ci_secret_values_for_session(session_id).await;
    assert_eq!(values, vec![SECRET.to_owned()]);
    let redacted = starforged_core::ci::redact_ci_secrets_with_history(
        &format!("tail {SECRET}"),
        &format!("head {SECRET}"),
        &values,
    );
    assert_no_variant(&redacted, "render-time redaction");
}
