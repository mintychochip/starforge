//! M4a S1: `starforged index rebuild` over a file-backed data dir.
//!
//! Seeds one public repository, one Trail (with a comment), and one completed
//! session through `Core`, then exercises the real CLI both ways: while the
//! seeding process holds the index writer the rebuild fails with the
//! "stop the server" message; after it is dropped the rebuild succeeds and
//! the index answers searches with the expected documents.
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};
use starforged::admin::open_core;
use starforged::config::Config;
use starforged_core::Core;
use starforged_core::accounts::CreateUser;
use starforged_core::ingest::IngestAuth;
use starforged_core::permission::Visibility;
use starforged_core::repos::CreateRepo;
use starforged_core::tokens::{Scope, TokenAuth};
use starforged_index::{EventQuery, Scope as IndexScope, SearchIndex};

const ULID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FC1";

/// Writes a minimal `starforged.toml` rooted at `data_dir` and returns it.
fn write_config(dir: &Path, data_dir: &Path) -> PathBuf {
    std::fs::create_dir_all(data_dir).unwrap();
    let config = dir.join("starforged.toml");
    let text = format!(
        "[server]\n\
         http_addr = \"127.0.0.1:0\"\n\
         base_url = \"http://127.0.0.1:0\"\n\
         [security]\n\
         secret_key = \"{secret}\"\n\
         [storage]\n\
         data_dir = \"{data}\"\n\
         [database]\n\
         url = \"sqlite://{data}/starforge.db?mode=rwc\"\n\
         auto_migrate = true\n",
        secret = "0".repeat(64),
        data = data_dir.display(),
    );
    std::fs::write(&config, text).unwrap();
    config
}

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "pi", "version": "2.1"},
        "models": ["m1"],
        "title": "rebuild fixture",
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

fn event(seq: u64, kind: &str, payload: Value) -> String {
    let mut line = json!({"v": 1, "seq": seq, "ts": "2026-11-04T00:00:00Z", "kind": kind});
    for (k, v) in payload.as_object().unwrap() {
        line[k] = v.clone();
    }
    line.to_string()
}

/// Opens a `Core` over `config_path`, seeding one public repository, one
/// Trail with a comment, and one completed session whose segment carries
/// searchable text, a tool name, a file path, plus reasoning and a tool
/// result that must never be indexed.
async fn seed(config_path: &Path) -> Core {
    let config = Config::load(config_path).unwrap();
    let core = open_core(&config, PathBuf::from(env!("CARGO_BIN_EXE_starforged")))
        .await
        .unwrap();
    let alice = core
        .create_user(CreateUser {
            handle: "alice".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    core.create_repo(
        &alice,
        "alice",
        CreateRepo {
            name: "proj".into(),
            description: String::new(),
            visibility: Visibility::Public,
            readme: false,
        },
    )
    .await
    .unwrap();
    core.create_trail(
        &alice,
        "alice",
        "proj",
        "Quyx plumbline repair",
        "Fix the qux handle",
    )
    .await
    .unwrap();
    core.add_comment(&alice, "alice", "proj", 1, "plumbline follow-up with quux")
        .await
        .unwrap();

    let token = TokenAuth {
        user: alice.clone(),
        scopes: vec![Scope::SessionUpload],
        token_id: 0,
    };
    let auth: IngestAuth = core
        .authorize_upload(&token, "alice", "proj")
        .await
        .unwrap();
    core.upsert_session_meta(&auth, ULID, &meta_body(ULID))
        .await
        .unwrap();
    let lines = [
        event(0, "user_message", json!({"text": "quyx rebuild plumbline"})),
        event(
            1,
            "tool_call",
            json!({"tool": {"name": "bash", "input": {"cmd": "echo quietly"}}}),
        ),
        event(
            2,
            "file_change",
            json!({"path": "src/plumbline.rs", "change": "modify"}),
        ),
        event(3, "reasoning", json!({"text": "subway shortcuts"})),
        event(
            4,
            "tool_result",
            json!({"result": {"output": "outputword", "is_error": false}}),
        ),
    ];
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    core.put_segment(&auth, ULID, 0, &bytes, Some(hash))
        .await
        .unwrap();
    core.complete_session(&auth, ULID).await.unwrap();
    core.publish_session(&alice, &auth.access, ULID)
        .await
        .unwrap();
    core
}

fn rebuild(config_path: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_starforged"))
        .arg("--config")
        .arg(config_path)
        .arg("index")
        .arg("rebuild")
        .output()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebuild_fails_while_the_writer_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = write_config(dir.path(), &dir.path().join("data"));
    // The seeding `Core` holds the tantivy writer for its whole lifetime.
    let core = seed(&config_path).await;

    let out = rebuild(&config_path);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "rebuild must fail while the writer is held: {combined}"
    );
    assert!(
        combined.contains("stop the server"),
        "the failure must say to stop the server: {combined}"
    );

    drop(core);
    let out = rebuild(&config_path);
    assert!(
        out.status.success(),
        "rebuild succeeds once the writer is released: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebuild_produces_the_expected_counts() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_path = write_config(dir.path(), &data_dir);
    drop(seed(&config_path).await);

    let out = rebuild(&config_path);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "rebuild failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("1 trail") && stdout.contains("3 event"),
        "rebuild prints the counts: {stdout}"
    );

    let index = SearchIndex::open_or_create(&data_dir.join("index")).unwrap();
    assert_eq!(
        index.stats().unwrap(),
        starforged_index::IndexStats {
            trails: 1,
            events: 3
        },
        "one Trail and the three searchable events (reasoning and tool results produce no documents)"
    );
    let scope = IndexScope {
        signed_in: true,
        readable: Vec::new(),
        member: Vec::new(),
        admin: Vec::new(),
        viewer_id: Some(1),
    };
    let search = |q: &str| {
        index
            .search_events(
                &EventQuery {
                    q: q.to_owned(),
                    ..Default::default()
                },
                &scope,
                0,
                20,
            )
            .unwrap()
            .len()
    };
    assert_eq!(search("plumbline"), 2, "user text and the file path");
    assert_eq!(search("bash"), 1, "the tool name");
    assert_eq!(search("subway"), 0, "reasoning is never indexed");
    assert_eq!(search("outputword"), 0, "tool outputs are never indexed");
    assert_eq!(search("quietly"), 0, "tool inputs are never indexed");
}
