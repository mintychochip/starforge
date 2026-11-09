//! `memory search|context` against an in-process search stub.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::Query;
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use starforge_cli::api::ApiClient;
use starforge_cli::commands::memory;
use starforge_cli::commands::trail::{TextJson, TrailCtx};

#[tokio::test]
async fn memory_search_and_context_use_the_global_search() {
    let seen = Arc::new(Mutex::new(HashMap::new()));
    let app = Router::new().route(
        "/api/v1/search/sessions",
        get({
            let seen = seen.clone();
            move |Query(params): Query<HashMap<String, String>>| {
                let seen = seen.clone();
                async move {
                    *seen.lock().unwrap() = params;
                    Json(json!({
                        "results": [{
                            "repo": "alice/proj",
                            "session": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                            "agent": "pi",
                            "title": "fix login",
                            "events": [{
                                "seq": 3,
                                "kind": "user_message",
                                "snippet": "the login bug"
                            }]
                        }],
                        "page": 1,
                        "per_page": 20,
                        "has_more": false
                    }))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let base = format!("http://{addr}");
    let api = ApiClient::new(&base, "alice/proj", "token").unwrap();
    let ctx = TrailCtx::new(api, std::path::Path::new("/tmp"), None, Vec::new());

    let (out, code) = memory::search(
        &ctx,
        "login",
        Some("alice/proj"),
        Some("pi"),
        20,
        TextJson::Text,
    )
    .await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("alice/proj"), "{out}");
    assert!(out.contains("fix login"), "{out}");
    assert!(out.contains("the login bug"), "{out}");
    let params = seen.lock().unwrap().clone();
    assert_eq!(params.get("q").map(String::as_str), Some("login"));
    assert_eq!(params.get("repo").map(String::as_str), Some("alice/proj"));
    assert_eq!(params.get("agent").map(String::as_str), Some("pi"));
    assert_eq!(params.get("per_page").map(String::as_str), Some("20"));

    let (out, code) = memory::context(&ctx, "login", None, 10, None).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("<untrusted-data"), "{out}");
    assert!(out.contains("the login bug"), "{out}");
    assert!(out.contains("Session memory"), "{out}");
}
