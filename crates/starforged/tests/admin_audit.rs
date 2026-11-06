mod common;

use common::{TestServer, get_text};
use serde_json::Value;
use starforged_core::accounts::{CreateUser, User};
use starforged_core::tokens::Scope;

async fn admin(s: &TestServer) -> User {
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(common::PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
}

/// Inserts one audit row with an explicit timestamp; returns its id.
async fn seed(
    s: &TestServer,
    actor: Option<i64>,
    action: &str,
    target: &str,
    ip: &str,
    user_agent: &str,
    created_at: i64,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO audit_log (actor_id, action, target, detail, ip, user_agent, created_at) \
         VALUES ($1, $2, $3, '', $4, $5, $6) RETURNING id",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(ip)
    .bind(user_agent)
    .bind(created_at)
    .fetch_one(s.core.db().pool())
    .await
    .unwrap()
}

async fn api_entries(client: &reqwest::Client, s: &TestServer, token: &str, query: &str) -> Value {
    let response = client
        .get(s.url(&format!("/api/v1/admin/audit{query}")))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "audit API failed");
    response.json().await.unwrap()
}

fn targets(body: &Value) -> Vec<&str> {
    body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["target"].as_str().unwrap())
        .collect()
}

/// The `after` cursor of the page's "Older entries" link, if it has one.
/// The href joins params with `&amp;`, so the cursor follows `after=`.
fn next_cursor(html: &str) -> Option<String> {
    html.find("after=").map(|at| {
        html[at + 6..]
            .chars()
            .take_while(|&c| c != '"' && c != '&')
            .collect()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filters_narrow_results() {
    let s = TestServer::start().await;
    let root = admin(&s).await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let token = s.token(&root, &[Scope::Admin]).await;
    let client = reqwest::Client::new();
    // 1_700_000_000 is 2023-11-14T22:13:20Z; 1_000_000_000 is 2001-09-09T01:46:40Z.
    seed(
        &s,
        Some(alice.id),
        "session.create",
        "repo:alice/proj",
        "10.0.0.1",
        "agent-a",
        1_700_000_000,
    )
    .await;
    seed(
        &s,
        Some(bob.id),
        "session.create",
        "repo:bob/proj",
        "10.0.0.2",
        "agent-b",
        1_700_000_100,
    )
    .await;
    seed(
        &s,
        Some(alice.id),
        "session.delete",
        "repo:alice/proj",
        "10.0.0.1",
        "agent-a",
        1_700_000_200,
    )
    .await;
    seed(
        &s,
        Some(alice.id),
        "auth.login_failed",
        "user:alice",
        "10.0.0.9",
        "agent-x",
        1_700_000_300,
    )
    .await;
    seed(
        &s,
        None,
        "session.create",
        "repo:100%proj",
        "",
        "",
        1_700_000_400,
    )
    .await;
    seed(
        &s,
        None,
        "session.create",
        "repo:100xproj",
        "",
        "",
        1_700_000_500,
    )
    .await;
    seed(
        &s,
        Some(alice.id),
        "session.create",
        "repo:alice/old",
        "10.0.0.1",
        "agent-a",
        1_000_000_000,
    )
    .await;

    // Newest first overall. The `action` filter scopes this to the seeded rows,
    // so audit rows written by setup never interfere.
    let all = api_entries(&client, &s, &token, "?action=session.").await;
    assert_eq!(
        targets(&all),
        [
            "repo:alice/old",
            "repo:100xproj",
            "repo:100%proj",
            "repo:alice/proj",
            "repo:bob/proj",
            "repo:alice/proj",
        ],
        "newest first:\n{all}"
    );

    // Actor handle, case-insensitive.
    let by_actor = api_entries(&client, &s, &token, "?actor=ALICE").await;
    assert_eq!(targets(&by_actor).len(), 4, "actor filter:\n{by_actor}");
    assert!(!targets(&by_actor).contains(&"repo:bob/proj"));

    // Action: exact versus prefix.
    let exact = api_entries(&client, &s, &token, "?action=auth.login_failed").await;
    assert_eq!(targets(&exact), ["user:alice"]);
    let prefix = api_entries(&client, &s, &token, "?action=session.").await;
    assert_eq!(targets(&prefix).len(), 6, "action prefix:\n{prefix}");

    // Target substring, with LIKE wildcards in the input matched literally.
    let substring = api_entries(&client, &s, &token, "?target=alice/").await;
    assert_eq!(targets(&substring).len(), 3, "target filter:\n{substring}");
    let literal = api_entries(&client, &s, &token, "?target=100%25").await;
    assert_eq!(
        targets(&literal),
        ["repo:100%proj"],
        "LIKE-escaped target:\n{literal}"
    );

    // Dates: from/to bound the whole UTC day.
    let day = api_entries(&client, &s, &token, "?from=2023-11-14&to=2023-11-14").await;
    assert_eq!(targets(&day).len(), 6, "same-day window:\n{day}");
    let old = api_entries(&client, &s, &token, "?from=2001-09-09&to=2001-09-09").await;
    assert_eq!(targets(&old), ["repo:alice/old"], "old day:\n{old}");
    let empty = api_entries(&client, &s, &token, "?from=2001-09-08&to=2001-09-08").await;
    assert_eq!(targets(&empty).len(), 0, "neighbouring day:\n{empty}");

    // Keyset cursor walks to older rows.
    let first = api_entries(&client, &s, &token, "?limit=2").await;
    assert_eq!(targets(&first).len(), 2);
    let after = first["next_after"].as_i64().unwrap();
    let second = api_entries(&client, &s, &token, &format!("?limit=2&after={after}")).await;
    assert_eq!(targets(&second).len(), 2, "second page:\n{second}");
    assert!(
        targets(&first)
            .iter()
            .all(|t| !targets(&second).contains(t))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pagination_is_stable_while_rows_arrive() {
    let s = TestServer::start().await;
    let root = admin(&s).await;
    let (client, _csrf) = s.login("root").await;
    let token = s.token(&root, &[Scope::Admin]).await;
    let http = reqwest::Client::new();

    for i in 1..=60 {
        seed(
            &s,
            Some(root.id),
            "test.row",
            &format!("row:{i:03}"),
            "10.0.0.1",
            "agent",
            1_700_000_000 + i,
        )
        .await;
    }
    let page_one = get_text(&client, &s.url("/admin/audit")).await;
    assert!(page_one.contains("row:060"), "page one newest:\n{page_one}");
    assert!(page_one.contains("row:011"), "page one tail:\n{page_one}");
    assert!(!page_one.contains("row:010"), "page one cut:\n{page_one}");
    let cursor = next_cursor(&page_one).expect("page one has an older link");

    // New rows arrive while the admin is between pages.
    for i in 61..=63 {
        seed(
            &s,
            Some(root.id),
            "test.row",
            &format!("row:{i:03}"),
            "10.0.0.1",
            "agent",
            1_700_000_000 + i,
        )
        .await;
    }

    let page_two = get_text(&client, &s.url(&format!("/admin/audit?after={cursor}"))).await;
    assert!(page_two.contains("row:010"), "page two:\n{page_two}");
    assert!(page_two.contains("row:001"), "page two tail:\n{page_two}");
    assert!(
        !page_two.contains("row:063"),
        "new rows never shift old pages:\n{page_two}"
    );
    assert!(
        !page_two.contains("row:060"),
        "no overlap with page one:\n{page_two}"
    );
    assert!(next_cursor(&page_two).is_none(), "last page:\n{page_two}");

    // The API cursors the same way.
    let first = api_entries(&http, &s, &token, "?limit=2").await;
    assert_eq!(targets(&first), ["row:063", "row:062"]);
    let after = first["next_after"].as_i64().unwrap();
    seed(
        &s,
        Some(root.id),
        "test.row",
        "row:064",
        "10.0.0.1",
        "agent",
        1_700_000_100,
    )
    .await;
    let second = api_entries(&http, &s, &token, &format!("?limit=2&after={after}")).await;
    assert_eq!(
        targets(&second),
        ["row:061", "row:060"],
        "stable cursor:\n{second}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_matches_page() {
    let s = TestServer::start().await;
    let root = admin(&s).await;
    let (client, _csrf) = s.login("root").await;
    let token = s.token(&root, &[Scope::Admin]).await;
    let http = reqwest::Client::new();
    let alice = s.user("alice").await;

    seed(
        &s,
        Some(alice.id),
        "session.create",
        "repo:alice/proj",
        "10.0.0.1",
        "agent-a",
        1_700_000_000,
    )
    .await;
    seed(
        &s,
        Some(root.id),
        "user.suspend",
        "user:alice",
        "10.0.0.2",
        "agent-b",
        1_700_000_100,
    )
    .await;

    let page = get_text(&client, &s.url("/admin/audit?action=session.")).await;
    let api = api_entries(&http, &s, &token, "?action=session.").await;
    assert_eq!(targets(&api), ["repo:alice/proj"], "api:\n{api}");
    // Every API entry renders on the page, in API order.
    let mut at = 0;
    for target in targets(&api) {
        let found = page[at..]
            .find(target)
            .unwrap_or_else(|| panic!("{target} renders in api order:\n{page}"));
        at += found + target.len();
    }
    let entry = &api["entries"][0];
    for field in ["action", "target", "ip", "user_agent"] {
        assert!(
            page.contains(entry[field].as_str().unwrap()),
            "field {field} renders:\n{page}"
        );
    }
    assert_eq!(entry["actor"], "alice");
    assert_eq!(entry["created_at"], "2023-11-14T22:13:20Z");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_shape() {
    let s = TestServer::start().await;
    let root = admin(&s).await;
    let alice = s.user("alice").await;
    let (alice_client, _csrf) = s.login("alice").await;
    let anon = s.browser();
    let http = reqwest::Client::new();

    // Non-admins get 404 on the page, like every other admin page.
    assert_eq!(
        anon.get(s.url("/admin/audit"))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "anonymous page"
    );
    assert_eq!(
        alice_client
            .get(s.url("/admin/audit"))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "non-admin page"
    );
    // The API needs a token (401), the admin scope (403), and a site admin (404).
    let no_token = http.get(s.url("/api/v1/admin/audit")).send().await.unwrap();
    assert_eq!(no_token.status(), 401, "anonymous api");
    // A non-admin cannot mint an admin-scoped token (Forbidden), so build the
    // token while alice is an admin, then demote her: the token keeps its
    // scope but its owner is no longer a site admin.
    let alice = s.core.grant_admin(&root, alice.id).await.unwrap();
    let alice_admin_scoped = s.token(&alice, &[Scope::Admin]).await;
    s.core.revoke_admin(&root, alice.id).await.unwrap();
    let non_admin = http
        .get(s.url("/api/v1/admin/audit"))
        .bearer_auth(&alice_admin_scoped)
        .send()
        .await
        .unwrap();
    assert_eq!(non_admin.status(), 404, "non-admin api");
    let root_read = s.token(&root, &[Scope::RepoRead]).await;
    let wrong_scope = http
        .get(s.url("/api/v1/admin/audit"))
        .bearer_auth(&root_read)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_scope.status(), 403, "wrong scope api");
    let root_admin = s.token(&root, &[Scope::Admin]).await;
    let allowed = http
        .get(s.url("/api/v1/admin/audit"))
        .bearer_auth(&root_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), 200, "admin api");
    assert!(allowed.json::<Value>().await.unwrap()["entries"].is_array());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_values_render_escaped() {
    let s = TestServer::start().await;
    let root = admin(&s).await;
    let (client, _csrf) = s.login("root").await;

    seed(
        &s,
        Some(root.id),
        "test.row",
        "<img src=x onerror=alert(1)>",
        "10.0.0.1",
        "<script>alert(1)</script>",
        1_700_000_000,
    )
    .await;

    let page = get_text(&client, &s.url("/admin/audit")).await;
    assert!(
        page.contains("&#60;script&#62;alert(1)&#60;/script&#62;"),
        "escaped user agent:\n{page}"
    );
    assert!(
        page.contains("&#60;img src=x onerror=alert(1)&#62;"),
        "escaped target:\n{page}"
    );
    assert!(
        !page.contains("<script>alert(1)</script>"),
        "raw user agent:\n{page}"
    );
    assert!(
        !page.contains("<img src=x onerror=alert(1)>"),
        "raw target:\n{page}"
    );

    // Filter values echoed into the form are escaped too.
    let filtered = get_text(
        &client,
        &s.url("/admin/audit?actor=%22%3E%3Csvg%20onload=alert(1)%3E"),
    )
    .await;
    assert!(
        !filtered.contains("\"><svg onload=alert(1)>"),
        "raw filter echo:\n{filtered}"
    );
    assert!(
        filtered.contains("&#34;&#62;&#60;svg onload=alert(1)&#62;"),
        "escaped filter echo:\n{filtered}"
    );
}
