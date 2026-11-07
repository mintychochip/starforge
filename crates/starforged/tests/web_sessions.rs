//! Repository sessions list (`GET /{owner}/{repo}/sessions`) and viewer
//! parent/children links. Sessions are inserted directly with controlled
//! `started_at`/`parent_ulid`/`lifecycle`; the page assertions run through
//! the real router as a signed-in browser.
mod common;

use common::*;
use starforged_core::permission::Visibility;
use starforged_db::sessions::{self as db_sessions, NewSession};

const ULID_PARENT: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA0";
const ULID_CHILD: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA1";
const ULID_CHILD_TWO: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA2";
const ULID_GRANDCHILD: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA3";
const ULID_TOP: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA4";
const ULID_UNTITLED: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA5";
const ULID_UNREADABLE_PARENT: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA6";
const ULID_ORPHAN: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA7";
const ULID_OLDEST: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA8";
const ULID_MIDDLE: &str = "01ARZ3NDEKTSV4RRFFQ69G5LA9";
const ULID_NEWEST: &str = "01ARZ3NDEKTSV4RRFFQ69G5LAB";
const ULID_NEWEST_TWO: &str = "01ARZ3NDEKTSV4RRFFQ69G5LAC";

#[allow(clippy::too_many_arguments)]
async fn insert(
    s: &TestServer,
    repo_id: i64,
    uploader_id: i64,
    ulid: &str,
    title: &str,
    agent: &str,
    started_at: i64,
    ended_at: Option<i64>,
    parent_ulid: Option<&str>,
    lifecycle: &str,
    turns: i64,
    tool_calls: i64,
) {
    db_sessions::insert_session(
        s.core.db(),
        &NewSession {
            repo_id,
            ulid,
            uploader_id,
            agent_name: agent,
            agent_version: "2.1",
            models: "[]",
            title,
            branch: "main",
            head_sha: "",
            started_at,
            ended_at,
            parent_ulid,
            usage_input: 0,
            usage_output: 0,
            usage_cache_read: 0,
            usage_cache_write: 0,
            usage_reasoning: 0,
            files_touched: "[]",
            turn_count: turns,
            tool_call_count: tool_calls,
            lifecycle,
            quarantine: "none",
            quarantine_reason: "",
            quarantine_detail: "",
            visibility: "inherit",
            raw_enabled: 0,
            redaction_fingerprint: "fp",
            redaction_counts: "{}",
            capture_mode: "cli",
            cli_version: "1.0.0",
            adapter_verified: 1,
        },
    )
    .await
    .unwrap();
}

async fn repo_id(
    s: &TestServer,
    owner: &str,
    repo: &str,
    user: &starforged_core::accounts::User,
) -> i64 {
    s.core
        .repo_for(Some(user), owner, repo)
        .await
        .unwrap()
        .repo
        .id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_defaults_to_top_level_newest_first() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let rid = repo_id(&s, "alice", "proj", &alice).await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_PARENT,
        "Parent session",
        "pi",
        1_700_000_000,
        None,
        None,
        "receiving",
        2,
        3,
    )
    .await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_CHILD,
        "Child session",
        "pi",
        1_700_003_600,
        None,
        Some(ULID_PARENT),
        "receiving",
        1,
        1,
    )
    .await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_TOP,
        "Top session",
        "pi",
        1_700_007_200,
        Some(1_700_010_800),
        None,
        "complete",
        1,
        1,
    )
    .await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_UNTITLED,
        "",
        "pi",
        1_700_000_500,
        None,
        None,
        "receiving",
        0,
        0,
    )
    .await;

    let (client, _csrf) = s.login("alice").await;
    let list = get_text(&client, &s.url("/alice/proj/sessions")).await;
    // Top-level by default: the child is hidden, the rest show.
    assert!(list.contains("Top session"), "{list}");
    assert!(list.contains("Parent session"), "{list}");
    assert!(!list.contains("Child session"), "{list}");
    assert!(list.contains("Untitled session"), "{list}");
    // Newest first.
    let top_pos = list.find("Top session").unwrap();
    let untitled_pos = list.find("Untitled session").unwrap();
    let parent_pos = list.find("Parent session").unwrap();
    assert!(
        top_pos < untitled_pos && untitled_pos < parent_pos,
        "{list}"
    );
    // Row fields: agent, ended time (not "in progress"), turns, tool calls,
    // and the direct-subagent count (parent has one child, the top has none).
    let parent_row = between(&list, "Parent session", "</tr>");
    assert!(parent_row.contains("pi 2.1"), "{parent_row}");
    assert!(parent_row.contains("<td>2</td>"), "{parent_row}");
    assert!(parent_row.contains("<td>3</td>"), "{parent_row}");
    assert!(parent_row.contains("<td>1</td>"), "{parent_row}");
    let top_row = between(&list, "Top session", "</tr>");
    assert!(!top_row.contains("in progress"), "{top_row}");
    assert!(top_row.contains("<td>0</td>"), "{top_row}");
    let untitled_row = between(&list, "Untitled session", "</tr>");
    assert!(untitled_row.contains("in progress"), "{untitled_row}");
    // Tabs mark the sessions page current.
    assert!(
        list.contains(r#"href="/alice/proj/sessions" aria-current="page""#),
        "{list}"
    );

    let all = get_text(&client, &s.url("/alice/proj/sessions?all=1")).await;
    assert!(all.contains("Child session"), "{all}");
    let top_pos = all.find("Top session").unwrap();
    let child_pos = all.find("Child session").unwrap();
    let parent_pos = all.find("Parent session").unwrap();
    assert!(top_pos < child_pos && child_pos < parent_pos, "{all}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn list_honours_filters_and_pagination() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let rid = repo_id(&s, "alice", "proj", &alice).await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_PARENT,
        "Pi session",
        "pi",
        1_700_000_000,
        None,
        None,
        "receiving",
        1,
        1,
    )
    .await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_TOP,
        "Claude session",
        "claude",
        1_700_003_600,
        Some(1_700_007_200),
        None,
        "complete",
        1,
        1,
    )
    .await;
    let (client, _csrf) = s.login("alice").await;

    let by_agent = get_text(&client, &s.url("/alice/proj/sessions?agent=claude")).await;
    assert!(by_agent.contains("Claude session"), "{by_agent}");
    assert!(!by_agent.contains("Pi session"), "{by_agent}");

    let complete = get_text(&client, &s.url("/alice/proj/sessions?state=complete")).await;
    assert!(complete.contains("Claude session"), "{complete}");
    assert!(!complete.contains("Pi session"), "{complete}");

    let receiving = get_text(&client, &s.url("/alice/proj/sessions?state=receiving")).await;
    assert!(receiving.contains("Pi session"), "{receiving}");
    assert!(!receiving.contains("Claude session"), "{receiving}");

    // Pagination: 51 sessions at 50 per page.
    for i in 0..51 {
        let ulid = format!("01ARZ3NDEKTSV4RRFFQ69LOB{i:02}");
        let title = format!("Page session {i:02}");
        insert(
            &s,
            rid,
            alice.id,
            &ulid,
            &title,
            "pi",
            1_700_100_000 + i * 60,
            None,
            None,
            "receiving",
            0,
            0,
        )
        .await;
    }
    let first = get_text(&client, &s.url("/alice/proj/sessions")).await;
    assert!(first.contains("Page session 50"), "{first}");
    assert!(!first.contains("Page session 00"), "{first}");
    assert!(first.contains("Next"), "{first}");
    let second = get_text(&client, &s.url("/alice/proj/sessions?page=2")).await;
    assert!(second.contains("Page session 00"), "{second}");
    assert!(!second.contains("Page session 50"), "{second}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_repo_list_is_404_for_anonymous() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let client = s.browser();
    let response = client
        .get(s.url("/alice/proj/sessions"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    // A readable empty repository shows the empty state, not an error.
    s.repo(&alice, "empty", Visibility::Public).await;
    let empty = get_text(&client, &s.url("/alice/empty/sessions")).await;
    assert!(empty.contains("No sessions yet."), "{empty}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_links_parent_and_children() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let rid = repo_id(&s, "alice", "proj", &alice).await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_PARENT,
        "My parent",
        "pi",
        1_700_000_000,
        None,
        None,
        "complete",
        1,
        1,
    )
    .await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_CHILD,
        "My child",
        "pi",
        1_700_003_600,
        None,
        Some(ULID_PARENT),
        "receiving",
        1,
        1,
    )
    .await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_CHILD_TWO,
        "Second child",
        "pi",
        1_700_007_200,
        None,
        Some(ULID_PARENT),
        "receiving",
        1,
        1,
    )
    .await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_GRANDCHILD,
        "My grandchild",
        "pi",
        1_700_010_800,
        None,
        Some(ULID_CHILD),
        "receiving",
        1,
        1,
    )
    .await;

    let (client, _csrf) = s.login("alice").await;

    let parent = get_text(
        &client,
        &s.url(&format!("/alice/proj/sessions/{ULID_PARENT}")),
    )
    .await;
    assert!(parent.contains("Subagent sessions (2)"), "{parent}");
    assert!(
        parent.contains(&format!(r#"href="/alice/proj/sessions/{ULID_CHILD}""#)),
        "{parent}"
    );
    assert!(
        parent.contains(&format!(r#"href="/alice/proj/sessions/{ULID_CHILD_TWO}""#)),
        "{parent}"
    );
    // Direct children only, oldest first.
    assert!(!parent.contains("My grandchild"), "{parent}");
    let first_child = parent.find("My child").unwrap();
    let second_child = parent.find("Second child").unwrap();
    assert!(first_child < second_child, "{parent}");

    let child = get_text(
        &client,
        &s.url(&format!("/alice/proj/sessions/{ULID_CHILD}")),
    )
    .await;
    assert!(child.contains("Subagent of My parent"), "{child}");
    assert!(
        child.contains(&format!(r#"href="/alice/proj/sessions/{ULID_PARENT}""#)),
        "{child}"
    );
    assert!(child.contains("Subagent sessions (1)"), "{child}");
    assert!(child.contains("My grandchild"), "{child}");

    let grandchild = get_text(
        &client,
        &s.url(&format!("/alice/proj/sessions/{ULID_GRANDCHILD}")),
    )
    .await;
    assert!(grandchild.contains("Subagent of My child"), "{grandchild}");
    assert!(!grandchild.contains("Subagent sessions ("), "{grandchild}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_parent_is_hidden_and_child_lists_top_level() {
    let s = TestServer::start().await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    let alice = s.user("alice").await;
    s.repo(&carol, "proj", Visibility::Public).await;
    let rid = repo_id(&s, "carol", "proj", &carol).await;
    // Bob's unpublished session: alice (a non-member) cannot read it on a
    // public repository. Alice's published orphan names it as parent.
    insert(
        &s,
        rid,
        bob.id,
        ULID_UNREADABLE_PARENT,
        "Hidden parent",
        "pi",
        1_700_000_000,
        None,
        None,
        "complete",
        1,
        1,
    )
    .await;

    insert(
        &s,
        rid,
        alice.id,
        ULID_ORPHAN,
        "Orphan child",
        "pi",
        1_700_003_600,
        None,
        Some(ULID_UNREADABLE_PARENT),
        "complete",
        1,
        1,
    )
    .await;
    db_sessions::set_visibility(
        s.core.db(),
        db_sessions::session_by_ulid(s.core.db(), rid, ULID_ORPHAN)
            .await
            .unwrap()
            .unwrap()
            .id,
        "published",
    )
    .await
    .unwrap();

    let (client, _csrf) = s.login("alice").await;
    let list = get_text(&client, &s.url("/carol/proj/sessions")).await;
    assert!(list.contains("Orphan child"), "{list}");
    assert!(!list.contains("Hidden parent"), "{list}");

    let orphan = get_text(
        &client,
        &s.url(&format!("/carol/proj/sessions/{ULID_ORPHAN}")),
    )
    .await;
    assert!(!orphan.contains("Subagent of"), "{orphan}");

    let hidden = client
        .get(s.url(&format!("/carol/proj/sessions/{ULID_UNREADABLE_PARENT}")))
        .send()
        .await
        .unwrap();
    assert_eq!(hidden.status(), 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_capped_keeps_newest_readable_sessions() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let rid = repo_id(&s, "alice", "proj", &alice).await;
    // Three sessions: the oldest is unreadable to bob (unpublished on a
    // public repo, not a member); with a candidate cap of 2 the newest
    // readable session must still appear. Oldest-first candidate
    // selection would let the unreadable oldest row and the middle one
    // crowd the newest out.
    insert(
        &s,
        rid,
        alice.id,
        ULID_OLDEST,
        "Oldest unreadable",
        "pi",
        1_700_000_000,
        None,
        None,
        "complete",
        1,
        1,
    )
    .await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_MIDDLE,
        "Middle published",
        "pi",
        1_700_000_100,
        None,
        None,
        "complete",
        1,
        1,
    )
    .await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_NEWEST,
        "Newest published",
        "pi",
        1_700_000_200,
        None,
        None,
        "complete",
        1,
        1,
    )
    .await;
    // A fourth, newest row makes the cap actually cut: the newest three
    // candidates are NEWEST_TWO, NEWEST, MIDDLE, while oldest-first would
    // fetch OLDEST (unreadable), MIDDLE, NEWEST and lose NEWEST_TWO.
    insert(
        &s,
        rid,
        alice.id,
        ULID_NEWEST_TWO,
        "Newest two published",
        "pi",
        1_700_000_300,
        None,
        None,
        "complete",
        1,
        1,
    )
    .await;
    for ulid in [ULID_MIDDLE, ULID_NEWEST, ULID_NEWEST_TWO] {
        db_sessions::set_visibility(
            s.core.db(),
            db_sessions::session_by_ulid(s.core.db(), rid, ulid)
                .await
                .unwrap()
                .unwrap()
                .id,
            "published",
        )
        .await
        .unwrap();
    }
    let access = s.core.repo_for(Some(&bob), "alice", "proj").await.unwrap();
    let filter = starforged_core::read::RepoSessionFilter::default();
    let (items, total) = s
        .core
        .list_repo_sessions_page_capped(Some(&bob), &access, &filter, 1, 10, 2)
        .await
        .unwrap();
    let ulids: Vec<&str> = items.iter().map(|i| i.session.ulid.as_str()).collect();
    assert_eq!(ulids, vec![ULID_NEWEST_TWO, ULID_NEWEST, ULID_MIDDLE]);
    assert_eq!(total, 3);
}

fn child_ulid(index: usize) -> String {
    format!("01ARZ3NDEKTSV4RRFFQ69G5{:04}", index)
}

async fn insert_many_children(s: &TestServer, rid: i64, uploader: i64, n: usize) {
    for i in 0..n {
        let ulid = child_ulid(i);
        insert(
            s,
            rid,
            uploader,
            &ulid,
            &format!("Child {i}"),
            "pi",
            1_700_003_600 + i as i64,
            None,
            Some(ULID_PARENT),
            "complete",
            1,
            1,
        )
        .await;
    }
}

fn child_link_count(page: &str) -> usize {
    page.matches(r#"<li><a href="/alice/proj/sessions/"#)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_caps_children_at_fifty_with_note() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let rid = repo_id(&s, "alice", "proj", &alice).await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_PARENT,
        "Parent session",
        "pi",
        1_700_000_000,
        None,
        None,
        "receiving",
        2,
        3,
    )
    .await;
    insert_many_children(&s, rid, alice.id, 51).await;
    let (client, _csrf) = s.login("alice").await;
    let parent = get_text(
        &client,
        &s.url(&format!("/alice/proj/sessions/{ULID_PARENT}")),
    )
    .await;
    assert!(parent.contains("Subagent sessions (50)"), "{parent}");
    assert_eq!(child_link_count(&parent), 50, "{parent}");
    assert!(
        parent.contains("Showing the first 50 subagent sessions."),
        "{parent}"
    );
    assert!(!parent.contains("Child 50"), "{parent}");
    assert!(parent.contains("Child 0"), "{parent}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_lists_all_children_below_cap_without_note() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    let rid = repo_id(&s, "alice", "proj", &alice).await;
    insert(
        &s,
        rid,
        alice.id,
        ULID_PARENT,
        "Parent session",
        "pi",
        1_700_000_000,
        None,
        None,
        "receiving",
        2,
        3,
    )
    .await;
    insert_many_children(&s, rid, alice.id, 49).await;
    let (client, _csrf) = s.login("alice").await;
    let parent = get_text(
        &client,
        &s.url(&format!("/alice/proj/sessions/{ULID_PARENT}")),
    )
    .await;
    assert!(parent.contains("Subagent sessions (49)"), "{parent}");
    assert_eq!(child_link_count(&parent), 49, "{parent}");
    assert!(
        !parent.contains("Showing the first 50 subagent sessions."),
        "{parent}"
    );
}
