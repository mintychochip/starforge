//! Task F7: Trail-page security sweep.
//!
//! Permission matrix over every new M2f route and form (roles ×
//! public/internal/private), the §6.4 session-visibility matrix over every
//! session surface, the hostile-input corpus through every newly rendered
//! M2f field (escaped-present plus raw-absent per payload), CSRF on every
//! new form with state unchanged after a forged POST, and archived-repo
//! refusal of every mutation. Every assertion pins real behavior (codes,
//! rows, bytes). Determinism: pushes through HTTP git are followed by
//! bounded `wait_for_revisions` polls (never bare sleeps); API-driven steps
//! need only direct reads.
mod common;

use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;
use starforged_db::checks as db_checks;

const FULL: &[Scope] = &[Scope::RepoRead, Scope::RepoWrite, Scope::TrailWrite];

const ULID_COMMIT: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
const ULID_HAND: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB1";
const ULID_EXTRA: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB2";
const ULID_DAVE: &str = "01ARZ3NDEKTSV4RRFFQ69G5FB7";

const PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<details ontoggle=alert(1)>x</details>",
    "<a href=\"javascript:alert(1)\">x</a>",
    "\"><script>alert(1)</script>",
    "[redacted:<script>]",
    "\u{202E}reversed",
];

/// Executable markup must never reach the page: these tokens are absent from
/// every legitimate trail/change/commit template, so any occurrence is
/// attacker markup rendered live. Escaped text (`&#60;img …`) passes — it
/// is inert — and so does a bare `javascript:` scheme inside escaped text;
/// only a live link (`<a href="javascript:…`) can execute. `<details>` is
/// deliberately absent here: the change page uses it legitimately for diffs,
/// so the `<details>` corpus vector is pinned per payload (raw absent,
/// escaped present) plus the live-handler scan below.
fn assert_no_live_markup(page: &str, surface: &str) {
    let lower = page.to_lowercase();
    for raw in [
        "<script",
        "<img",
        "<svg",
        "<iframe",
        "<object",
        "<embed",
        "<a href=\"javascript",
        "<a href=\"data:",
        "attacker.example",
    ] {
        assert!(!lower.contains(raw), "{raw} live on {surface}");
    }
    let tag = live_handler_tag(&lower);
    assert!(tag.is_none(), "live event handler on {surface}: {tag:?}");
}
/// The first real tag carrying an `on*=` handler attribute, if any.
fn live_handler_tag(lower: &str) -> Option<String> {
    let bytes = lower.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] != b'>' {
            j += 1;
        }
        let tag = &lower[i..j.min(bytes.len())];
        if has_handler_attr(tag) {
            return Some(tag.to_owned());
        }
        i = j + 1;
    }
    None
}

/// True when the tag span carries a real `on*=` attribute: only matches at
/// attribute depth (outside quoted values), so an escaped payload inside a
/// `value="…"` stays inert and unflagged. Entity-escaped quotes never open
/// a quoted region, so tracking raw quotes is sound.
fn has_handler_attr(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    let mut quote = 0u8;
    let mut i = 0;
    while i + 3 < bytes.len() {
        let b = bytes[i];
        if quote != 0 {
            if b == quote {
                quote = 0;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            quote = b;
            i += 1;
            continue;
        }
        if b == b' '
            && bytes[i + 1] == b'o'
            && bytes[i + 2] == b'n'
            && bytes[i + 3].is_ascii_alphabetic()
        {
            let mut j = i + 4;
            while j < bytes.len() && bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            let mut k = j;
            while k < bytes.len() && bytes[k] == b' ' {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b'=' {
                return true;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

/// Mirror of askama's `Html` escaper (`"`→`&#34;`, `&`→`&#38;`,
/// `'`→`&#39;`, `<`→`&#60;`, `>`→`&#62;`).
fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("&#34;"),
            '&' => out.push_str("&#38;"),
            '\'' => out.push_str("&#39;"),
            '<' => out.push_str("&#60;"),
            '>' => out.push_str("&#62;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Every corpus vector must be inert on the page: its raw form absent and
/// its escaped form present (proving the payload actually rendered).
fn assert_payload_escaped(page: &str, payload: &str, surface: &str) {
    assert!(
        !page.contains(payload),
        "raw payload renders on {surface}: {payload:?}"
    );
    assert!(
        page.contains(&escape_html(payload)),
        "escaped payload missing on {surface}: {payload:?}"
    );
}

/// A corpus vector rendered inert on an escaped surface: raw-absent plus
/// escaped-present (proving it rendered), or verbatim-present when there is
/// nothing to escape (the bidi mark, inert without markup).
fn assert_corpus_inert(page: &str, payload: &str, surface: &str) {
    if escape_html(payload) == *payload {
        assert!(page.contains(payload), "plain payload missing on {surface}");
    } else {
        assert_payload_escaped(page, payload, surface);
    }
}

fn meta_body(ulid: &str, title: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": title,
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "feature/widget", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}
async fn web_status(client: &reqwest::Client, method: &str, url: &str) -> u16 {
    match method {
        "GET" => client.get(url).send().await.unwrap().status().as_u16(),
        "POST" => client.post(url).send().await.unwrap().status().as_u16(),
        _ => panic!("method {method}"),
    }
}

async fn session_id(s: &TestServer, repo_id: i64, ulid: &str) -> i64 {
    starforged_db::sessions::session_by_ulid(s.core.db(), repo_id, ulid)
        .await
        .unwrap()
        .unwrap()
        .id
}

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    bob: starforged_core::accounts::User,
    carol: starforged_core::accounts::User,
    wendy: starforged_core::accounts::User,
    mia: starforged_core::accounts::User,
    adam: starforged_core::accounts::User,
    root: starforged_core::accounts::User,
    dave: starforged_core::accounts::User,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let wendy = s.user("wendy").await;
        let mia = s.user("mia").await;
        let adam = s.user("adam").await;
        let dave = s.user("dave").await;
        s.core
            .create_user(starforged_core::accounts::CreateUser {
                handle: "root".into(),
                password: Some(PASSWORD.into()),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let root = s.core.user_by_handle("root").await.unwrap().unwrap();
        for repo in ["proj", "innie", "open"] {
            let visibility = match repo {
                "proj" => Visibility::Private,
                "innie" => Visibility::Internal,
                _ => Visibility::Public,
            };
            s.repo(&alice, repo, visibility).await;
            for (handle, perm) in [
                ("bob", Permission::Triage),
                ("carol", Permission::Read),
                ("wendy", Permission::Write),
                ("mia", Permission::Maintain),
                ("adam", Permission::Admin),
            ] {
                s.core
                    .set_collaborator(&alice, "alice", repo, handle, perm)
                    .await
                    .unwrap();
            }
        }
        Ctx {
            s,
            alice,
            bob,
            carol,
            wendy,
            mia,
            adam,
            root,
            dave,
        }
    }

    async fn tok(&self, user: &starforged_core::accounts::User) -> String {
        self.s.token(user, FULL).await
    }

    async fn repo_id(&self, repo: &str) -> i64 {
        self.s
            .core
            .repo_for(Some(&self.alice), "alice", repo)
            .await
            .unwrap()
            .repo
            .id
    }

    fn api(&self, repo: &str, rest: &str) -> String {
        self.s.url(&format!("/api/v1/repos/alice/{repo}{rest}"))
    }

    fn web(&self, repo: &str, rest: &str) -> String {
        self.s.url(&format!("/alice/{repo}{rest}"))
    }
}

struct RepoSetup {
    n: i64,
    head: String,
    change_id: i64,
}

/// Pushes `main` plus a one-commit `feature/x` branch, files trail 1 with a
/// branch change, uploads a commit-claimed session and a hand-linked
/// session, and uploads one unlinked session for the link matrix.
async fn setup_repo(c: &Ctx, repo: &str) -> RepoSetup {
    let full = c.tok(&c.alice).await;
    let n =
        c.s.core
            .create_trail(&c.alice, "alice", repo, "sweep trail", "intent")
            .await
            .unwrap()
            .number;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# hi\n")]).await;
    let url = c.s.git_url("alice", repo, Some(&full));
    git_ok(&work, &["push", "-q", &url, "main"]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "feature/x"]).await;
    let head = git_ok(&work, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    c.s.core
        .create_branch_change(&c.alice, "alice", repo, n, "feature/x", "main")
        .await
        .unwrap();
    let repo_id = c.repo_id(repo).await;
    let change_id =
        starforged_db::changes::open_branch_changes(c.s.core.db(), repo_id, "feature/x")
            .await
            .unwrap()
            .into_iter()
            .next()
            .expect("change exists")
            .id;

    let upload = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    for (ulid, title) in [
        (ULID_COMMIT, "commit session seven"),
        (ULID_HAND, "hand session seven"),
        (ULID_EXTRA, "spare session seven"),
    ] {
        let put = client
            .put(c.api(repo, &format!("/sessions/{ulid}")))
            .bearer_auth(&upload)
            .json(&meta_body(ulid, title))
            .send()
            .await
            .unwrap();
        assert!(put.status().is_success(), "upload {ulid}: {}", put.status());
    }
    let claim = client
        .post(c.api(repo, &format!("/sessions/{ULID_COMMIT}/links")))
        .bearer_auth(&upload)
        .json(&json!({"links": [{"sha": head, "confidence": "exact"}]}))
        .send()
        .await
        .unwrap();
    assert!(claim.status().is_success(), "claim: {}", claim.status());
    c.s.core
        .link_trail_session(&c.alice, "alice", repo, n, ULID_HAND)
        .await
        .unwrap();
    RepoSetup { n, head, change_id }
}

/// Pushes one more commit to `feature/x` and waits for revision 2.
async fn push_second_commit(c: &Ctx, repo: &str, change_id: i64) -> String {
    let full = c.tok(&c.alice).await;
    let url = c.s.git_url("alice", repo, Some(&full));
    let tmp = tempfile::tempdir().unwrap();
    let seed = work_repo(tmp.path(), "seed", &[("x.txt", "x\n")]).await;
    git_ok(&seed, &["fetch", "-q", &url, "feature/x:feature/x"]).await;
    git_ok(&seed, &["checkout", "-q", "feature/x"]).await;
    commit_files(&seed, &[("b.txt", b"two\n")], "add three").await;
    git_ok(&seed, &["push", "-q", &url, "feature/x"]).await;
    let sha = git_ok(&seed, &["rev-parse", "HEAD"])
        .await
        .trim()
        .to_owned();
    wait_for_revisions(&c.s, change_id).await;
    sha
}

async fn wait_for_revisions(s: &TestServer, change_id: i64) {
    let start = Instant::now();
    loop {
        let revs = starforged_db::changes::revisions_of_change(s.core.db(), change_id)
            .await
            .unwrap();
        let pointed = starforged_db::changes::change_by_id(s.core.db(), change_id)
            .await
            .unwrap()
            .and_then(|row| row.current_revision_id);
        if revs.len() == 2
            && pointed.is_some_and(|id| revs.iter().any(|r| r.id == id && r.number == 2))
        {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "timed out waiting for revision 2 (have {})",
            revs.len()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn api_status(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    token: Option<&str>,
    body: Option<Value>,
) -> (reqwest::StatusCode, Value) {
    let mut req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "DELETE" => client.delete(url),
        _ => panic!("method {method}"),
    };
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    if let Some(body) = body {
        req = req.json(&body);
    }
    let res = req.send().await.unwrap();
    let status = res.status();
    let parsed = res.json::<Value>().await.unwrap_or(Value::Null);
    (status, parsed)
}

/// Permission matrix over the new API routes: reads need repo access (404
/// for non-readers, never 403, 401 without a token); link/unlink need
/// triage+ (403 below); archived repos refuse mutations with 422.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_api() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    for repo in ["proj", "innie", "open"] {
        let setup = setup_repo(&c, repo).await;
        let n = setup.n;
        let tokens = [
            ("alice", c.tok(&c.alice).await),
            ("bob", c.tok(&c.bob).await),
            ("carol", c.tok(&c.carol).await),
            ("wendy", c.tok(&c.wendy).await),
            ("mia", c.tok(&c.mia).await),
            ("adam", c.tok(&c.adam).await),
            ("root", c.tok(&c.root).await),
            ("dave", c.tok(&c.dave).await),
        ];
        let tok = |h: &str| tokens.iter().find(|(x, _)| *x == h).unwrap().1.clone();
        // Non-readers get 404 on every read; readers get 200.
        let want_read = |h: &str| {
            if repo == "proj" && h == "dave" {
                404
            } else {
                200
            }
        };
        for (handle, t) in &tokens {
            let want = want_read(handle);
            let (s, b) = api_status(
                &client,
                "GET",
                &c.api(repo, &format!("/trails/{n}/sessions")),
                Some(t),
                None,
            )
            .await;
            assert_eq!(s.as_u16(), want, "{handle} GET sessions in {repo}: {b}");
            let (s, b) = api_status(
                &client,
                "GET",
                &c.api(repo, &format!("/trails/{n}/changes")),
                Some(t),
                None,
            )
            .await;
            assert_eq!(s.as_u16(), want, "{handle} list changes in {repo}: {b}");
            let (s, b) = api_status(
                &client,
                "GET",
                &c.api(repo, &format!("/trails/{n}/changes/1")),
                Some(t),
                None,
            )
            .await;
            assert_eq!(s.as_u16(), want, "{handle} get change in {repo}: {b}");
            let (s, b) = api_status(
                &client,
                "GET",
                &c.api(repo, &format!("/trails/{n}/changes/1/diff")),
                Some(t),
                None,
            )
            .await;
            assert_eq!(s.as_u16(), want, "{handle} get diff in {repo}: {b}");
            // Pending draft reads: no draft exists, so readers get 404 too;
            // non-readers get 404 without revealing the change.
            let (s, _) = api_status(
                &client,
                "GET",
                &c.api(repo, &format!("/trails/{n}/changes/1/reviews/pending")),
                Some(t),
                None,
            )
            .await;
            assert_eq!(s.as_u16(), 404, "{handle} GET pending in {repo}");
            let (s, _) = api_status(
                &client,
                "DELETE",
                &c.api(repo, &format!("/trails/{n}/changes/1/reviews/pending")),
                Some(t),
                None,
            )
            .await;
            assert_eq!(s.as_u16(), 404, "{handle} DELETE pending in {repo}");
        }
        // Anonymous API callers get 401 on mutations; reads are
        // visibility-shaped (404 on private/internal, 200 on public).
        let want_anon = if repo == "open" { 200 } else { 404 };
        let (s, _) = api_status(
            &client,
            "GET",
            &c.api(repo, &format!("/trails/{n}/sessions")),
            None,
            None,
        )
        .await;
        assert_eq!(s.as_u16(), want_anon, "anon GET sessions in {repo}");
        let (s, _) = api_status(
            &client,
            "POST",
            &c.api(repo, &format!("/trails/{n}/sessions")),
            None,
            Some(json!({"session": ULID_EXTRA})),
        )
        .await;
        assert_eq!(s.as_u16(), 401, "anon link in {repo}");

        // Link/unlink need triage+: read users get 403 (write outranks
        // triage, so writers pass). Strangers: 404 on private (repo
        // invisible) and public (unpublished sessions hide from
        // non-members); 403 on internal, where implicit read makes the
        // session readable but the permission check fires.
        let want_dave = if repo == "innie" { 403 } else { 404 };
        for (handle, want) in [("dave", want_dave), ("carol", 403)] {
            let (s, _) = api_status(
                &client,
                "POST",
                &c.api(repo, &format!("/trails/{n}/sessions")),
                Some(&tok(handle)),
                Some(json!({"session": ULID_EXTRA})),
            )
            .await;
            assert_eq!(s.as_u16(), want, "{handle} link in {repo}");
            let (s, _) = api_status(
                &client,
                "DELETE",
                &c.api(repo, &format!("/trails/{n}/sessions/{ULID_HAND}")),
                Some(&tok(handle)),
                None,
            )
            .await;
            assert_eq!(s.as_u16(), want, "{handle} unlink in {repo}");
        }
        // Triage links, maintain unlinks; both round-trip the sessions JSON.
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(repo, &format!("/trails/{n}/sessions")),
            Some(&tok("bob")),
            Some(json!({"session": ULID_EXTRA})),
        )
        .await;
        assert_eq!(s.as_u16(), 200, "bob link in {repo}: {b}");
        assert!(
            b["linked"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["ulid"] == ULID_EXTRA),
            "bob link visible: {b}"
        );
        // A writer passes the triage threshold too.
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(repo, &format!("/trails/{n}/sessions")),
            Some(&tok("wendy")),
            Some(json!({"session": ULID_HAND})),
        )
        .await;
        assert_eq!(s.as_u16(), 200, "wendy link in {repo}: {b}");
        let (s, b) = api_status(
            &client,
            "DELETE",
            &c.api(repo, &format!("/trails/{n}/sessions/{ULID_EXTRA}")),
            Some(&tok("mia")),
            None,
        )
        .await;
        assert_eq!(s.as_u16(), 200, "mia unlink in {repo}: {b}");

        // Pending thread + comment need only read; the draft stays the
        // author's own; dismissing a pending review is 422 for triage and
        // 403 for its read-only author.
        let thread_body = json!({
            "path": "a.txt", "side": "head",
            "start_line": 1, "end_line": 1,
            "body": "draft nit", "pending": true,
        });
        // Any signed-in reader may open a thread: strangers 404 on private
        // and post drafts elsewhere.
        let (s, _) = api_status(
            &client,
            "POST",
            &c.api(repo, &format!("/trails/{n}/changes/1/threads")),
            Some(&tok("dave")),
            Some(thread_body.clone()),
        )
        .await;
        assert_eq!(
            s.as_u16(),
            if repo == "proj" { 404 } else { 201 },
            "dave pending thread in {repo}"
        );
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(repo, &format!("/trails/{n}/changes/1/threads")),
            Some(&tok("carol")),
            Some(thread_body),
        )
        .await;
        assert_eq!(s.as_u16(), 201, "carol pending thread in {repo}: {b}");
        let tid = b["id"].as_i64().unwrap();
        let (s, b) = api_status(
            &client,
            "GET",
            &c.api(repo, &format!("/trails/{n}/changes/1/reviews/pending")),
            Some(&tok("carol")),
            None,
        )
        .await;
        assert_eq!(s.as_u16(), 200, "carol reads own draft in {repo}: {b}");
        assert_eq!(b["comments"].as_array().unwrap().len(), 1, "{b}");
        let (s, _) = api_status(
            &client,
            "GET",
            &c.api(repo, &format!("/trails/{n}/changes/1/reviews/pending")),
            Some(&tok("bob")),
            None,
        )
        .await;
        assert_eq!(s.as_u16(), 404, "bob cannot read carol's draft in {repo}");
        // Gate reports never count another user's draft threads: with a
        // resolved-threads rule in place, carol's invisible draft keeps the
        // gates passing for everyone else.
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(repo, "/gate-rules"),
            Some(&tok("alice")),
            Some(json!({
                "required_approvals": 0, "dismiss_on_push": false,
                "block_on_request_changes": false, "required_contexts": [],
                "require_up_to_date": false, "require_threads_resolved": true,
                "require_session_evidence": false, "allowed_methods": ["merge"],
            })),
        )
        .await;
        assert_eq!(s.as_u16(), 201, "rule create in {repo}: {b}");
        let (s, b) = api_status(
            &client,
            "GET",
            &c.api(repo, &format!("/trails/{n}/changes/1/gates")),
            Some(&tok("bob")),
            None,
        )
        .await;
        assert_eq!(s.as_u16(), 200, "gates read in {repo}: {b}");
        assert!(
            !b.to_string().contains("unresolved thread"),
            "foreign draft invisible to gates in {repo}: {b}"
        );
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(
                repo,
                &format!("/trails/{n}/changes/1/threads/{tid}/comments"),
            ),
            Some(&tok("carol")),
            Some(json!({"body": "second draft", "pending": true})),
        )
        .await;
        assert_eq!(s.as_u16(), 201, "carol pending comment in {repo}: {b}");
        // A foreign user's comment POST to a draft-only thread gives 404
        // (fixed behavior): the thread is invisible to non-authors.
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(
                repo,
                &format!("/trails/{n}/changes/1/threads/{tid}/comments"),
            ),
            Some(&tok("bob")),
            Some(json!({"body": "intruder"})),
        )
        .await;
        assert_eq!(
            s.as_u16(),
            404,
            "bob cannot comment on carol's draft in {repo}: {b}"
        );
        // A foreign draft `review_id` is rejected on public threads too.
        let (s_pub, pub_body) = api_status(
            &client,
            "POST",
            &c.api(repo, &format!("/trails/{n}/changes/1/threads")),
            Some(&tok("bob")),
            Some(json!({
                "path": "a.txt", "side": "head",
                "start_line": 1, "end_line": 1, "body": "public thread",
            })),
        )
        .await;
        assert_eq!(
            s_pub.as_u16(),
            201,
            "bob public thread in {repo}: {pub_body}"
        );
        let pub_tid = pub_body["id"].as_i64().unwrap();
        // The public unresolved thread blocks the rule; resolving it
        // passes again — while carol's draft stays invisible throughout.
        let (s, b) = api_status(
            &client,
            "GET",
            &c.api(repo, &format!("/trails/{n}/changes/1/gates")),
            Some(&tok("bob")),
            None,
        )
        .await;
        assert_eq!(s.as_u16(), 200, "gates read in {repo}: {b}");
        assert!(
            b.to_string().contains("unresolved thread"),
            "public thread blocks gates in {repo}: {b}"
        );
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(
                repo,
                &format!("/trails/{n}/changes/1/threads/{pub_tid}/resolve"),
            ),
            Some(&tok("bob")),
            None,
        )
        .await;
        assert_eq!(s.as_u16(), 200, "resolve in {repo}: {b}");
        let (s, b) = api_status(
            &client,
            "GET",
            &c.api(repo, &format!("/trails/{n}/changes/1/gates")),
            Some(&tok("bob")),
            None,
        )
        .await;
        assert_eq!(s.as_u16(), 200, "gates read in {repo}: {b}");
        assert!(
            !b.to_string().contains("unresolved thread"),
            "resolved gates pass with draft open in {repo}: {b}"
        );
        let draft_id =
            c.s.core
                .pending_review(Some(&c.carol), "alice", repo, n, 1)
                .await
                .unwrap()
                .expect("draft")
                .id;
        // A foreign draft `review_id` is rejected exactly like an unknown id
        // (422 "unknown review"): the two stay indistinguishable.
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(
                repo,
                &format!("/trails/{n}/changes/1/threads/{pub_tid}/comments"),
            ),
            Some(&tok("bob")),
            Some(json!({"body": "hijack", "review_id": draft_id})),
        )
        .await;
        assert_eq!(
            s.as_u16(),
            422,
            "foreign draft review_id rejected in {repo}: {b}"
        );
        assert!(
            b.to_string().contains("unknown review"),
            "same error as unknown ids in {repo}: {b}"
        );
        let (s, _) = api_status(
            &client,
            "POST",
            &c.api(repo, &format!("/trails/{n}/changes/1/reviews/1/dismiss")),
            Some(&tok("carol")),
            None,
        )
        .await;
        assert_eq!(s.as_u16(), 403, "author cannot dismiss in {repo}");
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(
                repo,
                &format!("/trails/{n}/changes/1/reviews/{draft_id}/dismiss"),
            ),
            Some(&tok("bob")),
            None,
        )
        .await;
        assert_eq!(s.as_u16(), 422, "pending dismiss rejected in {repo}: {b}");

        // Merge needs write+: read and triage get 403, strangers 404/403,
        // and a writer passes the permission check (gates decide 200/422).
        let want_deny = if repo == "proj" { 404 } else { 403 };
        for (handle, want) in [("carol", 403), ("bob", 403), ("dave", want_deny)] {
            let (s, _) = api_status(
                &client,
                "POST",
                &c.api(repo, &format!("/trails/{n}/changes/1/merge")),
                Some(&tok(handle)),
                Some(json!({"method": "merge"})),
            )
            .await;
            assert_eq!(s.as_u16(), want, "{handle} merge in {repo}");
        }
        let (s, b) = api_status(
            &client,
            "POST",
            &c.api(repo, &format!("/trails/{n}/changes/1/merge")),
            Some(&tok("wendy")),
            Some(json!({"method": "merge"})),
        )
        .await;
        assert!(
            s.as_u16() != 403 && s.as_u16() != 404,
            "wendy passes merge permission in {repo}: {b}"
        );
        // Above-threshold roles pass every mutation threshold on every
        // visibility: maintain, admin, owner, and the site admin link,
        // unlink, and merge without 403/404 (gates decide merge 200/422).
        for handle in ["mia", "adam", "alice", "root"] {
            let (s, b) = api_status(
                &client,
                "POST",
                &c.api(repo, &format!("/trails/{n}/sessions")),
                Some(&tok(handle)),
                Some(json!({"session": ULID_EXTRA})),
            )
            .await;
            assert_eq!(s.as_u16(), 200, "{handle} link in {repo}: {b}");
            let (s, b) = api_status(
                &client,
                "DELETE",
                &c.api(repo, &format!("/trails/{n}/sessions/{ULID_EXTRA}")),
                Some(&tok(handle)),
                None,
            )
            .await;
            assert_eq!(s.as_u16(), 200, "{handle} unlink in {repo}: {b}");
            let (s, b) = api_status(
                &client,
                "POST",
                &c.api(repo, &format!("/trails/{n}/changes/1/merge")),
                Some(&tok(handle)),
                Some(json!({"method": "merge"})),
            )
            .await;
            assert!(
                s.as_u16() != 403 && s.as_u16() != 404,
                "{handle} passes merge permission in {repo}: {b}"
            );
        }
    }
}

/// Inter-revision diff errors on the API: unknown revisions 404,
/// `from == to` 422, non-readers 404.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_api_inter_revision_diff() {
    let c = Ctx::start().await;
    let client = reqwest::Client::new();
    let setup = setup_repo(&c, "proj").await;
    push_second_commit(&c, "proj", setup.change_id).await;
    let n = setup.n;
    let alice = c.tok(&c.alice).await;
    let dave = c.tok(&c.dave).await;
    let (s, b) = api_status(
        &client,
        "GET",
        &c.api("proj", &format!("/trails/{n}/changes/1/diff?from=1&to=2")),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(s.as_u16(), 200, "from/to diff: {b}");
    let (s, b) = api_status(
        &client,
        "GET",
        &c.api("proj", &format!("/trails/{n}/changes/1/diff?from=2&to=2")),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(s.as_u16(), 422, "from == to: {b}");
    let (s, b) = api_status(
        &client,
        "GET",
        &c.api("proj", &format!("/trails/{n}/changes/1/diff?from=1&to=9")),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(s.as_u16(), 404, "unknown to: {b}");
    let (s, b) = api_status(
        &client,
        "GET",
        &c.api("proj", &format!("/trails/{n}/changes/1/diff?from=1&to=2")),
        Some(&dave),
        None,
    )
    .await;
    assert_eq!(s.as_u16(), 404, "stranger diff: {b}");
}

/// Permission matrix over the new web routes and forms: tab pages, the
/// changes list, the inter-revision view, the viewed toggle, the pending
/// discard form, and the gate-panel merge form.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_web() {
    let c = Ctx::start().await;
    for repo in ["proj", "innie", "open"] {
        setup_repo(&c, repo).await;
    }
    // Revision 2 on proj only, for the inter-revision view.
    let proj_change = starforged_db::changes::open_branch_changes(
        c.s.core.db(),
        c.repo_id("proj").await,
        "feature/x",
    )
    .await
    .unwrap()
    .into_iter()
    .next()
    .unwrap()
    .id;
    push_second_commit(&c, "proj", proj_change).await;

    let anon = c.s.browser();
    let mut browsers: Vec<(String, reqwest::Client, String)> = Vec::new();
    for user in [
        &c.alice, &c.bob, &c.carol, &c.wendy, &c.mia, &c.adam, &c.root, &c.dave,
    ] {
        let (client, csrf) = c.s.login(&user.handle).await;
        browsers.push((user.handle.clone(), client, csrf));
    }
    let browser = |h: &str| browsers.iter().find(|(x, _, _)| x == h).unwrap().1.clone();
    // The session CSRF from sign-in works on every form; the detail page
    // itself 404s for non-readers, so it cannot supply the token.
    let token = |h: &str| browsers.iter().find(|(x, _, _)| x == h).unwrap().2.clone();

    for repo in ["proj", "innie", "open"] {
        let sessions = c.web(repo, "/trails/1/sessions");
        let changes = c.web(repo, "/trails/1/changes");
        let stranger_reads = repo != "proj";
        // Tab pages and the changes list: strangers 404 on private, read
        // elsewhere; members read everywhere.
        for url in [&sessions, &changes] {
            assert_eq!(
                web_status(&browser("dave"), "GET", url).await,
                if stranger_reads { 200 } else { 404 },
                "dave GET {url}"
            );
            assert_eq!(
                web_status(&browser("carol"), "GET", url).await,
                200,
                "carol GET {url}"
            );
            assert_eq!(
                web_status(&anon, "GET", url).await,
                if repo == "open" { 200 } else { 404 },
                "anon GET {url}"
            );
        }
        // The merge form posts to the change merge route: writers see it,
        // readers do not.
        let detail = c.web(repo, "/trails/1/changes/1");
        let wendy_page = get_text(&browser("wendy"), &detail).await;
        assert!(
            wendy_page.contains("/changes/1/merge"),
            "writer sees merge form in {repo}"
        );
        let carol_page = get_text(&browser("carol"), &detail).await;
        assert!(
            !carol_page.contains("/changes/1/merge"),
            "reader sees no merge form in {repo}"
        );
        // Viewed toggles render for signed-in readers (dave counts on
        // internal/public) and never for anonymous viewers.
        assert!(
            carol_page.contains("name=\"viewed\""),
            "reader sees viewed toggles in {repo}"
        );
        if stranger_reads {
            let dave_page = get_text(&browser("dave"), &detail).await;
            assert!(
                dave_page.contains("name=\"viewed\""),
                "stranger-reader sees viewed toggles in {repo}"
            );
        }
        let anon_page = {
            let res = anon.get(&detail).send().await.unwrap();
            assert_eq!(
                res.status().as_u16(),
                if repo == "open" { 200 } else { 404 },
                "anon GET detail in {repo}"
            );
            res.text().await.unwrap()
        };
        if repo == "open" {
            assert!(
                !anon_page.contains("name=\"viewed\""),
                "anonymous sees no toggles"
            );
            assert!(
                !anon_page.contains("name=\"_csrf\""),
                "anonymous detail carries no forms"
            );
        }
        // Viewed toggle: readers mark (303), strangers 404 on private and
        // mark elsewhere, anonymous is bounced to sign-in.
        let viewed = c.web(repo, "/trails/1/changes/1/viewed");
        let t = token("carol");
        let res = browser("carol")
            .post(&viewed)
            .form(&[("_csrf", t.as_str()), ("path", "a.txt"), ("viewed", "1")])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 303, "carol marks viewed");
        let t = token("dave");
        let res = browser("dave")
            .post(&viewed)
            .form(&[("_csrf", t.as_str()), ("path", "a.txt"), ("viewed", "1")])
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status().as_u16(),
            if stranger_reads { 303 } else { 404 },
            "dave marks viewed in {repo}"
        );
        let res = anon
            .post(&viewed)
            .form(&[("path", "a.txt"), ("viewed", "1")])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 303, "anon bounced in {repo}");

        // Link/unlink: triage posts (303), read gets 403, strangers 404 on
        // private (repo invisible) and public (unpublished sessions hide
        // from non-members), 403 on internal (implicit read reaches the
        // permission check). Write outranks triage, so writers pass.
        let link = c.web(repo, "/trails/1/sessions");
        let unlink = c.web(repo, &format!("/trails/1/sessions/{ULID_HAND}/unlink"));
        let want_dave = if repo == "innie" { 403 } else { 404 };
        for (handle, want) in [("carol", 403), ("dave", want_dave)] {
            let t = token(handle);
            let res = browser(handle)
                .post(&link)
                .form(&[("_csrf", t.as_str()), ("session", ULID_EXTRA)])
                .send()
                .await
                .unwrap();
            assert_eq!(res.status().as_u16(), want, "{handle} web link in {repo}");
            let t = token(handle);
            let res = browser(handle)
                .post(&unlink)
                .form(&[("_csrf", t.as_str())])
                .send()
                .await
                .unwrap();
            assert_eq!(res.status().as_u16(), want, "{handle} web unlink in {repo}");
        }
        let t = token("bob");
        let res = browser("bob")
            .post(&link)
            .form(&[("_csrf", t.as_str()), ("session", ULID_EXTRA)])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 303, "bob web link in {repo}");
        // A writer passes the triage threshold too.
        let t = token("wendy");
        let res = browser("wendy")
            .post(&unlink)
            .form(&[("_csrf", t.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 303, "wendy web unlink in {repo}");

        // Discard with no draft is 404 for readers; strangers 404 on
        // private without revealing the change.
        let discard = c.web(repo, "/trails/1/changes/1/reviews/pending");
        for (handle, want) in [("bob", 404), ("dave", 404)] {
            let t = token(handle);
            let res = browser(handle)
                .post(&discard)
                .form(&[("_csrf", t.as_str())])
                .send()
                .await
                .unwrap();
            assert_eq!(
                res.status().as_u16(),
                want,
                "{handle} web discard in {repo}"
            );
        }

        // Merge form: read and triage get 403, writers pass permission
        // (gates decide 303/422), strangers 404 on private and 403
        // elsewhere, anonymous is bounced to sign-in.
        let merge = c.web(repo, "/trails/1/changes/1/merge");
        for (handle, want) in [("carol", 403), ("bob", 403)] {
            let t = token(handle);
            let res = browser(handle)
                .post(&merge)
                .form(&[("_csrf", t.as_str()), ("method", "merge")])
                .send()
                .await
                .unwrap();
            assert_eq!(res.status().as_u16(), want, "{handle} web merge in {repo}");
        }
        let t = token("dave");
        let res = browser("dave")
            .post(&merge)
            .form(&[("_csrf", t.as_str()), ("method", "merge")])
            .send()
            .await
            .unwrap();
        assert_eq!(
            res.status().as_u16(),
            if stranger_reads { 403 } else { 404 },
            "dave web merge in {repo}"
        );
        let t = token("wendy");
        let res = browser("wendy")
            .post(&merge)
            .form(&[("_csrf", t.as_str()), ("method", "merge")])
            .send()
            .await
            .unwrap();
        assert!(
            res.status().as_u16() != 403 && res.status().as_u16() != 404,
            "wendy passes merge permission in {repo}: {}",
            res.status()
        );
        let res = anon
            .post(&merge)
            .form(&[("method", "merge")])
            .send()
            .await
            .unwrap();
        assert_eq!(res.status().as_u16(), 303, "anon bounced at merge");
        // Above-threshold roles pass every web threshold too: maintain,
        // admin, owner, and the site admin link, unlink, and post the
        // merge form without 403/404 on every visibility.
        for handle in ["mia", "adam", "alice", "root"] {
            let t = token(handle);
            let res = browser(handle)
                .post(&link)
                .form(&[("_csrf", t.as_str()), ("session", ULID_EXTRA)])
                .send()
                .await
                .unwrap();
            assert_eq!(res.status().as_u16(), 303, "{handle} web link in {repo}");
            let t = token(handle);
            let res = browser(handle)
                .post(&unlink)
                .form(&[("_csrf", t.as_str())])
                .send()
                .await
                .unwrap();
            assert_eq!(res.status().as_u16(), 303, "{handle} web unlink in {repo}");
            let t = token(handle);
            let res = browser(handle)
                .post(&merge)
                .form(&[("_csrf", t.as_str()), ("method", "merge")])
                .send()
                .await
                .unwrap();
            assert!(
                res.status().as_u16() != 403 && res.status().as_u16() != 404,
                "{handle} passes web merge permission in {repo}: {}",
                res.status()
            );
        }
    }

    // Inter-revision view on proj: the pair renders, `from == to` is 422,
    // unknown revisions are 404.
    let carol = browser("carol");
    let page = get_text(&carol, &c.web("proj", "/trails/1/changes/1?from=1&to=2")).await;
    assert!(
        page.contains("b.txt"),
        "inter-revision diff shows rev 2 file:\n{page}"
    );
    assert_eq!(
        web_status(
            &carol,
            "GET",
            &c.web("proj", "/trails/1/changes/1?from=2&to=2")
        )
        .await,
        422,
        "web from == to"
    );
    assert_eq!(
        web_status(
            &carol,
            "GET",
            &c.web("proj", "/trails/1/changes/1?from=1&to=9")
        )
        .await,
        404,
        "web unknown to"
    );
    assert_eq!(
        web_status(
            &browser("dave"),
            "GET",
            &c.web("proj", "/trails/1/changes/1?from=1&to=2")
        )
        .await,
        404,
        "stranger inter-revision view"
    );
}

/// Archived repos refuse every new mutation (422) while reads keep working,
/// on both the API and the web.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn matrix_archived() {
    let c = Ctx::start().await;
    let setup = setup_repo(&c, "proj").await;
    let n = setup.n;
    let client = reqwest::Client::new();
    let alice = c.tok(&c.alice).await;
    // A public thread predates the archive, so comment refusal is pinnable.
    let carol_tok =
        c.s.token(&c.carol, &[Scope::RepoRead, Scope::TrailWrite])
            .await;
    let (s, b) = api_status(
        &client,
        "POST",
        &c.api("proj", &format!("/trails/{n}/changes/1/threads")),
        Some(&carol_tok),
        Some(json!({
            "path": "a.txt", "side": "head",
            "start_line": 1, "end_line": 1, "body": "pre-archive",
        })),
    )
    .await;
    assert_eq!(s.as_u16(), 201, "pre-archive thread: {b}");
    let pre_tid = b["id"].as_i64().unwrap();
    c.s.core
        .archive_repo(&c.alice, "alice", "proj")
        .await
        .unwrap();

    // Reads keep working.
    let (s, b) = api_status(
        &client,
        "GET",
        &c.api("proj", &format!("/trails/{n}/sessions")),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(s.as_u16(), 200, "archived sessions GET: {b}");
    let (alice_browser, _) = c.s.login("alice").await;
    let page = get_text(&alice_browser, &c.web("proj", "/trails/1/sessions")).await;
    assert!(page.contains("sweep trail"), "archived tab reads:\n{page}");

    // Every mutation refuses with 422 on the API…
    for (method, url, body) in [
        (
            "POST",
            c.api("proj", &format!("/trails/{n}/sessions")),
            Some(json!({"session": ULID_EXTRA})),
        ),
        (
            "DELETE",
            c.api("proj", &format!("/trails/{n}/sessions/{ULID_HAND}")),
            None,
        ),
        (
            "POST",
            c.api("proj", &format!("/trails/{n}/changes/1/threads")),
            Some(json!({
                "path": "a.txt", "side": "head",
                "start_line": 1, "end_line": 1, "body": "x",
            })),
        ),
        (
            "POST",
            c.api("proj", &format!("/trails/{n}/changes/1/merge")),
            Some(json!({"method": "merge"})),
        ),
    ] {
        let (s, b) = api_status(&client, method, &url, Some(&alice), body).await;
        assert_eq!(s.as_u16(), 422, "{method} {url} archived: {b}");
        assert!(b.to_string().contains("archived"), "archived message: {b}");
    }

    // …and on the web (422 re-renders of the owning tab).
    let detail = c.web("proj", "/trails/1/changes/1");
    let token = extract_input(&get_text(&alice_browser, &detail).await, "_csrf");
    for (url, form) in [
        (
            c.web("proj", "/trails/1/sessions"),
            vec![("_csrf", token.as_str()), ("session", ULID_EXTRA)],
        ),
        (
            c.web("proj", "/trails/1/changes/1/viewed"),
            vec![
                ("_csrf", token.as_str()),
                ("path", "a.txt"),
                ("viewed", "1"),
            ],
        ),
        (
            c.web("proj", "/trails/1/changes/1/merge"),
            vec![("_csrf", token.as_str()), ("method", "merge")],
        ),
    ] {
        let res = alice_browser.post(&url).form(&form).send().await.unwrap();
        assert_eq!(res.status().as_u16(), 422, "web archived {url}");
    }
    let res = alice_browser
        .post(c.web("proj", "/trails/1/changes/1/threads"))
        .form(&[
            ("_csrf", token.as_str()),
            ("path", "a.txt"),
            ("side", "head"),
            ("start", "1"),
            ("end", "1"),
            ("body", "x"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status().as_u16(), 422, "web archived thread");
    // The pending family and the unlink form refuse too, with state
    // unchanged: the hand link stays, and no thread, comment, or review
    // row appears.
    let threads_before = starforged_db::changes::threads_of_change(c.s.core.db(), setup.change_id)
        .await
        .unwrap()
        .len();
    let comments_before = starforged_db::changes::comments_of_thread(c.s.core.db(), pre_tid)
        .await
        .unwrap()
        .len();
    let reviews_before = starforged_db::changes::reviews_of_change(c.s.core.db(), setup.change_id)
        .await
        .unwrap()
        .len();
    for (url, form) in [
        (
            c.web("proj", &format!("/trails/1/sessions/{ULID_HAND}/unlink")),
            vec![("_csrf", token.as_str())],
        ),
        (
            c.web("proj", "/trails/1/changes/1/threads"),
            vec![
                ("_csrf", token.as_str()),
                ("path", "a.txt"),
                ("side", "head"),
                ("start", "1"),
                ("end", "1"),
                ("body", "draft"),
                ("pending", "true"),
            ],
        ),
        (
            c.web(
                "proj",
                &format!("/trails/1/changes/1/threads/{pre_tid}/comments"),
            ),
            vec![
                ("_csrf", token.as_str()),
                ("body", "late comment"),
                ("pending", "true"),
            ],
        ),
        (
            c.web("proj", "/trails/1/changes/1/reviews"),
            vec![
                ("_csrf", token.as_str()),
                ("verdict", "approve"),
                ("body", "late review"),
            ],
        ),
        (
            c.web("proj", "/trails/1/changes/1/reviews/pending"),
            vec![("_csrf", token.as_str())],
        ),
    ] {
        let res = alice_browser.post(&url).form(&form).send().await.unwrap();
        assert_eq!(res.status().as_u16(), 422, "web archived {url}");
    }
    let (s, b) = api_status(
        &client,
        "GET",
        &c.api("proj", &format!("/trails/{n}/sessions")),
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(s.as_u16(), 200, "{b}");
    assert!(
        b["linked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["ulid"] == ULID_HAND),
        "hand link survives: {b}"
    );
    assert_eq!(
        starforged_db::changes::threads_of_change(c.s.core.db(), setup.change_id)
            .await
            .unwrap()
            .len(),
        threads_before,
        "no thread rows"
    );
    assert_eq!(
        starforged_db::changes::comments_of_thread(c.s.core.db(), pre_tid)
            .await
            .unwrap()
            .len(),
        comments_before,
        "no comment rows"
    );
    assert_eq!(
        starforged_db::changes::reviews_of_change(c.s.core.db(), setup.change_id)
            .await
            .unwrap()
            .len(),
        reviews_before,
        "no review rows"
    );
}

/// §6.4 over every Trail-page session surface: quarantined, unpublished on
/// a public repo, and published sessions × Sessions tab, Sessions API,
/// `has_sessions`, timeline rows, and the commit panel. No unreadable
/// session's title, ULID, or totals reach a viewer who cannot read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn section_64_all_surfaces() {
    let c = Ctx::start().await;
    // Dave is a repo writer (member, non-admin) on the public repo.
    c.s.core
        .set_collaborator(&c.alice, "alice", "open", "dave", Permission::Write)
        .await
        .unwrap();
    let setup = setup_repo(&c, "open").await;
    let n = setup.n;
    let head = setup.head.clone();
    // Dave uploads a session of his own; alice hand-links it.
    let dave_upload = c.s.token(&c.dave, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let put = client
        .put(c.api("open", &format!("/sessions/{ULID_DAVE}")))
        .bearer_auth(&dave_upload)
        .json(&meta_body(ULID_DAVE, "dave session seven"))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "dave upload: {}", put.status());
    c.s.core
        .link_trail_session(&c.alice, "alice", "open", n, ULID_DAVE)
        .await
        .unwrap();

    let repo_id = c.repo_id("open").await;
    let alice = c.tok(&c.alice).await;
    let dave = c.tok(&c.dave).await;
    async fn sessions_body(
        client: &reqwest::Client,
        c: &Ctx,
        token: Option<&str>,
        n: i64,
    ) -> (reqwest::StatusCode, Value) {
        let mut req = client.get(c.api("open", &format!("/trails/{n}/sessions")));
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let res = req.send().await.unwrap();
        let status = res.status();
        let body = res.json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }
    async fn listed(client: &reqwest::Client, c: &Ctx, token: Option<&str>, q: &str) -> Vec<i64> {
        let mut req = client.get(c.api("open", &format!("/trails{q}")));
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let res = req.send().await.unwrap();
        assert_eq!(res.status(), 200, "{q}");
        res.json::<Value>().await.unwrap()["trails"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["number"].as_i64().unwrap())
            .collect()
    }
    // Unpublished: invisible to anonymous and stranger members on every
    // surface; `has_sessions` follows the same predicate in SQL.
    let (s, b) = sessions_body(&client, &c, None, n).await;
    assert_eq!(s.as_u16(), 200, "anon API reads on open: {b}");
    assert_eq!(
        b["commits"],
        json!([]),
        "anon sees nothing unpublished: {b}"
    );
    let anon_web = c.s.browser();
    let tab = get_text(&anon_web, &c.web("open", &format!("/trails/{n}/sessions"))).await;
    for leak in [
        ULID_COMMIT,
        ULID_HAND,
        ULID_DAVE,
        ULID_EXTRA,
        "commit session seven",
        "hand session seven",
        "dave session seven",
        "spare session seven",
    ] {
        assert!(!tab.contains(leak), "anon tab leaks {leak}");
    }
    let trail_page = get_text(&anon_web, &c.web("open", &format!("/trails/{n}"))).await;
    for leak in [ULID_COMMIT, ULID_HAND, ULID_DAVE] {
        assert!(!trail_page.contains(leak), "anon timeline leaks {leak}");
    }
    let commit_page = get_text(&anon_web, &c.web("open", &format!("/commit/{head}"))).await;
    for leak in [ULID_COMMIT, "commit session seven"] {
        assert!(
            !commit_page.contains(leak),
            "anon commit panel leaks {leak}"
        );
    }
    assert_eq!(
        listed(&client, &c, None, "?has_sessions=true").await,
        Vec::<i64>::new(),
        "anon has_sessions"
    );
    // A writer member reads everything while unpublished.
    let (s, b) = sessions_body(&client, &c, Some(&dave), n).await;
    assert_eq!(s.as_u16(), 200, "{b}");
    assert_eq!(
        b["commits"][0]["sessions"][0]["ulid"],
        json!(ULID_COMMIT),
        "{b}"
    );
    assert_eq!(
        listed(&client, &c, Some(&dave), "?has_sessions=true").await,
        vec![n]
    );

    // Quarantined: only the uploader and repo admins. Dave uploaded
    // ULID_DAVE, so he keeps that one and loses the other two.
    for ulid in [ULID_COMMIT, ULID_HAND, ULID_DAVE] {
        starforged_db::sessions::set_quarantine(
            c.s.core.db(),
            session_id(&c.s, repo_id, ulid).await,
            "quarantined",
            "probe",
            "",
        )
        .await
        .unwrap();
    }
    let (s, b) = sessions_body(&client, &c, Some(&dave), n).await;
    assert_eq!(s.as_u16(), 200, "{b}");
    let raw = b.to_string();
    assert!(
        !raw.contains(ULID_COMMIT),
        "dave sees quarantined commit link: {b}"
    );
    assert!(
        !raw.contains(ULID_HAND),
        "dave sees quarantined hand link: {b}"
    );
    assert!(
        raw.contains(ULID_DAVE),
        "uploader keeps own quarantined session: {b}"
    );
    assert!(
        !raw.contains("commit session seven") && !raw.contains("hand session seven"),
        "quarantined titles hidden but uploader title shown: {b}"
    );
    assert_eq!(
        listed(&client, &c, Some(&dave), "?has_sessions=true").await,
        vec![n],
        "uploader still links the trail"
    );
    let (s, b) = sessions_body(&client, &c, Some(&alice), n).await;
    assert_eq!(s.as_u16(), 200, "{b}");
    assert!(
        b.to_string().contains(ULID_COMMIT),
        "owner reads quarantined: {b}"
    );
    let bob = c.tok(&c.bob).await;
    let (s, b) = sessions_body(&client, &c, Some(&bob), n).await;
    assert_eq!(s.as_u16(), 200, "{b}");
    assert_eq!(
        b["commits"],
        json!([]),
        "triage non-admin sees nothing: {b}"
    );
    assert_eq!(
        b["totals"]["total"],
        json!(0),
        "no totals leak to non-readers: {b}"
    );
    assert_eq!(
        listed(&client, &c, Some(&bob), "?has_sessions=true").await,
        Vec::<i64>::new()
    );
    let bob_web = {
        let (client, _) = c.s.login("bob").await;
        client
    };
    let tab = get_text(&bob_web, &c.web("open", &format!("/trails/{n}/sessions"))).await;
    for leak in [ULID_COMMIT, ULID_HAND, ULID_DAVE, "commit session seven"] {
        assert!(!tab.contains(leak), "triage tab leaks {leak}");
    }
    // The timeline rows and the commit panel obey quarantine too: neither
    // the stranger-reader nor anonymous viewers see titles or ULIDs there.
    for (viewer, page) in [(&bob_web, "triage"), (&anon_web, "anon")] {
        let trail_page = get_text(viewer, &c.web("open", &format!("/trails/{n}"))).await;
        for leak in [ULID_COMMIT, ULID_HAND, ULID_DAVE, "commit session seven"] {
            assert!(!trail_page.contains(leak), "{page} timeline leaks {leak}");
        }
        let commit_page = get_text(viewer, &c.web("open", &format!("/commit/{head}"))).await;
        for leak in [ULID_COMMIT, "commit session seven"] {
            assert!(
                !commit_page.contains(leak),
                "{page} commit panel leaks {leak}"
            );
        }
    }

    // Published: anonymous readers see every linked surface.
    for ulid in [ULID_COMMIT, ULID_HAND, ULID_DAVE] {
        let id = session_id(&c.s, repo_id, ulid).await;
        starforged_db::sessions::set_quarantine(c.s.core.db(), id, "none", "", "")
            .await
            .unwrap();
        starforged_db::sessions::set_visibility(c.s.core.db(), id, "published")
            .await
            .unwrap();
    }
    let (s, b) = sessions_body(&client, &c, Some(&dave), n).await;
    assert_eq!(s.as_u16(), 200, "{b}");
    assert!(
        b.to_string().contains(ULID_COMMIT) && b.to_string().contains(ULID_DAVE),
        "published: {b}"
    );
    assert!(
        b["totals"]["total"].as_i64().unwrap() > 0,
        "published totals: {b}"
    );
    let tab = get_text(&anon_web, &c.web("open", &format!("/trails/{n}/sessions"))).await;
    assert!(tab.contains(ULID_COMMIT), "anon tab after publish");
    assert_eq!(
        listed(&client, &c, None, "?has_sessions=true").await,
        vec![n]
    );
    let trail_page = get_text(&anon_web, &c.web("open", &format!("/trails/{n}"))).await;
    assert!(
        trail_page.contains(ULID_COMMIT),
        "anon timeline after publish"
    );
    let commit_page = get_text(&anon_web, &c.web("open", &format!("/commit/{head}"))).await;
    assert!(
        commit_page.contains(ULID_COMMIT),
        "anon commit panel after publish"
    );
}

/// Hostile-input corpus through every newly rendered M2f field. Each vector
/// asserts raw-absent plus escaped-present (proving it rendered) — except
/// pending comment bodies, which render as sanitized Markdown, so the
/// sanitizer strips hostile markup instead of escaping it and raw-absent
/// (plus draft visibility) is the pin — plus the live-markup and
/// live-handler scans on every page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xss_corpus() {
    let c = Ctx::start().await;
    let setup = setup_repo(&c, "proj").await;
    let n = setup.n;
    let payload_title = "<script>alert(1)</script>";
    let payload_comment = "\"><script>alert(4)</script>";

    // Hostile session titles render escaped on the Sessions tab and the
    // commit panel.
    let upload = c.s.token(&c.alice, &[Scope::SessionUpload]).await;
    let client = reqwest::Client::new();
    let xss_ulid = "01ARZ3NDEKTSV4RRFFQ69G5FB9";
    let put = client
        .put(c.api("proj", &format!("/sessions/{xss_ulid}")))
        .bearer_auth(&upload)
        .json(&meta_body(xss_ulid, payload_title))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "xss upload: {}", put.status());
    let claim = client
        .post(c.api("proj", &format!("/sessions/{xss_ulid}/links")))
        .bearer_auth(&upload)
        .json(&json!({"links": [{"sha": setup.head, "confidence": "exact"}]}))
        .send()
        .await
        .unwrap();
    assert!(claim.status().is_success(), "xss claim: {}", claim.status());
    // Full corpus through session titles: each payload uploads, claims the
    // head commit, and must render inert on the Sessions tab.
    for (i, payload) in PAYLOADS.iter().enumerate() {
        let ulid = format!("01ARZ3NDEKTSV4RRFFQ69G5FC{i}");
        let put = client
            .put(c.api("proj", &format!("/sessions/{ulid}")))
            .bearer_auth(&upload)
            .json(&meta_body(&ulid, payload))
            .send()
            .await
            .unwrap();
        assert!(put.status().is_success(), "corpus upload {i}");
        let link = client
            .post(c.api("proj", &format!("/sessions/{ulid}/links")))
            .bearer_auth(&upload)
            .json(&json!({"links": [{"sha": setup.head, "confidence": "exact"}]}))
            .send()
            .await
            .unwrap();
        assert!(link.status().is_success(), "corpus claim {i}");
    }

    // Hostile commit subjects: one push carrying the whole corpus as commit
    // subjects; one session is claimed to each new SHA so every subject's
    // group renders on the Sessions tab.
    let full = c.tok(&c.alice).await;
    let url = c.s.git_url("alice", "proj", Some(&full));
    let tmp = tempfile::tempdir().unwrap();
    let seed = work_repo(tmp.path(), "seed", &[("x.txt", "x\n")]).await;
    git_ok(&seed, &["fetch", "-q", &url, "feature/x:feature/x"]).await;
    git_ok(&seed, &["checkout", "-q", "feature/x"]).await;
    let mut subject_shas = Vec::new();
    for (i, payload) in PAYLOADS.iter().enumerate() {
        let name = format!("evil{i}.txt");
        commit_files(&seed, &[(name.as_str(), b"evil\n".as_slice())], payload).await;
        subject_shas.push(
            git_ok(&seed, &["rev-parse", "HEAD"])
                .await
                .trim()
                .to_owned(),
        );
    }
    git_ok(&seed, &["push", "-q", &url, "feature/x"]).await;
    wait_for_revisions(&c.s, setup.change_id).await;
    for (i, sha) in subject_shas.iter().enumerate() {
        let ulid = format!("01ARZ3NDEKTSV4RRFFQ69G5FC{i}");
        let link = client
            .post(c.api("proj", &format!("/sessions/{ulid}/links")))
            .bearer_auth(&upload)
            .json(&json!({"links": [{"sha": sha, "confidence": "exact"}]}))
            .send()
            .await
            .unwrap();
        assert!(link.status().is_success(), "subject claim {i}");
    }

    // Hostile file paths: committed on a second trail's change.
    let n2 =
        c.s.core
            .create_trail(&c.alice, "alice", "proj", "path trail", "intent")
            .await
            .unwrap()
            .number;
    let tmp2 = tempfile::tempdir().unwrap();
    let work2 = work_repo(tmp2.path(), "w2", &[("README.md", "# hi\n")]).await;
    git_ok(&work2, &["fetch", "-q", &url, "main"]).await;
    git_ok(
        &work2,
        &["checkout", "-q", "-b", "feature/evil", "FETCH_HEAD"],
    )
    .await;
    let path_names: Vec<String> = PAYLOADS
        .iter()
        .enumerate()
        .map(|(i, p)| format!("{p}-{i}.txt"))
        .collect();
    let path_refs: Vec<(&str, &[u8])> = path_names
        .iter()
        .map(|n| (n.as_str(), b"hostile\n".as_slice()))
        .collect();
    commit_files(&work2, &path_refs, "hostile paths").await;
    git_ok(&work2, &["push", "-q", &url, "feature/evil"]).await;
    c.s.core
        .create_branch_change(&c.alice, "alice", "proj", n2, "feature/evil", "main")
        .await
        .unwrap();

    // Hostile check context/description through the API (full corpus, one
    // status each), plus a `javascript:` target with a distinct marker below
    // Core validation (which rightly rejects it).
    let head2 = subject_shas.last().unwrap().clone();
    for (i, payload) in PAYLOADS.iter().enumerate() {
        c.s.core
            .submit_status(
                &c.alice,
                "alice",
                "proj",
                &head2,
                "failure",
                &format!("ctx-{i} {payload}"),
                Some("https://ci.example.com/evil"),
                Some(payload),
            )
            .await
            .unwrap();
    }
    let repo_id = c.repo_id("proj").await;
    db_checks::insert_check(
        c.s.core.db(),
        repo_id,
        &head2,
        "xss-link-marker",
        "failure",
        Some("javascript:alert(9)//marker-zq7"),
        Some("hostile"),
        Some(c.alice.id),
        starforged_db::now(),
    )
    .await
    .unwrap();

    // Hostile pending comment body, visible to its author only.
    let carol_tok = c.tok(&c.carol).await;
    let (s, b) = api_status(
        &client,
        "POST",
        &c.api("proj", &format!("/trails/{n}/changes/1/threads")),
        Some(&carol_tok),
        Some(json!({
            "path": "a.txt", "side": "head",
            "start_line": 1, "end_line": 1,
            "body": payload_comment, "pending": true,
        })),
    )
    .await;
    assert_eq!(s.as_u16(), 201, "pending xss thread: {b}");

    let (alice_browser, _) = c.s.login("alice").await;
    let (carol_browser, _) = c.s.login("carol").await;
    let (bob_browser, _) = c.s.login("bob").await;

    let tab = get_text(
        &alice_browser,
        &c.web("proj", &format!("/trails/{n}/sessions")),
    )
    .await;
    assert_payload_escaped(&tab, payload_title, "sessions tab title");
    for payload in PAYLOADS {
        assert_corpus_inert(&tab, payload, "sessions tab corpus");
    }
    assert_no_live_markup(&tab, "sessions tab");

    let commit = get_text(
        &alice_browser,
        &c.web("proj", &format!("/commit/{}", setup.head)),
    )
    .await;
    assert_payload_escaped(&commit, payload_title, "commit panel title");
    assert_no_live_markup(&commit, "commit panel");

    let change = get_text(
        &alice_browser,
        &c.web("proj", &format!("/trails/{n2}/changes/1")),
    )
    .await;
    // File paths go through git diff headers, which C-quote pathnames
    // containing `"` (plus the diff's `b/` prefix, absorbed by substring
    // matching): pin raw-absent plus whichever escaped form renders.
    for payload in PAYLOADS {
        let plain = escape_html(payload);
        let quoted = escape_html(&payload.replace('"', "\\\""));
        assert!(
            !change.contains(payload) || plain == *payload,
            "raw path renders: {payload:?}"
        );
        assert!(
            change.contains(&plain) || change.contains(&quoted),
            "escaped path missing: {payload:?}"
        );
    }
    assert_no_live_markup(&change, "change page");

    let trail_page = get_text(&alice_browser, &c.web("proj", &format!("/trails/{n}"))).await;
    for (i, payload) in PAYLOADS.iter().enumerate() {
        let ctx = format!("ctx-{i} {payload}");
        assert_corpus_inert(&trail_page, &ctx, "timeline check context");
        assert_corpus_inert(&trail_page, payload, "timeline check description");
    }
    // The `javascript:` target carries a distinct marker and never becomes
    // a link — the marker is absent raw (the substring itself also appears
    // inside escaped corpus session titles, so the link form is pinned too).
    assert!(
        !trail_page.contains("marker-zq7"),
        "javascript URL leaked:\n{trail_page}"
    );
    assert!(
        !trail_page.contains("href=\"javascript:"),
        "javascript URL linked:\n{trail_page}"
    );
    assert!(
        trail_page.contains("href=\"https://ci.example.com/evil\""),
        "https target links:\n{trail_page}"
    );
    assert_no_live_markup(&trail_page, "trail timeline");

    // Pending comment bodies render as sanitized Markdown for the author —
    // the sanitizer strips the hostile element rather than escaping it —
    // and stay absent for everyone else.
    let mine = get_text(
        &carol_browser,
        &c.web("proj", &format!("/trails/{n}/changes/1")),
    )
    .await;
    assert!(
        !mine.contains(payload_comment),
        "raw pending comment renders:\n{mine}"
    );
    assert!(
        mine.contains("Finish your review"),
        "draft still visible to author:\n{mine}"
    );
    assert_no_live_markup(&mine, "change page with draft");
    let others = get_text(
        &bob_browser,
        &c.web("proj", &format!("/trails/{n}/changes/1")),
    )
    .await;
    assert!(
        !others.contains(payload_comment) && !others.contains(&escape_html(payload_comment)),
        "foreign draft leaks:\n{others}"
    );
    assert_no_live_markup(&others, "change page without draft");
}

/// Every new form refuses forged (and foreign) CSRF tokens with 403, and
/// the state is unchanged afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn csrf_matrix() {
    let c = Ctx::start().await;
    let setup = setup_repo(&c, "proj").await;
    let n = setup.n;
    let client = reqwest::Client::new();
    let alice_tok = c.tok(&c.alice).await;
    let (alice, _) = c.s.login("alice").await;
    let (carol, _) = c.s.login("carol").await;
    let detail = c.web("proj", "/trails/1/changes/1");
    let carol_csrf = extract_input(&get_text(&carol, &detail).await, "_csrf");
    async fn forged(client: &reqwest::Client, url: &str, form: &[(&str, &str)]) -> u16 {
        client
            .post(url)
            .form(form)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    // Sessions link/unlink: 403, and the link set is unchanged.
    let link = c.web("proj", "/trails/1/sessions");
    let unlink = c.web("proj", &format!("/trails/1/sessions/{ULID_HAND}/unlink"));
    let linked_before = api_status(
        &client,
        "GET",
        &c.api("proj", &format!("/trails/{n}/sessions")),
        Some(&alice_tok),
        None,
    )
    .await
    .1["linked"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(
        forged(
            &alice,
            &link,
            &[("_csrf", "bogus"), ("session", ULID_EXTRA)]
        )
        .await,
        403,
        "forged link"
    );
    assert_eq!(
        forged(&alice, &unlink, &[("_csrf", carol_csrf.as_str())]).await,
        403,
        "foreign unlink"
    );
    let linked_after = api_status(
        &client,
        "GET",
        &c.api("proj", &format!("/trails/{n}/sessions")),
        Some(&alice_tok),
        None,
    )
    .await
    .1["linked"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(linked_before, linked_after, "link set unchanged");

    // Viewed toggle: 403, and no viewed mark is stored.
    assert_eq!(
        forged(
            &carol,
            &c.web("proj", "/trails/1/changes/1/viewed"),
            &[("_csrf", "bogus"), ("path", "a.txt"), ("viewed", "1")]
        )
        .await,
        403,
        "forged viewed"
    );
    let views =
        starforged_db::changes::file_views_of_change(c.s.core.db(), setup.change_id, c.carol.id)
            .await
            .unwrap();
    assert!(views.is_empty(), "viewed unchanged: {views:?}");

    // Pending discard: 403, and the draft survives.
    let carol_tok = c.tok(&c.carol).await;
    let (s, _) = api_status(
        &client,
        "POST",
        &c.api("proj", &format!("/trails/{n}/changes/1/threads")),
        Some(&carol_tok),
        Some(json!({
            "path": "a.txt", "side": "head",
            "start_line": 1, "end_line": 1,
            "body": "csrf draft", "pending": true,
        })),
    )
    .await;
    assert_eq!(s.as_u16(), 201);
    assert_eq!(
        forged(
            &carol,
            &c.web("proj", "/trails/1/changes/1/reviews/pending"),
            &[("_csrf", "bogus")]
        )
        .await,
        403,
        "forged discard"
    );
    let (s, _) = api_status(
        &client,
        "GET",
        &c.api("proj", &format!("/trails/{n}/changes/1/reviews/pending")),
        Some(&carol_tok),
        None,
    )
    .await;
    assert_eq!(s.as_u16(), 200, "draft survives forged discard");

    // Thread + comment + review submit: 403, and counts are unchanged.
    let threads_before = starforged_db::changes::threads_of_change(c.s.core.db(), setup.change_id)
        .await
        .unwrap()
        .len();
    assert_eq!(
        forged(
            &carol,
            &c.web("proj", "/trails/1/changes/1/threads"),
            &[
                ("_csrf", "bogus"),
                ("path", "a.txt"),
                ("side", "head"),
                ("start", "1"),
                ("end", "1"),
                ("body", "forged thread"),
            ]
        )
        .await,
        403,
        "forged thread"
    );
    let threads_after = starforged_db::changes::threads_of_change(c.s.core.db(), setup.change_id)
        .await
        .unwrap()
        .len();
    assert_eq!(threads_before, threads_after, "threads unchanged");
    // A real thread to hang the forged comment on.
    let (s, b) = api_status(
        &client,
        "POST",
        &c.api("proj", &format!("/trails/{n}/changes/1/threads")),
        Some(&carol_tok),
        Some(json!({
            "path": "a.txt", "side": "head",
            "start_line": 1, "end_line": 1, "body": "csrf thread",
        })),
    )
    .await;
    assert_eq!(s.as_u16(), 201, "{b}");
    let tid = b["id"].as_i64().unwrap();
    let comments_before = starforged_db::changes::comments_of_thread(c.s.core.db(), tid)
        .await
        .unwrap()
        .len();
    assert_eq!(
        forged(
            &carol,
            &c.web(
                "proj",
                &format!("/trails/1/changes/1/threads/{tid}/comments")
            ),
            &[("_csrf", "bogus"), ("body", "forged comment")]
        )
        .await,
        403,
        "forged comment"
    );
    let comments_after = starforged_db::changes::comments_of_thread(c.s.core.db(), tid)
        .await
        .unwrap()
        .len();
    assert_eq!(comments_before, comments_after, "comments unchanged");
    let reviews_before = starforged_db::changes::reviews_of_change(c.s.core.db(), setup.change_id)
        .await
        .unwrap()
        .len();
    assert_eq!(
        forged(
            &carol,
            &c.web("proj", "/trails/1/changes/1/reviews"),
            &[
                ("_csrf", "bogus"),
                ("verdict", "approve"),
                ("body", "forged")
            ]
        )
        .await,
        403,
        "forged review"
    );
    let reviews_after = starforged_db::changes::reviews_of_change(c.s.core.db(), setup.change_id)
        .await
        .unwrap()
        .len();
    assert_eq!(reviews_before, reviews_after, "reviews unchanged");

    // Merge: 403, and the change stays open.
    assert_eq!(
        forged(
            &alice,
            &c.web("proj", "/trails/1/changes/1/merge"),
            &[("_csrf", "bogus"), ("method", "merge")]
        )
        .await,
        403,
        "forged merge"
    );
    let row = starforged_db::changes::change_by_id(c.s.core.db(), setup.change_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "open", "change still open");
}
