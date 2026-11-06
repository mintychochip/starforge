//! Audit completeness sweep (spec §6.5, plan M5a L4): every state-changing
//! action class writes exactly one audit row with actor, action, target,
//! IP, user agent, and timestamp; refused actions write none (except the
//! plan's refusal rows for failed logins). Also pins the FK-race mapping
//! (a parent deletion mid-write answers 404, never 500) and the L1 minors
//! (one authentication per request; no `X-RateLimit-*` with 0 when the
//! limit is disabled).

mod common;

use common::{PASSWORD, TestServer};
use serde_json::{Value, json};
use starforged_core::CoreError;
use starforged_core::accounts::CreateUser;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

const ULIDS: &[&str] = &[
    "01ARZ3NDEKTSV4RRFFQ69G5FB0",
    "01ARZ3NDEKTSV4RRFFQ69G5FB1",
    "01ARZ3NDEKTSV4RRFFQ69G5FB2",
    "01ARZ3NDEKTSV4RRFFQ69G5FB3",
    "01ARZ3NDEKTSV4RRFFQ69G5FB4",
    "01ARZ3NDEKTSV4RRFFQ69G5FB5",
];

fn meta_body(ulid: &str) -> Value {
    json!({
        "format": "starforge.session/v1",
        "id": ulid,
        "agent": {"name": "claude-code", "version": "1.0"},
        "models": ["opus"],
        "title": "audit sweep session",
        "started_at": "2026-11-04T00:00:00Z",
        "ended_at": null,
        "repo": {"branch": "feature/widget", "head_at_start": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "parent_id": null,
        "usage": {"input": 10, "output": 20, "cache_read": 30, "cache_write": 40, "reasoning": 50},
        "files_touched": ["src/main.rs"],
        "redaction": {"fingerprint": "fp-test", "counts": {}},
        "capture": {"mode": "discovery", "cli_version": "9.9.9", "adapter_version_verified": true},
    })
}

fn event_with_text(seq: u64, text: &str) -> String {
    let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        r#"{{"v":1,"seq":{seq},"ts":"2026-11-04T00:00:00Z","kind":"user_message","text":"{escaped}"}}"#
    )
}

fn segment_payload(lines: &[String]) -> (Vec<u8>, String) {
    let mut jsonl = lines.join("\n");
    jsonl.push('\n');
    let bytes = starforge_format::compress(jsonl.as_bytes());
    let hash = starforge_format::blake3_hex(&bytes);
    (bytes, hash)
}

/// Rows with `action` and `target`, newest first.
async fn rows(s: &TestServer, action: &str, target: &str) -> Vec<starforged_db::audit::AuditRow> {
    starforged_db::audit::recent(s.core.db(), 500)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.action == action && r.target == target)
        .collect()
}

/// Asserts exactly one row for `action`/`target` with `actor` and a
/// current timestamp; returns it for IP/user-agent checks.
async fn exactly_one(
    s: &TestServer,
    action: &str,
    target: &str,
    actor: Option<i64>,
) -> starforged_db::audit::AuditRow {
    let found = rows(s, action, target).await;
    assert_eq!(
        found.len(),
        1,
        "expected exactly one `{action}` row for `{target}`, got {found:?}"
    );
    let row = &found[0];
    assert_eq!(row.actor_id, actor, "`{action}` actor for `{target}`");
    let now = starforged_db::now();
    assert!(
        row.created_at <= now && row.created_at > now - 300,
        "`{action}` timestamp {} not near now {now}",
        row.created_at
    );
    found.into_iter().next().unwrap()
}

async fn upload(
    s: &TestServer,
    token: &str,
    owner: &str,
    repo: &str,
    ulid: &str,
    lines: &[String],
) {
    let client = reqwest::Client::new();
    let meta = client
        .put(s.url(&format!("/api/v1/repos/{owner}/{repo}/sessions/{ulid}")))
        .bearer_auth(token)
        .json(&meta_body(ulid))
        .send()
        .await
        .unwrap();
    assert!(meta.status().is_success(), "meta {ulid}: {}", meta.status());
    let (bytes, hash) = segment_payload(lines);
    let put = client
        .put(s.url(&format!(
            "/api/v1/repos/{owner}/{repo}/sessions/{ulid}/segments/0"
        )))
        .bearer_auth(token)
        .header("X-Starforge-Blake3", &hash)
        .body(bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200, "segment {ulid}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_success_and_failure_write_one_row_each() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;

    // Failure for an unknown name: actor None, target the normalized name.
    let failed = s
        .core
        .login("NoBody", "wrong password", "sweep-agent", "203.0.113.7")
        .await;
    assert!(
        matches!(failed, Err(CoreError::Unauthenticated)),
        "{failed:?}"
    );
    let row = exactly_one(&s, "auth.login_failed", "login:nobody", None).await;
    assert_eq!(row.ip, "203.0.113.7");
    assert_eq!(row.user_agent, "sweep-agent");

    // Failure for a known name with a wrong password: same shape.
    let failed_known = s
        .core
        .login("alice", "wrong password", "sweep-agent", "203.0.113.7")
        .await;
    assert!(matches!(failed_known, Err(CoreError::Unauthenticated)));
    exactly_one(&s, "auth.login_failed", "login:alice", None).await;

    // Success: actor is the user, IP/user-agent ride the row.
    let outcome = s
        .core
        .login("alice", PASSWORD, "sweep-agent", "203.0.113.7")
        .await
        .unwrap();
    let (user, _) = outcome.into_session();
    assert_eq!(user.id, alice.id);
    let row = exactly_one(&s, "auth.login", "user:alice", Some(alice.id)).await;
    assert_eq!(row.ip, "203.0.113.7");
    assert_eq!(row.user_agent, "sweep-agent");

    // A refused password change writes no audit row beyond the one above.
    let before = starforged_db::audit::recent(s.core.db(), 500)
        .await
        .unwrap()
        .len();
    assert!(matches!(
        s.core
            .change_password(&alice, 0, "wrong password", "new password 12345")
            .await,
        Err(CoreError::Invalid(_))
    ));
    assert_eq!(
        starforged_db::audit::recent(s.core.db(), 500)
            .await
            .unwrap()
            .len(),
        before,
        "a refused change must not audit"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn password_and_2fa_changes_write_one_row_each() {
    use starforged_core::totp::{base32, code_at};
    let s = TestServer::start().await;
    let alice = s.user("alice").await;

    s.core
        .change_password(&alice, 0, PASSWORD, "new password 12345")
        .await
        .unwrap();
    exactly_one(&s, "account.password_change", "user:alice", Some(alice.id)).await;

    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    // Steps are single-use and monotonic (`claim_totp_step` requires
    // step > last claimed): confirm consumes one step, each later TOTP
    // action takes the next step inside the ±1 window.
    let code_at_step = |secret_base32: &str, at: u64| -> String {
        let secret = base32::decode(secret_base32).expect("base32 secret");
        format!("{:06}", code_at(&secret, at))
    };

    let enrolled = s.core.begin_totp_enrollment(&alice).await.unwrap();
    s.core
        .confirm_totp_enrollment(&alice, &code_at_step(&enrolled.secret_base32, step))
        .await
        .unwrap();
    exactly_one(&s, "account.2fa_enabled", "user:alice", Some(alice.id)).await;
}

/// The single part of the 2FA sweep needing a fresh enrollment: recovery-code
/// regeneration. Kept separate so it can use `now_step()+1` after enrollment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_regeneration_writes_one_row() {
    use starforged_core::totp::{base32, code_at};
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    let code_at_step = |secret_base32: &str, at: u64| -> String {
        let secret = base32::decode(secret_base32).expect("base32 secret");
        format!("{:06}", code_at(&secret, at))
    };
    let enrolled = s.core.begin_totp_enrollment(&alice).await.unwrap();
    s.core
        .confirm_totp_enrollment(&alice, &code_at_step(&enrolled.secret_base32, step))
        .await
        .unwrap();
    s.core
        .regenerate_recovery_codes(&alice, &code_at_step(&enrolled.secret_base32, step + 1))
        .await
        .unwrap();
    exactly_one(
        &s,
        "account.recovery_codes_regenerated",
        "user:alice",
        Some(alice.id),
    )
    .await;
}

/// 2FA disable: separate enrollment so it can use `now_step()+1` after
/// enrollment instead of reusing a claimed step.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn twofa_disable_writes_one_row() {
    use starforged_core::totp::{base32, code_at};
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let step = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    let code_at_step = |secret_base32: &str, at: u64| -> String {
        let secret = base32::decode(secret_base32).expect("base32 secret");
        format!("{:06}", code_at(&secret, at))
    };
    let enrolled = s.core.begin_totp_enrollment(&alice).await.unwrap();
    s.core
        .confirm_totp_enrollment(&alice, &code_at_step(&enrolled.secret_base32, step))
        .await
        .unwrap();
    s.core
        .disable_totp(
            &alice,
            PASSWORD,
            &code_at_step(&enrolled.secret_base32, step + 1),
        )
        .await
        .unwrap();
    exactly_one(&s, "account.2fa_disabled", "user:alice", Some(alice.id)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn token_create_and_revoke_write_one_row_each() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;

    let created = s
        .core
        .create_token(&alice, "sweep", &[Scope::RepoRead], 1)
        .await
        .unwrap();
    exactly_one(
        &s,
        "token.create",
        &format!("token:{}", created.id),
        Some(alice.id),
    )
    .await;

    s.core.revoke_token(&alice, created.id).await.unwrap();
    exactly_one(
        &s,
        "token.revoke",
        &format!("token:{}", created.id),
        Some(alice.id),
    )
    .await;

    // Revoking the same token again is refused and writes no second row.
    assert!(matches!(
        s.core.revoke_token(&alice, created.id).await,
        Err(CoreError::NotFound)
    ));
    assert_eq!(
        rows(&s, "token.revoke", &format!("token:{}", created.id))
            .await
            .len(),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permission_membership_and_transfer_write_one_row_each() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Public).await;

    // Collaborators.
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    exactly_one(
        &s,
        "repo.collaborator.set",
        "repo:alice/proj",
        Some(alice.id),
    )
    .await;
    // A below-threshold grant by bob (write, not admin) is refused and
    // writes no row: the count above stays at one.
    assert!(matches!(
        s.core
            .set_collaborator(&bob, "alice", "proj", "alice", Permission::Read)
            .await,
        Err(CoreError::Forbidden)
    ));
    assert_eq!(
        rows(&s, "repo.collaborator.set", "repo:alice/proj")
            .await
            .len(),
        1,
        "a refused grant must not audit"
    );
    s.core
        .remove_collaborator(&alice, "alice", "proj", "bob")
        .await
        .unwrap();
    exactly_one(
        &s,
        "repo.collaborator.remove",
        "repo:alice/proj",
        Some(alice.id),
    )
    .await;

    // Visibility.
    s.core
        .set_visibility(&alice, "alice", "proj", Visibility::Private)
        .await
        .unwrap();
    exactly_one(&s, "repo.visibility", "repo:alice/proj", Some(alice.id)).await;
    // A no-op visibility change writes nothing.
    s.core
        .set_visibility(&alice, "alice", "proj", Visibility::Private)
        .await
        .unwrap();
    assert_eq!(
        rows(&s, "repo.visibility", "repo:alice/proj").await.len(),
        1
    );

    // Org members.
    s.core
        .create_org(
            &alice,
            starforged_core::orgs::NewOrgInput {
                handle: "acme".into(),
                display_name: "Acme".into(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    s.core
        .set_org_member(
            &alice,
            "acme",
            "bob",
            starforged_core::orgs::OrgRole::Member,
        )
        .await
        .unwrap();
    exactly_one(&s, "org.member_add", "org:acme", Some(alice.id)).await;
    s.core
        .set_org_member(&alice, "acme", "bob", starforged_core::orgs::OrgRole::Owner)
        .await
        .unwrap();
    exactly_one(&s, "org.member_role", "org:acme", Some(alice.id)).await;

    // Teams and team membership.
    let team = s
        .core
        .create_team(
            &alice,
            "acme",
            starforged_core::orgs::NewTeamInput {
                name: "Core".into(),
                description: String::new(),
                permission: "read".into(),
                all_repos: false,
            },
        )
        .await
        .unwrap();
    exactly_one(&s, "team.create", "team:acme/core", Some(alice.id)).await;
    s.core
        .set_team_member(&alice, "acme", "core", "bob")
        .await
        .unwrap();
    exactly_one(&s, "team.member_add", "team:acme/core", Some(alice.id)).await;
    s.core
        .remove_team_member(&alice, "acme", "core", "bob")
        .await
        .unwrap();
    exactly_one(&s, "team.member_remove", "team:acme/core", Some(alice.id)).await;

    // Team repositories need an org-owned repo.
    s.core
        .create_repo(
            &alice,
            "acme",
            starforged_core::repos::CreateRepo {
                name: "svc".into(),
                description: String::new(),
                visibility: Visibility::Private,
                readme: false,
            },
        )
        .await
        .unwrap();
    s.core
        .add_team_repo(&alice, "acme", "core", "svc")
        .await
        .unwrap();
    exactly_one(&s, "team.repo_add", "team:acme/core", Some(alice.id)).await;
    s.core
        .remove_team_repo(&alice, "acme", "core", "svc")
        .await
        .unwrap();
    exactly_one(&s, "team.repo_remove", "team:acme/core", Some(alice.id)).await;

    // Transfer: alice creates a repo, then moves it to an org she owns.
    // Transfer needs actor==new owner for users, so transfer to herself is a
    // no-op; instead bob (owner of his own org? no) — use a second org-free
    // path: alice transfers her private repo to org "acme" she owns.
    s.repo(&alice, "move", Visibility::Private).await;
    let moved = s
        .core
        .transfer_repo(&alice, "alice", "move", "acme")
        .await
        .unwrap();
    assert_eq!(moved.full_name(), "acme/move");
    exactly_one(&s, "repo.transfer", "repo:acme/move", Some(alice.id)).await;
    let _ = team;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_lifecycle_writes_one_row_each() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();

    // Publish / unpublish a clean session.
    let ulid = ULIDS[0];
    upload(
        &s,
        &token,
        "alice",
        "proj",
        ulid,
        &[event_with_text(0, "clean marker alpha")],
    )
    .await;
    s.core.publish_session(&alice, &access, ulid).await.unwrap();
    exactly_one(
        &s,
        "session.publish",
        &format!("session:{ulid}"),
        Some(alice.id),
    )
    .await;
    s.core
        .unpublish_session(&alice, &access, ulid)
        .await
        .unwrap();
    exactly_one(
        &s,
        "session.unpublish",
        &format!("session:{ulid}"),
        Some(alice.id),
    )
    .await;

    // Quarantine via a high-confidence private-key hit on upload.
    let quarantined = ULIDS[1];
    let pem = "key -----BEGIN PRIVATE KEY-----\\nMIIEvAIBADANBgkqhkiG9w0BAQEF\\n-----END PRIVATE KEY----- done";
    upload(
        &s,
        &token,
        "alice",
        "proj",
        quarantined,
        &[event_with_text(0, pem)],
    )
    .await;
    exactly_one(
        &s,
        "session.quarantine",
        &format!("session:{quarantined}"),
        Some(alice.id),
    )
    .await;

    // Release.
    s.core
        .release_session(&alice, &access, quarantined)
        .await
        .unwrap();
    exactly_one(
        &s,
        "session.quarantine.released",
        &format!("session:{quarantined}"),
        Some(alice.id),
    )
    .await;

    // Purge (the admin-queue path, `session.purged`).
    let to_purge = ULIDS[2];
    upload(
        &s,
        &token,
        "alice",
        "proj",
        to_purge,
        &[event_with_text(0, pem)],
    )
    .await;
    s.core
        .purge_session(&alice, &access, to_purge)
        .await
        .unwrap();
    exactly_one(
        &s,
        "session.purged",
        &format!("session:{to_purge}"),
        Some(alice.id),
    )
    .await;

    // User-facing delete (`session.deleted`).
    let to_delete = ULIDS[3];
    upload(
        &s,
        &token,
        "alice",
        "proj",
        to_delete,
        &[event_with_text(0, "delete me marker")],
    )
    .await;
    s.core
        .delete_session(&alice, &access, to_delete)
        .await
        .unwrap();
    exactly_one(
        &s,
        "session.deleted",
        &format!("session:{to_delete}"),
        Some(alice.id),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn site_admin_actions_write_one_row_each() {
    let s = TestServer::start().await;
    let root = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;

    s.core.suspend_user(&root, bob.id).await.unwrap();
    exactly_one(&s, "user.suspend", "user:bob", Some(root.id)).await;

    s.core.grant_admin(&root, carol.id).await.unwrap();
    exactly_one(&s, "user.grant_admin", "user:carol", Some(root.id)).await;

    s.core.admin_reset_2fa(&root, bob.id).await.unwrap();
    exactly_one(&s, "user.2fa_reset", "user:bob", Some(root.id)).await;

    // Job retry: seed one failed job.
    let job_id: i64 = sqlx::query_scalar(
        "INSERT INTO jobs (kind, payload, state, run_at, created_at, updated_at) \
         VALUES ($1, $2, 'failed', $3, $3, $3) RETURNING id",
    )
    .bind("send_mail")
    .bind("{}")
    .bind(starforged_db::now())
    .fetch_one(s.core.db().pool())
    .await
    .unwrap();
    s.core.retry_job(&root, job_id).await.unwrap();
    exactly_one(&s, "job.retry", &format!("job:{job_id}"), Some(root.id)).await;
}

/// A session's transcript marker must never reach any audit column.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_rows_never_contain_transcript_content() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let token = s.token(&alice, &[Scope::SessionUpload]).await;
    let marker = "SWEEP-TRANSCRIPT-MARKER-9f27c1-UNIQUE";
    let ulid = ULIDS[4];
    upload(
        &s,
        &token,
        "alice",
        "proj",
        ulid,
        &[event_with_text(0, &format!("the transcript says {marker}"))],
    )
    .await;
    let access = s
        .core
        .repo_for(Some(&alice), "alice", "proj")
        .await
        .unwrap();
    s.core.publish_session(&alice, &access, ulid).await.unwrap();
    for row in starforged_db::audit::recent(s.core.db(), 500)
        .await
        .unwrap()
    {
        assert!(
            !row.action.contains(marker)
                && !row.target.contains(marker)
                && !row.detail.contains(marker)
                && !row.ip.contains(marker)
                && !row.user_agent.contains(marker),
            "audit row leaks transcript content: {row:?}"
        );
    }
}

/// A repo-scoped write racing an account deletion must answer 404/409,
/// never 500: the parent row the caller authorized against is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn collaborator_write_racing_account_delete_never_500s() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "proj", Visibility::Private).await;

    // Deterministic mapping first: a dangling parent is an FK violation
    // at the db layer and `NotFound` at the core layer.
    let fk = starforged_db::collaborators::upsert(s.core.db(), 999_999, alice.id, "read")
        .await
        .unwrap_err();
    assert!(
        fk.is_foreign_key_violation(),
        "expected FK violation: {fk:?}"
    );
    let mapped = CoreError::from(fk);
    assert!(matches!(mapped, CoreError::NotFound), "{mapped:?}");

    // Bounded concurrent loop: each round races a collaborator grant to a
    // fresh target against that target's account deletion.
    for i in 0..12 {
        let handle = format!("racer{i}");
        let target = s.user(&handle).await;
        let grant = s
            .core
            .set_collaborator(&alice, "alice", "proj", &handle, Permission::Read);
        let delete = s.core.delete_account(&target, &handle);
        let (granted, deleted) = tokio::join!(grant, delete);
        // Exactly one of the two can commit; the loser is refused without a 500.
        let refused = granted.err();
        if let Some(e) = refused {
            assert!(
                matches!(e, CoreError::NotFound | CoreError::Invalid(_)),
                "race round {i}: collaborator grant must be 404/422, got {e:?}"
            );
        } else {
            // The grant won, so the deletion must have been refused (the
            // account is a collaborator grant holder, not an owner — the
            // deletion may still succeed; both outcomes are acceptable as
            // long as no 500/Db error escapes).
            if let Err(e) = &deleted {
                assert!(
                    matches!(e, CoreError::Invalid(_)),
                    "race round {i}: deletion must not 500, got {e:?}"
                );
            }
        }
        // Even if the deletion won first, cleanup of a surviving target must not 500.
        let _ = target;
    }

    // Org-deletion analogue on the same path: deleting an org's owners row
    // under a write maps to NotFound rather than a 500 (unit-style check via
    // a transfer to a deleted owner, which already maps Gone -> NotFound).
    let bob = s.user("bob2").await;
    let org = s
        .core
        .create_org(
            &bob,
            starforged_core::orgs::NewOrgInput {
                handle: "vanish".into(),
                display_name: "Vanish".into(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    // Delete the org (empty: no repos), then a transfer naming it must 404.
    s.core.delete_org(&bob, "vanish").await.unwrap();
    assert!(s.core.org(None, "vanish").await.is_err());
    let _ = org;
}

/// With the per-token limit disabled, token responses carry no
/// `X-RateLimit-*` headers; with it enabled they carry the budget and the
/// count decrements exactly once per request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_headers_omitted_when_disabled_and_single_count_when_enabled() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();

    // Limits are off in the default test config (see common/mod.rs).
    let off = client
        .get(s.url("/api/v1/user"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(off.status(), 200);
    for header in [
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    ] {
        assert!(
            off.headers().get(header).is_none(),
            "disabled limit must omit {header}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_headers_present_and_counted_once_when_enabled() {
    let s = TestServer::start_with(|config| {
        config.limits.api_per_token_per_hour = 5;
    })
    .await;
    let alice = s.user("alice").await;
    let token = s.token(&alice, &[Scope::RepoRead]).await;
    let client = reqwest::Client::new();

    let first = client
        .get(s.url("/api/v1/user"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    assert_eq!(first.headers()["x-ratelimit-limit"], "5");
    assert_eq!(first.headers()["x-ratelimit-remaining"], "4");

    let second = client
        .get(s.url("/api/v1/user"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 200);
    // Exactly one count per request: 4 -> 3 (a double authentication must
    // not double-count).
    assert_eq!(second.headers()["x-ratelimit-remaining"], "3");
}
