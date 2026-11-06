//! Org base permissions (M3a A1): the one-resolver grant path over org repos.

mod common;

use common::*;
use starforged_core::orgs::{NewOrgInput, OrgPatch};
use starforged_core::permission::{Permission, Visibility};
use starforged_core::repos::CreateRepo;
use starforged_db::sessions::{NewSession, insert_session};

struct Ctx {
    s: TestServer,
    alice: starforged_core::accounts::User,
    bob: starforged_core::accounts::User,
    carol: starforged_core::accounts::User,
    org_id: i64,
}

impl Ctx {
    async fn start() -> Ctx {
        let s = TestServer::start().await;
        let alice = s.user("alice").await;
        let bob = s.user("bob").await;
        let carol = s.user("carol").await;
        let view = s
            .core
            .create_org(
                &alice,
                NewOrgInput {
                    handle: "acme".into(),
                    display_name: "Acme".into(),
                    description: String::new(),
                },
            )
            .await
            .unwrap();
        let _ = view;
        s.core
            .set_org_member(
                &alice,
                "acme",
                "bob",
                starforged_core::orgs::OrgRole::Member,
            )
            .await
            .unwrap();
        let org_id = s.core.org(None, "acme").await.unwrap().id;
        Ctx {
            s,
            alice,
            bob,
            carol,
            org_id,
        }
    }

    /// Creates `name` under `alice`, then moves it into the org the way A3's
    /// repository creation will (org repos do not exist yet in A1).
    async fn move_to_org(&self, name: &str, visibility: Visibility) -> i64 {
        let repo = self
            .s
            .core
            .create_repo(
                &self.alice,
                CreateRepo {
                    name: name.into(),
                    description: String::new(),
                    visibility,
                    readme: false,
                },
            )
            .await
            .unwrap();
        sqlx::query("UPDATE repos SET owner_id = $1 WHERE id = $2")
            .bind(self.org_id)
            .bind(repo.id)
            .execute(self.s.core.db().pool())
            .await
            .unwrap();
        repo.id
    }

    async fn set_base(&self, base: &str) {
        self.s
            .core
            .update_org(
                &self.alice,
                "acme",
                OrgPatch {
                    display_name: None,
                    description: None,
                    base_permission: Some(base.into()),
                },
            )
            .await
            .unwrap();
    }

    async fn insert_session(&self, repo_id: i64, ulid: &str, visibility: &str) {
        insert_session(
            &self.s.core.db().clone(),
            &NewSession {
                repo_id,
                ulid,
                uploader_id: self.alice.id,
                agent_name: "pi",
                agent_version: "0.1.0",
                models: "{}",
                title: "t",
                branch: "work",
                head_sha: "abc",
                started_at: 1,
                ended_at: None,
                parent_ulid: None,
                usage_input: 0,
                usage_output: 0,
                usage_cache_read: 0,
                usage_cache_write: 0,
                usage_reasoning: 0,
                files_touched: "[]",
                turn_count: 0,
                tool_call_count: 0,
                lifecycle: "receiving",
                quarantine: "none",
                quarantine_reason: "",
                quarantine_detail: "",
                visibility,
                raw_enabled: 0,
                redaction_fingerprint: "",
                redaction_counts: "{}",
                capture_mode: "full",
                cli_version: "0",
                adapter_verified: 0,
            },
        )
        .await
        .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn base_read_grants_read_and_membership() {
    let c = Ctx::start().await;
    let repo_id = c.move_to_org("proj", Visibility::Private).await;
    c.set_base("read").await;

    let repo =
        c.s.core
            .repo_for(Some(&c.bob), "acme", "proj")
            .await
            .unwrap();
    assert_eq!(repo.permission, Permission::Read);
    assert!(c.s.core.is_repo_member(repo_id, c.bob.id).await.unwrap());

    // Org owners get Admin.
    let owner =
        c.s.core
            .repo_for(Some(&c.alice), "acme", "proj")
            .await
            .unwrap();
    assert_eq!(owner.permission, Permission::Admin);
    assert!(c.s.core.is_repo_member(repo_id, c.alice.id).await.unwrap());

    // Strangers get nothing on a private org repo.
    assert!(
        c.s.core
            .repo_for(Some(&c.carol), "acme", "proj")
            .await
            .is_err()
    );
    assert!(!c.s.core.is_repo_member(repo_id, c.carol.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn base_none_gives_nothing_beyond_public_read() {
    let c = Ctx::start().await;
    let repo_id = c.move_to_org("pub", Visibility::Public).await;
    c.set_base("none").await;

    // Implicit public read still applies, but it is not membership.
    let repo =
        c.s.core
            .repo_for(Some(&c.bob), "acme", "pub")
            .await
            .unwrap();
    assert_eq!(repo.permission, Permission::Read);
    assert!(!c.s.core.is_repo_member(repo_id, c.bob.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn base_members_see_unpublished_sessions_on_public_repos() {
    let c = Ctx::start().await;
    c.move_to_org("pub", Visibility::Public).await;
    c.insert_session(
        c.s.core
            .repo_for(Some(&c.alice), "acme", "pub")
            .await
            .unwrap()
            .repo
            .id,
        "01H0000000000000000000000",
        "inherit",
    )
    .await;

    // Without a base grant, the unpublished session hides from non-members...
    c.set_base("none").await;
    assert!(
        c.s.core
            .authorize_session_read_by_ulid(
                Some(&c.bob),
                "acme",
                "pub",
                "01H0000000000000000000000"
            )
            .await
            .is_err()
    );

    // ...and the base grant reveals it, while strangers still 404.
    c.set_base("read").await;
    assert!(
        c.s.core
            .authorize_session_read_by_ulid(
                Some(&c.bob),
                "acme",
                "pub",
                "01H0000000000000000000000"
            )
            .await
            .is_ok()
    );
    assert!(
        c.s.core
            .authorize_session_read_by_ulid(
                Some(&c.carol),
                "acme",
                "pub",
                "01H0000000000000000000000"
            )
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn highest_of_base_and_collaborator_wins() {
    let c = Ctx::start().await;
    c.move_to_org("proj", Visibility::Private).await;
    c.set_base("read").await;

    c.s.core
        .set_collaborator(&c.alice, "acme", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    let repo =
        c.s.core
            .repo_for(Some(&c.bob), "acme", "proj")
            .await
            .unwrap();
    assert_eq!(repo.permission, Permission::Write);

    c.s.core
        .remove_collaborator(&c.alice, "acme", "proj", "bob")
        .await
        .unwrap();
    let repo =
        c.s.core
            .repo_for(Some(&c.bob), "acme", "proj")
            .await
            .unwrap();
    assert_eq!(repo.permission, Permission::Read);
}
