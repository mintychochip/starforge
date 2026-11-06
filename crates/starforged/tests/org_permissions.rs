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

impl Ctx {
    /// Seeds a team straight into the database (the API/ tables land in the
    /// committed migration; the HTTP routes arrive with A2).
    async fn seed_team(&self, name: &str, permission: &str, all_repos: bool) -> i64 {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        sqlx::query_scalar::<_, i64>(
            "INSERT INTO teams (org_id, name, lower_name, description, permission, all_repos, created_at, updated_at) \
             VALUES ($1, $2, $3, '', $4, $5, $6, $7) RETURNING id",
        )
        .bind(self.org_id)
        .bind(name)
        .bind(name.to_ascii_lowercase())
        .bind(permission)
        .bind(i64::from(all_repos))
        .bind(ts)
        .bind(ts)
        .fetch_one(self.s.core.db().pool())
        .await
        .unwrap()
    }

    async fn seed_team_member(&self, team_id: i64, user_id: i64) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        sqlx::query("INSERT INTO team_members (team_id, user_id, created_at) VALUES ($1, $2, $3)")
            .bind(team_id)
            .bind(user_id)
            .bind(ts)
            .execute(self.s.core.db().pool())
            .await
            .unwrap();
    }

    async fn seed_team_repo(&self, team_id: i64, repo_id: i64) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        sqlx::query("INSERT INTO team_repos (team_id, repo_id, created_at) VALUES ($1, $2, $3)")
            .bind(team_id)
            .bind(repo_id)
            .bind(ts)
            .execute(self.s.core.db().pool())
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_team_with_all_repos_grants_write_everywhere() {
    let c = Ctx::start().await;
    let one = c.move_to_org("one", Visibility::Private).await;
    let two = c.move_to_org("two", Visibility::Private).await;
    let team = c.seed_team("Dev", "write", true).await;
    c.seed_team_member(team, c.bob.id).await;

    for (id, name) in [(one, "one"), (two, "two")] {
        let repo = c.s.core.repo_for(Some(&c.bob), "acme", name).await.unwrap();
        assert_eq!(repo.permission, Permission::Write, "team grant on {name}");
        assert!(c.s.core.is_repo_member(id, c.bob.id).await.unwrap());
    }
    // Strangers still see nothing on the private org repos.
    assert!(
        c.s.core
            .repo_for(Some(&c.carol), "acme", "one")
            .await
            .is_err()
    );
    assert!(!c.s.core.is_repo_member(one, c.carol.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selected_team_covers_only_its_set() {
    let c = Ctx::start().await;
    let one = c.move_to_org("one", Visibility::Private).await;
    let two = c.move_to_org("two", Visibility::Private).await;
    let team = c.seed_team("Triage", "triage", false).await;
    c.seed_team_member(team, c.bob.id).await;
    c.seed_team_repo(team, one).await;

    let repo =
        c.s.core
            .repo_for(Some(&c.bob), "acme", "one")
            .await
            .unwrap();
    assert_eq!(repo.permission, Permission::Triage);
    assert!(c.s.core.is_repo_member(one, c.bob.id).await.unwrap());
    assert!(
        c.s.core
            .repo_for(Some(&c.bob), "acme", "two")
            .await
            .is_err()
    );
    assert!(!c.s.core.is_repo_member(two, c.bob.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn highest_of_base_team_and_collaborator_wins() {
    let c = Ctx::start().await;
    c.move_to_org("proj", Visibility::Private).await;
    c.set_base("read").await;
    let team = c.seed_team("Dev", "triage", true).await;
    c.seed_team_member(team, c.bob.id).await;

    // Team triage beats base read.
    let repo =
        c.s.core
            .repo_for(Some(&c.bob), "acme", "proj")
            .await
            .unwrap();
    assert_eq!(repo.permission, Permission::Triage);

    // A collaborator write beats the team triage.
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

    // Dropping the collaborator falls back to the team grant, not the base.
    c.s.core
        .remove_collaborator(&c.alice, "acme", "proj", "bob")
        .await
        .unwrap();
    let repo =
        c.s.core
            .repo_for(Some(&c.bob), "acme", "proj")
            .await
            .unwrap();
    assert_eq!(repo.permission, Permission::Triage);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_team_member_repo_or_team_drops_grant() {
    let c = Ctx::start().await;
    let one = c.move_to_org("one", Visibility::Private).await;
    c.move_to_org("two", Visibility::Private).await;
    let team = c.seed_team("Dev", "write", false).await;
    c.seed_team_member(team, c.bob.id).await;
    c.seed_team_repo(team, one).await;
    let granted = || async {
        c.s.core
            .repo_for(Some(&c.bob), "acme", "one")
            .await
            .map(|r| r.permission)
    };
    assert_eq!(granted().await.unwrap(), Permission::Write);

    // Removing the member drops the grant immediately.
    sqlx::query("DELETE FROM team_members WHERE team_id = $1 AND user_id = $2")
        .bind(team)
        .bind(c.bob.id)
        .execute(c.s.core.db().pool())
        .await
        .unwrap();
    assert!(granted().await.is_err());
    c.seed_team_member(team, c.bob.id).await;
    assert_eq!(granted().await.unwrap(), Permission::Write);

    // Removing the repository drops the grant immediately.
    sqlx::query("DELETE FROM team_repos WHERE team_id = $1 AND repo_id = $2")
        .bind(team)
        .bind(one)
        .execute(c.s.core.db().pool())
        .await
        .unwrap();
    assert!(granted().await.is_err());
    c.seed_team_repo(team, one).await;
    assert_eq!(granted().await.unwrap(), Permission::Write);

    // Deleting the team drops the grant immediately.
    sqlx::query("DELETE FROM teams WHERE id = $1")
        .bind(team)
        .execute(c.s.core.db().pool())
        .await
        .unwrap();
    assert!(granted().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_member_removal_drops_team_grants() {
    let c = Ctx::start().await;
    let one = c.move_to_org("one", Visibility::Private).await;
    let team = c.seed_team("Dev", "write", true).await;
    c.seed_team_member(team, c.bob.id).await;
    assert_eq!(
        c.s.core
            .repo_for(Some(&c.bob), "acme", "one")
            .await
            .unwrap()
            .permission,
        Permission::Write
    );

    c.s.core
        .remove_org_member(&c.alice, "acme", "bob")
        .await
        .unwrap();
    assert!(
        c.s.core
            .repo_for(Some(&c.bob), "acme", "one")
            .await
            .is_err()
    );
    assert!(!c.s.core.is_repo_member(one, c.bob.id).await.unwrap());
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM team_members WHERE team_id = $1")
        .bind(team)
        .fetch_one(c.s.core.db().pool())
        .await
        .unwrap();
    assert_eq!(left, 0, "team membership left behind");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn team_grant_makes_member_and_admits_refs_for_push() {
    let c = Ctx::start().await;
    let repo_id = c.move_to_org("proj", Visibility::Private).await;
    let team = c.seed_team("Dev", "write", true).await;
    c.seed_team_member(team, c.bob.id).await;
    assert!(c.s.core.is_repo_member(repo_id, c.bob.id).await.unwrap());
    starforged_db::repos::set_refs_for_access(c.s.core.db(), repo_id, "members")
        .await
        .unwrap();

    // Bob holds no collaborator grant — only the team grant — yet his
    // read-token push to refs/for is admitted as a member push.
    let token =
        c.s.token(&c.bob, &[starforged_core::tokens::Scope::RepoRead])
            .await;
    let tmp = tempfile::tempdir().unwrap();
    let work = work_repo(tmp.path(), "work", &[("README.md", "# proj\n")]).await;
    // The org repo starts empty: land a base branch first so refs/for has a base.
    let owner_token =
        c.s.token(&c.alice, &[starforged_core::tokens::Scope::RepoWrite])
            .await;
    git_ok(
        &work,
        &[
            "push",
            &c.s.git_url("acme", "proj", Some(&owner_token)),
            "main",
        ],
    )
    .await;
    commit_files(&work, &[("bob.txt", b"bob\n")], "bob proposal").await;
    git_ok(
        &work,
        &[
            "push",
            &c.s.git_url("acme", "proj", Some(&token)),
            "HEAD:refs/for/main/x",
        ],
    )
    .await;
    let kind = loop {
        let found = starforged_db::changes::open_agit_change(
            c.s.core.db(),
            repo_id,
            c.bob.id,
            "main",
            "x",
            None,
        )
        .await
        .unwrap();
        if let Some(change) = found {
            break change.kind;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert_eq!(kind, "agit");
}
