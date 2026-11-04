//! Site administration: listing, suspending, roles, creation, and deletion of users.
//!
//! Every method takes the acting `admin` first and answers `Forbidden` unless they are a site admin.
//! Demoting, suspending, or deleting the last active site admin is refused so the site is never
//! left without an administrator.

use starforged_db::{repos as db_repos, users, web_sessions};

use crate::accounts::{CreateUser, User};
use crate::{Core, CoreError, CoreResult};

/// A user plus how many live repositories they own, for the admin detail page.
#[derive(Debug, Clone)]
pub struct UserSummary {
    pub user: User,
    pub repo_count: i64,
}

fn forbidden_unless_admin(admin: &User) -> CoreResult<()> {
    if !admin.is_admin {
        return Err(CoreError::Forbidden);
    }
    Ok(())
}

async fn refresh(core: &Core, id: i64) -> CoreResult<User> {
    core.user_by_id(id).await?.ok_or(CoreError::NotFound)
}

async fn load_target(core: &Core, target_id: i64) -> CoreResult<User> {
    users::by_id(core.db(), target_id)
        .await?
        .map(User::from)
        .ok_or(CoreError::NotFound)
}

fn last_admin_error() -> CoreError {
    CoreError::Invalid(
        "You are the only site administrator; make another user an administrator first.".into(),
    )
}

async fn ensure_not_last_admin(core: &Core, target: &User) -> CoreResult<()> {
    if target.is_admin
        && target.active
        && users::count_active_admins_except(core.db(), target.id).await? == 0
    {
        return Err(last_admin_error());
    }
    Ok(())
}

impl Core {
    pub async fn admin_list_users(
        &self,
        admin: &User,
        query: &str,
        limit: i64,
    ) -> CoreResult<Vec<User>> {
        forbidden_unless_admin(admin)?;
        let rows = users::list_users(self.db(), &query.to_ascii_lowercase(), limit).await?;
        Ok(rows.into_iter().map(User::from).collect())
    }

    pub async fn admin_get_user(&self, admin: &User, handle: &str) -> CoreResult<UserSummary> {
        forbidden_unless_admin(admin)?;
        let row = users::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        let repo_count = db_repos::list_by_owner(self.db(), row.id).await?.len() as i64;
        Ok(UserSummary {
            user: User::from(row),
            repo_count,
        })
    }

    pub async fn suspend_user(&self, admin: &User, target_id: i64) -> CoreResult<User> {
        forbidden_unless_admin(admin)?;
        let target = load_target(self, target_id).await?;
        if admin.id == target.id {
            return Err(CoreError::Invalid("You cannot suspend yourself.".into()));
        }
        if !target.active {
            return Err(CoreError::Invalid(
                "The account is already suspended.".into(),
            ));
        }
        ensure_not_last_admin(self, &target).await?;
        users::set_state(self.db(), target.id, "suspended").await?;
        web_sessions::delete_for_user(self.db(), target.id).await?;
        self.audit(
            Some(admin.id),
            "user.suspend",
            &format!("user:{}", target.handle),
            "",
        )
        .await?;
        refresh(self, target.id).await
    }

    pub async fn unsuspend_user(&self, admin: &User, target_id: i64) -> CoreResult<User> {
        forbidden_unless_admin(admin)?;
        let target = load_target(self, target_id).await?;
        if target.active {
            return Err(CoreError::Invalid("The account is not suspended.".into()));
        }
        users::set_state(self.db(), target.id, "active").await?;
        self.audit(
            Some(admin.id),
            "user.unsuspend",
            &format!("user:{}", target.handle),
            "",
        )
        .await?;
        refresh(self, target.id).await
    }

    pub async fn grant_admin(&self, admin: &User, target_id: i64) -> CoreResult<User> {
        forbidden_unless_admin(admin)?;
        let target = load_target(self, target_id).await?;
        if target.is_admin {
            return refresh(self, target.id).await;
        }
        users::set_is_admin(self.db(), target.id, true).await?;
        self.audit(
            Some(admin.id),
            "user.grant_admin",
            &format!("user:{}", target.handle),
            "",
        )
        .await?;
        refresh(self, target.id).await
    }

    pub async fn revoke_admin(&self, admin: &User, target_id: i64) -> CoreResult<User> {
        forbidden_unless_admin(admin)?;
        let target = load_target(self, target_id).await?;
        if !target.is_admin {
            return refresh(self, target.id).await;
        }
        ensure_not_last_admin(self, &target).await?;
        users::set_is_admin(self.db(), target.id, false).await?;
        self.audit(
            Some(admin.id),
            "user.revoke_admin",
            &format!("user:{}", target.handle),
            "",
        )
        .await?;
        refresh(self, target.id).await
    }

    pub async fn admin_create_user(&self, admin: &User, mut input: CreateUser) -> CoreResult<User> {
        forbidden_unless_admin(admin)?;
        input.email_verified = true;
        let user = self.create_user(input).await?;
        self.audit(
            Some(admin.id),
            "user.create",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        Ok(user)
    }

    pub async fn admin_delete_user(&self, admin: &User, target_id: i64) -> CoreResult<()> {
        forbidden_unless_admin(admin)?;
        let target = load_target(self, target_id).await?;
        if admin.id == target.id {
            return Err(CoreError::Invalid("You cannot delete yourself.".into()));
        }
        ensure_not_last_admin(self, &target).await?;
        let owned = db_repos::list_by_owner(self.db(), target.id).await?;
        if !owned.is_empty() {
            let names = owned
                .iter()
                .map(|r| r.name.clone())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(CoreError::Invalid(format!(
                "The account still owns repositories: {names}."
            )));
        }
        self.purge_deleted_repos_of(target.id, Some(admin.id))
            .await?;
        self.audit(
            Some(admin.id),
            "user.delete",
            &format!("user:{}", target.handle),
            "",
        )
        .await?;
        users::delete(self.db(), target.id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permission::Visibility;
    use crate::repos::CreateRepo;
    use crate::testing::test_core;

    const PASSWORD: &str = "correct horse battery staple extra";

    async fn admin_user(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            password: Some(PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    async fn plain_user(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    async fn two_admins() -> (Core, User, User) {
        let (core, _f) = test_core().await;
        let root = admin_user(&core, "root").await;
        let vice = admin_user(&core, "vice").await;
        (core, root, vice)
    }

    #[tokio::test]
    async fn suspend_ends_sessions_and_last_admin_is_protected() {
        let (core, root, vice) = two_admins().await;
        // Non-admin cannot suspend.
        let bob = plain_user(&core, "bob").await;
        assert!(matches!(
            core.suspend_user(&bob, bob.id).await,
            Err(CoreError::Forbidden)
        ));
        // Self-suspend refused.
        assert!(matches!(
            core.suspend_user(&root, root.id).await,
            Err(CoreError::Invalid(_))
        ));
        // Suspend works and ends web sessions.
        let (_, session) = core
            .login("bob", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
        let suspended = core.suspend_user(&root, bob.id).await.unwrap();
        assert!(!suspended.active);
        assert!(
            core.web_session(&session.cookie_value)
                .await
                .unwrap()
                .is_none()
        );
        // Suspending an already-suspended user is refused.
        assert!(matches!(
            core.suspend_user(&root, bob.id).await,
            Err(CoreError::Invalid(_))
        ));
        // Last active admin cannot be suspended: suspend vice first so root is last.
        core.suspend_user(&root, vice.id).await.unwrap();
        assert!(matches!(
            core.suspend_user(&root, root.id).await,
            Err(CoreError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn unsuspend_reactivates_and_refuses_active_accounts() {
        let (core, root, _) = two_admins().await;
        let bob = plain_user(&core, "bob").await;
        assert!(matches!(
            core.unsuspend_user(&bob, bob.id).await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.unsuspend_user(&root, bob.id).await,
            Err(CoreError::Invalid(_))
        ));
        core.suspend_user(&root, bob.id).await.unwrap();
        let active = core.unsuspend_user(&root, bob.id).await.unwrap();
        assert!(active.active);
    }

    #[tokio::test]
    async fn grant_and_revoke_admin_guard_the_last_admin() {
        let (core, root, vice) = two_admins().await;
        let bob = plain_user(&core, "bob").await;
        assert!(matches!(
            core.grant_admin(&bob, bob.id).await,
            Err(CoreError::Forbidden)
        ));
        let bob = core.grant_admin(&root, bob.id).await.unwrap();
        assert!(bob.is_admin);
        // Self-demote is allowed while another admin exists.
        let root = core.revoke_admin(&root, root.id).await.unwrap();
        assert!(!root.is_admin);
        // The last active admin cannot be demoted: vice demotes bob first, leaving only vice.
        core.revoke_admin(&vice, bob.id).await.unwrap();
        assert!(matches!(
            core.revoke_admin(&vice, vice.id).await,
            Err(CoreError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn grant_and_revoke_noops_change_nothing_and_audit_nothing() {
        use starforged_db::audit;
        let (core, _f) = test_core().await;
        let root = admin_user(&core, "root").await;
        let bob = plain_user(&core, "bob").await;
        async fn action_count(core: &Core, action: &str) -> usize {
            audit::recent(core.db(), 100)
                .await
                .unwrap()
                .into_iter()
                .filter(|e| e.action == action)
                .count()
        }
        // Revoking a non-admin is a no-op: same user back, no audit entry.
        let same = core.revoke_admin(&root, bob.id).await.unwrap();
        assert!(!same.is_admin);
        assert_eq!(action_count(&core, "user.revoke_admin").await, 0);
        // Grant once: one audit entry.
        let bob = core.grant_admin(&root, bob.id).await.unwrap();
        assert!(bob.is_admin);
        assert_eq!(action_count(&core, "user.grant_admin").await, 1);
        // Granting again changes and audits nothing.
        let same = core.grant_admin(&root, bob.id).await.unwrap();
        assert!(same.is_admin);
        assert_eq!(action_count(&core, "user.grant_admin").await, 1);
        // Revoke, then revoking again is a no-op.
        let bob = core.revoke_admin(&root, bob.id).await.unwrap();
        assert!(!bob.is_admin);
        assert_eq!(action_count(&core, "user.revoke_admin").await, 1);
        let same = core.revoke_admin(&root, bob.id).await.unwrap();
        assert!(!same.is_admin);
        assert_eq!(action_count(&core, "user.revoke_admin").await, 1);
    }

    #[tokio::test]
    async fn admin_list_and_get_users() {
        let (core, root, _) = two_admins().await;
        let bob = plain_user(&core, "bob").await;
        assert!(matches!(
            core.admin_list_users(&bob, "", 200).await,
            Err(CoreError::Forbidden)
        ));
        let handles = core
            .admin_list_users(&root, "", 200)
            .await
            .unwrap()
            .into_iter()
            .map(|u| u.handle)
            .collect::<Vec<_>>();
        assert_eq!(handles, vec!["bob", "root", "vice"]);
        let filtered = core
            .admin_list_users(&root, "VICE", 200)
            .await
            .unwrap()
            .into_iter()
            .map(|u| u.handle)
            .collect::<Vec<_>>();
        assert_eq!(filtered, vec!["vice"]);
        assert!(matches!(
            core.admin_get_user(&bob, "root").await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.admin_get_user(&root, "nobody").await,
            Err(CoreError::NotFound)
        ));
        let summary = core.admin_get_user(&root, "BOB").await.unwrap();
        assert_eq!(summary.user.handle, "bob");
        assert_eq!(summary.repo_count, 0);
    }

    #[tokio::test]
    async fn admin_create_user_verifies_the_address() {
        let (core, root, _) = two_admins().await;
        let bob = plain_user(&core, "bob").await;
        assert!(matches!(
            core.admin_create_user(
                &bob,
                CreateUser {
                    handle: "mallory".into(),
                    ..Default::default()
                }
            )
            .await,
            Err(CoreError::Forbidden)
        ));
        let mallory = core
            .admin_create_user(
                &root,
                CreateUser {
                    handle: "mallory".into(),
                    email: Some("mallory@example.com".into()),
                    password: Some(PASSWORD.into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(mallory.email_verified);
        assert_eq!(mallory.email.as_deref(), Some("mallory@example.com"));
    }

    #[tokio::test]
    async fn admin_delete_user_guards_and_purges() {
        let (core, root, vice) = two_admins().await;
        let bob = plain_user(&core, "bob").await;
        // Non-admin cannot delete.
        assert!(matches!(
            core.admin_delete_user(&bob, root.id).await,
            Err(CoreError::Forbidden)
        ));
        // Self-delete refused.
        assert!(matches!(
            core.admin_delete_user(&root, root.id).await,
            Err(CoreError::Invalid(_))
        ));
        // Last active admin cannot be deleted: suspend vice and root so solo is the only active
        // admin, then have the suspended vice (still an admin) attempt the delete.
        let solo = plain_user(&core, "solo").await;
        core.suspend_user(&root, vice.id).await.unwrap();
        let solo = core.grant_admin(&root, solo.id).await.unwrap();
        core.suspend_user(&solo, root.id).await.unwrap();
        assert!(matches!(
            core.admin_delete_user(&vice, solo.id).await,
            Err(CoreError::Invalid(_))
        ));
        // Refused while the target owns live repositories.
        let owner = plain_user(&core, "owner").await;
        core.create_repo(
            &owner,
            CreateRepo {
                name: "proj".into(),
                description: String::new(),
                visibility: Visibility::Public,
                readme: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            core.admin_delete_user(&solo, owner.id).await,
            Err(CoreError::Invalid(_))
        ));
        // Deleted repositories are purged with the account.
        core.delete_repo(&owner, "owner", "proj", "owner/proj")
            .await
            .unwrap();
        core.admin_delete_user(&solo, owner.id).await.unwrap();
        assert!(core.user_by_handle("owner").await.unwrap().is_none());
        assert!(
            starforged_db::repos::list_deleted_by_owner(core.db(), owner.id)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
