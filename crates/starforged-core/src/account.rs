//! Account settings (forge-basics design §4.6): profile, email address, password, and web sessions.

use std::pin::Pin;

use starforged_db::orgs as db_orgs;
use starforged_db::repos as db_repos;
use starforged_db::sessions as db_sessions;
use starforged_db::{now, users, web_sessions};

use crate::accounts::{User, hash_password};
use crate::email_tokens::{Purpose, VERIFY_TTL_SECS};
use crate::{Core, CoreError, CoreResult, mail, validate};

/// Bounded batch size for account deletion's per-session removal (D4).
pub(crate) const ACCOUNT_DELETE_BATCH: i64 = 100;

/// The future an [`AccountDeleteHook`] returns.
pub type AccountDeleteHookFuture = Pin<Box<dyn Future<Output = CoreResult<()>> + Send>>;

/// Test seam for the account-deletion interruption test (mirrors
/// [`crate::merge::PreCasHook`]): fired after each uploaded session
/// [`Core::delete_uploaded_sessions`] removes, while the account row still
/// exists. Returning an error aborts the deletion mid-way, keeping the
/// already-removed sessions gone — a rerun must then finish the job. The
/// hook is async so tests can insert work mid-deletion (e.g. a session
/// arriving after the drain).
#[derive(Clone)]
pub struct AccountDeleteHook(std::sync::Arc<dyn Fn() -> AccountDeleteHookFuture + Send + Sync>);
impl std::fmt::Debug for AccountDeleteHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountDeleteHook(..)")
    }
}

impl AccountDeleteHook {
    pub fn new(
        hook: impl Fn() -> AccountDeleteHookFuture + Send + Sync + 'static,
    ) -> AccountDeleteHook {
        AccountDeleteHook(std::sync::Arc::new(hook))
    }

    // The hook runs through `(hook.0)` at the call site.
}

/// One signed-in browser, for the sessions page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: i64,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub user_agent: String,
    pub ip: String,
}

/// What a request to change the email address did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailChange {
    /// Mail is off: the new address is in use now, unverified.
    Changed,
    /// A confirmation link went to the new address; the change happens when it is used.
    ConfirmationSent,
    /// A confirmation link went out less than 5 minutes ago, so nothing was sent.
    Throttled,
}

pub(crate) fn email_taken() -> CoreError {
    CoreError::Conflict("That email address is already in use.".into())
}

impl Core {
    pub async fn update_profile(&self, user: &User, display_name: &str) -> CoreResult<User> {
        let display_name = validate::display_name(display_name)?;
        users::set_display_name(self.db(), user.id, &display_name).await?;
        self.audit(
            Some(user.id),
            "account.profile",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        self.user_by_id(user.id).await?.ok_or(CoreError::NotFound)
    }

    /// Changes the password after checking the current one; every session except `current_session` ends.
    pub async fn change_password(
        &self,
        user: &User,
        current_session: i64,
        current: &str,
        new: &str,
    ) -> CoreResult<()> {
        if self
            .authenticate_password(&user.handle, current)
            .await
            .is_err()
        {
            return Err(CoreError::Invalid(
                "The current password is incorrect.".into(),
            ));
        }
        validate::password(new)?;
        let hash = hash_password(new.to_owned()).await?;
        users::set_password_hash(self.db(), user.id, &hash).await?;
        web_sessions::delete_for_user_except(self.db(), user.id, current_session).await?;
        self.audit(
            Some(user.id),
            "account.password_change",
            &format!("user:{}", user.handle),
            "",
        )
        .await?;
        Ok(())
    }

    /// With mail, a confirmation link goes to the new address and the change waits for it; without mail,
    /// the new address applies at once, unverified.
    pub async fn change_email(&self, user: &User, new_email: &str) -> CoreResult<EmailChange> {
        let email = validate::email(new_email)?;
        if user.email.as_deref() == Some(email.as_str()) {
            return Err(CoreError::Invalid(
                "That is already your email address.".into(),
            ));
        }
        if users::by_email(self.db(), &email).await?.is_some() {
            return Err(email_taken());
        }
        if !self.mail_enabled() {
            users::set_email(self.db(), user.id, Some(&email), false)
                .await
                .map_err(|e| {
                    if e.is_unique_violation() {
                        email_taken()
                    } else {
                        e.into()
                    }
                })?;
            self.audit(
                Some(user.id),
                "account.email_change",
                &format!("user:{}", user.handle),
                "",
            )
            .await?;
            return Ok(EmailChange::Changed);
        }
        let Some(secret) = self
            .issue_email_token(user.id, Purpose::ChangeEmail, &email, VERIFY_TTL_SECS, true)
            .await?
        else {
            return Ok(EmailChange::Throttled);
        };
        let link = format!("{}/verify/{secret}", self.config().base_url);
        self.queue_email(mail::confirm_email(&email, &user.handle, &link)?)
            .await?;
        Ok(EmailChange::ConfirmationSent)
    }

    pub async fn list_sessions(&self, user: &User) -> CoreResult<Vec<SessionInfo>> {
        Ok(web_sessions::list_for_user(self.db(), user.id, now())
            .await?
            .into_iter()
            .map(|row| SessionInfo {
                id: row.id,
                created_at: row.created_at,
                last_seen_at: row.last_seen_at,
                user_agent: row.user_agent,
                ip: row.ip,
            })
            .collect())
    }

    /// Ends one of the user's sessions; `NotFound` for a session that is not theirs.
    pub async fn revoke_session(&self, user: &User, session_id: i64) -> CoreResult<()> {
        if !web_sessions::delete_by_id_for_user(self.db(), session_id, user.id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "account.session_revoke",
            &format!("user:{}", user.handle),
            &format!("session:{session_id}"),
        )
        .await
    }

    /// Ends every session of the user except `keep`; returns how many ended.
    pub async fn revoke_other_sessions(&self, user: &User, keep: i64) -> CoreResult<u64> {
        let ended = web_sessions::delete_for_user_except(self.db(), user.id, keep).await?;
        self.audit(
            Some(user.id),
            "account.session_revoke",
            &format!("user:{}", user.handle),
            "others",
        )
        .await?;
        Ok(ended)
    }

    /// Installs (or clears) the account-deletion interruption test hook.
    pub fn set_account_delete_hook(&self, hook: Option<AccountDeleteHook>) {
        if let Ok(mut guard) = self.inner.account_delete_hook.lock() {
            *guard = hook;
        }
    }

    /// Fires the interruption test hook, if one is installed.
    async fn fire_account_delete_hook(&self) -> CoreResult<()> {
        let hook = self
            .inner
            .account_delete_hook
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        match hook {
            Some(hook) => (hook.0)().await,
            None => Ok(()),
        }
    }

    /// Deletes every session the user uploaded, through
    /// [`Core::remove_session_rows`] (blob refcount decrements, commit links,
    /// and search-index documents), in bounded batches (D4). Each step is
    /// idempotent: a rerun after an interruption finds only the sessions
    /// that remain. Returns how many sessions were removed.
    pub(crate) async fn delete_uploaded_sessions(&self, user_id: i64) -> CoreResult<usize> {
        let mut removed_total = 0;
        loop {
            let batch =
                db_sessions::sessions_uploaded_by(self.db(), user_id, ACCOUNT_DELETE_BATCH).await?;
            if batch.is_empty() {
                return Ok(removed_total);
            }
            for session in &batch {
                self.remove_session_rows(
                    Some(user_id),
                    session.repo_id,
                    session,
                    "session.deleted",
                )
                .await?;
                removed_total += 1;
                self.fire_account_delete_hook().await?;
            }
        }
    }

    /// Deletes the account once the user typed their handle (forge-basics design §4.6). Refused while the user
    /// owns repositories that are not deleted, is the only active site admin, or is the only owner of an
    /// organization — every refusal is re-checked inside the final locked transaction that deletes the
    /// user row (see `delete_user_unless_sole_owner`), so a concurrent demotion, owner removal, repo
    /// creation, or session upload cannot produce a state the row-delete cascade would silently
    /// destroy. Access tokens and web sessions are revoked after the pre-checks, so a deleting
    /// account can no longer act. Their uploaded sessions go through the session-delete path
    /// (blob refcounts, index documents) before the user row, in bounded batches, so an interrupted
    /// deletion finishes on rerun (D4). Their deleted repositories are purged at once; collaborator
    /// grants go with the account; audit entries stay with the actor cleared.
    pub async fn delete_account(&self, user: &User, confirm: &str) -> CoreResult<()> {
        if confirm.trim().to_ascii_lowercase() != user.handle {
            return Err(CoreError::Invalid(format!(
                "Type your handle, {}, to confirm.",
                user.handle
            )));
        }
        let owned: Vec<String> = db_repos::list_by_owner(self.db(), user.id)
            .await?
            .into_iter()
            .map(|r| r.name)
            .collect();
        if !owned.is_empty() {
            return Err(CoreError::Invalid(format!(
                "Delete your repositories first: {}.",
                owned.join(", ")
            )));
        }
        if user.is_admin && users::count_active_admins_except(self.db(), user.id).await? == 0 {
            return Err(CoreError::Invalid(
                "You are the only site administrator; make another user an administrator first."
                    .into(),
            ));
        }
        let sole = db_orgs::sole_owned_orgs(self.db(), user.id).await?;
        if !sole.is_empty() {
            return Err(CoreError::Invalid(format!(
                "You are the only owner of {}: make another user an owner first.",
                sole.join(", ")
            )));
        }
        // Credentials end before the drain: the user can no longer act
        // while their sessions are being removed.
        starforged_db::tokens::revoke_for_user(self.db(), user.id).await?;
        web_sessions::delete_for_user(self.db(), user.id).await?;
        // Drain, purge, and the atomic final step — bounded retries when
        // sessions or repositories arrive after the drain (the final step
        // re-checks every refusal inside its transaction, so nothing the
        // cascade would silently drop is ever lost).
        for attempt in 0..3 {
            self.delete_uploaded_sessions(user.id).await?;
            self.purge_deleted_repos_of(user.id, Some(user.id)).await?;
            match db_orgs::delete_user_unless_sole_owner(self.db(), user.id).await? {
                db_orgs::AccountDelete::Deleted => break,
                db_orgs::AccountDelete::SessionsRemain(_)
                | db_orgs::AccountDelete::OwnedRepos(_) => {
                    if attempt == 2 {
                        return Err(CoreError::Invalid(
                            "Account deletion did not finish: new activity arrived; try again."
                                .into(),
                        ));
                    }
                }
                db_orgs::AccountDelete::SoleAdmin => {
                    return Err(CoreError::Invalid(
                        "You are the only site administrator; make another user an administrator first."
                            .into(),
                    ));
                }
                db_orgs::AccountDelete::SoleOwner(ids) => {
                    let mut handles = Vec::new();
                    for org_id in ids {
                        if let Some(handle) = db_orgs::owner_handle_by_id(self.db(), org_id).await?
                        {
                            handles.push(handle);
                        }
                    }
                    return Err(CoreError::Invalid(format!(
                        "You are the only owner of {}: make another user an owner first.",
                        handles.join(", ")
                    )));
                }
            }
        }
        // Recorded after the account goes, with no actor: the same final row
        // as clearing the actor over the user-row delete, without writing an
        // entry for a deletion that was refused.
        self.audit(None, "account.delete", &format!("user:{}", user.handle), "")
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{test_core, test_core_with, user, with_file_mail};

    const PASSWORD: &str = "correct horse battery";
    const NEW_PASSWORD: &str = "a brand new password";

    async fn alice(core: &Core) -> User {
        core.create_user(CreateUser {
            handle: "alice".into(),
            email: Some("alice@example.com".into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn changing_the_password_ends_other_sessions() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        let (_, first) = core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap()
            .into_session();
        let (_, second) = core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap()
            .into_session();
        let current = core
            .web_session(&first.cookie_value)
            .await
            .unwrap()
            .unwrap()
            .session_id;
        let wrong = core
            .change_password(&alice, current, "not my password", NEW_PASSWORD)
            .await
            .unwrap_err();
        assert!(
            matches!(&wrong, CoreError::Invalid(m) if m.contains("current password")),
            "{wrong}"
        );
        core.change_password(&alice, current, PASSWORD, NEW_PASSWORD)
            .await
            .unwrap();
        assert!(
            core.web_session(&first.cookie_value)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            core.web_session(&second.cookie_value)
                .await
                .unwrap()
                .is_none()
        );
        core.login("alice", NEW_PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sessions_are_listed_and_revoked_by_their_owner() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        let bob = user(&core, "bob").await;
        core.login("alice", PASSWORD, "firefox", "10.0.0.1")
            .await
            .unwrap();
        core.login("alice", PASSWORD, "curl", "10.0.0.2")
            .await
            .unwrap();
        let listed = core.list_sessions(&alice).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(
            listed
                .iter()
                .any(|s| s.user_agent == "firefox" && s.ip == "10.0.0.1")
        );
        assert!(matches!(
            core.revoke_session(&bob, listed[0].id).await,
            Err(CoreError::NotFound)
        ));
        core.revoke_session(&alice, listed[0].id).await.unwrap();
        assert_eq!(core.list_sessions(&alice).await.unwrap().len(), 1);
        assert_eq!(
            core.revoke_other_sessions(&alice, listed[1].id)
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn activity_is_recorded_at_most_every_five_minutes() {
        let (core, _f) = test_core().await;
        alice(&core).await;
        let (_, session) = core
            .login("alice", PASSWORD, "ua", "127.0.0.1")
            .await
            .unwrap()
            .into_session();
        let last_seen = || async {
            let ts: i64 = sqlx::query_scalar("SELECT last_seen_at FROM web_sessions")
                .fetch_one(core.db().pool())
                .await
                .unwrap();
            ts
        };
        sqlx::query("UPDATE web_sessions SET last_seen_at = $1")
            .bind(100_i64)
            .execute(core.db().pool())
            .await
            .unwrap();
        core.web_session(&session.cookie_value)
            .await
            .unwrap()
            .unwrap();
        assert!(last_seen().await >= starforged_db::now() - 5);
        let recent = starforged_db::now() - 60;
        sqlx::query("UPDATE web_sessions SET last_seen_at = $1")
            .bind(recent)
            .execute(core.db().pool())
            .await
            .unwrap();
        core.web_session(&session.cookie_value)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            last_seen().await,
            recent,
            "recent activity is not rewritten"
        );
    }

    #[tokio::test]
    async fn email_changes_need_confirmation_when_mail_is_on() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = alice(&core).await;
        core.create_user(CreateUser {
            handle: "bob".into(),
            email: Some("bob@example.com".into()),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(matches!(
            core.change_email(&alice, "bob@example.com").await,
            Err(CoreError::Conflict(_))
        ));
        assert!(matches!(
            core.change_email(&alice, "alice@example.com").await,
            Err(CoreError::Invalid(_))
        ));
        assert_eq!(
            core.change_email(&alice, "alice@new.example")
                .await
                .unwrap(),
            EmailChange::ConfirmationSent
        );
        assert_eq!(
            core.change_email(&alice, "alice@other.example")
                .await
                .unwrap(),
            EmailChange::Throttled
        );
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(mail[0].contains("To: alice@new.example"), "{}", mail[0]);
        assert_eq!(
            core.user_by_id(alice.id)
                .await
                .unwrap()
                .unwrap()
                .email
                .as_deref(),
            Some("alice@example.com"),
            "the old address stays until the link is used"
        );
        let link = crate::mail::testing::find_link(&mail[0], "/verify/").unwrap();
        let secret = link.rsplit('/').next().unwrap();
        assert!(core.email_link_valid(secret).await.unwrap());
        let user = core.verify_email(secret).await.unwrap();
        assert_eq!(
            (user.email.as_deref(), user.email_verified),
            (Some("alice@new.example"), true)
        );
    }

    #[tokio::test]
    async fn without_mail_email_changes_apply_unverified() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        assert_eq!(
            core.change_email(&alice, "Alice@New.example")
                .await
                .unwrap(),
            EmailChange::Changed
        );
        let user = core.user_by_id(alice.id).await.unwrap().unwrap();
        assert_eq!(
            (user.email.as_deref(), user.email_verified),
            (Some("alice@new.example"), false)
        );
    }

    #[tokio::test]
    async fn display_names_are_validated() {
        let (core, _f) = test_core().await;
        let alice = alice(&core).await;
        assert_eq!(
            core.update_profile(&alice, "  Alice L.  ")
                .await
                .unwrap()
                .display_name,
            "Alice L."
        );
        assert!(matches!(
            core.update_profile(&alice, &"x".repeat(101)).await,
            Err(CoreError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn change_email_links_survive_an_address_conflict() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let alice = alice(&core).await;
        assert_eq!(
            core.change_email(&alice, "shared@example.com")
                .await
                .unwrap(),
            EmailChange::ConfirmationSent
        );
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        let link = crate::mail::testing::find_link(&mail[0], "/verify/").unwrap();
        let secret = link.rsplit('/').next().unwrap().to_owned();
        core.create_user(CreateUser {
            handle: "bob".into(),
            email: Some("shared@example.com".into()),
            ..Default::default()
        })
        .await
        .unwrap();
        assert!(matches!(
            core.verify_email(&secret).await,
            Err(CoreError::Conflict(_))
        ));
        assert!(
            core.email_link_valid(&secret).await.unwrap(),
            "the link is still usable"
        );
        assert_eq!(
            core.user_by_id(alice.id)
                .await
                .unwrap()
                .unwrap()
                .email
                .as_deref(),
            Some("alice@example.com")
        );
    }
    #[tokio::test]
    async fn accounts_go_only_without_repositories_and_never_the_last_admin() {
        use crate::accounts::CreateUser;
        use crate::permission::{Permission, Visibility};
        use crate::repos::CreateRepo;
        use crate::tokens::Scope;
        let (core, _f) = test_core().await;
        let root = core
            .create_user(CreateUser {
                handle: "root".into(),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        let repo = |name: &str| CreateRepo {
            name: name.into(),
            description: String::new(),
            visibility: Visibility::Public,
            readme: false,
        };
        let kept = core
            .create_repo(&alice, "alice", repo("kept"))
            .await
            .unwrap();
        let gone = core
            .create_repo(&alice, "alice", repo("gone"))
            .await
            .unwrap();
        core.create_repo(&bob, "bob", repo("theirs")).await.unwrap();
        core.set_collaborator(&bob, "bob", "theirs", "alice", Permission::Write)
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "gone", "alice/gone")
            .await
            .unwrap();
        core.create_token(&alice, "laptop", &[Scope::RepoRead], 30)
            .await
            .unwrap();
        assert!(matches!(
            core.delete_account(&alice, "bob").await,
            Err(CoreError::Invalid(_))
        ));
        let refused = core.delete_account(&alice, "alice").await;
        assert!(
            matches!(&refused, Err(CoreError::Invalid(m)) if m.contains("kept")),
            "{refused:?}"
        );
        let last_admin = core.delete_account(&root, "root").await;
        assert!(
            matches!(&last_admin, Err(CoreError::Invalid(m)) if m.contains("only site administrator")),
            "{last_admin:?}"
        );
        core.delete_repo(&alice, "alice", "kept", "alice/kept")
            .await
            .unwrap();
        core.delete_account(&alice, " ALICE ").await.unwrap();
        assert!(core.user_by_handle("alice").await.unwrap().is_none());
        for id in [kept.id, gone.id] {
            assert!(
                starforged_db::repos::by_id(core.db(), id)
                    .await
                    .unwrap()
                    .is_none(),
                "deleted repositories are purged at once"
            );
            assert!(!core.repo_path(id).exists());
        }
        assert!(
            core.collaborators(&bob, "bob", "theirs")
                .await
                .unwrap()
                .is_empty(),
            "collaborator grants go with the account"
        );
        let tokens: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM access_tokens")
            .fetch_one(core.db().pool())
            .await
            .unwrap();
        assert_eq!(tokens, 0);
        let entry = starforged_db::audit::recent(core.db(), 1)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(
            (entry.action.as_str(), entry.target.as_str(), entry.actor_id),
            ("account.delete", "user:alice", None),
            "the entry survives with its actor cleared"
        );
        user(&core, "alice").await;
    }
}
