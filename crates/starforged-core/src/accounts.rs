//! Accounts: creation, password authentication, lookups.

use std::sync::OnceLock;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use starforged_db::users::{self, NewUser, UserRow};

use crate::{Core, CoreError, CoreResult, validate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: i64,
    pub handle: String,
    pub display_name: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub is_admin: bool,
    pub active: bool,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> User {
        User {
            id: row.id,
            handle: row.handle,
            display_name: row.display_name,
            email: row.email,
            email_verified: row.email_verified,
            is_admin: row.is_admin,
            active: row.state == "active",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CreateUser {
    pub handle: String,
    pub display_name: String,
    pub email: Option<String>,
    /// The caller vouches for `email`: site admins creating accounts, and sign-ups through an invite that was
    /// sent to that address.
    pub email_verified: bool,
    /// `None` creates an account that cannot sign in with a password.
    pub password: Option<String>,
    pub is_admin: bool,
}

impl Core {
    pub async fn create_user(&self, input: CreateUser) -> CoreResult<User> {
        let handle = validate::handle(&input.handle)?;
        let email = input.email.as_deref().map(validate::email).transpose()?;
        let display_name = validate::display_name(&input.display_name)?;
        let password_hash = match input.password {
            Some(password) => {
                validate::password(&password)?;
                Some(hash_password(password).await?)
            }
            None => None,
        };
        let new = NewUser {
            handle: &handle,
            display_name: &display_name,
            email: email.as_deref(),
            email_verified: input.email_verified && email.is_some(),
            password_hash: password_hash.as_deref(),
            is_admin: input.is_admin,
        };
        let id = users::insert(self.db(), &new).await.map_err(|e| {
            if e.is_unique_violation() {
                CoreError::Conflict("that handle or email is already taken".into())
            } else {
                e.into()
            }
        })?;
        self.user_by_id(id)
            .await?
            .ok_or_else(|| CoreError::Internal("user missing after insert".into()))
    }

    /// `login` is a handle or an email. Unknown accounts, wrong passwords, password-less accounts,
    /// and suspended accounts all fail with `Unauthenticated`.
    pub async fn authenticate_password(&self, login: &str, password: &str) -> CoreResult<User> {
        let login = login.trim().to_ascii_lowercase();
        let row = if login.contains('@') {
            users::by_email(self.db(), &login).await?
        } else {
            users::by_handle(self.db(), &login).await?
        };
        let stored = row.as_ref().and_then(|r| r.password_hash.clone());
        let has_password = stored.is_some();
        // Unknown accounts are verified against a dummy hash so timing does not reveal which logins exist.
        let matches = verify_password(stored, password.to_owned()).await?;
        match row {
            Some(row) if matches && has_password && row.state == "active" => Ok(row.into()),
            _ => Err(CoreError::Unauthenticated),
        }
    }

    pub async fn user_by_id(&self, id: i64) -> CoreResult<Option<User>> {
        Ok(users::by_id(self.db(), id).await?.map(User::from))
    }

    pub async fn user_by_handle(&self, handle: &str) -> CoreResult<Option<User>> {
        Ok(
            users::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
                .await?
                .map(User::from),
        )
    }
}

pub(crate) async fn hash_password(password: String) -> CoreResult<String> {
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
    })
    .await
    .map_err(|e| CoreError::Internal(e.to_string()))?
    .map_err(|e| CoreError::Internal(e.to_string()))
}

async fn verify_password(stored: Option<String>, password: String) -> CoreResult<bool> {
    tokio::task::spawn_blocking(move || {
        let hash = stored.unwrap_or_else(|| dummy_hash().to_owned());
        PasswordHash::new(&hash)
            .map(|parsed| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            })
            .unwrap_or(false)
    })
    .await
    .map_err(|e| CoreError::Internal(e.to_string()))
}

fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        Argon2::default()
            .hash_password(b"starforge timing equalizer")
            .expect("argon2 hashing works")
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_core, user};

    const PASSWORD: &str = "correct horse battery";

    #[tokio::test]
    async fn create_and_authenticate_by_handle_or_email() {
        let (core, _f) = test_core().await;
        let created = core
            .create_user(CreateUser {
                handle: "Alice".into(),
                email: Some("Alice@Example.com".into()),
                password: Some(PASSWORD.into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(created.handle, "alice");
        assert_eq!(created.email.as_deref(), Some("alice@example.com"));
        assert!(created.active);
        assert_eq!(
            core.authenticate_password("alice", PASSWORD)
                .await
                .unwrap()
                .id,
            created.id
        );
        assert_eq!(
            core.authenticate_password("ALICE@example.com", PASSWORD)
                .await
                .unwrap()
                .id,
            created.id
        );
        assert!(matches!(
            core.authenticate_password("alice", "wrong password!").await,
            Err(CoreError::Unauthenticated)
        ));
        assert!(matches!(
            core.authenticate_password("nobody", PASSWORD).await,
            Err(CoreError::Unauthenticated)
        ));
        assert_eq!(
            core.user_by_handle("ALICE").await.unwrap().unwrap().id,
            created.id
        );
    }

    #[tokio::test]
    async fn rejects_duplicates_and_invalid_input() {
        let (core, _f) = test_core().await;
        user(&core, "alice").await;
        let dup = core
            .create_user(CreateUser {
                handle: "ALICE".into(),
                ..Default::default()
            })
            .await;
        assert!(matches!(dup, Err(CoreError::Conflict(_))));
        let reserved = core
            .create_user(CreateUser {
                handle: "login".into(),
                ..Default::default()
            })
            .await;
        assert!(matches!(reserved, Err(CoreError::Invalid(_))));
        let short = core
            .create_user(CreateUser {
                handle: "bob".into(),
                password: Some("short".into()),
                ..Default::default()
            })
            .await;
        assert!(matches!(short, Err(CoreError::Invalid(_))));
    }

    #[tokio::test]
    async fn suspended_and_passwordless_accounts_cannot_log_in() {
        let (core, _f) = test_core().await;
        let carol = core
            .create_user(CreateUser {
                handle: "carol".into(),
                password: Some(PASSWORD.into()),
                ..Default::default()
            })
            .await
            .unwrap();
        starforged_db::users::set_state(core.db(), carol.id, "suspended")
            .await
            .unwrap();
        assert!(matches!(
            core.authenticate_password("carol", PASSWORD).await,
            Err(CoreError::Unauthenticated)
        ));
        assert!(!core.user_by_id(carol.id).await.unwrap().unwrap().active);
        user(&core, "dave").await;
        assert!(matches!(
            core.authenticate_password("dave", "").await,
            Err(CoreError::Unauthenticated)
        ));
    }
}
