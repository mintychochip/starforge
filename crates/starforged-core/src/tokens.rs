//! Personal access tokens (spec §6.1): `sfp_` + 64 hex characters, stored as SHA-256, scoped, expiring.

use starforged_db::tokens::{self as db_tokens, NewToken, TokenRow};

use crate::accounts::User;
use crate::{Core, CoreError, CoreResult, crypto};

pub const TOKEN_PREFIX: &str = "sfp_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    RepoRead,
    RepoWrite,
    TrailWrite,
    SessionUpload,
    SandboxRun,
    Admin,
}

impl Scope {
    pub const ALL: [Scope; 6] = [
        Scope::RepoRead,
        Scope::RepoWrite,
        Scope::TrailWrite,
        Scope::SessionUpload,
        Scope::SandboxRun,
        Scope::Admin,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Scope::RepoRead => "repo:read",
            Scope::RepoWrite => "repo:write",
            Scope::TrailWrite => "trail:write",
            Scope::SessionUpload => "session:upload",
            Scope::SandboxRun => "sandbox:run",
            Scope::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|scope| scope.as_str() == s)
    }
}

/// Parses a comma- or whitespace-separated scope list, dropping duplicates. Unknown or empty lists are invalid.
pub fn parse_scopes(input: &str) -> CoreResult<Vec<Scope>> {
    let mut scopes = Vec::new();
    for part in input
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
    {
        let scope = Scope::parse(part)
            .ok_or_else(|| CoreError::Invalid(format!("unknown scope '{part}'")))?;
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        return Err(CoreError::Invalid("at least one scope is required".into()));
    }
    Ok(scopes)
}

pub fn format_scopes(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether `held` allows an operation needing `needed`: `repo:write` implies `repo:read`; `admin` implies everything.
pub fn grants(held: &[Scope], needed: Scope) -> bool {
    held.contains(&needed)
        || held.contains(&Scope::Admin)
        || (needed == Scope::RepoRead && held.contains(&Scope::RepoWrite))
}

#[derive(Debug, Clone)]
pub struct CreatedToken {
    pub id: i64,
    /// Shown to the user once; only its hash is stored.
    pub secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    pub id: i64,
    pub name: String,
    /// Last four characters of the secret.
    pub hint: String,
    pub scopes: Vec<Scope>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct TokenAuth {
    pub user: User,
    pub scopes: Vec<Scope>,
    pub token_id: i64,
}

impl Core {
    pub async fn create_token(
        &self,
        user: &User,
        name: &str,
        scopes: &[Scope],
        expires_in_days: u32,
    ) -> CoreResult<CreatedToken> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(CoreError::Invalid("token names are 1-64 characters".into()));
        }
        if !(1..=366).contains(&expires_in_days) {
            return Err(CoreError::Invalid("tokens expire after 1-366 days".into()));
        }
        if scopes.is_empty() {
            return Err(CoreError::Invalid("at least one scope is required".into()));
        }
        if scopes.contains(&Scope::Admin) && !user.is_admin {
            return Err(CoreError::Forbidden);
        }
        let secret = format!("{TOKEN_PREFIX}{}", crypto::random_hex(32));
        let hint = &secret[secret.len() - 4..];
        let expires_at = starforged_db::now() + i64::from(expires_in_days) * 86_400;
        let id = db_tokens::insert(
            self.db(),
            &NewToken {
                user_id: user.id,
                name,
                token_hash: &crypto::sha256_hex(&secret),
                token_hint: hint,
                scopes: &format_scopes(scopes),
                expires_at,
            },
        )
        .await?;
        self.audit(Some(user.id), "token.create", &format!("token:{id}"), name)
            .await?;
        Ok(CreatedToken { id, secret })
    }

    /// Resolves a secret to its user and scopes. Unknown, revoked, and expired tokens, and tokens of
    /// suspended users, fail with `Unauthenticated`.
    pub async fn authenticate_token(&self, secret: &str) -> CoreResult<TokenAuth> {
        if !secret.starts_with(TOKEN_PREFIX) {
            return Err(CoreError::Unauthenticated);
        }
        let row = db_tokens::by_hash(self.db(), &crypto::sha256_hex(secret))
            .await?
            .ok_or(CoreError::Unauthenticated)?;
        if row.revoked_at.is_some() || row.expires_at <= starforged_db::now() {
            return Err(CoreError::Unauthenticated);
        }
        let user = self
            .user_by_id(row.user_id)
            .await?
            .filter(|u| u.active)
            .ok_or(CoreError::Unauthenticated)?;
        let scopes = parse_scopes(&row.scopes)?;
        db_tokens::touch(self.db(), row.id).await?;
        Ok(TokenAuth {
            user,
            scopes,
            token_id: row.id,
        })
    }

    pub async fn list_tokens(&self, user: &User) -> CoreResult<Vec<TokenInfo>> {
        db_tokens::list_for_user(self.db(), user.id)
            .await?
            .into_iter()
            .map(token_info)
            .collect()
    }

    pub async fn revoke_token(&self, user: &User, token_id: i64) -> CoreResult<()> {
        if !db_tokens::revoke(self.db(), user.id, token_id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "token.revoke",
            &format!("token:{token_id}"),
            "",
        )
        .await
    }
}

fn token_info(row: TokenRow) -> CoreResult<TokenInfo> {
    Ok(TokenInfo {
        id: row.id,
        name: row.name,
        hint: row.token_hint,
        scopes: parse_scopes(&row.scopes)?,
        created_at: row.created_at,
        expires_at: row.expires_at,
        last_used_at: row.last_used_at,
        revoked: row.revoked_at.is_some(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_core, user};

    #[test]
    fn scope_parsing_and_implication() {
        assert_eq!(
            parse_scopes("repo:read, repo:write repo:read").unwrap(),
            vec![Scope::RepoRead, Scope::RepoWrite]
        );
        assert!(parse_scopes("").is_err());
        assert!(parse_scopes("repo:delete").is_err());
        assert!(grants(&[Scope::RepoWrite], Scope::RepoRead));
        assert!(!grants(&[Scope::RepoRead], Scope::RepoWrite));
        assert!(grants(&[Scope::Admin], Scope::SessionUpload));
        assert!(grants(&[Scope::Admin], Scope::SandboxRun));
        assert!(!grants(&[Scope::RepoWrite], Scope::SandboxRun));
        assert_eq!(
            format_scopes(&[Scope::RepoRead, Scope::TrailWrite]),
            "repo:read trail:write"
        );
    }

    #[test]
    fn sandbox_run_scope_round_trip() {
        assert_eq!(Scope::ALL.len(), 6);
        assert_eq!(Scope::SandboxRun.as_str(), "sandbox:run");
        assert_eq!(Scope::parse("sandbox:run"), Some(Scope::SandboxRun));
        assert_eq!(
            parse_scopes("sandbox:run").unwrap(),
            vec![Scope::SandboxRun]
        );
        assert_eq!(
            format_scopes(&parse_scopes("sandbox:run").unwrap()),
            "sandbox:run"
        );
        assert!(parse_scopes("bogus:run").is_err());
    }

    #[tokio::test]
    async fn token_lifecycle_is_audited() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let created = core
            .create_token(&alice, "laptop", &[Scope::RepoWrite], 30)
            .await
            .unwrap();
        assert!(created.secret.starts_with(TOKEN_PREFIX));
        assert_eq!(created.secret.len(), TOKEN_PREFIX.len() + 64);
        let auth = core.authenticate_token(&created.secret).await.unwrap();
        assert_eq!(
            (auth.user.id, auth.scopes.clone(), auth.token_id),
            (alice.id, vec![Scope::RepoWrite], created.id)
        );
        let listed = core.list_tokens(&alice).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].hint, created.secret[created.secret.len() - 4..]);
        assert!(
            listed[0].last_used_at.is_some(),
            "authentication records last use"
        );
        assert!(!listed[0].revoked);
        core.revoke_token(&alice, created.id).await.unwrap();
        assert!(matches!(
            core.authenticate_token(&created.secret).await,
            Err(CoreError::Unauthenticated)
        ));
        assert!(matches!(
            core.revoke_token(&alice, created.id).await,
            Err(CoreError::NotFound)
        ));
        let actions: Vec<String> = starforged_db::audit::recent(core.db(), 10)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions, vec!["token.revoke", "token.create"]);
    }

    #[tokio::test]
    async fn rejects_foreign_expired_and_malformed_tokens() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        assert!(matches!(
            core.authenticate_token("ghp_abc").await,
            Err(CoreError::Unauthenticated)
        ));
        let unknown = format!("{TOKEN_PREFIX}{}", "0".repeat(64));
        assert!(matches!(
            core.authenticate_token(&unknown).await,
            Err(CoreError::Unauthenticated)
        ));
        assert!(matches!(
            core.create_token(&alice, "x", &[Scope::Admin], 1).await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.create_token(&alice, " ", &[Scope::RepoRead], 1).await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.create_token(&alice, "x", &[Scope::RepoRead], 0).await,
            Err(CoreError::Invalid(_))
        ));
        let token = core
            .create_token(&alice, "x", &[Scope::RepoRead], 1)
            .await
            .unwrap();
        assert!(matches!(
            core.revoke_token(&bob, token.id).await,
            Err(CoreError::NotFound)
        ));
        sqlx::query("UPDATE access_tokens SET expires_at = $1 WHERE id = $2")
            .bind(0_i64)
            .bind(token.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        assert!(matches!(
            core.authenticate_token(&token.secret).await,
            Err(CoreError::Unauthenticated)
        ));
    }
}
