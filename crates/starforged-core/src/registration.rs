//! Sign-up (forge-basics design §4.1): registration modes, invites, and verification of new addresses.

use starforged_db::invites::{self, InviteRow};
use starforged_db::now;

use crate::accounts::{CreateUser, User};
use crate::{Core, CoreError, CoreResult, crypto, validate};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    /// Only holders of an invite link sign up.
    Invite,
    /// Anyone signs up.
    Open,
    /// Addresses at `allowed_domains` sign up; requires mail.
    Domains,
}

impl RegistrationMode {
    pub fn parse(s: &str) -> Option<RegistrationMode> {
        match s {
            "invite" => Some(RegistrationMode::Invite),
            "open" => Some(RegistrationMode::Open),
            "domains" => Some(RegistrationMode::Domains),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RegistrationMode::Invite => "invite",
            RegistrationMode::Open => "open",
            RegistrationMode::Domains => "domains",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub mode: RegistrationMode,
    /// Lowercase domains that `domains` mode accepts.
    pub allowed_domains: Vec<String>,
}

impl Default for Registration {
    fn default() -> Registration {
        Registration {
            mode: RegistrationMode::Invite,
            allowed_domains: Vec::new(),
        }
    }
}

pub struct SignUp {
    pub handle: String,
    pub email: String,
    pub password: String,
    pub display_name: String,
    /// The code from an invite link; an invite lets its holder sign up in every mode.
    pub invite: Option<String>,
}

#[derive(Debug)]
pub enum SignedUp {
    /// The account can sign in now.
    Active(User),
    /// A verification link went to the account's address.
    VerificationSent(User),
}

impl SignedUp {
    pub fn user(&self) -> &User {
        match self {
            SignedUp::Active(user) | SignedUp::VerificationSent(user) => user,
        }
    }
}

fn unusable_invite() -> CoreError {
    CoreError::Invalid("This invite link is invalid, already used, or expired.".into())
}

impl Core {
    pub fn registration(&self) -> &Registration {
        &self.config().registration
    }

    /// Whether `/join` accepts people without an invite link (`open` and `domains` modes).
    pub fn sign_up_open(&self) -> bool {
        self.registration().mode != RegistrationMode::Invite
    }

    pub async fn sign_up(&self, input: SignUp) -> CoreResult<SignedUp> {
        let email = validate::email(&input.email)?;
        let code = input
            .invite
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_owned);
        let invite = match code {
            Some(code) => Some(self.claim_invite(&code).await?),
            None => None,
        };
        let result = self.sign_up_as(input, &email, invite.as_ref()).await;
        if let Some(invite) = &invite {
            match &result {
                Ok(signed_up) => {
                    invites::set_used_by(self.db(), invite.id, signed_up.user().id).await?
                }
                Err(_) => invites::release(self.db(), invite.id).await?,
            }
        }
        result
    }

    async fn sign_up_as(
        &self,
        input: SignUp,
        email: &str,
        invite: Option<&InviteRow>,
    ) -> CoreResult<SignedUp> {
        let verified_by_invite = match invite {
            Some(invite) => match &invite.email {
                Some(bound) if bound != email => {
                    return Err(CoreError::Invalid(
                        "This invite is for a different email address.".into(),
                    ));
                }
                Some(_) => true,
                None => false,
            },
            None => {
                self.check_open_sign_up(email)?;
                false
            }
        };
        let user = self
            .create_user(CreateUser {
                handle: input.handle,
                display_name: input.display_name,
                email: Some(email.to_owned()),
                email_verified: verified_by_invite,
                password: Some(input.password),
                is_admin: false,
            })
            .await?;
        let how = if invite.is_some() { "invite" } else { "" };
        self.audit(
            Some(user.id),
            "account.sign_up",
            &format!("user:{}", user.handle),
            how,
        )
        .await?;
        if self.mail_enabled() && !user.email_verified {
            self.send_verification(&user).await?;
            Ok(SignedUp::VerificationSent(user))
        } else {
            Ok(SignedUp::Active(user))
        }
    }

    /// Sign-up without an invite: refused in `invite` mode, limited to the listed domains in `domains` mode.
    fn check_open_sign_up(&self, email: &str) -> CoreResult<()> {
        let registration = self.registration();
        match registration.mode {
            RegistrationMode::Invite => {
                Err(CoreError::Invalid("Sign-up is by invitation only.".into()))
            }
            RegistrationMode::Open => Ok(()),
            RegistrationMode::Domains => {
                let domain = email.rsplit_once('@').map(|(_, d)| d).unwrap_or("");
                if registration.allowed_domains.iter().any(|d| d == domain) {
                    Ok(())
                } else {
                    Err(CoreError::Invalid(format!(
                        "Sign-up is limited to addresses at {}.",
                        registration.allowed_domains.join(", ")
                    )))
                }
            }
        }
    }

    /// Claims the invite behind `code` for a sign-up in progress.
    async fn claim_invite(&self, code: &str) -> CoreResult<InviteRow> {
        let row = invites::by_code_hash(self.db(), &crypto::sha256_hex(code))
            .await?
            .ok_or_else(unusable_invite)?;
        if invites::claim(self.db(), row.id, now()).await? {
            Ok(row)
        } else {
            Err(unusable_invite())
        }
    }

    /// For the sign-up form: the address a usable invite is bound to. `Invalid` when the code is unknown,
    /// used, revoked, or expired.
    pub async fn invite_email(&self, code: &str) -> CoreResult<Option<String>> {
        let row = invites::by_code_hash(self.db(), &crypto::sha256_hex(code))
            .await?
            .filter(|r| r.used_at.is_none() && r.revoked_at.is_none() && r.expires_at > now())
            .ok_or_else(unusable_invite)?;
        Ok(row.email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_core, test_core_with, with_file_mail};

    fn sign_up(handle: &str, email: &str, invite: Option<&str>) -> SignUp {
        SignUp {
            handle: handle.into(),
            email: email.into(),
            password: "correct horse battery".into(),
            display_name: String::new(),
            invite: invite.map(str::to_owned),
        }
    }

    async fn admin(core: &Core) -> User {
        core.create_user(CreateUser {
            handle: "root".into(),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    fn code_of(link: &str) -> String {
        link.split("invite=").nth(1).unwrap().to_owned()
    }

    #[tokio::test]
    async fn invite_mode_needs_an_invite_and_invites_work_once() {
        let (core, _f) = test_core().await;
        assert!(!core.sign_up_open());
        let closed = core
            .sign_up(sign_up("alice", "alice@example.com", None))
            .await
            .unwrap_err();
        assert!(
            matches!(&closed, CoreError::Invalid(m) if m.contains("invitation")),
            "{closed}"
        );

        let root = admin(&core).await;
        let invite = core.create_invite(&root, None).await.unwrap();
        assert!(!invite.emailed);
        let code = code_of(&invite.link);
        assert_eq!(core.invite_email(&code).await.unwrap(), None);
        let taken = core
            .sign_up(sign_up("root", "x@example.com", Some(&code)))
            .await
            .unwrap_err();
        assert!(
            matches!(taken, CoreError::Conflict(_)),
            "the handle is taken"
        );
        let alice = match core
            .sign_up(sign_up("alice", "alice@example.com", Some(&code)))
            .await
            .unwrap()
        {
            SignedUp::Active(user) => user,
            other => panic!("{other:?}"),
        };
        assert!(
            !alice.email_verified,
            "an invite without an address verifies nothing"
        );
        let reused = core
            .sign_up(sign_up("bob", "bob@example.com", Some(&code)))
            .await
            .unwrap_err();
        assert!(
            matches!(&reused, CoreError::Invalid(m) if m.contains("invite")),
            "{reused}"
        );
    }

    #[tokio::test]
    async fn email_bound_invites_verify_that_address() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        let root = admin(&core).await;
        let invite = core
            .create_invite(&root, Some("Carol@Example.com"))
            .await
            .unwrap();
        assert!(invite.emailed);
        core.run_due_jobs().await.unwrap();
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(
            mail[0].contains("To: carol@example.com") && mail[0].contains("root invited you"),
            "{}",
            mail[0]
        );
        let code = code_of(&invite.link);
        assert_eq!(
            core.invite_email(&code).await.unwrap().as_deref(),
            Some("carol@example.com")
        );
        let wrong = core
            .sign_up(sign_up("carol", "mallory@example.com", Some(&code)))
            .await
            .unwrap_err();
        assert!(
            matches!(&wrong, CoreError::Invalid(m) if m.contains("different email")),
            "{wrong}"
        );
        match core
            .sign_up(sign_up("carol", "carol@example.com", Some(&code)))
            .await
            .unwrap()
        {
            SignedUp::Active(user) => assert!(user.email_verified),
            other => panic!("{other:?}"),
        }
        core.run_due_jobs().await.unwrap();
        assert_eq!(
            fixture.mail().len(),
            1,
            "no verification email for an invited address"
        );
    }

    #[tokio::test]
    async fn open_and_domains_modes() {
        let (core, fixture) = test_core_with(|config, dir| {
            with_file_mail(config, dir);
            config.registration.mode = RegistrationMode::Open;
        })
        .await;
        assert!(core.sign_up_open());
        match core
            .sign_up(sign_up("dana", "dana@example.com", None))
            .await
            .unwrap()
        {
            SignedUp::VerificationSent(user) => assert!(!user.email_verified),
            other => panic!("{other:?}"),
        }
        core.run_due_jobs().await.unwrap();
        assert!(fixture.mail()[0].contains("Subject: Verify your email address"));

        let (core, _f) = test_core_with(|config, dir| {
            with_file_mail(config, dir);
            config.registration = Registration {
                mode: RegistrationMode::Domains,
                allowed_domains: vec!["example.com".into()],
            };
        })
        .await;
        let outside = core
            .sign_up(sign_up("eve", "eve@elsewhere.org", None))
            .await
            .unwrap_err();
        assert!(
            matches!(&outside, CoreError::Invalid(m) if m.contains("example.com")),
            "{outside}"
        );
        assert!(matches!(
            core.sign_up(sign_up("erin", "erin@example.com", None))
                .await
                .unwrap(),
            SignedUp::VerificationSent(_)
        ));
    }
}
