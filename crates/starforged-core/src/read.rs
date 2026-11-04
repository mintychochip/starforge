//! Session read rules (spec §6.4): who may see a session transcript.
//!
//! Denials are [`CoreError::NotFound`] (never `Forbidden`), so session ULIDs
//! stay undiscoverable — the same convention as [`Core::repo_for`] for
//! repositories the viewer cannot read.

use starforged_db::{
    collaborators, repos as db_repos, sessions as db_sessions, sessions::SessionRow,
};

use crate::{
    Core, CoreError, CoreResult,
    accounts::User,
    permission::{Permission, Viewer, effective},
    repos::{Repo, RepoAccess},
};

impl Core {
    /// Whether `user_id` holds an explicit grant on the repository: ownership or a
    /// collaborator row. Implicit public/internal read does not count.
    ///
    /// Team grants and org base permissions do not exist yet (orgs are M3); only
    /// what exists today is counted.
    pub async fn is_repo_member(&self, repo_id: i64, user_id: i64) -> CoreResult<bool> {
        let row = db_repos::by_id(self.db(), repo_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if row.owner_id == user_id {
            return Ok(true);
        }
        Ok(collaborators::permission(self.db(), repo_id, user_id)
            .await?
            .is_some())
    }

    /// The read-rule check over already-loaded rows. The caller must have
    /// established repo readability separately (or use
    /// [`Core::authorize_session_read_by_ulid`], which does); a viewer with no
    /// effective repo permission is denied (row 1).
    pub async fn authorize_session_read(
        &self,
        viewer: Option<Viewer>,
        repo: &Repo,
        session: &SessionRow,
    ) -> CoreResult<()> {
        if session.repo_id != repo.id {
            return Err(CoreError::NotFound);
        }
        // The collaborator lookup below serves both the effective-permission
        // check and membership, so no separate `is_repo_member` query is
        // needed here; that helper exists for callers holding only ids.
        let collaborator = match viewer {
            Some(v) => collaborators::permission(self.db(), repo.id, v.user_id)
                .await?
                .as_deref()
                .and_then(Permission::parse),
            None => None,
        };
        // Row 1: no effective read → 404 (not 403, so ULIDs stay undiscoverable).
        let permission = effective(repo.owner_id, repo.visibility, viewer, collaborator)
            .ok_or(CoreError::NotFound)?;
        let is_owner = viewer.map(|v| v.user_id == repo.owner_id).unwrap_or(false);
        let is_member = is_owner || collaborator.is_some();
        let is_admin = permission >= Permission::Admin;
        if can_read_session(viewer, repo, session, is_member, is_admin) {
            Ok(())
        } else {
            Err(CoreError::NotFound)
        }
    }

    /// [`Core::repo_for`] (read precondition — invisible repos 404 here) plus
    /// session lookup (unknown ULIDs 404) plus
    /// [`Core::authorize_session_read`]. Page handlers call this once and never
    /// duplicate the check.
    pub async fn authorize_session_read_by_ulid(
        &self,
        user: Option<&User>,
        owner: &str,
        name: &str,
        ulid: &str,
    ) -> CoreResult<(RepoAccess, SessionRow)> {
        let access = self.repo_for(user, owner, name).await?;
        let session = db_sessions::session_by_ulid(self.db(), access.repo.id, ulid)
            .await?
            .ok_or(CoreError::NotFound)?;
        // Suspended users are anonymous, mirroring `permission_on`.
        let viewer = user.filter(|u| u.active).map(|u| Viewer {
            user_id: u.id,
            is_admin: u.is_admin,
        });
        self.authorize_session_read(viewer, &access.repo, &session)
            .await?;
        Ok((access, session))
    }
}

/// Pure read rule: may `viewer` see `session` on `repo`?
///
/// `is_member` is [`Core::is_repo_member`] (explicit grant only — implicit
/// public/internal read does not count); `is_admin` is whether the viewer's
/// effective repo permission is `Admin` or higher (owners and site admins count;
/// see [`effective`]).
///
/// Every arm names the truth-table rows it implements.
pub fn can_read_session(
    viewer: Option<Viewer>,
    repo: &Repo,
    session: &SessionRow,
    is_member: bool,
    is_admin: bool,
) -> bool {
    // Row 12: site admins read everything.
    if viewer.map(|v| v.is_admin).unwrap_or(false) {
        return true;
    }
    let is_owner = viewer.map(|v| v.user_id == repo.owner_id).unwrap_or(false);
    let is_uploader = viewer
        .map(|v| v.user_id == session.uploader_id)
        .unwrap_or(false);
    // Rows 8-10: quarantine gate — uploader or repo admin only.
    if session.quarantine == "quarantined" {
        return is_uploader || is_owner || is_admin;
    }
    // Row 11: `released` follows the normal visibility rules below.
    // Owners read everything that is not quarantined.
    if is_owner {
        return true;
    }
    if session.visibility == "published" {
        // Rows 2, 5, 6: anyone holding repo read (implicit or explicit).
        return repo_readable(viewer, repo, is_member);
    }
    // Rows 3, 4, 5, 6, 7: unpublished sessions follow the repo: explicit
    // members only (implicit public/internal read does not count).
    is_member
}

/// Whether the viewer holds repo read: explicit membership, or the implicit
/// read public repositories give everyone and internal repositories give
/// signed-in users. Mirrors [`effective`] without a collaborator lookup.
fn repo_readable(viewer: Option<Viewer>, repo: &Repo, is_member: bool) -> bool {
    if is_member {
        return true;
    }
    match repo.visibility {
        crate::permission::Visibility::Public => true,
        crate::permission::Visibility::Internal => viewer.is_some(),
        crate::permission::Visibility::Private => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::permission::Visibility;
    use crate::repos::CreateRepo;
    use crate::testing::{test_core, user};

    fn repo(visibility: Visibility) -> Repo {
        Repo {
            id: 1,
            owner_id: 7,
            owner: "alice".into(),
            name: "demo".into(),
            description: String::new(),
            visibility,
            default_branch: "main".into(),
            archived_at: None,
            deleted_at: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn session_row(uploader_id: i64, visibility: &str, quarantine: &str) -> SessionRow {
        SessionRow {
            id: 1,
            repo_id: 1,
            ulid: "01TEST".into(),
            uploader_id,
            agent_name: "pi".into(),
            agent_version: "0.1.0".into(),
            models: "{}".into(),
            title: "t".into(),
            branch: "work".into(),
            head_sha: "abc".into(),
            started_at: 1,
            ended_at: None,
            parent_ulid: None,
            usage_input: 0,
            usage_output: 0,
            usage_cache_read: 0,
            usage_cache_write: 0,
            usage_reasoning: 0,
            files_touched: "[]".into(),
            turn_count: 0,
            tool_call_count: 0,
            lifecycle: "receiving".into(),
            quarantine: quarantine.into(),
            quarantine_reason: String::new(),
            quarantine_detail: String::new(),
            visibility: visibility.into(),
            raw_enabled: 0,
            redaction_fingerprint: String::new(),
            redaction_counts: "{}".into(),
            capture_mode: "full".into(),
            cli_version: "0".into(),
            adapter_verified: 0,
            created_at: 0,
            updated_at: 0,
        }
    }

    const OWNER: i64 = 7;
    const MEMBER: i64 = 8;
    const STRANGER: i64 = 9;

    fn anon() -> Option<Viewer> {
        None
    }

    fn signed(id: i64) -> Option<Viewer> {
        Some(Viewer {
            user_id: id,
            is_admin: false,
        })
    }

    fn admin(id: i64) -> Option<Viewer> {
        Some(Viewer {
            user_id: id,
            is_admin: true,
        })
    }

    /// One case per truth-table row: (repo visibility, viewer, session
    /// visibility, quarantine, uploader, member, admin, expected).
    #[allow(clippy::type_complexity)]
    #[test]
    fn read_rule_truth_table() {
        type Case = (
            Visibility,
            Option<Viewer>,
            &'static str,
            &'static str,
            i64,
            bool,
            bool,
            bool,
        );
        let cases: Vec<Case> = vec![
            // Row 1: no effective read → deny (private/inherit, nobody).
            (
                Visibility::Private,
                anon(),
                "inherit",
                "none",
                MEMBER,
                false,
                false,
                false,
            ),
            // Row 1b: internal + anonymous has no read either.
            (
                Visibility::Internal,
                anon(),
                "published",
                "none",
                MEMBER,
                false,
                false,
                false,
            ),
            // Row 2: public + published → anyone, even anonymous.
            (
                Visibility::Public,
                anon(),
                "published",
                "none",
                MEMBER,
                false,
                false,
                true,
            ),
            (
                Visibility::Public,
                signed(STRANGER),
                "published",
                "none",
                MEMBER,
                false,
                false,
                true,
            ),
            // Row 3: public + unpublished + member → allow.
            (
                Visibility::Public,
                signed(MEMBER),
                "inherit",
                "none",
                OWNER,
                true,
                false,
                true,
            ),
            // Row 4: public + unpublished + implicit-read-only non-member → deny.
            (
                Visibility::Public,
                signed(STRANGER),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            (
                Visibility::Public,
                anon(),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            // Row 5: internal + signed-in + published → allow; inherit + member → allow.
            (
                Visibility::Internal,
                signed(STRANGER),
                "published",
                "none",
                MEMBER,
                false,
                false,
                true,
            ),
            (
                Visibility::Internal,
                signed(MEMBER),
                "inherit",
                "none",
                OWNER,
                true,
                false,
                true,
            ),
            // Row 5b: internal + inherit + signed-in non-member → deny.
            (
                Visibility::Internal,
                signed(STRANGER),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            // Row 6: private + member with read → allow (published and inherit).
            (
                Visibility::Private,
                signed(MEMBER),
                "inherit",
                "none",
                OWNER,
                true,
                false,
                true,
            ),
            (
                Visibility::Private,
                signed(MEMBER),
                "published",
                "none",
                OWNER,
                true,
                false,
                true,
            ),
            // Row 7: private + non-member → deny.
            (
                Visibility::Private,
                signed(STRANGER),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            (
                Visibility::Private,
                signed(STRANGER),
                "published",
                "none",
                OWNER,
                false,
                false,
                false,
            ),
            // Row 8: quarantined + uploader → allow (even without any other grant).
            (
                Visibility::Private,
                signed(STRANGER),
                "inherit",
                "quarantined",
                STRANGER,
                false,
                false,
                true,
            ),
            // Row 9: quarantined + repo admin (not uploader) → allow.
            (
                Visibility::Private,
                signed(MEMBER),
                "inherit",
                "quarantined",
                OWNER,
                true,
                true,
                true,
            ),
            // Row 10: quarantined + member (not uploader/admin) → deny.
            (
                Visibility::Private,
                signed(MEMBER),
                "inherit",
                "quarantined",
                OWNER,
                true,
                false,
                false,
            ),
            (
                Visibility::Public,
                signed(STRANGER),
                "published",
                "quarantined",
                OWNER,
                false,
                false,
                false,
            ),
            // Row 11: released → normal visibility rules apply.
            (
                Visibility::Public,
                signed(MEMBER),
                "inherit",
                "released",
                OWNER,
                true,
                false,
                true,
            ),
            (
                Visibility::Public,
                signed(STRANGER),
                "inherit",
                "released",
                OWNER,
                false,
                false,
                false,
            ),
            (
                Visibility::Public,
                anon(),
                "published",
                "released",
                OWNER,
                false,
                false,
                true,
            ),
            // Row 12: site admin → allow (normal and quarantined).
            (
                Visibility::Private,
                admin(99),
                "inherit",
                "none",
                OWNER,
                false,
                false,
                true,
            ),
            (
                Visibility::Private,
                admin(99),
                "published",
                "quarantined",
                OWNER,
                false,
                false,
                true,
            ),
        ];
        for (i, (visibility, viewer, sess_vis, quarantine, uploader, member, is_admin, expect)) in
            cases.into_iter().enumerate()
        {
            let r = repo(visibility);
            let s = session_row(uploader, sess_vis, quarantine);
            assert_eq!(
                can_read_session(viewer, &r, &s, member, is_admin),
                expect,
                "case {i}: {visibility:?}/{sess_vis}/{quarantine} member={member} admin={is_admin}"
            );
        }
    }

    fn new_session<'a>(
        repo_id: i64,
        ulid: &'a str,
        uploader_id: i64,
        visibility: &'a str,
        quarantine: &'a str,
    ) -> db_sessions::NewSession<'a> {
        db_sessions::NewSession {
            repo_id,
            ulid,
            uploader_id,
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
            quarantine,
            quarantine_reason: "",
            quarantine_detail: "",
            visibility,
            raw_enabled: 0,
            redaction_fingerprint: "",
            redaction_counts: "{}",
            capture_mode: "full",
            cli_version: "0",
            adapter_verified: 0,
        }
    }

    async fn mk_repo(core: &Core, owner: &User, name: &str, visibility: Visibility) -> Repo {
        core.create_repo(
            owner,
            CreateRepo {
                name: name.into(),
                description: String::new(),
                visibility,
                readme: false,
            },
        )
        .await
        .expect("create repo")
    }

    fn as_viewer(u: &User) -> Option<Viewer> {
        Some(Viewer {
            user_id: u.id,
            is_admin: u.is_admin,
        })
    }

    struct Seeded {
        core: Core,
        alice: User,
        bob: User,
        carol: User,
        root: User,
        priv_repo: Repo,
        pub_repo: Repo,
        int_repo: Repo,
    }

    impl Seeded {
        async fn session(
            &self,
            repo: &Repo,
            ulid: &str,
            uploader: &User,
            visibility: &str,
            quarantine: &str,
        ) -> SessionRow {
            let id = db_sessions::insert_session(
                self.core.db(),
                &new_session(repo.id, ulid, uploader.id, visibility, quarantine),
            )
            .await
            .unwrap();
            db_sessions::session_by_id(self.core.db(), id)
                .await
                .unwrap()
                .unwrap()
        }

        async fn check(
            &self,
            viewer: Option<Viewer>,
            repo: &Repo,
            session: &SessionRow,
        ) -> Result<(), CoreError> {
            self.core
                .authorize_session_read(viewer, repo, session)
                .await
        }
    }

    async fn seed() -> Seeded {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        let carol = user(&core, "carol").await;
        let root = core
            .create_user(CreateUser {
                handle: "root".into(),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let priv_repo = mk_repo(&core, &alice, "secret", Visibility::Private).await;
        let pub_repo = mk_repo(&core, &alice, "open", Visibility::Public).await;
        let int_repo = mk_repo(&core, &alice, "team", Visibility::Internal).await;
        core.set_collaborator(&alice, "alice", "secret", "bob", Permission::Write)
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "open", "bob", Permission::Read)
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "team", "bob", Permission::Read)
            .await
            .unwrap();
        Seeded {
            core,
            alice,
            bob,
            carol,
            root,
            priv_repo,
            pub_repo,
            int_repo,
        }
    }

    #[tokio::test]
    async fn authorize_end_to_end_matrix() {
        let s = seed().await;
        // Row 1: private repo invisible to strangers → NotFound.
        let sess = s
            .session(&s.priv_repo, "01E1", &s.alice, "inherit", "none")
            .await;
        assert!(matches!(
            s.check(as_viewer(&s.carol), &s.priv_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            s.check(None, &s.priv_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Row 2: public + published → anonymous Ok.
        let sess = s
            .session(&s.pub_repo, "01E2", &s.alice, "published", "none")
            .await;
        assert!(s.check(None, &s.pub_repo, &sess).await.is_ok());
        // Rows 3/4: public + inherit → member Ok, stranger/anon NotFound.
        let sess = s
            .session(&s.pub_repo, "01E34", &s.alice, "inherit", "none")
            .await;
        assert!(s.check(as_viewer(&s.bob), &s.pub_repo, &sess).await.is_ok());
        assert!(matches!(
            s.check(as_viewer(&s.carol), &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            s.check(None, &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Row 5: internal + published → signed-in Ok; inherit + member Ok; inherit + stranger denied.
        let sess = s
            .session(&s.int_repo, "01E5P", &s.alice, "published", "none")
            .await;
        assert!(
            s.check(as_viewer(&s.carol), &s.int_repo, &sess)
                .await
                .is_ok()
        );
        assert!(matches!(
            s.check(None, &s.int_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        let sess = s
            .session(&s.int_repo, "01E5I", &s.alice, "inherit", "none")
            .await;
        assert!(s.check(as_viewer(&s.bob), &s.int_repo, &sess).await.is_ok());
        assert!(matches!(
            s.check(as_viewer(&s.carol), &s.int_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Rows 6/7: private + inherit → member Ok, stranger denied.
        let sess = s
            .session(&s.priv_repo, "01E67", &s.alice, "inherit", "none")
            .await;
        assert!(
            s.check(as_viewer(&s.bob), &s.priv_repo, &sess)
                .await
                .is_ok()
        );
        // Row 8: quarantined + uploader → Ok (bob's own session, quarantined).
        let sess = s
            .session(&s.priv_repo, "01E8", &s.bob, "inherit", "quarantined")
            .await;
        assert!(
            s.check(as_viewer(&s.bob), &s.priv_repo, &sess)
                .await
                .is_ok()
        );
        // Row 9: quarantined + owner (repo admin, not uploader) → Ok.
        assert!(
            s.check(as_viewer(&s.alice), &s.priv_repo, &sess)
                .await
                .is_ok()
        );
        // Row 10: quarantined + member (not uploader/admin) → NotFound.
        // (carol cannot read the private repo at all; use a public-repo case instead.)
        let sess = s
            .session(&s.pub_repo, "01E10", &s.alice, "inherit", "quarantined")
            .await;
        assert!(matches!(
            s.check(as_viewer(&s.bob), &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Row 11: released → normal rules (public inherit: member Ok, stranger denied).
        let sess = s
            .session(&s.pub_repo, "01E11", &s.alice, "inherit", "released")
            .await;
        assert!(s.check(as_viewer(&s.bob), &s.pub_repo, &sess).await.is_ok());
        assert!(matches!(
            s.check(as_viewer(&s.carol), &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
        // Row 12: site admin → Ok everywhere, including quarantined as non-uploader.
        let sess = s
            .session(&s.priv_repo, "01E12", &s.alice, "inherit", "quarantined")
            .await;
        assert!(
            s.check(as_viewer(&s.root), &s.priv_repo, &sess)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn authorize_rejects_cross_repo_sessions() {
        let s = seed().await;
        let sess = s
            .session(&s.priv_repo, "01EX", &s.alice, "inherit", "none")
            .await;
        assert!(matches!(
            s.check(as_viewer(&s.alice), &s.pub_repo, &sess).await,
            Err(CoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn authorize_by_ulid_wires_lookup_and_check() {
        let s = seed().await;
        s.session(&s.pub_repo, "01EULID", &s.alice, "published", "none")
            .await;
        let (access, row) = s
            .core
            .authorize_session_read_by_ulid(None, "alice", "open", "01EULID")
            .await
            .unwrap();
        assert_eq!(access.repo.id, s.pub_repo.id);
        assert_eq!(row.ulid, "01EULID");
        assert!(matches!(
            s.core
                .authorize_session_read_by_ulid(None, "alice", "open", "01NOPE")
                .await,
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            s.core
                .authorize_session_read_by_ulid(None, "alice", "secret", "01EULID")
                .await,
            Err(CoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn membership_excludes_implicit_read() {
        let s = seed().await;
        // Owner and explicit collaborators count…
        assert!(
            s.core
                .is_repo_member(s.priv_repo.id, s.alice.id)
                .await
                .unwrap()
        );
        assert!(
            s.core
                .is_repo_member(s.priv_repo.id, s.bob.id)
                .await
                .unwrap()
        );
        // …implicit public/internal read does not.
        assert!(
            !s.core
                .is_repo_member(s.pub_repo.id, s.carol.id)
                .await
                .unwrap()
        );
        assert!(
            !s.core
                .is_repo_member(s.int_repo.id, s.carol.id)
                .await
                .unwrap()
        );
        assert!(
            !s.core
                .is_repo_member(s.priv_repo.id, s.carol.id)
                .await
                .unwrap()
        );
        assert!(matches!(
            s.core.is_repo_member(999_999, s.carol.id).await,
            Err(CoreError::NotFound)
        ));
    }
}
