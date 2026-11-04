//! Repositories: creation, permission-checked lookup, collaborators.

use std::path::Path;

use starforged_db::collaborators;
use starforged_db::now;
use starforged_db::redirects;
use starforged_db::repos::{self as db_repos, NewRepo, RepoRow};
use starforged_git::write::Identity;

use crate::accounts::User;
use crate::permission::{self, Permission, Viewer, Visibility};
use crate::{Core, CoreError, CoreResult, validate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    pub id: i64,
    pub owner_id: i64,
    pub owner: String,
    pub name: String,
    pub description: String,
    pub visibility: Visibility,
    pub default_branch: String,
    /// When the repository was archived; an archived repository refuses pushes (forge-basics design §5.4).
    pub archived_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Repo {
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

/// A repository plus the viewer's effective permission — proof that the viewer may at least read it.
#[derive(Debug, Clone)]
pub struct RepoAccess {
    pub repo: Repo,
    pub permission: Permission,
}

#[derive(Debug, Clone)]
pub struct CreateRepo {
    pub name: String,
    pub description: String,
    pub visibility: Visibility,
    /// Commit a `README.md` (the name as a heading, then the description) as the first commit of `main`.
    pub readme: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collaborator {
    pub user_id: i64,
    pub handle: String,
    pub permission: Permission,
}

fn to_repo(row: RepoRow) -> CoreResult<Repo> {
    let visibility = Visibility::parse(&row.visibility)
        .ok_or_else(|| CoreError::Internal(format!("unknown visibility '{}'", row.visibility)))?;
    Ok(Repo {
        id: row.id,
        owner_id: row.owner_id,
        owner: row.owner_handle,
        name: row.name,
        description: row.description,
        visibility,
        default_branch: row.default_branch,
        archived_at: row.archived_at,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Suspended users are treated as anonymous.
fn viewer(user: Option<&User>) -> Option<Viewer> {
    user.filter(|u| u.active).map(|u| Viewer {
        user_id: u.id,
        is_admin: u.is_admin,
    })
}

/// Longest repository description, in characters.
const MAX_DESCRIPTION_CHARS: usize = 350;

/// Trims a description and checks its length.
fn checked_description(input: &str) -> CoreResult<String> {
    let description = input.trim();
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(CoreError::Invalid(
            "descriptions are at most 350 characters".into(),
        ));
    }
    Ok(description.to_owned())
}

/// Splits a request path `/{owner}/{segment}{rest}` into the owner, the repository segment (which may end in
/// `.git`), and the rest (empty, or starting with `/`). `None` without two non-empty segments.
pub fn split_repo_path(path: &str) -> Option<(&str, &str, &str)> {
    let path = path.strip_prefix('/')?;
    let (owner, after) = path.split_once('/')?;
    let (segment, rest) = match after.find('/') {
        Some(at) => after.split_at(at),
        None => (after, ""),
    };
    if owner.is_empty() || segment.is_empty() {
        return None;
    }
    Some((owner, segment, rest))
}

impl Core {
    /// Creates a repository owned by `actor` (organizations arrive in M3) and its bare git directory, with a
    /// README commit when `input.readme` is set (forge-basics design §5.1).
    pub async fn create_repo(&self, actor: &User, input: CreateRepo) -> CoreResult<Repo> {
        let name = validate::repo_name(&input.name)?;
        let description = checked_description(&input.description)?;
        let new = NewRepo {
            owner_id: actor.id,
            name: &name,
            description: &description,
            visibility: input.visibility.as_str(),
            default_branch: "main",
        };
        let id = db_repos::insert(self.db(), &new).await.map_err(|e| {
            if e.is_unique_violation() {
                CoreError::Conflict(format!("{}/{name} already exists", actor.handle))
            } else {
                e.into()
            }
        })?;
        let path = self.repo_path(id);
        if let Err(err) = self
            .initialize(actor, &path, &name, &description, input.readme)
            .await
        {
            db_repos::delete(self.db(), id).await?;
            let _ = tokio::fs::remove_dir_all(&path).await;
            return Err(err);
        }
        let repo = self.reload_repo(id).await?;
        self.audit(
            Some(actor.id),
            "repo.create",
            &format!("repo:{}", repo.full_name()),
            repo.visibility.as_str(),
        )
        .await?;
        Ok(repo)
    }

    /// Creates the bare repository and, when asked, its first commit with a README.
    async fn initialize(
        &self,
        actor: &User,
        path: &Path,
        name: &str,
        description: &str,
        readme: bool,
    ) -> CoreResult<()> {
        starforged_git::init::init_bare(path, "main", &self.config().hook_exe).await?;
        if readme {
            let (author, email) = self.commit_identity(actor);
            let text = if description.is_empty() {
                format!("# {name}\n")
            } else {
                format!("# {name}\n\n{description}\n")
            };
            starforged_git::write::initial_commit(
                path,
                "main",
                &[("README.md", text.as_bytes())],
                Identity {
                    name: &author,
                    email: &email,
                    time: now(),
                },
                "Initial commit",
            )
            .await?;
        }
        Ok(())
    }

    /// The name and email on commits the server writes for `user`: the display name (or the handle), and the
    /// verified email or `<handle>@users.noreply.<host of base_url>`.
    pub(crate) fn commit_identity(&self, user: &User) -> (String, String) {
        let name = if user.display_name.is_empty() {
            user.handle.clone()
        } else {
            user.display_name.clone()
        };
        let email = match &user.email {
            Some(email) if user.email_verified => email.clone(),
            _ => {
                let host = url::Url::parse(&self.config().base_url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned))
                    .unwrap_or_else(|| "localhost".to_owned());
                format!("{}@users.noreply.{host}", user.handle)
            }
        };
        (name, email)
    }

    /// The repository and the viewer's permission. A missing repository and one the viewer cannot read
    /// are both `NotFound`.
    pub async fn repo_for(
        &self,
        user: Option<&User>,
        owner: &str,
        name: &str,
    ) -> CoreResult<RepoAccess> {
        let row = db_repos::by_owner_and_name(self.db(), owner, name)
            .await?
            .ok_or(CoreError::NotFound)?;
        let repo = to_repo(row)?;
        let permission = self
            .permission_on(&repo, user)
            .await?
            .ok_or(CoreError::NotFound)?;
        Ok(RepoAccess { repo, permission })
    }

    /// [`Core::repo_for`] plus a minimum permission: below it, signed-in viewers get `Forbidden` and
    /// anonymous viewers `Unauthenticated`.
    pub async fn require_repo(
        &self,
        user: Option<&User>,
        owner: &str,
        name: &str,
        needed: Permission,
    ) -> CoreResult<RepoAccess> {
        let access = self.repo_for(user, owner, name).await?;
        if access.permission < needed {
            return Err(if viewer(user).is_some() {
                CoreError::Forbidden
            } else {
                CoreError::Unauthenticated
            });
        }
        Ok(access)
    }

    pub async fn permission_on(
        &self,
        repo: &Repo,
        user: Option<&User>,
    ) -> CoreResult<Option<Permission>> {
        let v = viewer(user);
        let collaborator = match v {
            Some(v) => collaborators::permission(self.db(), repo.id, v.user_id)
                .await?
                .as_deref()
                .and_then(Permission::parse),
            None => None,
        };
        Ok(permission::effective(
            repo.owner_id,
            repo.visibility,
            v,
            collaborator,
        ))
    }

    /// Repositories of `owner` that `user` can read, by name. `NotFound` when the owner does not exist.
    pub async fn repos_of(&self, user: Option<&User>, owner: &str) -> CoreResult<Vec<Repo>> {
        let owner_row = starforged_db::users::by_handle(self.db(), &owner.to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        let mut visible = Vec::new();
        for row in db_repos::list_by_owner(self.db(), owner_row.id).await? {
            let repo = to_repo(row)?;
            if self.permission_on(&repo, user).await?.is_some() {
                visible.push(repo);
            }
        }
        Ok(visible)
    }

    /// The user's own repositories, then the ones they collaborate on.
    pub async fn dashboard_repos(&self, user: &User) -> CoreResult<Vec<Repo>> {
        let mut repos = Vec::new();
        for row in db_repos::list_by_owner(self.db(), user.id).await? {
            repos.push(to_repo(row)?);
        }
        for row in db_repos::list_collaborating(self.db(), user.id).await? {
            repos.push(to_repo(row)?);
        }
        Ok(repos)
    }

    pub async fn collaborators(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
    ) -> CoreResult<Vec<Collaborator>> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        collaborators::list(self.db(), access.repo.id)
            .await?
            .into_iter()
            .map(|row| {
                let permission = Permission::parse(&row.permission).ok_or_else(|| {
                    CoreError::Internal(format!("unknown permission '{}'", row.permission))
                })?;
                Ok(Collaborator {
                    user_id: row.user_id,
                    handle: row.handle,
                    permission,
                })
            })
            .collect()
    }

    pub async fn set_collaborator(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        handle: &str,
        permission: Permission,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        let target = self
            .user_by_handle(handle)
            .await?
            .ok_or_else(|| CoreError::Invalid(format!("no user named '{handle}'")))?;
        if target.id == access.repo.owner_id {
            return Err(CoreError::Invalid(
                "the owner already has admin access".into(),
            ));
        }
        collaborators::upsert(self.db(), access.repo.id, target.id, permission.as_str()).await?;
        let detail = format!("{}={}", target.handle, permission.as_str());
        self.audit(
            Some(actor.id),
            "repo.collaborator.set",
            &format!("repo:{}", access.repo.full_name()),
            &detail,
        )
        .await
    }

    pub async fn remove_collaborator(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        handle: &str,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        let target = self
            .user_by_handle(handle)
            .await?
            .ok_or(CoreError::NotFound)?;
        if !collaborators::remove(self.db(), access.repo.id, target.id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(actor.id),
            "repo.collaborator.remove",
            &format!("repo:{}", access.repo.full_name()),
            &target.handle,
        )
        .await
    }
}

impl Core {
    /// Maintainers and up: replaces the description (forge-basics design §5.2).
    pub async fn set_repo_description(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        description: &str,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        let description = checked_description(description)?;
        if description != access.repo.description {
            db_repos::set_description(self.db(), access.repo.id, &description).await?;
        }
        self.reload_repo(access.repo.id).await
    }

    /// Maintainers and up: makes the existing branch `branch` the default and points the bare repository's
    /// `HEAD` at it, so new clones check it out.
    pub async fn set_default_branch(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        branch: &str,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Maintain)
            .await?;
        if access.repo.default_branch == branch {
            return Ok(access.repo);
        }
        if !self.branches(&access).await?.iter().any(|b| b == branch) {
            return Err(CoreError::Invalid(format!(
                "there is no branch named '{branch}'"
            )));
        }
        starforged_git::write::set_head(&self.repo_path(access.repo.id), branch).await?;
        db_repos::set_default_branch(self.db(), access.repo.id, branch).await?;
        self.audit(
            Some(actor.id),
            "repo.default_branch",
            &format!("repo:{}", access.repo.full_name()),
            branch,
        )
        .await?;
        self.reload_repo(access.repo.id).await
    }

    /// Admins: changes who can read the repository.
    pub async fn set_visibility(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        visibility: Visibility,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        let old = access.repo.visibility;
        if old == visibility {
            return Ok(access.repo);
        }
        db_repos::set_visibility(self.db(), access.repo.id, visibility.as_str()).await?;
        self.audit(
            Some(actor.id),
            "repo.visibility",
            &format!("repo:{}", access.repo.full_name()),
            &format!("{} -> {}", old.as_str(), visibility.as_str()),
        )
        .await?;
        self.reload_repo(access.repo.id).await
    }

    /// Admins: renames the repository. The old name keeps working through a redirect (forge-basics design §5.3).
    pub async fn rename_repo(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        new_name: &str,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        let new_name = validate::repo_name(new_name)?;
        let old = access.repo;
        if new_name == old.name {
            return Ok(old);
        }
        db_repos::rename(self.db(), old.id, &new_name)
            .await
            .map_err(|e| {
                if e.is_unique_violation() {
                    CoreError::Conflict(format!("{}/{new_name} already exists", old.owner))
                } else {
                    e.into()
                }
            })?;
        let repo = self.reload_repo(old.id).await?;
        self.audit(
            Some(actor.id),
            "repo.rename",
            &format!("repo:{}", repo.full_name()),
            &old.name,
        )
        .await?;
        Ok(repo)
    }

    /// Admins: archives the repository; it stays readable and refuses pushes until it is unarchived.
    pub async fn archive_repo(&self, actor: &User, owner: &str, name: &str) -> CoreResult<Repo> {
        self.set_archived(actor, owner, name, true).await
    }

    /// Admins: lifts the archive.
    pub async fn unarchive_repo(&self, actor: &User, owner: &str, name: &str) -> CoreResult<Repo> {
        self.set_archived(actor, owner, name, false).await
    }

    async fn set_archived(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        archived: bool,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        if access.repo.archived_at.is_some() == archived {
            return Ok(access.repo);
        }
        db_repos::set_archived(self.db(), access.repo.id, archived.then(now)).await?;
        let action = if archived {
            "repo.archive"
        } else {
            "repo.unarchive"
        };
        self.audit(
            Some(actor.id),
            action,
            &format!("repo:{}", access.repo.full_name()),
            "",
        )
        .await?;
        self.reload_repo(access.repo.id).await
    }

    /// The repository that `owner/name` was renamed to, when `user` can read it. `None` when a repository has
    /// that name, no redirect exists, or the viewer cannot read the target, so an old name of a private
    /// repository answers like a missing one.
    pub async fn moved_repo(
        &self,
        user: Option<&User>,
        owner: &str,
        name: &str,
    ) -> CoreResult<Option<Repo>> {
        if db_repos::by_owner_and_name(self.db(), owner, name)
            .await?
            .is_some()
        {
            return Ok(None);
        }
        let Some(id) = redirects::target(
            self.db(),
            &owner.to_ascii_lowercase(),
            &name.to_ascii_lowercase(),
        )
        .await?
        else {
            return Ok(None);
        };
        let Some(row) = db_repos::by_id(self.db(), id).await? else {
            return Ok(None);
        };
        let repo = to_repo(row)?;
        Ok(self.permission_on(&repo, user).await?.map(|_| repo))
    }

    /// The repository as stored now.
    async fn reload_repo(&self, id: i64) -> CoreResult<Repo> {
        to_repo(
            db_repos::by_id(self.db(), id)
                .await?
                .ok_or(CoreError::NotFound)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::testing::{seed_branches, test_core, user};

    fn new(name: &str, visibility: Visibility) -> CreateRepo {
        CreateRepo {
            name: name.into(),
            description: String::new(),
            visibility,
            readme: false,
        }
    }

    #[tokio::test]
    async fn repo_paths_are_sharded_by_the_last_two_digits() {
        let (core, _f) = test_core().await;
        let root = core.config().repos_dir.clone();
        assert_eq!(core.repo_path(7), root.join("07").join("7.git"));
        assert_eq!(core.repo_path(1234), root.join("34").join("1234.git"));
    }

    #[tokio::test]
    async fn create_repo_initializes_a_bare_repository() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let repo = core
            .create_repo(
                &alice,
                CreateRepo {
                    name: "Proj".into(),
                    description: " demo ".into(),
                    visibility: Visibility::Private,
                    readme: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            (
                repo.owner.as_str(),
                repo.name.as_str(),
                repo.description.as_str(),
                repo.default_branch.as_str()
            ),
            ("alice", "Proj", "demo", "main")
        );
        assert_eq!(repo.full_name(), "alice/Proj");
        let path = core.repo_path(repo.id);
        assert!(path.join("HEAD").is_file());
        assert!(path.join("hooks/pre-receive").is_file());
        assert!(matches!(
            core.create_repo(&alice, new("proj", Visibility::Public))
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert!(matches!(
            core.create_repo(&alice, new("x.git", Visibility::Public))
                .await,
            Err(CoreError::Invalid(_))
        ));
        let actions: Vec<String> = starforged_db::audit::recent(core.db(), 5)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert_eq!(actions, vec!["repo.create"]);
    }

    #[tokio::test]
    async fn a_readme_commit_uses_the_owners_identity() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        core.create_repo(
            &alice,
            CreateRepo {
                name: "proj".into(),
                description: "A demo".into(),
                visibility: Visibility::Public,
                readme: true,
            },
        )
        .await
        .unwrap();
        let access = core.repo_for(Some(&alice), "alice", "proj").await.unwrap();
        let main = core.resolve(&access, "main").await.unwrap();
        let log = core.log(&access, &main.commit_id, 0, 10).await.unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(
            (log[0].author_name.as_str(), log[0].author_email.as_str()),
            ("alice", "alice@users.noreply.forge.test")
        );
        let readme = core
            .blob(&access, &main.commit_id, "README.md")
            .await
            .unwrap();
        assert_eq!(readme.bytes.unwrap(), b"# proj\n\nA demo\n");

        for (handle, display_name, verified, expected) in [
            ("bo", "Bo Diaz", true, ("Bo Diaz", "bo@example.com")),
            ("cy", "", false, ("cy", "cy@users.noreply.forge.test")),
        ] {
            let owner = core
                .create_user(CreateUser {
                    handle: handle.into(),
                    display_name: display_name.into(),
                    email: Some(format!("{handle}@example.com")),
                    email_verified: verified,
                    ..Default::default()
                })
                .await
                .unwrap();
            core.create_repo(
                &owner,
                CreateRepo {
                    name: "notes".into(),
                    description: String::new(),
                    visibility: Visibility::Private,
                    readme: true,
                },
            )
            .await
            .unwrap();
            let access = core.repo_for(Some(&owner), handle, "notes").await.unwrap();
            let main = core.resolve(&access, "main").await.unwrap();
            let log = core.log(&access, &main.commit_id, 0, 1).await.unwrap();
            assert_eq!(
                (log[0].author_name.as_str(), log[0].author_email.as_str()),
                expected,
                "{handle}: only a verified address is used"
            );
            assert_eq!(
                core.blob(&access, &main.commit_id, "README.md")
                    .await
                    .unwrap()
                    .bytes
                    .unwrap(),
                b"# notes\n"
            );
        }
    }

    #[tokio::test]
    async fn access_follows_visibility_and_collaborators() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        core.create_repo(&alice, new("secret", Visibility::Private))
            .await
            .unwrap();

        assert!(matches!(
            core.repo_for(Some(&bob), "alice", "secret").await,
            Err(CoreError::NotFound)
        ));
        assert!(matches!(
            core.repo_for(None, "alice", "secret").await,
            Err(CoreError::NotFound)
        ));
        assert_eq!(
            core.repo_for(Some(&alice), "ALICE", "Secret")
                .await
                .unwrap()
                .permission,
            Permission::Admin
        );

        core.set_collaborator(&alice, "alice", "secret", "bob", Permission::Write)
            .await
            .unwrap();
        assert_eq!(
            core.repo_for(Some(&bob), "alice", "secret")
                .await
                .unwrap()
                .permission,
            Permission::Write
        );
        assert!(matches!(
            core.require_repo(Some(&bob), "alice", "secret", Permission::Admin)
                .await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.set_collaborator(&bob, "alice", "secret", "bob", Permission::Admin)
                .await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.set_collaborator(&alice, "alice", "secret", "alice", Permission::Read)
                .await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.set_collaborator(&alice, "alice", "secret", "nobody", Permission::Read)
                .await,
            Err(CoreError::Invalid(_))
        ));
        assert_eq!(
            core.collaborators(&alice, "alice", "secret").await.unwrap(),
            vec![Collaborator {
                user_id: bob.id,
                handle: "bob".into(),
                permission: Permission::Write
            }]
        );
        assert_eq!(core.repos_of(Some(&bob), "alice").await.unwrap().len(), 1);
        assert_eq!(core.dashboard_repos(&bob).await.unwrap().len(), 1);

        core.remove_collaborator(&alice, "alice", "secret", "bob")
            .await
            .unwrap();
        assert!(core.repos_of(Some(&bob), "alice").await.unwrap().is_empty());
        assert!(matches!(
            core.remove_collaborator(&alice, "alice", "secret", "bob")
                .await,
            Err(CoreError::NotFound)
        ));

        core.create_repo(&alice, new("open", Visibility::Public))
            .await
            .unwrap();
        assert_eq!(
            core.repo_for(None, "alice", "open")
                .await
                .unwrap()
                .permission,
            Permission::Read
        );
        assert!(matches!(
            core.require_repo(None, "alice", "open", Permission::Write)
                .await,
            Err(CoreError::Unauthenticated)
        ));
        let anonymous: Vec<String> = core
            .repos_of(None, "alice")
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(anonymous, vec!["open"]);
        assert_eq!(core.dashboard_repos(&alice).await.unwrap().len(), 2);
        assert!(matches!(
            core.repos_of(None, "nobody").await,
            Err(CoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn settings_follow_maintain_and_admin_permissions() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let mia = user(&core, "mia").await;
        let walt = user(&core, "walt").await;
        let bob = user(&core, "bob").await;
        core.create_repo(&alice, new("proj", Visibility::Private))
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "walt", Permission::Write)
            .await
            .unwrap();

        let repo = core
            .set_repo_description(&mia, "alice", "proj", "  A demo  ")
            .await
            .unwrap();
        assert_eq!(repo.description, "A demo");
        assert!(matches!(
            core.set_repo_description(&walt, "alice", "proj", "x").await,
            Err(CoreError::Forbidden)
        ));
        assert!(
            matches!(
                core.set_repo_description(&bob, "alice", "proj", "x").await,
                Err(CoreError::NotFound)
            ),
            "people who cannot read the repository learn nothing"
        );
        assert!(matches!(
            core.set_repo_description(&mia, "alice", "proj", &"x".repeat(351))
                .await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.set_visibility(&mia, "alice", "proj", Visibility::Public)
                .await,
            Err(CoreError::Forbidden)
        ));
        let repo = core
            .set_visibility(&alice, "alice", "proj", Visibility::Public)
            .await
            .unwrap();
        assert_eq!(repo.visibility, Visibility::Public);
        core.set_visibility(&alice, "alice", "proj", Visibility::Public)
            .await
            .unwrap();
        let audited: Vec<(String, String)> = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.action == "repo.visibility")
            .map(|e| (e.target, e.detail))
            .collect();
        assert_eq!(
            audited,
            vec![("repo:alice/proj".to_owned(), "private -> public".to_owned())],
            "a visibility that did not change is not audited"
        );
    }

    #[tokio::test]
    async fn the_default_branch_must_exist_and_moves_head() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let repo = core
            .create_repo(&alice, new("proj", Visibility::Public))
            .await
            .unwrap();
        assert!(matches!(
            core.set_default_branch(&alice, "alice", "proj", "dev")
                .await,
            Err(CoreError::Invalid(_))
        ));
        seed_branches(&core, repo.id, &["main", "dev"]);
        let changed = core
            .set_default_branch(&alice, "alice", "proj", "dev")
            .await
            .unwrap();
        assert_eq!(changed.default_branch, "dev");
        assert_eq!(
            std::fs::read_to_string(core.repo_path(repo.id).join("HEAD")).unwrap(),
            "ref: refs/heads/dev\n"
        );
        core.set_default_branch(&alice, "alice", "proj", "dev")
            .await
            .unwrap();
        let audited: Vec<String> = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.action == "repo.default_branch")
            .map(|e| e.detail)
            .collect();
        assert_eq!(audited, vec!["dev".to_owned()]);
    }
    #[test]
    fn request_paths_split_into_owner_repository_and_rest() {
        assert_eq!(split_repo_path("/alice/proj"), Some(("alice", "proj", "")));
        assert_eq!(
            split_repo_path("/alice/proj.git/info/refs"),
            Some(("alice", "proj.git", "/info/refs"))
        );
        assert_eq!(
            split_repo_path("/alice/proj/tree/main/src"),
            Some(("alice", "proj", "/tree/main/src"))
        );
        for no in ["/alice", "/alice/", "//proj", "alice/proj", ""] {
            assert_eq!(split_repo_path(no), None, "{no:?}");
        }
    }

    #[tokio::test]
    async fn renames_need_admin_and_old_names_lead_to_readers_only() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let mia = user(&core, "mia").await;
        let bob = user(&core, "bob").await;
        core.create_repo(&alice, new("proj", Visibility::Private))
            .await
            .unwrap();
        core.create_repo(&alice, new("other", Visibility::Private))
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
            .await
            .unwrap();
        assert!(matches!(
            core.rename_repo(&mia, "alice", "proj", "x").await,
            Err(CoreError::Forbidden)
        ));
        assert!(matches!(
            core.rename_repo(&alice, "alice", "proj", "x.git").await,
            Err(CoreError::Invalid(_))
        ));
        assert!(matches!(
            core.rename_repo(&alice, "alice", "proj", "OTHER").await,
            Err(CoreError::Conflict(_))
        ));
        let same = core
            .rename_repo(&alice, "alice", "proj", "proj")
            .await
            .unwrap();
        assert_eq!(same.name, "proj");
        let renamed = core
            .rename_repo(&alice, "alice", "proj", "Renamed")
            .await
            .unwrap();
        assert_eq!(renamed.full_name(), "alice/Renamed");
        assert!(matches!(
            core.repo_for(Some(&alice), "alice", "proj").await,
            Err(CoreError::NotFound)
        ));
        let moved = core
            .moved_repo(Some(&alice), "alice", "PROJ")
            .await
            .unwrap();
        assert_eq!(moved.map(|r| r.id), Some(renamed.id));
        assert!(
            core.moved_repo(Some(&mia), "alice", "proj")
                .await
                .unwrap()
                .is_some(),
            "collaborators follow the rename"
        );
        assert!(
            core.moved_repo(Some(&bob), "alice", "proj")
                .await
                .unwrap()
                .is_none(),
            "the private target stays hidden"
        );
        assert!(
            core.moved_repo(None, "alice", "proj")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            core.moved_repo(Some(&alice), "alice", "Renamed")
                .await
                .unwrap()
                .is_none(),
            "a live name is not a redirect"
        );
        let entry = starforged_db::audit::recent(core.db(), 1)
            .await
            .unwrap()
            .remove(0);
        assert_eq!(
            (
                entry.action.as_str(),
                entry.target.as_str(),
                entry.detail.as_str()
            ),
            ("repo.rename", "repo:alice/Renamed", "proj")
        );
    }

    #[tokio::test]
    async fn archiving_needs_admin_and_is_audited_once() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let mia = user(&core, "mia").await;
        core.create_repo(&alice, new("proj", Visibility::Public))
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "mia", Permission::Maintain)
            .await
            .unwrap();
        assert!(matches!(
            core.archive_repo(&mia, "alice", "proj").await,
            Err(CoreError::Forbidden)
        ));
        let archived = core.archive_repo(&alice, "alice", "proj").await.unwrap();
        assert!(archived.archived_at.is_some());
        core.archive_repo(&alice, "alice", "proj").await.unwrap();
        assert!(
            core.repo_for(None, "alice", "proj")
                .await
                .unwrap()
                .repo
                .archived_at
                .is_some(),
            "archived repositories stay readable"
        );
        let restored = core.unarchive_repo(&alice, "alice", "proj").await.unwrap();
        assert_eq!(restored.archived_at, None);
        let actions: Vec<String> = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .filter(|a| a.ends_with("archive"))
            .collect();
        assert_eq!(actions, vec!["repo.unarchive", "repo.archive"]);
    }
}
