//! Repositories: creation, permission-checked lookup, collaborators.

use starforged_db::collaborators;
use starforged_db::repos::{self as db_repos, NewRepo, RepoRow};

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

impl Core {
    /// Creates a repository owned by `actor` (organizations arrive in M3) and its bare git directory.
    pub async fn create_repo(&self, actor: &User, input: CreateRepo) -> CoreResult<Repo> {
        let name = validate::repo_name(&input.name)?;
        let description = input.description.trim();
        if description.chars().count() > 350 {
            return Err(CoreError::Invalid(
                "descriptions are at most 350 characters".into(),
            ));
        }
        let new = NewRepo {
            owner_id: actor.id,
            name: &name,
            description,
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
        if let Err(err) =
            starforged_git::init::init_bare(&path, "main", &self.config().hook_exe).await
        {
            db_repos::delete(self.db(), id).await?;
            let _ = tokio::fs::remove_dir_all(&path).await;
            return Err(err.into());
        }
        let repo = to_repo(
            db_repos::by_id(self.db(), id)
                .await?
                .ok_or(CoreError::NotFound)?,
        )?;
        self.audit(
            Some(actor.id),
            "repo.create",
            &format!("repo:{}", repo.full_name()),
            repo.visibility.as_str(),
        )
        .await?;
        Ok(repo)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{test_core, user};

    fn new(name: &str, visibility: Visibility) -> CreateRepo {
        CreateRepo {
            name: name.into(),
            description: String::new(),
            visibility,
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
}
