//! One git authorization path for the smart-HTTP and SSH transports (M3c):
//! repository resolution (including rename redirects), the read/write tier
//! decision, the `refs/for` read-tier gate, and archived-repository refusals.
//! HTTP and SSH both call [`Core::git_access`]; neither decides permissions
//! on its own (plan D5, global constraint "one authorization path").

use starforged_db::redirects;
use starforged_db::repos as db_repos;

use crate::accounts::User;
use crate::permission::Permission;
use crate::repos::{RepoAccess, to_repo};
use crate::{Core, CoreError, CoreResult};

/// The git service the caller wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitService {
    UploadPack,
    ReceivePack,
    UploadArchive,
}

/// Who is asking, with the token scopes HTTP carries.
#[derive(Debug, Clone)]
pub enum GitActor {
    /// An anonymous caller (HTTP only denies receive-pack for this actor).
    Anonymous { scope_read: bool, scope_write: bool },
    /// A signed-in user over HTTP (scopes from the token) or SSH (both true:
    /// a user key carries full account scope).
    User {
        user: User,
        scope_read: bool,
        scope_write: bool,
    },
    /// A deploy key, bound to exactly one repository. It never uses the
    /// `refs/for` read tier: read-only keys may only fetch, and `refs/for`
    /// needs an author.
    Deploy {
        key_id: i64,
        repo_id: i64,
        read_write: bool,
    },
}

/// The authorized repository, the pusher (none for anonymous and deploy keys),
/// and whether the write tier was taken.
#[derive(Debug, Clone)]
pub struct GitAccess {
    pub access: RepoAccess,
    pub user: Option<User>,
    pub write_path: bool,
}

impl Core {
    /// Authorizes one git operation. `owner` and `name` are the path segments
    /// without the optional `.git` suffix; unknown or unreadable repositories
    /// answer `NotFound` (no existence leak), except that a below-`Read`
    /// signed-in viewer is `Forbidden` and an anonymous below-`Read` caller
    /// is `Unauthenticated` — exactly [`Core::require_repo`] semantics, which
    /// the HTTP layer maps to 401/403/404.
    pub async fn git_access(
        &self,
        actor: &GitActor,
        owner: &str,
        name: &str,
        service: GitService,
    ) -> CoreResult<GitAccess> {
        let name = name.strip_suffix(".git").unwrap_or(name);
        match (actor, service) {
            (GitActor::Anonymous { scope_read, .. }, service) => {
                if service != GitService::UploadPack && service != GitService::UploadArchive {
                    // Anonymous pushes stay rejected so clients prompt for credentials.
                    return Err(CoreError::Unauthenticated);
                }
                if !scope_read {
                    return Err(CoreError::Forbidden);
                }
                let access = self
                    .resolve_git_repo(None, owner, name, Permission::Read)
                    .await?;
                Ok(GitAccess {
                    access,
                    user: None,
                    write_path: false,
                })
            }
            (
                GitActor::User {
                    user,
                    scope_read,
                    scope_write,
                },
                service,
            ) => {
                if service == GitService::ReceivePack {
                    // Receive-pack has two entry tiers: writers (`repo:write`
                    // scope + `Write` permission) and readers (`repo:read`
                    // scope + `Read` permission, `refs/for` only). The hook
                    // enforces the split per ref; this layer picks the tier.
                    let access = self
                        .resolve_git_repo(Some(user), owner, name, Permission::Read)
                        .await?;
                    let write_path = if *scope_write && access.permission >= Permission::Write {
                        true
                    } else if *scope_read {
                        self.refs_for_gate(&access, user).await?;
                        false
                    } else {
                        return Err(CoreError::Forbidden);
                    };
                    Ok(GitAccess {
                        access,
                        user: Some(user.clone()),
                        write_path,
                    })
                } else {
                    if !scope_read {
                        return Err(CoreError::Forbidden);
                    }
                    let access = self
                        .resolve_git_repo(Some(user), owner, name, Permission::Read)
                        .await?;
                    Ok(GitAccess {
                        access,
                        user: Some(user.clone()),
                        write_path: false,
                    })
                }
            }
            (
                GitActor::Deploy {
                    repo_id,
                    read_write,
                    ..
                },
                service,
            ) => {
                if service == GitService::ReceivePack && !read_write {
                    // A read-only deploy key may only fetch.
                    return Err(CoreError::Forbidden);
                }
                let access = self
                    .deploy_access(owner, name, *repo_id, *read_write)
                    .await?;
                Ok(GitAccess {
                    access,
                    user: None,
                    write_path: *read_write && service == GitService::ReceivePack,
                })
            }
        }
    }

    /// The `refs/for` read-tier gate: the repository must open `refs/for` to
    /// this user (`anyone_with_read` admits any reader; `members` needs an
    /// explicit grant). `Forbidden` when closed.
    async fn refs_for_gate(&self, access: &RepoAccess, user: &User) -> CoreResult<()> {
        let refs_for = self.refs_for_access(access.repo.id).await?;
        let allowed = match refs_for.as_str() {
            "anyone_with_read" => true,
            "members" => self.is_repo_member(access.repo.id, user.id).await?,
            _ => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(CoreError::Forbidden)
        }
    }

    /// The deploy key's repository, synthesized at the key's tier: read-only
    /// is `Read`, read-write is `Write` with no user. The requested path must
    /// name this repository, by its current name or through a rename
    /// redirect; any other name answers `NotFound` (no existence leak, and a
    /// deploy key never reaches another repository, not even a public one).
    async fn deploy_access(
        &self,
        owner: &str,
        name: &str,
        repo_id: i64,
        read_write: bool,
    ) -> CoreResult<RepoAccess> {
        let row = match db_repos::by_owner_and_name(self.db(), owner, name).await? {
            Some(row) if row.id == repo_id => row,
            Some(_) => return Err(CoreError::NotFound),
            None => {
                let target = redirects::target(
                    self.db(),
                    &owner.to_ascii_lowercase(),
                    &name.to_ascii_lowercase(),
                )
                .await?;
                if target != Some(repo_id) {
                    return Err(CoreError::NotFound);
                }
                db_repos::by_id(self.db(), repo_id)
                    .await?
                    .ok_or(CoreError::NotFound)?
            }
        };
        let repo = to_repo(row)?;
        if repo.deleted_at.is_some() {
            return Err(CoreError::NotFound);
        }
        Ok(RepoAccess {
            repo,
            permission: if read_write {
                Permission::Write
            } else {
                Permission::Read
            },
        })
    }
}

/// Repository resolution shared by the transports: the live name answers
/// directly; otherwise a rename redirect to a readable repository answers its
/// target. `NotFound` when neither matches (no existence leak: a private
/// renamed repository answers `NotFound` for callers that cannot read it).
impl Core {
    async fn resolve_git_repo(
        &self,
        user: Option<&User>,
        owner: &str,
        name: &str,
        needed: Permission,
    ) -> CoreResult<RepoAccess> {
        match self.require_repo(user, owner, name, needed).await {
            Err(CoreError::NotFound) => {}
            other => return other,
        }
        let Some(repo) = self.moved_repo(user, owner, name).await? else {
            return Err(CoreError::NotFound);
        };
        let permission = self
            .permission_on(&repo, user)
            .await?
            .ok_or(CoreError::NotFound)?;
        if permission < needed {
            return Err(if user.filter(|u| u.active).is_some() {
                CoreError::Forbidden
            } else {
                CoreError::Unauthenticated
            });
        }
        Ok(RepoAccess { repo, permission })
    }
}
