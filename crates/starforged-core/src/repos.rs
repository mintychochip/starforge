//! Repositories: creation, permission-checked lookup, collaborators.

use std::path::Path;

use starforged_db::collaborators;
use starforged_db::now;
use starforged_db::orgs as db_orgs;
use starforged_db::redirects;
use starforged_db::repos::{self as db_repos, NewRepo, RepoRow};
use starforged_db::sessions as db_sessions;
use starforged_git::write::Identity;

use crate::accounts::User;
use crate::orgs::{OrgRole, base_grant};
use crate::permission::{self, CollectedGrants, Permission, Viewer, Visibility};
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
    /// When the repository was deleted; a deleted repository answers like a missing one until it is restored
    /// or purged (forge-basics design §5.5).
    pub deleted_at: Option<i64>,
    /// Whether the repository is a pull mirror (M4b D4).
    pub mirror: bool,
    /// The one-time import state: `none|pending|running|done|failed` (M4b D3).
    pub import_state: String,
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

pub(crate) fn to_repo(row: RepoRow) -> CoreResult<Repo> {
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
        mirror: row.mirror != 0,
        import_state: row.import_state,
        archived_at: row.archived_at,
        deleted_at: row.deleted_at,
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

/// How long a deleted repository can be restored; the daily job purges it afterwards.
pub const RESTORE_SECS: i64 = 7 * 86_400;

/// Whether a repository deleted at `deleted_at` can still be restored at `now`. The daily purge takes exactly the
/// deletions for which this is false.
fn restorable(deleted_at: i64, now: i64) -> bool {
    deleted_at > now - RESTORE_SECS
}

/// A deleted repository that its owner can still restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedRepo {
    pub id: i64,
    pub name: String,
    pub deleted_at: i64,
    /// After this time the daily job removes it for good.
    pub purge_after: i64,
}

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
    /// Creates a repository owned by `owner` (the actor, or an org the actor
    /// owns) and its bare git directory, with a README commit when
    /// `input.readme` is set (forge-basics design §5.1). Creating under
    /// another user is 403; creating in an org needs the owner role (D5).
    pub async fn create_repo(
        &self,
        actor: &User,
        owner: &str,
        input: CreateRepo,
    ) -> CoreResult<Repo> {
        self.create_repo_with_import(actor, owner, input, None)
            .await
    }

    /// [`Core::create_repo`] with an optional one-time import (M4b D3).
    /// The import URL is checked first: a policy refusal is `Invalid`
    /// (422) before any repository exists. With an import, the repository
    /// starts empty (no README) in `pending`; otherwise it is ordinary.
    pub async fn create_repo_with_import(
        &self,
        actor: &User,
        owner: &str,
        input: CreateRepo,
        import: Option<crate::remotes::ImportInput>,
    ) -> CoreResult<Repo> {
        let prepared = match &import {
            Some(input) => Some(self.prepare_import(input).await?),
            None => None,
        };
        let name = validate::repo_name(&input.name)?;
        let description = checked_description(&input.description)?;
        let owner_row = db_orgs::owner_by_handle(self.db(), &owner.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        let (owner_id, in_org) = if owner_row.kind == "org" {
            if !actor.active || self.org_role(owner_row.id, actor.id).await? != Some(OrgRole::Owner)
            {
                return Err(CoreError::Forbidden);
            }
            (owner_row.id, true)
        } else {
            if owner_row.id != actor.id {
                return Err(CoreError::Forbidden);
            }
            (actor.id, false)
        };
        let new = NewRepo {
            owner_id,
            name: &name,
            description: &description,
            visibility: input.visibility.as_str(),
            default_branch: "main",
        };
        let id = if in_org {
            match db_repos::insert_org_repo(self.db(), owner_id, &new).await {
                Ok(Some(id)) => id,
                Ok(None) => return Err(CoreError::NotFound),
                Err(e) if e.is_unique_violation() => {
                    return Err(self.name_taken(owner_id, owner.trim(), &name).await);
                }
                Err(e) => return Err(e.into()),
            }
        } else {
            match db_repos::insert(self.db(), &new).await {
                Ok(id) => id,
                Err(e) if e.is_unique_violation() => {
                    return Err(self.name_taken(owner_id, owner.trim(), &name).await);
                }
                Err(e) => return Err(e.into()),
            }
        };
        let path = self.repo_path(id);
        // Initializing the bare directory writes inside it: hold the
        // shared lock so a backup never copies a half-created tree.
        let _repo_lock = self.repo_lock_shared(id).await?;
        if let Err(err) = self
            .initialize(
                actor,
                &path,
                &name,
                &description,
                input.readme && prepared.is_none(),
            )
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
        if let Some(prepared) = prepared {
            let _ = self
                .create_import_for_repo(actor.id, id, &repo.full_name(), prepared)
                .await?;
            return self.reload_repo(id).await;
        }
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

    /// Gathers every grant source for `repo` and `user` (D4): the org base
    /// permission and membership role when the owner is an org (one query),
    /// the covering team grants when signed in (one query), and the
    /// collaborator grant when signed in (one query). At most three queries.
    /// Suspended users are anonymous.
    pub async fn grants_for(
        &self,
        repo: &Repo,
        user: Option<&User>,
    ) -> CoreResult<CollectedGrants> {
        let v = viewer(user);
        let user_id = v.map(|v| v.user_id);
        let org =
            db_orgs::grant_for_repo_owner(self.db(), repo.owner_id, user_id.unwrap_or(0)).await?;
        let (org_owner, org_base) = match &org {
            Some((base, role)) => (
                role.as_deref() == Some("owner"),
                match role.as_deref() {
                    Some(_) => base_grant(base),
                    None => None,
                },
            ),
            None => (false, None),
        };
        // Only repositories owned by the team's org count, and only for
        // signed-in viewers: team members are org members, who are signed in.
        let teams = match (org.is_some(), user_id) {
            (true, Some(id)) => {
                db_orgs::covering_team_grants(self.db(), repo.owner_id, id, repo.id)
                    .await?
                    .iter()
                    .filter_map(|p| Permission::parse(p))
                    .collect()
            }
            _ => Vec::new(),
        };
        let collaborator = match user_id {
            Some(id) => collaborators::permission(self.db(), repo.id, id)
                .await?
                .as_deref()
                .and_then(Permission::parse),
            None => None,
        };
        Ok(CollectedGrants {
            site_admin: v.map(|v| v.is_admin).unwrap_or(false),
            user_owner: org.is_none() && user_id == Some(repo.owner_id),
            org_owner,
            org_base,
            teams,
            collaborator,
            visibility: repo.visibility,
            signed_in: v.is_some(),
        })
    }

    pub async fn permission_on(
        &self,
        repo: &Repo,
        user: Option<&User>,
    ) -> CoreResult<Option<Permission>> {
        Ok(permission::effective(
            &self.grants_for(repo, user).await?.as_grants(),
        ))
    }

    /// Repositories of `owner` that `user` can read, by name. `NotFound` when the owner does not exist.
    /// Owners are users and orgs alike: the handle namespace is shared (D1).
    pub async fn repos_of(&self, user: Option<&User>, owner: &str) -> CoreResult<Vec<Repo>> {
        let owner_row = db_orgs::owner_by_handle(self.db(), &owner.to_ascii_lowercase())
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

    /// Every repository where the user is a member (D4): the user's own,
    /// the ones they collaborate on, and the org ones their ownership, base
    /// permission, or team grants cover.
    pub async fn dashboard_repos(&self, user: &User) -> CoreResult<Vec<Repo>> {
        let mut seen = std::collections::HashSet::new();
        let mut repos = Vec::new();
        for row in db_repos::list_by_owner(self.db(), user.id)
            .await?
            .into_iter()
            .chain(db_repos::list_collaborating(self.db(), user.id).await?)
            .chain(db_repos::list_org_member_repos(self.db(), user.id).await?)
        {
            if seen.insert(row.id) {
                repos.push(to_repo(row)?);
            }
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

    /// The `refs/for` access mode for the pre-receive snapshot (G1 getter;
    /// unknown values fail closed in the hook policy, never here).
    pub async fn refs_for_access(&self, repo_id: i64) -> CoreResult<String> {
        Ok(db_repos::refs_for_access(self.db(), repo_id).await?)
    }
}

impl Core {
    /// Admin: sets the per-repository CI secret policy (`None` keeps the
    /// current value for that side). At least one side must be given.
    /// Returns the resulting `(allow_secrets_on_refs_for, env_secrets)`.
    pub async fn set_ci_secret_policy(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        allow_refs_for: Option<bool>,
        env_secrets: Option<bool>,
    ) -> CoreResult<(bool, bool)> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        if allow_refs_for.is_none() && env_secrets.is_none() {
            return Err(CoreError::Invalid(
                "at least one CI secret policy field is required".into(),
            ));
        }
        let (allow_refs_for, env_secrets) =
            db_repos::set_ci_secret_policy(self.db(), access.repo.id, allow_refs_for, env_secrets)
                .await?
                .ok_or(CoreError::NotFound)?;
        self.audit(
            Some(user.id),
            "ci.secret.policy",
            &format!("repo:{}", access.repo.id),
            &format!("allow_secrets_on_refs_for={allow_refs_for} env_secrets={env_secrets}"),
        )
        .await?;
        Ok((allow_refs_for, env_secrets))
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
        // `HEAD` is written inside the repository: hold the shared lock
        // for the duration (plan M5b O1).
        let _repo_lock = self.repo_lock_shared(access.repo.id).await?;
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
        self.enqueue_index(&crate::jobs::Job::IndexRepo {
            repo_id: access.repo.id,
        })
        .await;
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
        if let Err(e) = db_repos::rename(self.db(), old.id, &new_name).await {
            return Err(if e.is_unique_violation() {
                self.name_taken(old.owner_id, &old.owner, &new_name).await
            } else {
                e.into()
            });
        }
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

    /// Admins: moves the repository to another owner (D6, §8.5). Allowed when
    /// the actor is a repo admin and may create repositories under the new
    /// owner: the actor, or an org the actor owns (D6 — no site-admin
    /// bypass, matching org repository creation). The old `<owner>/<repo>`
    /// path redirects to the new one, the old org's team links drop,
    /// collaborators stay, and one `repo.transfer` audit row records the
    /// move. Archived repositories may be transferred; the name must be free
    /// at the target (422).
    pub async fn transfer_repo(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        new_owner: &str,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        let old = access.repo;
        let target = db_orgs::owner_by_handle(self.db(), &new_owner.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        let newcomer = if target.kind == "org" {
            if !actor.active {
                return Err(CoreError::Forbidden);
            }
            self.org_role(target.id, actor.id).await? == Some(OrgRole::Owner)
        } else {
            target.id == actor.id
        };
        if !newcomer {
            return Err(CoreError::Forbidden);
        }
        if target.id == old.owner_id {
            return Ok(old);
        }
        let old_full = old.full_name();
        match db_repos::transfer(self.db(), old.id, target.id).await {
            Ok(db_repos::TransferOutcome::Done { .. }) => {}
            Ok(db_repos::TransferOutcome::Clash) => {
                return Err(CoreError::Invalid(format!(
                    "{}/{} already exists",
                    new_owner.trim(),
                    old.name
                )));
            }
            Ok(db_repos::TransferOutcome::Gone) => return Err(CoreError::NotFound),
            Err(e) if e.is_unique_violation() => {
                return Err(self
                    .name_taken(target.id, new_owner.trim(), &old.name)
                    .await);
            }
            Err(e) => return Err(e.into()),
        }
        let repo = self.reload_repo(old.id).await?;
        self.audit(
            Some(actor.id),
            "repo.transfer",
            &format!("repo:{}", repo.full_name()),
            &format!("{old_full} -> {}", repo.full_name()),
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
        if repo.deleted_at.is_some() {
            return Ok(None);
        }
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

    /// The error for a name already used in `owner`'s namespace. A deleted repository keeps its name until it
    /// is purged, and the message says so.
    async fn name_taken(&self, owner_id: i64, owner: &str, name: &str) -> CoreError {
        match db_repos::deleted_name_exists(self.db(), owner_id, name).await {
            Ok(true) => CoreError::Conflict(format!(
                "{owner}/{name} already exists as a deleted repository; restore it, or use the name after it is removed for good"
            )),
            Ok(false) => CoreError::Conflict(format!("{owner}/{name} already exists")),
            Err(err) => err.into(),
        }
    }

    /// Admins: deletes the repository once `confirm` is `owner/name`. It answers 404 everywhere at once, keeps
    /// its name, and can be restored for [`RESTORE_SECS`] (forge-basics design §5.5).
    pub async fn delete_repo(
        &self,
        actor: &User,
        owner: &str,
        name: &str,
        confirm: &str,
    ) -> CoreResult<Repo> {
        let access = self
            .require_repo(Some(actor), owner, name, Permission::Admin)
            .await?;
        let full_name = access.repo.full_name();
        if confirm.trim() != full_name {
            return Err(CoreError::Invalid(format!("Type {full_name} to confirm.")));
        }
        db_repos::set_deleted(self.db(), access.repo.id, Some(now())).await?;
        self.audit(
            Some(actor.id),
            "repo.delete",
            &format!("repo:{full_name}"),
            "",
        )
        .await?;
        self.enqueue_index(&crate::jobs::Job::IndexRepo {
            repo_id: access.repo.id,
        })
        .await;
        self.reload_repo(access.repo.id).await
    }

    /// The user's own deleted repositories that can still be restored, the most recently deleted first.
    pub async fn deleted_repos(&self, user: &User) -> CoreResult<Vec<DeletedRepo>> {
        let now = now();
        let mut deleted = Vec::new();
        for row in db_repos::list_deleted_by_owner(self.db(), user.id).await? {
            if let Some(deleted_at) = row.deleted_at
                && restorable(deleted_at, now)
            {
                deleted.push(DeletedRepo {
                    id: row.id,
                    name: row.name,
                    deleted_at,
                    purge_after: deleted_at + RESTORE_SECS,
                });
            }
        }
        Ok(deleted)
    }

    /// Restores a deleted repository within [`RESTORE_SECS`]; anyone with
    /// `Admin` on it may (owners, org owners, and admin collaborators alike,
    /// plus site admins). Anyone else, and a repository that is not deleted
    /// or is past the window, gets `NotFound`.
    pub async fn restore_repo(&self, actor: &User, repo_id: i64) -> CoreResult<Repo> {
        let repo = to_repo(
            db_repos::by_id(self.db(), repo_id)
                .await?
                .ok_or(CoreError::NotFound)?,
        )?;
        let restorable = repo.deleted_at.is_some_and(|at| restorable(at, now()));
        let admin = self
            .permission_on(&repo, Some(actor))
            .await?
            .is_some_and(|p| p >= Permission::Admin);
        if !restorable || !admin {
            return Err(CoreError::NotFound);
        }
        db_repos::set_deleted(self.db(), repo.id, None).await?;
        self.audit(
            Some(actor.id),
            "repo.restore",
            &format!("repo:{}", repo.full_name()),
            "",
        )
        .await?;
        self.enqueue_index(&crate::jobs::Job::IndexRepo { repo_id: repo.id })
            .await;
        self.reload_repo(repo.id).await
    }

    /// The daily job: purges repositories deleted more than [`RESTORE_SECS`] ago; returns how many.
    pub async fn purge_deleted_repos(&self) -> CoreResult<usize> {
        let rows = db_repos::deleted_before(self.db(), now() - RESTORE_SECS).await?;
        let count = rows.len();
        for row in rows {
            self.purge_repo(&to_repo(row)?, None).await?;
        }
        Ok(count)
    }

    /// Removes a deleted repository for good: the directory moves to `<tmp_dir>/purge-<id>.git`, the rows go
    /// (collaborators and redirects cascade), then the directory is removed. Every step is safe to repeat
    /// after a crash.
    pub(crate) async fn purge_repo(&self, repo: &Repo, actor_id: Option<i64>) -> CoreResult<()> {
        // The caller's snapshot may be stale: purge only a repository that is still deleted.
        let still_deleted = db_repos::by_id(self.db(), repo.id)
            .await?
            .is_some_and(|row| row.deleted_at.is_some());
        if !still_deleted {
            return Ok(());
        }
        // Purge moves and deletes the repository directory: hold the
        // exclusive lock so no writer runs against it and a backup never
        // copies a half-removed tree (plan M5b O1).
        let _repo_lock = self.repo_lock_exclusive(repo.id).await?;
        let path = self.repo_path(repo.id);
        let tmp = &self.config().tmp_dir;
        let parked = tmp.join(format!("purge-{}.git", repo.id));
        let failed = |step: &str, err: std::io::Error| {
            CoreError::Internal(format!("purging {}: {step}: {err}", repo.full_name()))
        };
        if tokio::fs::try_exists(&path)
            .await
            .map_err(|e| failed("checking the directory", e))?
        {
            tokio::fs::create_dir_all(tmp)
                .await
                .map_err(|e| failed("creating the tmp directory", e))?;
            if tokio::fs::try_exists(&parked)
                .await
                .map_err(|e| failed("checking the tmp directory", e))?
            {
                tokio::fs::remove_dir_all(&parked)
                    .await
                    .map_err(|e| failed("clearing an earlier attempt", e))?;
            }
            tokio::fs::rename(&path, &parked)
                .await
                .map_err(|e| failed("parking the directory", e))?;
        }
        // Sessions go through the shared delete path first: the repository
        // row's cascade would otherwise orphan their blob references and
        // commit links (including `NULL`-session trailer rows).
        loop {
            let batch = db_sessions::sessions_of_repo(
                self.db(),
                repo.id,
                crate::account::ACCOUNT_DELETE_BATCH,
            )
            .await?;
            if batch.is_empty() {
                break;
            }
            for session in &batch {
                self.remove_session_rows(actor_id, repo.id, session, "session.purged")
                    .await?;
            }
        }
        db_repos::delete(self.db(), repo.id).await?;
        match tokio::fs::remove_dir_all(&parked).await {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(failed("removing the directory", err)),
        }
        self.audit(
            actor_id,
            "repo.purge",
            &format!("repo:{}", repo.full_name()),
            "",
        )
        .await?;
        self.enqueue_index(&crate::jobs::Job::IndexRepo { repo_id: repo.id })
            .await;
        Ok(())
    }

    /// Purges every deleted repository of `owner_id` now, whatever its age (account deletion).
    pub(crate) async fn purge_deleted_repos_of(
        &self,
        owner_id: i64,
        actor_id: Option<i64>,
    ) -> CoreResult<()> {
        for row in db_repos::list_deleted_by_owner(self.db(), owner_id).await? {
            self.purge_repo(&to_repo(row)?, actor_id).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::CreateUser;
    use crate::jobs::Job;
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
                "alice",
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
            core.create_repo(&alice, "alice", new("proj", Visibility::Public))
                .await,
            Err(CoreError::Conflict(_))
        ));
        assert!(matches!(
            core.create_repo(&alice, "alice", new("x.git", Visibility::Public))
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
            "alice",
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
                &owner.handle,
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
        core.create_repo(&alice, "alice", new("secret", Visibility::Private))
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

        core.create_repo(&alice, "alice", new("open", Visibility::Public))
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
        core.create_repo(&alice, "alice", new("proj", Visibility::Private))
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
            .create_repo(&alice, "alice", new("proj", Visibility::Public))
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
        core.create_repo(&alice, "alice", new("proj", Visibility::Private))
            .await
            .unwrap();
        core.create_repo(&alice, "alice", new("other", Visibility::Private))
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
        core.create_repo(&alice, "alice", new("proj", Visibility::Public))
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

    #[tokio::test]
    async fn deleted_repositories_vanish_keep_their_name_and_can_be_restored() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let bob = user(&core, "bob").await;
        let repo = core
            .create_repo(&alice, "alice", new("proj", Visibility::Public))
            .await
            .unwrap();
        core.set_collaborator(&alice, "alice", "proj", "bob", Permission::Admin)
            .await
            .unwrap();
        assert!(matches!(
            core.delete_repo(&alice, "alice", "proj", "alice/other")
                .await,
            Err(CoreError::Invalid(_))
        ));
        let deleted = core
            .delete_repo(&bob, "alice", "proj", " alice/proj ")
            .await
            .unwrap();
        assert!(
            deleted.deleted_at.is_some(),
            "an admin collaborator may delete"
        );
        for viewer in [Some(&alice), Some(&bob), None] {
            assert!(matches!(
                core.repo_for(viewer, "alice", "proj").await,
                Err(CoreError::NotFound)
            ));
        }
        assert!(
            core.repos_of(Some(&alice), "alice")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(core.dashboard_repos(&bob).await.unwrap().is_empty());
        assert!(
            core.repo_path(repo.id).exists(),
            "the data stays until the purge"
        );
        let taken = core
            .create_repo(&alice, "alice", new("PROJ", Visibility::Public))
            .await;
        assert!(
            matches!(&taken, Err(CoreError::Conflict(m)) if m.contains("deleted")),
            "{taken:?}"
        );
        let listed: Vec<String> = core
            .deleted_repos(&alice)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(listed, vec!["proj"]);
        assert!(
            core.deleted_repos(&bob).await.unwrap().is_empty(),
            "the list shows the user's own repositories"
        );
        let restored = core.restore_repo(&bob, repo.id).await.unwrap();
        assert_eq!(
            restored.deleted_at, None,
            "an admin collaborator restores too (delete already allows them)"
        );
        assert_eq!(
            core.repo_for(Some(&bob), "alice", "proj")
                .await
                .unwrap()
                .permission,
            Permission::Admin,
            "collaborators come back with the repository"
        );
        let actions: Vec<String> = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.action)
            .collect();
        assert!(actions.contains(&"repo.delete".to_owned()));
        assert!(actions.contains(&"repo.restore".to_owned()));
    }

    #[tokio::test]
    async fn the_daily_purge_removes_week_old_deletions() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let old = core
            .create_repo(&alice, "alice", new("old", Visibility::Public))
            .await
            .unwrap();
        let recent = core
            .create_repo(&alice, "alice", new("recent", Visibility::Public))
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "old", "alice/old")
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "recent", "alice/recent")
            .await
            .unwrap();
        sqlx::query("UPDATE repos SET deleted_at = $1 WHERE id = $2")
            .bind(now() - 8 * 86_400)
            .bind(old.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        assert!(
            matches!(
                core.restore_repo(&alice, old.id).await,
                Err(CoreError::NotFound)
            ),
            "past the restore window"
        );
        let listed: Vec<String> = core
            .deleted_repos(&alice)
            .await
            .unwrap()
            .into_iter()
            .map(|d| d.name)
            .collect();
        assert_eq!(listed, vec!["recent"]);
        core.enqueue(&Job::PurgeDeletedRepos).await.unwrap();
        core.run_due_jobs().await.unwrap();
        assert!(
            starforged_db::repos::by_id(core.db(), old.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!core.repo_path(old.id).exists());
        assert!(
            !core
                .config()
                .tmp_dir
                .join(format!("purge-{}.git", old.id))
                .exists()
        );
        assert!(
            starforged_db::repos::by_id(core.db(), recent.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(core.repo_path(recent.id).exists());
        let purged = starforged_db::audit::recent(core.db(), 20)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.action == "repo.purge")
            .unwrap();
        assert_eq!(
            (purged.target.as_str(), purged.actor_id),
            ("repo:alice/old", None)
        );
        core.create_repo(&alice, "alice", new("old", Visibility::Public))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_purge_interrupted_after_parking_the_directory_finishes() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        let repo = core
            .create_repo(&alice, "alice", new("proj", Visibility::Public))
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "proj", "alice/proj")
            .await
            .unwrap();
        sqlx::query("UPDATE repos SET deleted_at = $1 WHERE id = $2")
            .bind(now() - 8 * 86_400)
            .bind(repo.id)
            .execute(core.db().pool())
            .await
            .unwrap();
        let parked = core.config().tmp_dir.join(format!("purge-{}.git", repo.id));
        std::fs::create_dir_all(&core.config().tmp_dir).unwrap();
        std::fs::rename(core.repo_path(repo.id), &parked).unwrap();
        assert_eq!(core.purge_deleted_repos().await.unwrap(), 1);
        assert!(!parked.exists());
        assert!(
            starforged_db::repos::by_id(core.db(), repo.id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_purge_leaves_a_repository_restored_since_it_was_listed() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        core.create_repo(&alice, "alice", new("proj", Visibility::Public))
            .await
            .unwrap();
        let listed = core
            .delete_repo(&alice, "alice", "proj", "alice/proj")
            .await
            .unwrap();
        core.restore_repo(&alice, listed.id).await.unwrap();
        core.purge_repo(&listed, None).await.unwrap();
        assert!(core.repo_path(listed.id).exists());
        assert!(core.repo_for(Some(&alice), "alice", "proj").await.is_ok());
    }

    #[tokio::test]
    async fn old_names_of_deleted_repositories_lead_nowhere() {
        let (core, _f) = test_core().await;
        let alice = user(&core, "alice").await;
        core.create_repo(&alice, "alice", new("proj", Visibility::Public))
            .await
            .unwrap();
        core.rename_repo(&alice, "alice", "proj", "renamed")
            .await
            .unwrap();
        core.delete_repo(&alice, "alice", "renamed", "alice/renamed")
            .await
            .unwrap();
        assert!(
            core.moved_repo(Some(&alice), "alice", "proj")
                .await
                .unwrap()
                .is_none()
        );
    }
}
