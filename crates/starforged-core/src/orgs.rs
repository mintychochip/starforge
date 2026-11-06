//! Organizations: creation, membership, teams, base permissions, deletion (D1-D3, D7).
//!
//! An org is an `owners` row with `kind = 'org'` plus an `orgs` row sharing
//! its id. Any active signed-in user may create one and becomes its first
//! owner; owners add existing active users directly and manage teams.

use starforged_db::{now, orgs as db_orgs, repos as db_repos};

use crate::repos::{Repo, to_repo};
use crate::{Core, CoreError, CoreResult, accounts::User, permission::Permission, validate};

/// Longest org description, in characters (mirrors repository descriptions).
const MAX_DESCRIPTION_CHARS: usize = 350;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgRole {
    Owner,
    Member,
}

impl OrgRole {
    pub fn as_str(self) -> &'static str {
        match self {
            OrgRole::Owner => "owner",
            OrgRole::Member => "member",
        }
    }

    pub fn parse(s: &str) -> Option<OrgRole> {
        match s {
            "owner" => Some(OrgRole::Owner),
            "member" => Some(OrgRole::Member),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewOrgInput {
    pub handle: String,
    pub display_name: String,
    pub description: String,
}

#[derive(Debug, Clone, Default)]
pub struct OrgPatch {
    pub display_name: Option<String>,
    pub description: Option<String>,
    /// `none`, `read`, or `write`.
    pub base_permission: Option<String>,
}

/// The org profile: public fields plus member-only fields (`None` for
/// outsiders). The org page is public; membership is not (D4 visibility).
#[derive(Debug, Clone)]
pub struct OrgView {
    pub id: i64,
    pub handle: String,
    pub display_name: String,
    pub description: String,
    /// The org base permission, for members and site admins only.
    pub base_permission: Option<String>,
    /// For members and site admins only.
    pub member_count: Option<i64>,
    /// The viewer's own role, for members only.
    pub viewer_role: Option<OrgRole>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgMemberView {
    pub handle: String,
    pub display_name: String,
    pub role: OrgRole,
}

/// Trims a description and checks its length.
fn checked_description(input: &str) -> CoreResult<String> {
    let description = input.trim().to_owned();
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(CoreError::Invalid(format!(
            "descriptions are at most {MAX_DESCRIPTION_CHARS} characters"
        )));
    }
    Ok(description)
}

fn checked_base(input: &str) -> CoreResult<String> {
    match input {
        "none" | "read" | "write" => Ok(input.to_owned()),
        _ => Err(CoreError::Invalid(
            "base_permission must be none, read, or write".into(),
        )),
    }
}

fn ensure_active(user: &User) -> CoreResult<()> {
    if user.active {
        Ok(())
    } else {
        Err(CoreError::Forbidden)
    }
}

impl Core {
    /// Creates an org; the creator becomes its first owner (D1).
    pub async fn create_org(&self, user: &User, input: NewOrgInput) -> CoreResult<OrgView> {
        ensure_active(user)?;
        let handle = validate::handle(&input.handle)?;
        let display_name = if input.display_name.trim().is_empty() {
            handle.clone()
        } else {
            validate::display_name(&input.display_name)?
        };
        let description = checked_description(&input.description)?;
        let id = db_orgs::create(self.db(), &handle, &display_name, &description, user.id)
            .await
            .map_err(|e| {
                if e.is_unique_violation() {
                    CoreError::Invalid("that handle is already taken".into())
                } else {
                    e.into()
                }
            })?;
        self.audit(
            Some(user.id),
            "org.create",
            &format!("org:{handle}"),
            &handle,
        )
        .await?;
        Ok(OrgView {
            id,
            handle,
            display_name,
            description,
            base_permission: Some("none".into()),
            member_count: Some(1),
            viewer_role: Some(OrgRole::Owner),
        })
    }

    /// The org profile. Unknown handles are `NotFound`.
    pub async fn org(&self, viewer: Option<&User>, handle: &str) -> CoreResult<OrgView> {
        let viewer = viewer.filter(|u| u.active);
        let row = db_orgs::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        let role = match viewer {
            Some(u) => self.org_role(row.id, u.id).await?,
            None => None,
        };
        let privileged = viewer.map(|u| u.is_admin).unwrap_or(false) || role.is_some();
        Ok(OrgView {
            id: row.id,
            handle: row.handle,
            display_name: row.display_name,
            description: row.description,
            base_permission: privileged.then_some(row.base_permission),
            member_count: if privileged {
                Some(db_orgs::member_count(self.db(), row.id).await?)
            } else {
                None
            },
            viewer_role: role,
        })
    }

    /// Renames nothing (handles are immutable): edits the display name, the
    /// description, and the base permission. Owners only; no-ops write
    /// nothing, every real change writes one `org.update` row.
    pub async fn update_org(
        &self,
        user: &User,
        handle: &str,
        input: OrgPatch,
    ) -> CoreResult<OrgView> {
        ensure_active(user)?;
        let row = db_orgs::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        if self.org_role(row.id, user.id).await? != Some(OrgRole::Owner) {
            return Err(CoreError::Forbidden);
        }
        let display_name = match input.display_name {
            Some(d) if d.trim().is_empty() => row.handle.clone(),
            Some(d) => validate::display_name(&d)?,
            None => row.display_name.clone(),
        };
        let description = match input.description {
            Some(d) => checked_description(&d)?,
            None => row.description.clone(),
        };
        let base_permission = match input.base_permission {
            Some(b) => checked_base(&b)?,
            None => row.base_permission.clone(),
        };
        if display_name == row.display_name
            && description == row.description
            && base_permission == row.base_permission
        {
            return self.org(Some(user), &row.handle).await;
        }
        db_orgs::set(
            self.db(),
            row.id,
            &display_name,
            &description,
            &base_permission,
        )
        .await?;
        let mut changes = Vec::new();
        if display_name != row.display_name {
            changes.push(format!("display_name={display_name}"));
        }
        if description != row.description {
            changes.push("description=…".to_owned());
        }
        if base_permission != row.base_permission {
            changes.push(format!("base_permission={base_permission}"));
        }
        self.audit(
            Some(user.id),
            "org.update",
            &format!("org:{}", row.handle),
            &changes.join(" "),
        )
        .await?;
        self.org(Some(user), &row.handle).await
    }

    /// Deletes an org (D7): owners only, and only when it owns no live
    /// repositories and none soft-deleted inside the grace period. The
    /// count and the delete run in one per-org-locked transaction, so a
    /// racing creation or transfer cannot slip a repository in between.
    /// Teams and memberships cascade; the handle is freed. One `org.delete`
    /// audit row.
    pub async fn delete_org(&self, user: &User, handle: &str) -> CoreResult<()> {
        ensure_active(user)?;
        let row = db_orgs::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        if self.org_role(row.id, user.id).await? != Some(OrgRole::Owner) {
            return Err(CoreError::Forbidden);
        }
        let total =
            db_orgs::delete_serialized(self.db(), row.id, now() - crate::repos::RESTORE_SECS)
                .await?;
        if total > 0 {
            return Err(CoreError::Invalid(format!(
                "organization still owns {total} {}",
                if total == 1 {
                    "repository"
                } else {
                    "repositories"
                }
            )));
        }
        self.audit(
            Some(user.id),
            "org.delete",
            &format!("org:{}", row.handle),
            &row.handle,
        )
        .await
    }

    /// The member list: members and site admins only, everyone else 404s (D4
    /// visibility).
    pub async fn org_members(&self, viewer: &User, handle: &str) -> CoreResult<Vec<OrgMemberView>> {
        if !viewer.active {
            return Err(CoreError::NotFound);
        }
        let row = db_orgs::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        if !viewer.is_admin && self.org_role(row.id, viewer.id).await?.is_none() {
            return Err(CoreError::NotFound);
        }
        db_orgs::list_members(self.db(), row.id)
            .await?
            .into_iter()
            .map(|m| {
                Ok(OrgMemberView {
                    handle: m.handle,
                    display_name: m.display_name,
                    role: OrgRole::parse(&m.role).ok_or_else(|| {
                        CoreError::Internal(format!("unknown org role '{}'", m.role))
                    })?,
                })
            })
            .collect()
    }

    /// Adds an existing active user or changes their role. Owners only; the
    /// last owner cannot be demoted. No-ops write nothing; adds write one
    /// `org.member_add` row, role changes one `org.member_role` row.
    pub async fn set_org_member(
        &self,
        user: &User,
        handle: &str,
        member: &str,
        role: OrgRole,
    ) -> CoreResult<OrgMemberView> {
        ensure_active(user)?;
        let row = db_orgs::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        if self.org_role(row.id, user.id).await? != Some(OrgRole::Owner) {
            return Err(CoreError::Forbidden);
        }
        // `user_by_handle` joins `users`, so org handles can never resolve:
        // orgs cannot be members (D1).
        let target = self
            .user_by_handle(member)
            .await?
            .ok_or_else(|| CoreError::Invalid(format!("no user named '{member}'")))?;
        if !target.active {
            return Err(CoreError::Invalid(format!(
                "'{}' is suspended",
                target.handle
            )));
        }
        let view = |role: OrgRole| OrgMemberView {
            handle: target.handle.clone(),
            display_name: target.display_name.clone(),
            role,
        };
        let mut current = db_orgs::role(self.db(), row.id, target.id).await?;
        if current.is_none() {
            match db_orgs::add_member(self.db(), row.id, target.id, role.as_str()).await {
                Ok(()) => {
                    self.audit(
                        Some(user.id),
                        "org.member_add",
                        &format!("org:{}", row.handle),
                        &format!("{}={}", target.handle, role.as_str()),
                    )
                    .await?;
                    return Ok(view(role));
                }
                // Lost an add/add race: reconcile with the winner below
                // instead of failing 500 (A2 addendum).
                Err(e) if e.is_unique_violation() => {
                    current = db_orgs::role(self.db(), row.id, target.id).await?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        match current {
            None => Err(CoreError::NotFound),
            Some(existing) if existing == role.as_str() => Ok(view(role)),
            Some(_) => {
                if role == OrgRole::Member {
                    // Serialized demote (gate fix): the per-org lock plus the
                    // in-transaction re-checks close the READ COMMITTED write
                    // skew that orphaned orgs.
                    match db_orgs::demote_owner_serialized(self.db(), row.id, user.id, target.id)
                        .await?
                    {
                        db_orgs::OwnerChange::Done => {}
                        // A concurrent demotion won: already the target role.
                        db_orgs::OwnerChange::NoChange => return Ok(view(role)),
                        db_orgs::OwnerChange::LastOwner => {
                            return Err(CoreError::Invalid(
                                "the organization must keep at least one owner".into(),
                            ));
                        }
                        db_orgs::OwnerChange::Gone => return Err(CoreError::NotFound),
                        db_orgs::OwnerChange::Forbidden => return Err(CoreError::Forbidden),
                    }
                } else if !db_orgs::set_role(self.db(), row.id, target.id, role.as_str()).await? {
                    return Err(CoreError::NotFound);
                }
                self.audit(
                    Some(user.id),
                    "org.member_role",
                    &format!("org:{}", row.handle),
                    &format!("{}={}", target.handle, role.as_str()),
                )
                .await?;
                Ok(view(role))
            }
        }
    }

    /// Removes a member. Owners may remove anyone; a member may leave. The
    /// last owner cannot be removed. One `org.member_remove` row, and the
    /// member leaves every team of the org (D2). The removal runs in one
    /// per-org-locked transaction (gate fix), so racing owner changes cannot
    /// orphan the org.
    pub async fn remove_org_member(
        &self,
        user: &User,
        handle: &str,
        member: &str,
    ) -> CoreResult<()> {
        ensure_active(user)?;
        let row = db_orgs::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        let target = self
            .user_by_handle(member)
            .await?
            .ok_or(CoreError::NotFound)?;
        match db_orgs::remove_member_serialized(self.db(), row.id, user.id, target.id).await? {
            db_orgs::OwnerChange::Done => {}
            db_orgs::OwnerChange::LastOwner => {
                return Err(CoreError::Invalid(
                    "the organization must keep at least one owner".into(),
                ));
            }
            db_orgs::OwnerChange::Gone => return Err(CoreError::NotFound),
            db_orgs::OwnerChange::Forbidden => return Err(CoreError::Forbidden),
            // Removals always change something when they commit.
            db_orgs::OwnerChange::NoChange => return Err(CoreError::NotFound),
        }
        self.audit(
            Some(user.id),
            "org.member_remove",
            &format!("org:{}", row.handle),
            &target.handle,
        )
        .await
    }

    /// Handles of orgs where `user` is an owner, ordered by handle: the
    /// new-repository owner selector. Suspended users own nothing new.
    pub async fn owned_orgs(&self, user: &User) -> CoreResult<Vec<String>> {
        if !user.active {
            return Ok(Vec::new());
        }
        Ok(db_orgs::owned_by(self.db(), user.id).await?)
    }

    /// The viewer's org role, if any. Unknown orgs are `None` (callers that
    /// need 404 check existence first).
    pub(crate) async fn org_role(&self, org_id: i64, user_id: i64) -> CoreResult<Option<OrgRole>> {
        match db_orgs::role(self.db(), org_id, user_id).await? {
            Some(role) => Ok(Some(OrgRole::parse(&role).ok_or_else(|| {
                CoreError::Internal(format!("unknown org role '{role}'"))
            })?)),
            None => Ok(None),
        }
    }
}

/// Maps an org base-permission name to the grant it gives members: `none`
/// contributes nothing.
pub(crate) fn base_grant(base: &str) -> Option<Permission> {
    match base {
        "read" => Some(Permission::Read),
        "write" => Some(Permission::Write),
        _ => None,
    }
}

// --- Teams (A2, D3). -----------------------------------------------------------

/// A team: one permission level over all of the org's repositories, or over a
/// selected set (`all_repos` false).
#[derive(Debug, Clone)]
pub struct TeamView {
    pub id: i64,
    pub org_handle: String,
    pub name: String,
    pub slug: String,
    pub description: String,
    pub permission: Permission,
    pub all_repos: bool,
}

#[derive(Debug, Clone)]
pub struct NewTeamInput {
    pub name: String,
    pub description: String,
    pub permission: String,
    pub all_repos: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TeamPatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permission: Option<String>,
    pub all_repos: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeamMemberView {
    pub handle: String,
    pub display_name: String,
}

/// The team's URL slug: its lower name with spaces as `-`. One fn, used
/// everywhere a slug is derived or matched.
pub fn team_slug(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(' ', "-")
}

/// Team names: 1–64 characters of `A-Z a-z 0-9 space _ . -`.
fn checked_team_name(input: &str) -> CoreResult<String> {
    let name = input.trim();
    let ok = !name.is_empty()
        && name.chars().count() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '_' || c == '.' || c == '-');
    if !ok {
        return Err(CoreError::Invalid(
            "team names are 1–64 characters of A–Z a–z 0–9 space _ . -".into(),
        ));
    }
    Ok(name.to_owned())
}

fn checked_team_permission(input: &str) -> CoreResult<Permission> {
    Permission::parse(input.trim()).ok_or_else(|| {
        CoreError::Invalid("permission must be read, triage, write, maintain, or admin".into())
    })
}

fn team_view(org_handle: &str, row: db_orgs::TeamRow) -> CoreResult<TeamView> {
    Ok(TeamView {
        id: row.id,
        org_handle: org_handle.to_owned(),
        name: row.name.clone(),
        slug: team_slug(&row.lower_name),
        description: row.description,
        permission: Permission::parse(&row.permission).ok_or_else(|| {
            CoreError::Internal(format!("unknown team permission '{}'", row.permission))
        })?,
        all_repos: row.all_repos,
    })
}

impl Core {
    /// The org row when `user` owns it, else `Forbidden` (unknown orgs are
    /// `NotFound`). Suspended users cannot manage teams.
    async fn require_org_owner(&self, user: &User, handle: &str) -> CoreResult<db_orgs::OrgRow> {
        ensure_active(user)?;
        let row = db_orgs::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        if self.org_role(row.id, user.id).await? != Some(OrgRole::Owner) {
            return Err(CoreError::Forbidden);
        }
        Ok(row)
    }

    /// The org row when `viewer` may see member-only org data (a member or a
    /// site admin); everyone else gets `NotFound` (D8).
    async fn require_org_member_or_admin(
        &self,
        viewer: &User,
        handle: &str,
    ) -> CoreResult<db_orgs::OrgRow> {
        if !viewer.active {
            return Err(CoreError::NotFound);
        }
        let row = db_orgs::by_handle(self.db(), &handle.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)?;
        if !viewer.is_admin && self.org_role(row.id, viewer.id).await?.is_none() {
            return Err(CoreError::NotFound);
        }
        Ok(row)
    }

    /// The org's team addressed by its URL slug, else `NotFound`.
    async fn require_team(
        &self,
        org: &db_orgs::OrgRow,
        slug: &str,
    ) -> CoreResult<db_orgs::TeamRow> {
        db_orgs::team_by_slug(self.db(), org.id, &slug.trim().to_ascii_lowercase())
            .await?
            .ok_or(CoreError::NotFound)
    }

    /// Creates a team. Org owners only; names are unique per org,
    /// case-insensitively (slug collisions count too, so URLs stay unique).
    /// One `team.create` row.
    pub async fn create_team(
        &self,
        user: &User,
        handle: &str,
        input: NewTeamInput,
    ) -> CoreResult<TeamView> {
        let org = self.require_org_owner(user, handle).await?;
        let name = checked_team_name(&input.name)?;
        let description = checked_description(&input.description)?;
        let permission = checked_team_permission(&input.permission)?;
        let lower = name.to_ascii_lowercase();
        // Serialized behind the per-org lock (the UNIQUE constraint covers
        // only `lower_name`, so slug collisions need the check plus the
        // insert in one transaction); the loser reports 422, never 500.
        let id = match db_orgs::create_team(
            self.db(),
            org.id,
            &name,
            &lower,
            &description,
            permission.as_str(),
            input.all_repos,
        )
        .await
        {
            Ok(db_orgs::TeamCreate::Created(id)) => id,
            Ok(db_orgs::TeamCreate::Clash) => {
                return Err(CoreError::Invalid(format!("team '{name}' already exists")));
            }
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Invalid(format!("team '{name}' already exists")));
            }
            Err(e) => return Err(e.into()),
        };
        let slug = team_slug(&lower);
        self.audit(
            Some(user.id),
            "team.create",
            &format!("team:{}/{}", org.handle, slug),
            &format!(
                "permission={} all_repos={}",
                permission.as_str(),
                input.all_repos
            ),
        )
        .await?;
        Ok(TeamView {
            id,
            org_handle: org.handle,
            name,
            slug,
            description,
            permission,
            all_repos: input.all_repos,
        })
    }

    /// The org's teams, by name. Members and site admins only.
    pub async fn teams(&self, viewer: &User, handle: &str) -> CoreResult<Vec<TeamView>> {
        let org = self.require_org_member_or_admin(viewer, handle).await?;
        db_orgs::list_teams(self.db(), org.id)
            .await?
            .into_iter()
            .map(|row| team_view(&org.handle, row))
            .collect()
    }

    /// One team by URL slug. Members and site admins only.
    pub async fn team(&self, viewer: &User, handle: &str, slug: &str) -> CoreResult<TeamView> {
        let org = self.require_org_member_or_admin(viewer, handle).await?;
        let row = self.require_team(&org, slug).await?;
        team_view(&org.handle, row)
    }

    /// Renames (slugs follow), re-describes, re-permissions, or flips
    /// `all_repos`. Org owners only; no-ops write nothing, every real change
    /// writes one `team.update` row.
    pub async fn update_team(
        &self,
        user: &User,
        handle: &str,
        slug: &str,
        patch: TeamPatch,
    ) -> CoreResult<TeamView> {
        let org = self.require_org_owner(user, handle).await?;
        let row = self.require_team(&org, slug).await?;
        let current = team_view(&org.handle, row.clone())?;
        let name = match patch.name {
            Some(n) if n.trim().is_empty() => current.name.clone(),
            Some(n) => checked_team_name(&n)?,
            None => current.name.clone(),
        };
        let description = match patch.description {
            Some(d) => checked_description(&d)?,
            None => current.description.clone(),
        };
        let permission = match patch.permission {
            Some(p) => checked_team_permission(&p)?,
            None => current.permission,
        };
        let all_repos = patch.all_repos.unwrap_or(current.all_repos);
        if name == current.name
            && description == current.description
            && permission == current.permission
            && all_repos == current.all_repos
        {
            return Ok(current);
        }
        let lower = name.to_ascii_lowercase();
        // Serialized behind the per-org lock (finding 1): the clash check
        // and the update run in one transaction, so a racing conflicting
        // rename reports 422 instead of failing 500 on the UNIQUE constraint.
        match db_orgs::set_team(
            self.db(),
            org.id,
            row.id,
            &db_orgs::TeamFields {
                name: &name,
                lower_name: &lower,
                description: &description,
                permission: permission.as_str(),
                all_repos,
            },
        )
        .await
        {
            Ok(db_orgs::TeamUpdate::Done) => {}
            Ok(db_orgs::TeamUpdate::Clash) => {
                return Err(CoreError::Invalid(format!("team '{name}' already exists")));
            }
            Ok(db_orgs::TeamUpdate::Gone) => return Err(CoreError::NotFound),
            Err(e) if e.is_unique_violation() => {
                return Err(CoreError::Invalid(format!("team '{name}' already exists")));
            }
            Err(e) => return Err(e.into()),
        }
        let updated = team_view(
            &org.handle,
            db_orgs::TeamRow {
                name,
                lower_name: lower,
                description,
                permission: permission.as_str().into(),
                all_repos,
                ..row
            },
        )?;
        self.audit(
            Some(user.id),
            "team.update",
            &format!("team:{}/{}", org.handle, updated.slug),
            &format!("permission={} all_repos={}", permission.as_str(), all_repos),
        )
        .await?;
        Ok(updated)
    }

    /// Deletes a team; memberships and repo links cascade. Org owners only.
    /// One `team.delete` row.
    pub async fn delete_team(&self, user: &User, handle: &str, slug: &str) -> CoreResult<()> {
        let org = self.require_org_owner(user, handle).await?;
        let row = self.require_team(&org, slug).await?;
        db_orgs::delete_team(self.db(), row.id).await?;
        self.audit(
            Some(user.id),
            "team.delete",
            &format!("team:{}/{}", org.handle, team_slug(&row.lower_name)),
            &row.name,
        )
        .await
    }

    /// The team's members, by handle. Members and site admins only.
    pub async fn team_members(
        &self,
        viewer: &User,
        handle: &str,
        slug: &str,
    ) -> CoreResult<Vec<TeamMemberView>> {
        let org = self.require_org_member_or_admin(viewer, handle).await?;
        let row = self.require_team(&org, slug).await?;
        Ok(db_orgs::list_team_members(self.db(), row.id)
            .await?
            .into_iter()
            .map(|m| TeamMemberView {
                handle: m.handle,
                display_name: m.display_name,
            })
            .collect())
    }

    /// Adds an org member to the team. Org owners only; the target must
    /// already belong to the org (422 otherwise). Re-adding writes nothing;
    /// every real add writes one `team.member_add` row.
    pub async fn set_team_member(
        &self,
        user: &User,
        handle: &str,
        slug: &str,
        member: &str,
    ) -> CoreResult<TeamMemberView> {
        let org = self.require_org_owner(user, handle).await?;
        let row = self.require_team(&org, slug).await?;
        // `user_by_handle` joins `users`, so org handles can never resolve.
        let target = self
            .user_by_handle(member)
            .await?
            .ok_or_else(|| CoreError::Invalid(format!("no user named '{member}'")))?;
        if db_orgs::role(self.db(), org.id, target.id).await?.is_none() {
            return Err(CoreError::Invalid(format!(
                "'{}' is not a member of '{}'",
                target.handle, org.handle
            )));
        }
        if db_orgs::team_member_add(self.db(), row.id, target.id).await? {
            self.audit(
                Some(user.id),
                "team.member_add",
                &format!("team:{}/{}", org.handle, team_slug(&row.lower_name)),
                &target.handle,
            )
            .await?;
        }
        Ok(TeamMemberView {
            handle: target.handle,
            display_name: target.display_name,
        })
    }

    /// Removes a team member. Org owners only; unknown users and non-members
    /// are `NotFound`. One `team.member_remove` row.
    pub async fn remove_team_member(
        &self,
        user: &User,
        handle: &str,
        slug: &str,
        member: &str,
    ) -> CoreResult<()> {
        let org = self.require_org_owner(user, handle).await?;
        let row = self.require_team(&org, slug).await?;
        let target = self
            .user_by_handle(member)
            .await?
            .ok_or(CoreError::NotFound)?;
        if !db_orgs::team_member_remove(self.db(), row.id, target.id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "team.member_remove",
            &format!("team:{}/{}", org.handle, team_slug(&row.lower_name)),
            &target.handle,
        )
        .await
    }

    /// The team's repositories, by name. Members and site admins only.
    pub async fn team_repos(
        &self,
        viewer: &User,
        handle: &str,
        slug: &str,
    ) -> CoreResult<Vec<Repo>> {
        let org = self.require_org_member_or_admin(viewer, handle).await?;
        let row = self.require_team(&org, slug).await?;
        let mut repos = Vec::new();
        for id in db_orgs::list_team_repo_ids(self.db(), row.id).await? {
            if let Some(db_row) = db_repos::by_id(self.db(), id).await? {
                repos.push(to_repo(db_row)?);
            }
        }
        Ok(repos)
    }

    /// Links an org-owned repository to the team. Org owners only; a
    /// repository owned by someone else is 422, an unknown one 404.
    /// Re-linking writes nothing; every real link writes one `team.repo_add`
    /// row.
    pub async fn add_team_repo(
        &self,
        user: &User,
        handle: &str,
        slug: &str,
        repo: &str,
    ) -> CoreResult<()> {
        let org = self.require_org_owner(user, handle).await?;
        let row = self.require_team(&org, slug).await?;
        let name = repo.trim();
        let existing = db_repos::by_owner_and_name(self.db(), &org.handle, name).await?;
        let repo_id = match existing {
            Some(repo_row) => repo_row.id,
            None if db_orgs::repo_name_taken_by_other(
                self.db(),
                org.id,
                &name.to_ascii_lowercase(),
            )
            .await? =>
            {
                return Err(CoreError::Invalid(format!(
                    "'{name}' is not owned by '{}'",
                    org.handle
                )));
            }
            None => return Err(CoreError::NotFound),
        };
        if db_orgs::team_repo_add(self.db(), row.id, repo_id).await? {
            self.audit(
                Some(user.id),
                "team.repo_add",
                &format!("team:{}/{}", org.handle, team_slug(&row.lower_name)),
                name,
            )
            .await?;
        }
        Ok(())
    }

    /// Unlinks a repository from the team. Org owners only; unknown links are
    /// `NotFound`. One `team.repo_remove` row.
    pub async fn remove_team_repo(
        &self,
        user: &User,
        handle: &str,
        slug: &str,
        repo: &str,
    ) -> CoreResult<()> {
        let org = self.require_org_owner(user, handle).await?;
        let row = self.require_team(&org, slug).await?;
        let repo_row = db_repos::by_owner_and_name(self.db(), &org.handle, repo.trim())
            .await?
            .ok_or(CoreError::NotFound)?;
        if !db_orgs::team_repo_remove(self.db(), row.id, repo_row.id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "team.repo_remove",
            &format!("team:{}/{}", org.handle, team_slug(&row.lower_name)),
            repo.trim(),
        )
        .await
    }
}
