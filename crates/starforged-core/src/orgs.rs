//! Organizations: creation, membership, base permissions, deletion (D1-D3, D7).
//!
//! An org is an `owners` row with `kind = 'org'` plus an `orgs` row sharing
//! its id. Any active signed-in user may create one and becomes its first
//! owner; owners add existing active users directly. Team management arrives
//! in A2.

use starforged_db::{orgs as db_orgs, repos as db_repos};

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

    /// Deletes an org (D7): owners only, and only when it owns no
    /// repositories, including soft-deleted ones inside the grace period.
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
        let live = db_repos::list_by_owner(self.db(), row.id).await?.len();
        let deleted = db_repos::list_deleted_by_owner(self.db(), row.id)
            .await?
            .len();
        let total = live + deleted;
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
        db_orgs::delete(self.db(), row.id).await?;
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
        match db_orgs::role(self.db(), row.id, target.id).await? {
            Some(existing) if existing == role.as_str() => Ok(OrgMemberView {
                handle: target.handle,
                display_name: target.display_name,
                role,
            }),
            Some(existing) => {
                if existing == OrgRole::Owner.as_str()
                    && db_orgs::owner_count(self.db(), row.id).await? == 1
                {
                    return Err(CoreError::Invalid(
                        "the organization must keep at least one owner".into(),
                    ));
                }
                db_orgs::set_role(self.db(), row.id, target.id, role.as_str()).await?;
                self.audit(
                    Some(user.id),
                    "org.member_role",
                    &format!("org:{}", row.handle),
                    &format!("{}={}", target.handle, role.as_str()),
                )
                .await?;
                Ok(OrgMemberView {
                    handle: target.handle,
                    display_name: target.display_name,
                    role,
                })
            }
            None => {
                db_orgs::add_member(self.db(), row.id, target.id, role.as_str()).await?;
                self.audit(
                    Some(user.id),
                    "org.member_add",
                    &format!("org:{}", row.handle),
                    &format!("{}={}", target.handle, role.as_str()),
                )
                .await?;
                Ok(OrgMemberView {
                    handle: target.handle,
                    display_name: target.display_name,
                    role,
                })
            }
        }
    }

    /// Removes a member. Owners may remove anyone; a member may leave. The
    /// last owner cannot be removed. One `org.member_remove` row. (A2 also
    /// drops the member from the org's teams.)
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
        let actor_role = self.org_role(row.id, user.id).await?;
        if actor_role != Some(OrgRole::Owner) && target.id != user.id {
            if actor_role.is_none() {
                return Err(CoreError::NotFound);
            }
            return Err(CoreError::Forbidden);
        }
        let target_role = db_orgs::role(self.db(), row.id, target.id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if target_role == OrgRole::Owner.as_str()
            && db_orgs::owner_count(self.db(), row.id).await? == 1
        {
            return Err(CoreError::Invalid(
                "the organization must keep at least one owner".into(),
            ));
        }
        db_orgs::remove_member(self.db(), row.id, target.id).await?;
        self.audit(
            Some(user.id),
            "org.member_remove",
            &format!("org:{}", row.handle),
            &target.handle,
        )
        .await
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
