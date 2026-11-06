//! Tag and branch protection for pushes (spec §8.2, M3b): one [`Core`] fn
//! builds the whole git-RPC environment, including a protection snapshot
//! for the pusher, plus tag-protection CRUD. HTTP uses it now; SSH (M3c)
//! will reuse it.
//!
//! The hook process never opens the database: it enforces only this
//! snapshot. `exempt` is computed per pusher at spawn (a direct user entry
//! or team membership); `tag_ok` is true for maintain+.

use serde::{Deserialize, Serialize};
use starforged_db::{
    checks as db_checks, now, orgs as db_orgs, protection as db_protection, trails as db_trails,
    users as db_users,
};

use crate::accounts::User;
use crate::orgs::team_slug;
use crate::permission::Permission;
use crate::repos::RepoAccess;
use crate::{Core, CoreError, CoreResult};

/// The push allow-list of one gate rule, as handles and team slugs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushAllowlistDto {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub teams: Vec<String>,
}

/// The `push_allowlist` half of a gate-rule create/update body: `None` is
/// absent (unchanged on update, empty on create); `Some` replaces the whole
/// list. `null` is rejected like every other non-pattern field.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PushAllowlistInput {
    pub users: Vec<String>,
    pub teams: Vec<String>,
}

/// One tag protection for the API: a glob; any tag it matches needs
/// maintain+ to create, move, or delete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagProtectionDto {
    pub id: i64,
    pub pattern: String,
    pub created_at: i64,
}

/// `POST …/tag-protections` body: exactly `{"pattern"}`. Unknown fields are
/// 422, like every other security-control body.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagProtectionInput {
    pub pattern: Option<String>,
}

/// One branch rule in the hook's snapshot: the pattern, the three blocks,
/// and whether the pusher is exempt from the direct-push block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchRuleSnapshot {
    pub pattern: Option<String>,
    pub direct: bool,
    pub force: bool,
    pub delete: bool,
    pub exempt: bool,
}

/// The `STARFORGE_PROTECTION` snapshot: branch rules, tag-protection globs
/// with the pusher's `tag_ok` (true for maintain+), and the allow-listed
/// namespaces from `git.allowed_ref_namespaces`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionSnapshot {
    pub v: u32,
    #[serde(default)]
    pub branches: Vec<BranchRuleSnapshot>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_true")]
    pub tag_ok: bool,
    #[serde(default)]
    pub namespaces: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Core {
    /// The full environment for a git-RPC child: identity, permission, and
    /// nonce plus the protection snapshot for the pusher. Replaces the
    /// inline assembly that lived in `githttp`.
    pub async fn git_rpc_env(
        &self,
        access: &RepoAccess,
        user: Option<&User>,
        scope_write: bool,
        nonce: &str,
    ) -> CoreResult<Vec<(&'static str, String)>> {
        let refs_for = self.refs_for_access(access.repo.id).await?;
        let is_member = match user {
            Some(user) => self.is_repo_member(access.repo.id, user.id).await?,
            None => false,
        };
        let tag_ok = matches!(
            access.permission,
            crate::permission::Permission::Maintain | crate::permission::Permission::Admin
        );
        let snapshot = self
            .protection_snapshot(access.repo.id, user, tag_ok)
            .await?;
        let protection =
            serde_json::to_string(&snapshot).map_err(|e| CoreError::Internal(e.to_string()))?;
        let mut env = Vec::with_capacity(9);
        env.push(("STARFORGE_REPO_ID", access.repo.id.to_string()));
        if let Some(user) = user {
            env.push(("STARFORGE_USER_ID", user.id.to_string()));
            env.push(("STARFORGE_USER_HANDLE", user.handle.clone()));
        }
        env.push((
            "STARFORGE_PERMISSION",
            access.permission.as_str().to_owned(),
        ));
        env.push((
            "STARFORGE_IS_MEMBER",
            if is_member {
                "1".to_owned()
            } else {
                "0".to_owned()
            },
        ));
        env.push(("STARFORGE_REFS_FOR", refs_for));
        env.push((
            "STARFORGE_SCOPE_WRITE",
            if scope_write {
                "1".to_owned()
            } else {
                "0".to_owned()
            },
        ));
        env.push(("STARFORGE_PUSH_NONCE", nonce.to_owned()));
        env.push(("STARFORGE_PROTECTION", protection));
        // M4b one-time import: pushes are refused while an import is
        // pending or running (M4b D3). The hook enforces this snapshot only.
        let importing = self.import_in_progress(access.repo.id).await?;
        env.push((
            "STARFORGE_IMPORT_IN_PROGRESS",
            if importing {
                "1".to_owned()
            } else {
                "0".to_owned()
            },
        ));
        // M4b pull mirror: every branch/tag push is refused while the
        // mirror is enabled (M4b D4); `refs/for` stays open for discussion.
        env.push((
            "STARFORGE_MIRROR",
            if access.repo.mirror {
                "1".to_owned()
            } else {
                "0".to_owned()
            },
        ));
        // M5a rate-limit snapshot: the remaining hourly new-change budget
        // and the pusher's own open agit topics in this repo. Absent when the
        // limit is disabled (the hook then enforces nothing); the ingest
        // re-checks the budget independently (plan M5a D2).
        if let Some(user) = user
            && let Some(budget) = self.refs_for_budget(user.id).await?
        {
            env.push(("STARFORGE_REFS_FOR_BUDGET", budget.to_string()));
            let topics = self.refs_for_topics(access.repo.id, user.id).await?;
            env.push(("STARFORGE_REFS_FOR_TOPICS", topics.join("\n")));
        }
        Ok(env)
    }

    /// The protection snapshot for `repo_id`, with `exempt` resolved for
    /// `user`: a direct user entry, or membership in an allow-listed team.
    /// Team entries only exist on org-owned repositories for teams of that
    /// org (validated on write), so a membership check is the whole test.
    async fn protection_snapshot(
        &self,
        repo_id: i64,
        user: Option<&User>,
        tag_ok: bool,
    ) -> CoreResult<ProtectionSnapshot> {
        let mut branches = Vec::new();
        for row in db_checks::gate_rules_for_repo(self.db(), repo_id).await? {
            let mut exempt = false;
            if let Some(user) = user {
                for entry in db_protection::push_allowlist_for_rule(self.db(), row.id).await? {
                    if entry.user_id == Some(user.id) {
                        exempt = true;
                        break;
                    }
                    if let Some(team_id) = entry.team_id
                        && db_protection::is_team_member(self.db(), team_id, user.id).await?
                    {
                        exempt = true;
                        break;
                    }
                }
            }
            branches.push(BranchRuleSnapshot {
                pattern: row.pattern.clone(),
                direct: row.block_direct_push != 0,
                force: row.block_force_push != 0,
                delete: row.block_deletion != 0,
                exempt,
            });
        }
        let mut tags = Vec::new();
        for row in db_protection::tag_protections_for_repo(self.db(), repo_id).await? {
            tags.push(row.pattern);
        }
        Ok(ProtectionSnapshot {
            v: 1,
            branches,
            tags,
            tag_ok,
            namespaces: self.config().allowed_ref_namespaces.clone(),
        })
    }

    /// Resolves an allow-list to stored ids: every handle must name an
    /// existing user (handles read back lowercase); team slugs resolve only
    /// on org-owned repositories for teams of that org. Anything else is
    /// `Invalid` (422).
    pub(crate) async fn resolve_push_allowlist(
        &self,
        repo_owner_id: i64,
        input: &PushAllowlistInput,
    ) -> CoreResult<Vec<(Option<i64>, Option<i64>)>> {
        let mut out = Vec::with_capacity(input.users.len() + input.teams.len());
        for handle in &input.users {
            let trimmed = handle.trim();
            if trimmed.is_empty() {
                return Err(CoreError::Invalid("unknown user ''".into()));
            }
            let row = self
                .user_by_handle(trimmed)
                .await?
                .ok_or_else(|| CoreError::Invalid(format!("unknown user '{trimmed}'")))?;
            out.push((Some(row.id), None));
        }
        if !input.teams.is_empty() {
            let owner = repo_owner_handle(self, repo_owner_id).await?;
            let org = db_orgs::by_handle(self.db(), &owner)
                .await?
                .ok_or_else(|| {
                    CoreError::Invalid(
                        "team allow-list entries need an org-owned repository".to_owned(),
                    )
                })?;
            for slug in &input.teams {
                let trimmed = slug.trim().to_ascii_lowercase();
                if trimmed.is_empty() {
                    return Err(CoreError::Invalid("unknown team ''".into()));
                }
                let team = db_orgs::team_by_slug(self.db(), org.id, &trimmed)
                    .await?
                    .ok_or_else(|| CoreError::Invalid(format!("unknown team '{trimmed}'")))?;
                out.push((None, Some(team.id)));
            }
        }
        // Dedupe, keeping the first occurrence.
        let mut seen = std::collections::HashSet::new();
        out.retain(|entry| seen.insert(*entry));
        Ok(out)
    }

    /// The allow-list of a rule as handles and team slugs, for the DTO.
    /// A dangling id (a deleted user or team, which cascade the row away —
    /// unreachable) surfaces as `Internal`.
    pub(crate) async fn push_allowlist_dto(&self, rule_id: i64) -> CoreResult<PushAllowlistDto> {
        let mut users = Vec::new();
        let mut teams = Vec::new();
        for entry in db_protection::push_allowlist_for_rule(self.db(), rule_id).await? {
            if let Some(user_id) = entry.user_id {
                let row = db_users::by_id(self.db(), user_id).await?.ok_or_else(|| {
                    CoreError::Internal(format!("allow-list user {user_id} is gone"))
                })?;
                users.push(row.handle);
            } else if let Some(team_id) = entry.team_id {
                let team = db_orgs::team_by_id(self.db(), team_id)
                    .await?
                    .ok_or_else(|| {
                        CoreError::Internal(format!("allow-list team {team_id} is gone"))
                    })?;
                teams.push(team_slug(&team.lower_name));
            }
        }
        Ok(PushAllowlistDto { users, teams })
    }

    /// Tag protections of the repo in insert order. Any repository reader
    /// may list (like gate rules); a missing repo or one the viewer cannot
    /// read is `NotFound`.
    pub async fn list_tag_protections(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Vec<TagProtectionDto>> {
        let access = self.repo_for(viewer, owner, repo).await?;
        let mut out = Vec::new();
        for row in db_protection::tag_protections_for_repo(self.db(), access.repo.id).await? {
            out.push(TagProtectionDto {
                id: row.id,
                pattern: row.pattern,
                created_at: row.created_at,
            });
        }
        Ok(out)
    }

    /// Creates a tag protection (≥ `Maintain`): validates the glob, refuses
    /// archived repos and duplicate patterns, then records timeline + audit
    /// rows.
    pub async fn create_tag_protection(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        input: &TagProtectionInput,
    ) -> CoreResult<TagProtectionDto> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        let pattern = normalize_tag_pattern(input.pattern.clone())?;
        for row in db_protection::tag_protections_for_repo(self.db(), access.repo.id).await? {
            if row.pattern == pattern {
                return Err(CoreError::Conflict(format!(
                    "a tag protection for '{pattern}' already exists"
                )));
            }
        }
        let stamp = now();
        let row = db_protection::insert_tag_protection(self.db(), access.repo.id, &pattern, stamp)
            .await?;
        let view = TagProtectionDto {
            id: row.id,
            pattern: row.pattern,
            created_at: row.created_at,
        };
        let payload =
            serde_json::to_string(&view).map_err(|e| CoreError::Internal(e.to_string()))?;
        db_trails::insert_timeline(
            self.db(),
            access.repo.id,
            None,
            "tag_protection.created",
            Some(user.id),
            &payload,
            now(),
        )
        .await?;
        self.audit(
            Some(user.id),
            "tag_protection.created",
            &tag_protection_target(owner, repo, row.id),
            &payload,
        )
        .await?;
        Ok(view)
    }

    /// Deletes a tag protection (≥ `Maintain`); a missing id or another
    /// repo's id is `NotFound`. The timeline payload is the rule as it was.
    pub async fn delete_tag_protection(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        id: i64,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        let row = db_protection::tag_protection_by_id(self.db(), id, access.repo.id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let view = TagProtectionDto {
            id: row.id,
            pattern: row.pattern,
            created_at: row.created_at,
        };
        let payload =
            serde_json::to_string(&view).map_err(|e| CoreError::Internal(e.to_string()))?;
        if !db_protection::delete_tag_protection(self.db(), id, access.repo.id).await? {
            return Err(CoreError::NotFound);
        }
        db_trails::insert_timeline(
            self.db(),
            access.repo.id,
            None,
            "tag_protection.deleted",
            Some(user.id),
            &payload,
            now(),
        )
        .await?;
        self.audit(
            Some(user.id),
            "tag_protection.deleted",
            &tag_protection_target(owner, repo, id),
            &payload,
        )
        .await?;
        Ok(())
    }
}

/// The single "all tags" pattern is not a thing: a tag protection always
/// names a glob, 1–100 chars from exactly what
/// `starforged_git::refpolicy::pattern_matches` understands. Missing, null,
/// and blank patterns are `Invalid`.
fn normalize_tag_pattern(raw: Option<String>) -> CoreResult<String> {
    let Some(text) = raw else {
        return Err(CoreError::Invalid("pattern is required".into()));
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(CoreError::Invalid("pattern is required".into()));
    }
    let ok = (1..=100).contains(&trimmed.chars().count())
        && trimmed.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-' | b'*' | b'?')
        });
    if !ok {
        return Err(CoreError::Invalid(format!(
            "invalid pattern '{trimmed}' (1-100 chars of A-Z a-z 0-9 . _ / - and glob * ?)"
        )));
    }
    Ok(trimmed.to_owned())
}

fn tag_protection_target(owner: &str, repo: &str, id: i64) -> String {
    format!("tag_protection:{owner}/{repo}#{id}")
}

/// The lowercase handle of the repository's owner, for org detection.
async fn repo_owner_handle(core: &Core, owner_id: i64) -> CoreResult<String> {
    db_orgs::owner_handle_by_id(core.db(), owner_id)
        .await?
        .ok_or_else(|| CoreError::Internal(format!("owner {owner_id} is gone")))
}
