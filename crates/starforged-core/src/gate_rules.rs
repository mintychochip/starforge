//! Repository merge-gate rules (spec §6.2, M2c H7): CRUD on [`Core`].
//!
//! `gates.rs` stays read-only evaluation; everything that writes a rule
//! lives here. Any repo reader may list (rules hold no secrets, and the
//! change-page gate panel already shows readers each rule's requirements);
//! mutations need ≥ `Maintain` on a non-archived repo. One normalized
//! pattern exists per repo: a duplicate create or an update onto another
//! rule's pattern is `Conflict`. Two concurrent creates can both insert —
//! that window is accepted because duplicate rules AND together and stay
//! fail-closed. Every successful mutation writes exactly one timeline row
//! and one audit row in the same method, carrying the full normalized rule
//! (after the write for created/updated, as it was for deleted).

use serde::{Deserialize, Serialize};
use starforged_db::{checks as db_checks, now, trails as db_trails};

use crate::accounts::User;
use crate::checks::validate_context;
use crate::permission::Permission;
use crate::{Core, CoreError, CoreResult};

/// Merge methods a rule may restrict merges to; `[]` means all three.
const ALLOWED_METHODS: [&str; 3] = ["merge", "squash", "fast_forward"];

/// One gate rule for the API and the settings page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateRuleDto {
    pub id: i64,
    pub pattern: Option<String>,
    pub required_approvals: i64,
    pub dismiss_on_push: bool,
    pub block_on_request_changes: bool,
    pub required_contexts: Vec<String>,
    pub require_up_to_date: bool,
    pub require_threads_resolved: bool,
    pub require_session_evidence: bool,
    pub allowed_methods: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Create/update input with absent-vs-null tracking: `None` means absent
/// (the default on create, unchanged on update), `Some(None)` is an
/// explicit JSON `null` (`""` and `null` both mean all branches for
/// `pattern`; `null` for any other field is `Invalid`), and
/// `Some(Some(_))` is the new value.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GateRuleInput {
    #[serde(default, deserialize_with = "absent_or_null")]
    pub pattern: Option<Option<String>>,
    #[serde(default, deserialize_with = "absent_or_null")]
    pub required_approvals: Option<Option<i64>>,
    #[serde(default, deserialize_with = "absent_or_null")]
    pub dismiss_on_push: Option<Option<bool>>,
    #[serde(default, deserialize_with = "absent_or_null")]
    pub block_on_request_changes: Option<Option<bool>>,
    #[serde(default, deserialize_with = "absent_or_null")]
    pub required_contexts: Option<Option<Vec<String>>>,
    #[serde(default, deserialize_with = "absent_or_null")]
    pub require_up_to_date: Option<Option<bool>>,
    #[serde(default, deserialize_with = "absent_or_null")]
    pub require_threads_resolved: Option<Option<bool>>,
    #[serde(default, deserialize_with = "absent_or_null")]
    pub require_session_evidence: Option<Option<bool>>,
    #[serde(default, deserialize_with = "absent_or_null")]
    pub allowed_methods: Option<Option<Vec<String>>>,
}

/// Absent-vs-null tracking for request bodies: a missing field never reaches
/// the deserializer (field `default` yields `None` = absent), while a
/// present field — including an explicit JSON `null` — maps to
/// `Some(inner)`. Without this, `null` would silently default to absent.
fn absent_or_null<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// The merged, validated rule ready to store.
struct Normalized {
    pattern: Option<String>,
    approvals: i64,
    dismiss_on_push: bool,
    block_on_request_changes: bool,
    contexts: Vec<String>,
    up_to_date: bool,
    threads_resolved: bool,
    session_evidence: bool,
    methods: Vec<String>,
}

fn dto_of(row: &db_checks::GateRuleRow) -> CoreResult<GateRuleDto> {
    let contexts: Vec<String> = serde_json::from_str(&row.required_contexts)
        .map_err(|e| CoreError::Internal(format!("unreadable required_contexts: {e}")))?;
    let methods: Vec<String> = serde_json::from_str(&row.allowed_methods)
        .map_err(|e| CoreError::Internal(format!("unreadable allowed_methods: {e}")))?;
    Ok(GateRuleDto {
        id: row.id,
        pattern: row.pattern.clone(),
        required_approvals: row.required_approvals,
        dismiss_on_push: row.dismiss_on_push != 0,
        block_on_request_changes: row.block_on_request_changes != 0,
        required_contexts: contexts,
        require_up_to_date: row.require_up_to_date != 0,
        require_threads_resolved: row.require_threads_resolved != 0,
        require_session_evidence: row.require_session_evidence != 0,
        allowed_methods: methods,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// `null`/`""` is the one "all branches" representation; otherwise 1–100
/// chars from exactly what `pattern_matches` understands.
fn normalize_pattern(raw: Option<String>) -> CoreResult<Option<String>> {
    let Some(text) = raw else {
        return Ok(None);
    };
    if text.is_empty() {
        return Ok(None);
    }
    let len = text.chars().count();
    let ok = (1..=100).contains(&len)
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-' | b'*' | b'?')
        });
    if !ok {
        return Err(CoreError::Invalid(format!(
            "invalid pattern '{text}' (1-100 chars of A-Z a-z 0-9 . _ / - and glob * ?)"
        )));
    }
    Ok(Some(text))
}

fn resolve<T: Clone>(base: T, patch: &Option<Option<T>>, field: &str) -> CoreResult<T> {
    match patch {
        None => Ok(base),
        Some(None) => Err(CoreError::Invalid(format!("{field} must not be null"))),
        Some(Some(value)) => Ok(value.clone()),
    }
}

/// Merges `input` over `base` and validates the merged result as a whole.
fn normalize(base: &GateRuleDto, input: &GateRuleInput) -> CoreResult<Normalized> {
    let pattern = match &input.pattern {
        None => base.pattern.clone(),
        Some(slot) => normalize_pattern(slot.clone())?,
    };
    let approvals = resolve(
        base.required_approvals,
        &input.required_approvals,
        "required_approvals",
    )?;
    if !(0..=20).contains(&approvals) {
        return Err(CoreError::Invalid(format!(
            "invalid required_approvals '{approvals}' (expected 0-20)"
        )));
    }
    let mut contexts = resolve(
        base.required_contexts.clone(),
        &input.required_contexts,
        "required_contexts",
    )?;
    for ctx in &mut contexts {
        *ctx = ctx.trim().to_owned();
    }
    for ctx in &contexts {
        validate_context(ctx).map_err(|_| {
            CoreError::Invalid(format!(
                "invalid required_contexts entry '{ctx}' (each must be 1-100 characters)"
            ))
        })?;
    }
    let mut seen = std::collections::HashSet::new();
    contexts.retain(|ctx| seen.insert(ctx.clone()));
    if contexts.len() > 50 {
        return Err(CoreError::Invalid(
            "invalid required_contexts (at most 50 entries)".into(),
        ));
    }
    let mut methods = resolve(
        base.allowed_methods.clone(),
        &input.allowed_methods,
        "allowed_methods",
    )?;
    for method in &methods {
        if !ALLOWED_METHODS.contains(&method.as_str()) {
            return Err(CoreError::Invalid(format!(
                "invalid allowed_methods entry '{method}' (expected one of merge, squash, fast_forward)"
            )));
        }
    }
    let mut seen = std::collections::HashSet::new();
    methods.retain(|m| seen.insert(m.clone()));
    Ok(Normalized {
        pattern,
        approvals,
        dismiss_on_push: resolve(
            base.dismiss_on_push,
            &input.dismiss_on_push,
            "dismiss_on_push",
        )?,
        block_on_request_changes: resolve(
            base.block_on_request_changes,
            &input.block_on_request_changes,
            "block_on_request_changes",
        )?,
        contexts,
        up_to_date: resolve(
            base.require_up_to_date,
            &input.require_up_to_date,
            "require_up_to_date",
        )?,
        threads_resolved: resolve(
            base.require_threads_resolved,
            &input.require_threads_resolved,
            "require_threads_resolved",
        )?,
        session_evidence: resolve(
            base.require_session_evidence,
            &input.require_session_evidence,
            "require_session_evidence",
        )?,
        methods,
    })
}

fn default_dto() -> GateRuleDto {
    GateRuleDto {
        id: 0,
        pattern: None,
        required_approvals: 0,
        dismiss_on_push: false,
        block_on_request_changes: true,
        required_contexts: Vec::new(),
        require_up_to_date: false,
        require_threads_resolved: false,
        require_session_evidence: false,
        allowed_methods: Vec::new(),
        created_at: 0,
        updated_at: 0,
    }
}

fn gate_rule_target(owner: &str, repo: &str, id: i64) -> String {
    format!("gate_rule:{owner}/{repo}#{id}")
}

impl Core {
    /// Gate rules of the repo in insert order. Any reader may list; a
    /// missing repo or one the viewer cannot read is `NotFound`.
    pub async fn list_gate_rules(
        &self,
        viewer: Option<&User>,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Vec<GateRuleDto>> {
        let access = self.repo_for(viewer, owner, repo).await?;
        let mut out = Vec::new();
        for row in db_checks::gate_rules_for_repo(self.db(), access.repo.id).await? {
            out.push(dto_of(&row)?);
        }
        Ok(out)
    }

    /// Creates a rule (≥ `Maintain`): validates, refuses archived repos and
    /// duplicate patterns, then records timeline + audit rows.
    pub async fn create_gate_rule(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        input: &GateRuleInput,
    ) -> CoreResult<GateRuleDto> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        let rule = normalize(&default_dto(), input)?;
        for row in db_checks::gate_rules_for_repo(self.db(), access.repo.id).await? {
            if row.pattern == rule.pattern {
                return Err(CoreError::Conflict(format!(
                    "a gate rule for {} already exists",
                    rule.pattern.as_deref().unwrap_or("all branches")
                )));
            }
        }
        let contexts = serde_json::to_string(&rule.contexts)
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        let methods =
            serde_json::to_string(&rule.methods).map_err(|e| CoreError::Internal(e.to_string()))?;
        let row = db_checks::insert_gate_rule(
            self.db(),
            access.repo.id,
            rule.pattern.as_deref(),
            rule.approvals,
            rule.dismiss_on_push,
            rule.block_on_request_changes,
            &contexts,
            rule.up_to_date,
            rule.threads_resolved,
            rule.session_evidence,
            &methods,
            now(),
        )
        .await?;
        let view = dto_of(&row)?;
        let payload =
            serde_json::to_string(&view).map_err(|e| CoreError::Internal(e.to_string()))?;
        db_trails::insert_timeline(
            self.db(),
            access.repo.id,
            None,
            "gate_rule.created",
            Some(user.id),
            &payload,
            now(),
        )
        .await?;
        self.audit(
            Some(user.id),
            "gate_rule.created",
            &gate_rule_target(owner, repo, row.id),
            &payload,
        )
        .await?;
        Ok(view)
    }

    /// Updates a rule in place (≥ `Maintain`): absent fields stay, and the
    /// merged result is validated as a whole. A missing id or another
    /// repo's id is `NotFound`.
    pub async fn update_gate_rule(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        id: i64,
        input: &GateRuleInput,
    ) -> CoreResult<GateRuleDto> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Maintain)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid("repository is archived".into()));
        }
        let row = db_checks::gate_rule_by_id(self.db(), id, access.repo.id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let rule = normalize(&dto_of(&row)?, input)?;
        for other in db_checks::gate_rules_for_repo(self.db(), access.repo.id).await? {
            if other.id != id && other.pattern == rule.pattern {
                return Err(CoreError::Conflict(format!(
                    "a gate rule for {} already exists",
                    rule.pattern.as_deref().unwrap_or("all branches")
                )));
            }
        }
        let contexts = serde_json::to_string(&rule.contexts)
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        let methods =
            serde_json::to_string(&rule.methods).map_err(|e| CoreError::Internal(e.to_string()))?;
        let row = db_checks::update_gate_rule(
            self.db(),
            id,
            access.repo.id,
            &db_checks::GateRuleUpdate {
                pattern: Some(rule.pattern.as_deref()),
                approvals: Some(rule.approvals),
                dismiss_on_push: Some(rule.dismiss_on_push),
                block_rc: Some(rule.block_on_request_changes),
                contexts: Some(&contexts),
                up_to_date: Some(rule.up_to_date),
                threads: Some(rule.threads_resolved),
                session_ev: Some(rule.session_evidence),
                methods: Some(&methods),
            },
            now(),
        )
        .await?
        .ok_or(CoreError::NotFound)?;
        let view = dto_of(&row)?;
        let payload =
            serde_json::to_string(&view).map_err(|e| CoreError::Internal(e.to_string()))?;
        db_trails::insert_timeline(
            self.db(),
            access.repo.id,
            None,
            "gate_rule.updated",
            Some(user.id),
            &payload,
            now(),
        )
        .await?;
        self.audit(
            Some(user.id),
            "gate_rule.updated",
            &gate_rule_target(owner, repo, id),
            &payload,
        )
        .await?;
        Ok(view)
    }

    /// Deletes a rule (≥ `Maintain`); a missing id or another repo's id is
    /// `NotFound`. The timeline payload is the rule as it was, so the
    /// timeline alone reconstructs what was removed.
    pub async fn delete_gate_rule(
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
        let row = db_checks::gate_rule_by_id(self.db(), id, access.repo.id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let payload = serde_json::to_string(&dto_of(&row)?)
            .map_err(|e| CoreError::Internal(e.to_string()))?;
        if !db_checks::delete_gate_rule(self.db(), id, access.repo.id).await? {
            return Err(CoreError::NotFound);
        }
        db_trails::insert_timeline(
            self.db(),
            access.repo.id,
            None,
            "gate_rule.deleted",
            Some(user.id),
            &payload,
            now(),
        )
        .await?;
        self.audit(
            Some(user.id),
            "gate_rule.deleted",
            &gate_rule_target(owner, repo, id),
            &payload,
        )
        .await?;
        Ok(())
    }
}
