//! Trace Format v1 session metadata (`meta.json`).
//!
//! Spec: `docs/format/session-v1.md` (design §7.8). Unknown fields are
//! tolerated everywhere; [`SessionMeta::parse`] is the validating entry
//! point and reports precise [`FormatError`]s.

use std::collections::BTreeMap;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use ulid::Ulid;

use crate::FormatError;

pub const FORMAT_TAG: &str = "starforge.session/v1";

/// Session metadata: one JSON object per session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMeta {
    pub format: String,
    pub id: Ulid,
    #[serde(default)]
    pub agent: Agent,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub title: Option<String>,
    pub started_at: String,
    #[serde(default)]
    pub ended_at: Option<String>,
    #[serde(default)]
    pub repo: RepoInfo,
    #[serde(default)]
    pub parent_id: Option<Ulid>,
    #[serde(default)]
    pub usage: Usage,
    #[serde(default)]
    pub files_touched: Vec<String>,
    #[serde(default)]
    pub redaction: RedactionSummary,
    #[serde(default)]
    pub capture: CaptureInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Agent {
    pub name: AgentName,
    #[serde(default)]
    pub version: String,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            name: AgentName::ClaudeCode,
            version: String::new(),
        }
    }
}

/// Agent that produced the session. Unknown names are rejected by
/// [`SessionMeta::parse`] with [`FormatError::BadAgent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentName {
    ClaudeCode,
    Codex,
    Pi,
    Opencode,
    Gemini,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RepoInfo {
    #[serde(default)]
    pub remote_urls: Vec<String>,
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub head_at_start: String,
}

/// Token totals. Every counter defaults to `0` so older writers that omit a
/// counter still parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub input: u64,
    #[serde(default)]
    pub output: u64,
    #[serde(default)]
    pub cache_read: u64,
    #[serde(default)]
    pub cache_write: u64,
    #[serde(default)]
    pub reasoning: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RedactionSummary {
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureInfo {
    pub mode: CaptureMode,
    #[serde(default)]
    pub cli_version: String,
    #[serde(default)]
    pub adapter_version_verified: bool,
}

impl Default for CaptureInfo {
    fn default() -> Self {
        Self {
            mode: CaptureMode::Discovery,
            cli_version: String::new(),
            adapter_version_verified: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureMode {
    Hook,
    Discovery,
}

/// Raw session shape: every scalar arrives as a string so `parse` can report
/// [`FormatError::BadUlid`], [`FormatError::BadTimestamp`],
/// [`FormatError::BadAgent`], and [`FormatError::BadFormatTag`] instead of a
/// generic JSON error.
#[derive(Debug, Deserialize)]
struct RawSessionMeta {
    format: String,
    id: String,
    agent: RawAgent,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    title: Option<String>,
    started_at: String,
    #[serde(default)]
    ended_at: Option<String>,
    #[serde(default)]
    repo: RepoInfo,
    #[serde(default)]
    parent_id: Option<String>,
    #[serde(default)]
    usage: Usage,
    #[serde(default)]
    files_touched: Vec<String>,
    #[serde(default)]
    redaction: RedactionSummary,
    #[serde(default)]
    capture: Option<CaptureInfo>,
}

#[derive(Debug, Deserialize)]
struct RawAgent {
    name: String,
    #[serde(default)]
    version: String,
}

fn parse_ulid(_field: &'static str, value: &str) -> Result<Ulid, FormatError> {
    Ulid::from_str(value).map_err(|_| FormatError::BadUlid)
}

fn check_ts(field: &'static str, value: &str) -> Result<(), FormatError> {
    time::OffsetDateTime::parse(value, &Rfc3339)
        .map(|_| ())
        .map_err(|_| FormatError::BadTimestamp(field))
}

fn parse_agent_name(name: &str) -> Result<AgentName, FormatError> {
    match name {
        "claude-code" => Ok(AgentName::ClaudeCode),
        "codex" => Ok(AgentName::Codex),
        "pi" => Ok(AgentName::Pi),
        "opencode" => Ok(AgentName::Opencode),
        "gemini" => Ok(AgentName::Gemini),
        other => Err(FormatError::BadAgent(other.to_string())),
    }
}

impl SessionMeta {
    /// Parse and validate session metadata, rejecting bad tags, ULIDs,
    /// timestamps, and agent names with precise errors.
    pub fn parse(s: &str) -> Result<Self, FormatError> {
        let raw: RawSessionMeta = serde_json::from_str(s)?;
        if raw.format != FORMAT_TAG {
            return Err(FormatError::BadFormatTag);
        }
        let id = parse_ulid("id", &raw.id)?;
        let parent_id = raw
            .parent_id
            .map(|p| parse_ulid("parent_id", &p))
            .transpose()?;
        check_ts("started_at", &raw.started_at)?;
        if let Some(ref ended) = raw.ended_at {
            check_ts("ended_at", ended)?;
        }
        Ok(Self {
            format: raw.format,
            id,
            agent: Agent {
                name: parse_agent_name(&raw.agent.name)?,
                version: raw.agent.version,
            },
            models: raw.models,
            title: raw.title,
            started_at: raw.started_at,
            ended_at: raw.ended_at,
            repo: raw.repo,
            parent_id,
            usage: raw.usage,
            files_touched: raw.files_touched,
            redaction: raw.redaction,
            capture: raw.capture.unwrap_or_default(),
        })
    }
}
