//! Trace Format v1: canonical encoding, segmentation, and fingerprinting.
//!
//! Implements the Trace Format v1 spec (plan M1a): session metadata
//! ([`SessionMeta`]), normalized events ([`Event`]), and version handling.

pub mod agent;
pub mod events;
pub mod segments;
pub mod session;

pub use agent::{UNTRUSTED_BEGINS, UNTRUSTED_ENDS, wrap_untrusted};
pub use events::{
    AssistantMessage, Compaction, Event, EventKind, FileChange, FileChangeKind, Reasoning,
    SubagentBoundary, System, ToolCall, ToolOutcome, ToolRef, ToolResult, UserMessage, kind_name,
    parse_event,
};
pub use segments::{DEFAULT_SEGMENT_CAP, assemble, blake3_hex, compress, decompress, split_jsonl};
pub use session::{
    Agent, AgentName, CaptureInfo, CaptureMode, FORMAT_TAG, RedactionSummary, RepoInfo,
    SessionMeta, Usage,
};
use thiserror::Error;

/// Errors from parsing Trace Format v1 documents.
#[derive(Debug, Error)]
pub enum FormatError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported event version: {0}")]
    UnsupportedVersion(u32),
    #[error("event is missing its `kind` field")]
    MissingKind,
    #[error("event kind `{kind}` is missing required field `{field}`")]
    InvalidField { kind: String, field: String },
    #[error("invalid ULID")]
    BadUlid,
    #[error("invalid RFC 3339 timestamp in `{0}`")]
    BadTimestamp(&'static str),
    #[error("unknown agent name: {0}")]
    BadAgent(String),
    #[error("wrong format tag: expected `starforge.session/v1`")]
    BadFormatTag,
    #[error("segment failed to decompress")]
    Decompress,
    #[error("segment payload is not valid UTF-8")]
    BadUtf8,
}
