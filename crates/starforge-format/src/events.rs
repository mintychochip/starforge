//! Trace Format v1 events: one JSON object per JSONL line.
//!
//! Spec: `docs/format/events-v1.md` (design §7.8). Unknown `kind` values
//! parse into [`EventKind::Unknown`] and unknown top-level fields are
//! captured in [`Event::extra`]; both re-serialize unchanged.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::format_description::well_known::Rfc3339;

use crate::FormatError;
use crate::session::Usage;

/// One normalized event line.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub v: u32,
    pub seq: u64,
    pub ts: String,
    pub kind: EventKind,
    /// Unknown top-level fields, preserved across round-trips.
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    UserMessage(UserMessage),
    AssistantMessage(AssistantMessage),
    Reasoning(Reasoning),
    ToolCall(ToolCall),
    ToolResult(ToolResult),
    FileChange(FileChange),
    Compaction(Compaction),
    SubagentStart(SubagentBoundary),
    SubagentEnd(SubagentBoundary),
    System(System),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserMessage {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistantMessage {
    pub text: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub usage: Usage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reasoning {
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: ToolRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRef {
    pub name: String,
    #[serde(default)]
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResult {
    pub result: ToolOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolOutcome {
    #[serde(default)]
    pub output: String,
    #[serde(default)]
    pub is_error: bool,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub original_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub change: FileChangeKind,
    #[serde(default)]
    pub diff: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileChangeKind {
    Add,
    Modify,
    Delete,
    Rename,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Compaction {
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubagentBoundary {
    pub subagent_id: String,
    pub task: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct System {
    pub text: String,
}

/// `kind` string for each known variant.
pub fn kind_name(kind: &EventKind) -> &str {
    match kind {
        EventKind::UserMessage(_) => "user_message",
        EventKind::AssistantMessage(_) => "assistant_message",
        EventKind::Reasoning(_) => "reasoning",
        EventKind::ToolCall(_) => "tool_call",
        EventKind::ToolResult(_) => "tool_result",
        EventKind::FileChange(_) => "file_change",
        EventKind::Compaction(_) => "compaction",
        EventKind::SubagentStart(_) => "subagent_start",
        EventKind::SubagentEnd(_) => "subagent_end",
        EventKind::System(_) => "system",
        EventKind::Unknown(name) => name,
    }
}

fn invalid(kind: &str, err: serde_json::Error) -> FormatError {
    let msg = err.to_string();
    if let Some(rest) = msg.strip_prefix("missing field `")
        && let Some(field) = rest.strip_suffix('`')
    {
        return FormatError::InvalidField {
            kind: kind.to_string(),
            field: field.to_string(),
        };
    }
    FormatError::Json(err)
}

fn payload<T: for<'de> Deserialize<'de>>(kind: &str, value: &Value) -> Result<T, FormatError> {
    serde_json::from_value(value.clone()).map_err(|e| invalid(kind, e))
}

fn decode_kind(kind: &str, value: &Value) -> Result<EventKind, FormatError> {
    match kind {
        "user_message" => Ok(EventKind::UserMessage(payload(kind, value)?)),
        "assistant_message" => Ok(EventKind::AssistantMessage(payload(kind, value)?)),
        "reasoning" => Ok(EventKind::Reasoning(payload(kind, value)?)),
        "tool_call" => Ok(EventKind::ToolCall(payload(kind, value)?)),
        "tool_result" => Ok(EventKind::ToolResult(payload(kind, value)?)),
        "file_change" => {
            let fc: FileChange = serde_json::from_value(value.clone()).map_err(|e| {
                let msg = e.to_string();
                if msg.contains("unknown variant") {
                    return FormatError::InvalidField {
                        kind: kind.to_string(),
                        field: "change".to_string(),
                    };
                }
                invalid(kind, e)
            })?;
            Ok(EventKind::FileChange(fc))
        }
        "compaction" => Ok(EventKind::Compaction(payload(kind, value)?)),
        "subagent_start" => Ok(EventKind::SubagentStart(payload(kind, value)?)),
        "subagent_end" => Ok(EventKind::SubagentEnd(payload(kind, value)?)),
        "system" => Ok(EventKind::System(payload(kind, value)?)),
        other => Ok(EventKind::Unknown(other.to_string())),
    }
}

fn encode_kind(kind: &EventKind) -> Value {
    let mut map = match kind {
        EventKind::UserMessage(p) => serde_json::to_value(p),
        EventKind::AssistantMessage(p) => serde_json::to_value(p),
        EventKind::Reasoning(p) => serde_json::to_value(p),
        EventKind::ToolCall(p) => serde_json::to_value(p),
        EventKind::ToolResult(p) => serde_json::to_value(p),
        EventKind::FileChange(p) => serde_json::to_value(p),
        EventKind::Compaction(p) => serde_json::to_value(p),
        EventKind::SubagentStart(p) | EventKind::SubagentEnd(p) => serde_json::to_value(p),
        EventKind::System(p) => serde_json::to_value(p),
        EventKind::Unknown(_) => Ok(Value::Object(Default::default())),
    }
    .expect("payload serializes to an object");
    let obj = map.as_object_mut().expect("payload is an object");
    obj.insert(
        "kind".to_string(),
        Value::String(kind_name(kind).to_string()),
    );
    map
}

/// Parse and validate one event line.
pub fn parse_event(line: &str) -> Result<Event, FormatError> {
    let value: Value = serde_json::from_str(line)?;
    let obj = value.as_object().ok_or(FormatError::MissingKind)?;
    let v: u32 = match obj.get("v") {
        Some(raw) => serde_json::from_value(raw.clone()).map_err(FormatError::Json)?,
        None => {
            return Err(FormatError::InvalidField {
                kind: "event".to_string(),
                field: "v".to_string(),
            });
        }
    };
    if v != 1 {
        return Err(FormatError::UnsupportedVersion(v));
    }
    let kind_str = obj
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(FormatError::MissingKind)?;
    let missing = |field: &str| FormatError::InvalidField {
        kind: kind_str.to_string(),
        field: field.to_string(),
    };
    let seq = obj
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| missing("seq"))?;
    let ts = obj
        .get("ts")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("ts"))?;
    time::OffsetDateTime::parse(ts, &Rfc3339).map_err(|_| FormatError::BadTimestamp("ts"))?;
    let kind = decode_kind(kind_str, &value)?;
    let mut extra = BTreeMap::new();
    for (k, val) in obj {
        match k.as_str() {
            "v" | "seq" | "ts" | "kind" => {}
            _ => {
                // Known payload fields already live in `kind`; only genuinely
                // unknown fields land in `extra`.
                let payload_map = encode_kind(&kind);
                let known = payload_map
                    .as_object()
                    .is_some_and(|m| m.contains_key(k) && !matches!(kind, EventKind::Unknown(_)));
                if !known {
                    extra.insert(k.clone(), val.clone());
                }
            }
        }
    }
    Ok(Event {
        v,
        seq,
        ts: ts.to_string(),
        kind,
        extra,
    })
}

impl Serialize for Event {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = encode_kind(&self.kind);
        let obj = map.as_object_mut().expect("payload is an object");
        obj.insert("v".to_string(), Value::from(self.v));
        obj.insert("seq".to_string(), Value::from(self.seq));
        obj.insert("ts".to_string(), Value::String(self.ts.clone()));
        for (k, val) in &self.extra {
            obj.insert(k.clone(), val.clone());
        }
        map.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let line = Value::deserialize(d)?.to_string();
        parse_event(&line).map_err(serde::de::Error::custom)
    }
}
