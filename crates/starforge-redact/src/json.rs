//! JSON-aware redaction: event fields, JSON values, and JSONL streams.
//!
//! Redaction targets free-text/value fields only. Structural metadata —
//! versions, sequence numbers, timestamps, kind discriminants, flags,
//! model names, file paths, subagent ids, object keys — passes through
//! untouched. Object keys are never redacted; only string values are.

use std::collections::BTreeMap;

use serde_json::Value;
use starforge_format::{Event, EventKind};

use crate::rules::{Compiled, redact_text};

fn absorb(into: &mut BTreeMap<String, u64>, from: BTreeMap<String, u64>) {
    for (k, v) in from {
        *into.entry(k).or_insert(0) += v;
    }
}

/// Redact every string inside a JSON value in place (object keys intact).
pub fn redact_value(rules: &Compiled, value: &mut Value, counts: &mut BTreeMap<String, u64>) {
    match value {
        Value::String(s) => {
            let (out, c) = redact_text(rules, s);
            *s = out;
            absorb(counts, c);
        }
        Value::Array(items) => {
            for item in items {
                redact_value(rules, item, counts);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                redact_value(rules, v, counts);
            }
        }
        _ => {}
    }
}

fn redact_string(rules: &Compiled, s: &mut String, counts: &mut BTreeMap<String, u64>) {
    let (out, c) = redact_text(rules, s);
    *s = out;
    absorb(counts, c);
}

/// Redact an event's free-text/value fields, preserving structure.
///
/// Redacted: `text`, `output`, tool `input` (deep walk), `diff`,
/// `summary`, `task`, and `extra` values. Untouched: `v`, `seq`, `ts`,
/// the kind discriminant, `is_error`, `truncated`, `original_bytes`,
/// `model`, `path`, `subagent_id`, and `extra` keys.
pub fn redact_event(rules: &Compiled, event: &Event) -> (Event, BTreeMap<String, u64>) {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut out = event.clone();
    match &mut out.kind {
        EventKind::UserMessage(m) => redact_string(rules, &mut m.text, &mut counts),
        EventKind::AssistantMessage(m) => redact_string(rules, &mut m.text, &mut counts),
        EventKind::Reasoning(m) => redact_string(rules, &mut m.text, &mut counts),
        EventKind::ToolCall(call) => redact_value(rules, &mut call.tool.input, &mut counts),
        EventKind::ToolResult(res) => {
            redact_string(rules, &mut res.result.output, &mut counts);
        }
        EventKind::FileChange(fc) => {
            if let Some(diff) = fc.diff.as_mut() {
                redact_string(rules, diff, &mut counts);
            }
        }
        EventKind::Compaction(c) => {
            if let Some(summary) = c.summary.as_mut() {
                redact_string(rules, summary, &mut counts);
            }
        }
        EventKind::SubagentStart(b) | EventKind::SubagentEnd(b) => {
            redact_string(rules, &mut b.task, &mut counts);
        }
        EventKind::System(m) => redact_string(rules, &mut m.text, &mut counts),
        EventKind::Unknown(_) => {}
    }
    for value in out.extra.values_mut() {
        redact_value(rules, value, &mut counts);
    }
    (out, counts)
}

/// Redact a JSONL stream line by line, preserving line count and order.
///
/// A line that parses as a JSON object has its string values redacted
/// (keys intact) and is re-serialized; any other line is redacted as
/// plain text. A trailing newline is preserved.
pub fn redact_jsonl(rules: &Compiled, jsonl: &str) -> (String, BTreeMap<String, u64>) {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut lines_out: Vec<String> = Vec::new();
    for line in jsonl.lines() {
        match serde_json::from_str::<Value>(line) {
            Ok(Value::Object(mut map)) => {
                for v in map.values_mut() {
                    let mut owned = v.take();
                    redact_value(rules, &mut owned, &mut counts);
                    *v = owned;
                }
                lines_out.push(Value::Object(map).to_string());
            }
            _ => {
                let (out, c) = redact_text(rules, line);
                absorb(&mut counts, c);
                lines_out.push(out);
            }
        }
    }
    let mut out = lines_out.join("\n");
    if !lines_out.is_empty() && jsonl.ends_with('\n') {
        out.push('\n');
    }
    (out, counts)
}
