//! Codex CLI adapter: `<data_dir>/sessions/YYYY/MM/DD/rollout-*.jsonl`.
//!
//! Native shape (one JSON object per line): `prompt` records carrying user
//! input text; `response` records carrying model output `text` plus `model`
//! and token `usage` (and optionally a `reasoning_summary`, which emits a
//! second event after the message); `function_call` records with `name` and
//! `arguments` (a JSON-encoded string, mirroring the OpenAI function-call
//! shape — a plain object is accepted too); `function_call_output` records
//! carrying the tool `output`; `reasoning` records carrying reasoning
//! summaries; and `compacted` records carrying rolling-window compaction
//! context in `summary`. Every record may carry `cwd`, `session_id`
//! (`sessionId` is accepted too, for forward compatibility), `version`, and
//! `timestamp` (`ts` is accepted as a fallback key). A `compacted` record
//! closes prior context, but the adapter still emits every record exactly
//! once in file order: compaction is an ordinary record for cursor purposes
//! (consumed, counted in `lines`, assigned `seq`), so records after it are
//! neither reordered nor dropped.
//!
//! There is no pinned hook story for the covered Codex versions: the CLI
//! exposes no stable hook surface these versions commit to, so
//! [`Adapter::install_hooks`] and [`Adapter::remove_hooks`] both report
//! `Ok(vec![])` and discovery of the rollout files is the only capture path.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

use serde_json::Value;
use starforge_format::{
    Agent, AgentName, AssistantMessage, CaptureInfo, CaptureMode, Compaction, Event, EventKind,
    FORMAT_TAG, Reasoning, SessionMeta, System, ToolCall, ToolOutcome, ToolRef, ToolResult, Usage,
    UserMessage,
};
use time::format_description::well_known::Rfc3339;
use ulid::Ulid;

use crate::{Adapter, Candidate, CaptureError, Cursor, ReadOutput, Roots, workdir_inside};

/// Codex CLI adapter (unit struct; the [`Adapter`] trait is not object-safe).
pub struct CodexAdapter;

fn valid_ts(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &Rfc3339).is_ok()
}

/// Byte offset to resume from: `cursor.offset`, rounded back to the previous
/// `\n` when it lands mid-line (a foreign cursor; cursors produced by `read`
/// always sit on line starts).
fn round_to_line_start(bytes: &[u8], offset: u64) -> usize {
    let offset = offset as usize;
    if offset == 0 || bytes[offset - 1] == b'\n' {
        return offset;
    }
    match bytes[..offset].iter().rposition(|&b| b == b'\n') {
        Some(pos) => pos + 1,
        None => 0,
    }
}

/// Byte ranges of complete (`\n`-terminated) lines in `bytes[start..]`.
/// A trailing unterminated tail is live-write growth: left unconsumed.
fn complete_lines(bytes: &[u8], start: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut pos = start;
    while let Some(rel) = bytes[pos..].iter().position(|&b| b == b'\n') {
        out.push((pos, pos + rel));
        pos += rel + 1;
    }
    out
}

fn line_text(bytes: &[u8], span: (usize, usize)) -> &str {
    let mut s = &bytes[span.0..span.1];
    if s.ends_with(b"\r") {
        s = &s[..s.len() - 1];
    }
    std::str::from_utf8(s).unwrap_or("")
}

/// Render a tool-result `output`/`content` value (`string | array | scalar`)
/// as text.
fn content_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Value::String(s) => s.clone(),
                Value::Object(map) => map
                    .get("text")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| item.to_string()),
                other => other.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.to_string(),
    }
}

fn parse_usage(v: &Value) -> Usage {
    let n = |key: &str| v.get(key).and_then(Value::as_u64).unwrap_or(0);
    Usage {
        input: n("input_tokens"),
        output: n("output_tokens"),
        cache_read: n("cache_read_input_tokens"),
        cache_write: n("cache_creation_input_tokens"),
        reasoning: 0,
    }
}

fn is_error(v: &Value) -> bool {
    v.get("is_error")
        .or_else(|| v.get("isError"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// `file_path` carried by an `Edit`/`Write` tool input, if any.
fn edit_path(tool_name: &str, input: &Value) -> Option<String> {
    if tool_name != "Edit" && tool_name != "Write" && tool_name != "edit" && tool_name != "write" {
        return None;
    }
    input
        .get("file_path")
        .or_else(|| input.get("path"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Decode `function_call` arguments: a JSON-encoded string (the native shape)
/// or an already-structured object.
fn decode_arguments(v: &Value) -> Value {
    match v {
        Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone())),
        other => other.clone(),
    }
}

/// First `cwd` and `version` seen in a transcript (cheap identity scan).
/// Accepts both `session_id` and `sessionId` keys (identity only; the header
/// fold below does the same).
fn scan_identity(native_path: &std::path::Path) -> (Option<String>, Option<String>) {
    let Ok(bytes) = std::fs::read(native_path) else {
        return (None, None);
    };
    for span in complete_lines(&bytes, 0) {
        let text = line_text(&bytes, span);
        if text.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        let cwd = record
            .get("cwd")
            .and_then(Value::as_str)
            .map(str::to_string);
        let version = record
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_string);
        if cwd.is_some() || version.is_some() {
            return (cwd, version);
        }
    }
    (None, None)
}

/// Fold one parsed record into the session header accumulator.
#[derive(Default)]
struct HeaderFold {
    version: Option<String>,
    workdir: Option<String>,
    session_id: Option<String>,
    started_at: Option<String>,
    models: Vec<String>,
    usage: Usage,
    files_touched: Vec<String>,
}

impl HeaderFold {
    fn feed(&mut self, record: &Value, ts: &str) {
        if self.version.is_none()
            && let Some(v) = record.get("version").and_then(Value::as_str)
        {
            self.version = Some(v.to_string());
        }
        if self.workdir.is_none()
            && let Some(cwd) = record.get("cwd").and_then(Value::as_str)
        {
            self.workdir = Some(cwd.to_string());
        }
        if self.session_id.is_none()
            && let Some(id) = record
                .get("session_id")
                .or_else(|| record.get("sessionId"))
                .and_then(Value::as_str)
        {
            self.session_id = Some(id.to_string());
        }
        if self.started_at.is_none() {
            self.started_at = Some(ts.to_string());
        }
    }

    fn note_model(&mut self, model: &str) {
        if !model.is_empty() && !self.models.iter().any(|m| m == model) {
            self.models.push(model.to_string());
        }
    }

    fn note_usage(&mut self, u: Usage) {
        self.usage.input += u.input;
        self.usage.output += u.output;
        self.usage.cache_read += u.cache_read;
        self.usage.cache_write += u.cache_write;
        self.usage.reasoning += u.reasoning;
    }

    fn note_file(&mut self, workdir: &str, path: &str) {
        if let Some(rel) = crate::repo_relative(std::path::Path::new(workdir), path)
            && !self.files_touched.iter().any(|f| f == &rel)
        {
            self.files_touched.push(rel);
        }
    }
}

/// One parsed record's timestamp: native `timestamp` (or `ts`) when valid
/// RFC 3339, else `fallback_ts`.
fn record_ts(record: &Value, fallback_ts: &str) -> String {
    let native = record
        .get("timestamp")
        .or_else(|| record.get("ts"))
        .and_then(Value::as_str);
    match native {
        Some(ts) if valid_ts(ts) => ts.to_string(),
        _ => fallback_ts.to_string(),
    }
}

/// Map one parsed record to events (timestamps resolved, `seq` assigned by
/// the caller). Mutates `fold` with header facts (models, usage, files).
/// `raw` is the record's source line: unmapped `type` values fall back to
/// `system { text: <raw JSON> }` so no record is ever dropped, and
/// unrecognized blocks in a message-level `content` array each fall back to
/// `system { text: <raw block JSON> }` the same way.
fn record_events(
    raw: &str,
    record: &Value,
    fold: &mut HeaderFold,
    workdir: &str,
) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    let rtype = record.get("type").and_then(Value::as_str).unwrap_or("");
    let role = record.get("role").and_then(Value::as_str).unwrap_or("");
    match rtype {
        // User prompt. `response` with `role: "user"` is accepted for the
        // same shape, in case future versions fold prompts into responses.
        "prompt" => {
            if let Some(text) = prompt_text(record)
                && !text.is_empty()
            {
                kinds.push(EventKind::UserMessage(UserMessage { text }));
            }
            kinds.extend(unknown_block_kinds(record));
        }
        "response" if role == "user" => {
            if let Some(text) = prompt_text(record)
                && !text.is_empty()
            {
                kinds.push(EventKind::UserMessage(UserMessage { text }));
            }
            kinds.extend(unknown_block_kinds(record));
        }
        "response" => {
            let model = record.get("model").and_then(Value::as_str).unwrap_or("");
            if !model.is_empty() {
                fold.note_model(model);
            }
            let usage = record.get("usage").map(parse_usage).unwrap_or_default();
            fold.note_usage(usage);
            if let Some(text) = record.get("text").and_then(Value::as_str) {
                kinds.push(EventKind::AssistantMessage(AssistantMessage {
                    text: text.to_string(),
                    model: if model.is_empty() {
                        None
                    } else {
                        Some(model.to_string())
                    },
                    usage,
                }));
            }
            // A response may carry its reasoning summary inline; it emits a
            // second event after the message (this is the multi-event record
            // the incremental test resumes across).
            if let Some(summary) = record.get("reasoning_summary").and_then(Value::as_str)
                && !summary.is_empty()
            {
                kinds.push(EventKind::Reasoning(Reasoning {
                    text: summary.to_string(),
                }));
            }
            kinds.extend(unknown_block_kinds(record));
        }
        "function_call" => {
            let name = record
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let input = record
                .get("arguments")
                .map(decode_arguments)
                .or_else(|| record.get("input").cloned())
                .unwrap_or(Value::Null);
            if let Some(path) = edit_path(name, &input) {
                fold.note_file(workdir, &path);
            }
            kinds.push(EventKind::ToolCall(ToolCall {
                tool: ToolRef {
                    name: name.to_string(),
                    input,
                },
            }));
        }
        "function_call_output" => {
            let output = record
                .get("output")
                .map(content_to_string)
                .or_else(|| record.get("content").map(content_to_string))
                .unwrap_or_default();
            kinds.push(EventKind::ToolResult(ToolResult {
                result: ToolOutcome {
                    original_bytes: output.len() as u64,
                    output,
                    is_error: is_error(record),
                    truncated: false,
                },
            }));
        }
        "reasoning" => {
            let text = record
                .get("text")
                .and_then(Value::as_str)
                .or_else(|| record.get("summary").and_then(Value::as_str))
                .map(str::to_string)
                .or_else(|| {
                    let rendered = record
                        .get("content")
                        .map(content_to_string)
                        .unwrap_or_default();
                    if rendered.is_empty() {
                        None
                    } else {
                        Some(rendered)
                    }
                });
            if let Some(text) = text {
                kinds.push(EventKind::Reasoning(Reasoning { text }));
            }
        }
        "compacted" => {
            kinds.push(EventKind::Compaction(Compaction {
                summary: record
                    .get("summary")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }));
        }
        _ => {
            // Unknown record type: raw JSON into `system`. Never dropped.
            kinds.push(EventKind::System(System {
                text: raw.to_string(),
            }));
        }
    }
    kinds
}

/// `System` events for unrecognized blocks in a message-level `content`
/// array. Text-ish blocks are already represented in the message text (see
/// [`prompt_text`]); anything else is preserved as raw block JSON so no
/// native shape is ever dropped.
fn unknown_block_kinds(record: &Value) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    let Some(Value::Array(blocks)) = record.get("content") else {
        return kinds;
    };
    for b in blocks {
        if b.is_string() {
            continue;
        }
        let btype = b.get("type").and_then(Value::as_str).unwrap_or("");
        if matches!(btype, "text" | "input_text" | "output_text") {
            continue;
        }
        kinds.push(EventKind::System(System {
            text: b.to_string(),
        }));
    }
    kinds
}

/// Prompt text: `text`, else a rendered `content`.
fn prompt_text(record: &Value) -> Option<String> {
    if let Some(text) = record.get("text").and_then(Value::as_str) {
        return Some(text.to_string());
    }
    record.get("content").map(content_to_string)
}

/// Recursively collect `rollout-*.jsonl` files under `dir`, sorted for
/// determinism.
fn collect_rollouts(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rollouts(&path, out);
        } else if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("rollout-"))
            && path.extension().is_some_and(|x| x == "jsonl")
        {
            out.push(path);
        }
    }
}

impl Adapter for CodexAdapter {
    fn id(&self) -> AgentName {
        AgentName::Codex
    }

    const COVERED: &[&str] = &["0.42.0"];

    fn detect(&self, roots: &Roots) -> bool {
        let sessions = roots.data_dir.join("sessions");
        match std::fs::read_dir(&sessions) {
            Ok(entries) => entries.flatten().any(|e| e.path().is_dir()),
            Err(_) => false,
        }
    }

    /// No pinned hook story: the covered Codex versions expose no stable
    /// hook surface to write to, so discovery of the rollout files (below)
    /// is the only capture path and both directions report nothing.
    fn install_hooks(&self, _roots: &Roots) -> io::Result<Vec<PathBuf>> {
        Ok(vec![])
    }

    /// No pinned hook story (see [`Adapter::install_hooks`]): nothing to
    /// remove, so this also reports nothing.
    fn remove_hooks(&self, _roots: &Roots) -> io::Result<Vec<PathBuf>> {
        Ok(vec![])
    }

    fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate> {
        let mut out = Vec::new();
        let sessions = roots.data_dir.join("sessions");
        if !sessions.is_dir() {
            return out;
        }
        let mut files = Vec::new();
        collect_rollouts(&sessions, &mut files);
        for native_path in files {
            let session_key = native_path
                .strip_prefix(&sessions)
                .map(|rel| {
                    rel.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .unwrap_or_default();
            let (workdir, version) = scan_identity(&native_path);
            let workdir = workdir
                .map(PathBuf::from)
                .unwrap_or_else(|| roots.worktree.clone());
            if !workdir_inside(&roots.worktree, &workdir) {
                continue;
            }
            if let Some(cursor) = known.get(&session_key)
                && let Ok(meta) = std::fs::metadata(&native_path)
                && meta.len() <= cursor.offset
            {
                continue;
            }
            out.push(Candidate {
                session_key,
                native_path,
                agent_version: version.unwrap_or_default(),
                workdir,
            });
        }
        out
    }

    fn read(
        &self,
        candidate: &Candidate,
        cursor: &Cursor,
        fallback_ts: &str,
    ) -> Result<ReadOutput, CaptureError> {
        if !valid_ts(fallback_ts) {
            return Err(CaptureError::BadTimestamp(fallback_ts.to_string()));
        }
        let bytes = std::fs::read(&candidate.native_path)?;
        let len = bytes.len() as u64;
        if cursor.offset > len {
            return Err(CaptureError::CursorBeyondEnd(cursor.offset, len));
        }
        // Header pass: fold every complete line so the header always reflects
        // the full session, even on incremental reads.
        let all = complete_lines(&bytes, 0);
        let mut parsed: Vec<(String, String, Value)> = Vec::with_capacity(all.len());
        for span in &all {
            let text = line_text(&bytes, *span);
            if text.trim().is_empty() {
                continue;
            }
            let record: Value =
                serde_json::from_str(text).map_err(|e| CaptureError::BadNative(e.to_string()))?;
            if !record.is_object() {
                return Err(CaptureError::BadNative(
                    "record is not an object".to_string(),
                ));
            }
            let ts = record_ts(&record, fallback_ts);
            parsed.push((ts, text.to_string(), record));
        }
        let mut fold = HeaderFold::default();
        for (ts, _, record) in &parsed {
            fold.feed(record, ts);
        }
        let workdir = fold
            .workdir
            .clone()
            .unwrap_or_else(|| candidate.workdir.to_string_lossy().into_owned());
        // Event pass: now that the fold has seen every record (workdir known
        // for relativizing), map each record to its kinds.
        let mut kinds: Vec<(String, Vec<EventKind>)> = Vec::with_capacity(parsed.len());
        for (ts, raw, record) in &parsed {
            let ks = record_events(raw, record, &mut fold, &workdir);
            kinds.push((ts.clone(), ks));
        }

        // New records are those at index >= `cursor.lines`; the byte resume
        // point rounds a foreign mid-line cursor back to the previous `\n`.
        let start = round_to_line_start(&bytes, cursor.offset);
        let new_spans = complete_lines(&bytes, start);
        let total = parsed.len() as u64;
        let fresh = total.saturating_sub(cursor.lines.min(total));
        let mut events = Vec::new();
        let mut seq = cursor.next_seq();
        for (i, (ts, ks)) in kinds.iter().enumerate() {
            if (i as u64) < cursor.lines {
                continue;
            }
            for kind in ks {
                events.push(Event {
                    v: 1,
                    seq,
                    ts: ts.clone(),
                    kind: kind.clone(),
                    extra: BTreeMap::new(),
                });
                seq += 1;
            }
        }
        let next = if fresh == 0 {
            // Empty growth: events empty, cursor unchanged.
            *cursor
        } else {
            let advanced = new_spans
                .last()
                .map(|&(_, end)| (end + 1) as u64)
                .unwrap_or(start as u64);
            Cursor {
                offset: advanced,
                lines: cursor.lines + fresh,
                events: cursor.events + events.len() as u64,
            }
        };
        let version = fold.version.clone().unwrap_or_default();
        let covered = Self::COVERED.contains(&version.as_str());
        let id = fold
            .session_id
            .as_deref()
            .and_then(|s| Ulid::from_str(s).ok())
            .unwrap_or(Ulid::nil());
        let header = SessionMeta {
            format: FORMAT_TAG.to_string(),
            id,
            agent: Agent {
                name: AgentName::Codex,
                version,
            },
            models: fold.models.clone(),
            title: None,
            started_at: fold
                .started_at
                .clone()
                .unwrap_or_else(|| fallback_ts.to_string()),
            ended_at: None,
            repo: Default::default(),
            parent_id: None,
            usage: fold.usage,
            files_touched: fold.files_touched.clone(),
            redaction: Default::default(),
            capture: CaptureInfo {
                mode: CaptureMode::Discovery,
                cli_version: String::new(),
                adapter_version_verified: covered,
            },
        };
        Ok(ReadOutput {
            events,
            next,
            header,
        })
    }
}
