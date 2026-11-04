//! Claude Code adapter: `~/.claude/projects/<slug>/<session-id>.jsonl`.
//!
//! Native shape (one JSON object per line): `user` / `assistant` records
//! carrying a `message` object whose `content` array holds `text`, `thinking`,
//! `tool_use`, and `tool_result` blocks (assistant messages also carry
//! `model` and token `usage`), plus bare `summary` records holding compaction
//! context. Top-level `tool_use` / `tool_result` record shapes are accepted
//! too, for forward compatibility with hook-emitted events. Every record may
//! carry `cwd`, `sessionId`, `version`, and `timestamp`.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

use serde_json::Value;
use starforge_format::{
    Agent, AgentName, AssistantMessage, CaptureInfo, CaptureMode, Compaction, Event, EventKind,
    FORMAT_TAG, Reasoning, SessionMeta, ToolCall, ToolOutcome, ToolRef, ToolResult, Usage,
    UserMessage,
};
use time::format_description::well_known::Rfc3339;
use ulid::Ulid;

use crate::{Adapter, Candidate, CaptureError, Cursor, ReadOutput, Roots, workdir_inside};

/// Claude Code adapter (unit struct implementing [`Adapter`]).
pub struct ClaudeAdapter;

/// Hook snippet path relative to `Roots.config_dir`.
const HOOK_REL_PATH: &str = "claude-code/settings.json";
/// Marker proving a hook file was written by starforge.
const MARKER: &str = "starforge";

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

/// Render a tool-result `content` value (`string | array | scalar`) as text.
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
    if tool_name != "Edit" && tool_name != "Write" {
        return None;
    }
    input
        .get("file_path")
        .and_then(Value::as_str)
        .map(str::to_string)
}
/// Make `path` relative to `workdir` when it lies inside; else keep as-is.
fn relativize(workdir: &str, path: &str) -> String {
    let prefix = format!("{workdir}/");
    match path.strip_prefix(&prefix) {
        Some(rest) => rest.to_string(),
        None => path.to_string(),
    }
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
            && let Some(id) = record.get("sessionId").and_then(Value::as_str)
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
        let rel = relativize(workdir, path);
        if !self.files_touched.iter().any(|f| f == &rel) {
            self.files_touched.push(rel);
        }
    }
}

/// One parsed record's timestamp: native `timestamp` when valid RFC 3339,
/// else `fallback_ts`.
fn record_ts(record: &Value, fallback_ts: &str) -> String {
    match record.get("timestamp").and_then(Value::as_str) {
        Some(ts) if valid_ts(ts) => ts.to_string(),
        _ => fallback_ts.to_string(),
    }
}

/// Map one parsed record to events (timestamps resolved, `seq` assigned by
/// the caller). Mutates `fold` with header facts (models, usage, files).
fn record_events(record: &Value, fold: &mut HeaderFold, workdir: &str) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    let rtype = record.get("type").and_then(Value::as_str).unwrap_or("");
    match rtype {
        "user" => {
            if let Some(msg) = record.get("message") {
                kinds.extend(user_block_kinds(msg));
            }
        }
        "assistant" => {
            let msg = record.get("message");
            let model = msg
                .and_then(|m| m.get("model"))
                .and_then(Value::as_str)
                .or_else(|| record.get("model").and_then(Value::as_str))
                .unwrap_or("");
            if !model.is_empty() {
                fold.note_model(model);
            }
            let usage = msg
                .and_then(|m| m.get("usage"))
                .map(parse_usage)
                .unwrap_or_default();
            fold.note_usage(usage);
            if let Some(msg) = msg {
                kinds.extend(assistant_block_kinds(msg, model, usage, fold, workdir));
            }
        }
        "tool_use" => {
            let name = record
                .get("name")
                .or_else(|| record.get("tool"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let input = record.get("input").cloned().unwrap_or(Value::Null);
            kinds.push(tool_call_kind(name, &input, fold, workdir));
        }
        "tool_result" => {
            let output = record
                .get("output")
                .or_else(|| record.get("content"))
                .map(content_to_string)
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
        "summary" => {
            kinds.push(EventKind::Compaction(Compaction {
                summary: record
                    .get("summary")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }));
        }
        _ => {
            // Unknown record type: forward-compatible skip (still consumed).
        }
    }
    kinds
}

fn user_block_kinds(msg: &Value) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    match msg.get("content") {
        Some(Value::String(text)) => {
            kinds.push(EventKind::UserMessage(UserMessage { text: text.clone() }))
        }
        Some(Value::Array(blocks)) => {
            for b in blocks {
                let btype = b.get("type").and_then(Value::as_str).unwrap_or("");
                match btype {
                    "text" => {
                        if let Some(text) = b.get("text").and_then(Value::as_str) {
                            kinds.push(EventKind::UserMessage(UserMessage {
                                text: text.to_string(),
                            }));
                        }
                    }
                    "tool_result" => {
                        let output = b.get("content").map(content_to_string).unwrap_or_default();
                        kinds.push(EventKind::ToolResult(ToolResult {
                            result: ToolOutcome {
                                original_bytes: output.len() as u64,
                                output,
                                is_error: is_error(b),
                                truncated: false,
                            },
                        }));
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    kinds
}

fn assistant_block_kinds(
    msg: &Value,
    model: &str,
    usage: Usage,
    fold: &mut HeaderFold,
    workdir: &str,
) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    let model_opt = if model.is_empty() {
        None
    } else {
        Some(model.to_string())
    };
    let push_text = |text: &str, kinds: &mut Vec<EventKind>| {
        kinds.push(EventKind::AssistantMessage(AssistantMessage {
            text: text.to_string(),
            model: model_opt.clone(),
            usage,
        }));
    };
    match msg.get("content") {
        Some(Value::String(text)) => push_text(text, &mut kinds),
        Some(Value::Array(blocks)) => {
            for b in blocks {
                let btype = b.get("type").and_then(Value::as_str).unwrap_or("");
                match btype {
                    "text" => {
                        if let Some(text) = b.get("text").and_then(Value::as_str) {
                            push_text(text, &mut kinds);
                        }
                    }
                    "thinking" => {
                        if let Some(thinking) = b.get("thinking").and_then(Value::as_str) {
                            kinds.push(EventKind::Reasoning(Reasoning {
                                text: thinking.to_string(),
                            }));
                        }
                    }
                    "tool_use" => {
                        let name = b.get("name").and_then(Value::as_str).unwrap_or("unknown");
                        let input = b.get("input").cloned().unwrap_or(Value::Null);
                        kinds.push(tool_call_kind(name, &input, fold, workdir));
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    kinds
}

fn tool_call_kind(name: &str, input: &Value, fold: &mut HeaderFold, workdir: &str) -> EventKind {
    if let Some(path) = edit_path(name, input) {
        fold.note_file(workdir, &path);
    }
    EventKind::ToolCall(ToolCall {
        tool: ToolRef {
            name: name.to_string(),
            input: input.clone(),
        },
    })
}

impl Adapter for ClaudeAdapter {
    fn id(&self) -> AgentName {
        AgentName::ClaudeCode
    }

    const COVERED: &[&str] = &["1.2.3"];

    fn detect(&self, roots: &Roots) -> bool {
        let projects = roots.data_dir.join("projects");
        match std::fs::read_dir(&projects) {
            Ok(entries) => entries.flatten().any(|e| e.path().is_dir()),
            Err(_) => false,
        }
    }

    fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>> {
        let path = roots.config_dir.join(HOOK_REL_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let body = serde_json::json!({
            "_starforge": "starforge-managed SessionEnd hook; remove_hooks deletes this file",
            "hooks": {
                "SessionEnd": [
                    {
                        "matcher": "starforge",
                        "hooks": [
                            { "type": "command", "command": "starforge hook session-end" }
                        ]
                    }
                ]
            }
        });
        std::fs::write(&path, serde_json::to_string_pretty(&body).unwrap())?;
        Ok(vec![path])
    }

    fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>> {
        let path = roots.config_dir.join(HOOK_REL_PATH);
        match std::fs::read_to_string(&path) {
            Ok(body) if body.contains(MARKER) => {
                std::fs::remove_file(&path)?;
                Ok(vec![path])
            }
            _ => Ok(vec![]),
        }
    }

    fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate> {
        let mut out = Vec::new();
        let projects = roots.data_dir.join("projects");
        let Ok(slugs) = std::fs::read_dir(&projects) else {
            return out;
        };
        let mut slugs: Vec<_> = slugs.flatten().map(|e| e.path()).collect();
        slugs.sort();
        for slug_dir in slugs {
            if !slug_dir.is_dir() {
                continue;
            }
            let slug = slug_dir
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let Ok(files) = std::fs::read_dir(&slug_dir) else {
                continue;
            };
            let mut files: Vec<_> = files
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
                .collect();
            files.sort();
            for native_path in files {
                let stem = native_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let session_key = format!("{slug}/{stem}");
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
        let mut parsed: Vec<(String, Value)> = Vec::with_capacity(all.len());
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
            parsed.push((ts, record));
        }
        let mut fold = HeaderFold::default();
        for (ts, record) in &parsed {
            fold.feed(record, ts);
        }
        let workdir = fold
            .workdir
            .clone()
            .unwrap_or_else(|| candidate.workdir.to_string_lossy().into_owned());
        // Event pass: now that the fold has seen every record (workdir known
        // for relativizing), map each record to its kinds.
        let mut kinds: Vec<(String, Vec<EventKind>)> = Vec::with_capacity(parsed.len());
        for (ts, record) in &parsed {
            let ks = record_events(record, &mut fold, &workdir);
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
                name: AgentName::ClaudeCode,
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

/// First `cwd` and `version` seen in a transcript (cheap identity scan).
fn scan_identity(native_path: &std::path::Path) -> (Option<String>, Option<String>) {
    let Ok(bytes) = std::fs::read(native_path) else {
        return (None, None);
    };
    let mut cwd = None;
    let mut version = None;
    for (s, e) in complete_lines(&bytes, 0) {
        let text = line_text(&bytes, (s, e));
        if text.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        if cwd.is_none()
            && let Some(c) = record.get("cwd").and_then(Value::as_str)
        {
            cwd = Some(c.to_string());
        }
        if version.is_none()
            && let Some(v) = record.get("version").and_then(Value::as_str)
        {
            version = Some(v.to_string());
        }
        if cwd.is_some() && version.is_some() {
            break;
        }
    }
    (cwd, version)
}
