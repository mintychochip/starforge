//! Pi and omp adapters: `<data_dir>/.pi/agent/sessions/**/*.jsonl` (Pi,
//! recursive — real installs nest one dir per cwd) and
//! `<data_dir>/.omp/agent/sessions/**/*.jsonl` (omp, recursive).
//!
//! Native shape (one JSON object per line; every record carries `type`, `id`,
//! `parentId`, an ISO-8601 `timestamp`, and `runtime: { version }`, except
//! `title`, which carries `updatedAt` instead of `timestamp`):
//! - `session`: `{ version: <format version int>, id, timestamp, cwd,
//!   [title, titleSource] }` — the header record.
//! - `title`: `{ v, title, source: "auto", updatedAt, pad }`, usually line 1.
//!   `title_change`: `{ previousTitle, title, source, trigger }`.
//!   Empty or whitespace-only titles (the untitled placeholder `title`
//!   record) never set or clear the header title; the latest non-empty
//!   title wins.
//! - `message`: `{ message: {…} }` with `message.timestamp` an int (the
//!   record-level ISO `timestamp` is used). Roles:
//!   - `user`: `content: [{ type: "text", text }]` → one `user_message`
//!     (text blocks joined).
//!   - `assistant`: `{ api, model, provider, usage, stopReason, …,
//!     content: […] }` whose blocks, in order, are `thinking`
//!     (`{ thinking, … }`) → `reasoning`, `text` (`{ text, … }`) →
//!     `assistant_message` (with `model` and mapped `usage` attached exactly
//!     as the Claude adapter attaches them), and `toolCall`
//!     (`{ id, name, arguments }`) → `tool_call` (input = `arguments`).
//!     `usage` folds into the header totals even when the message carries
//!     only tool calls. Cost fields are ignored.
//!   - `toolResult`: `{ toolCallId, toolName, isError, details, content }`
//!     → `tool_result` paired by `toolCallId`; output is the text blocks
//!     joined (an image block becomes `[image: <mimeType>]`, never inlined);
//!     `details` is ignored.
//!   - `custom`: `{ customType, content, display, attribution }` → `system`
//!     with readable text.
//!   - `developer`: `content: [{ type: "text", text }]` → `system` with the
//!     joined text.
//! - `custom_message`: `{ customType, content, display, attribution }` — a
//!   message injected into the model's context (advisor, goal-mode context,
//!   etc.) → `system` with readable text (`content` string or joined text
//!   blocks).
//! - `ttsr_injection`: `{ injectedRules: [str] }` → `system` with readable
//!   text `Rules injected: <names joined by ", ">`.
//! - `compaction`: `{ summary, shortSummary, … }` → `compaction` (`summary`,
//!   falling back to `shortSummary`).
//! - `custom` with `customType: "session_exit"` does NOT end the session:
//!   omp resumes sessions by appending to the same file after an exit, so
//!   an exit is a skipped runtime marker like the other `custom` progress
//!   markers (no event). The header's `ended_at` is always `None`;
//!   sessions end by the 24 h idle rule in ingest.
//!
//! Intentionally skipped (no events), by documented rule:
//! - `session_init` — subagent bootstrap: its `task` duplicates the first
//!   user message, and the rest (system prompt, tools, output schema) is
//!   runtime configuration, so it yields no event.
//! - `model_usage` — auxiliary side calls (job widgets, captions, cache-warm),
//!   not conversation turns. The header's usage totals are the sum of
//!   assistant-message usage only.
//! - `mode_change`, `model_change`, `thinking_level_change` — runtime state,
//!   not conversation.
//! - `credential_pin` — credential bookkeeping; its contents are never
//!   captured.
//! - `custom` records, including `customType: "session_exit"` — progress/
//!   bookkeeping markers (e.g. the per-tool-call `tool_execution_start`
//!   thousands, HUD state, reminders). `session_exit` does not end the
//!   session: omp resumes by appending after an exit in the same file, so
//!   sessions end only by the 24 h idle rule.
//! - `session`, `title`, `title_change` — header facts only: `cwd` and the
//!   initial title come from `session`; the latest non-empty `title` /
//!   `title_change` wins the header title.
//!
//! Any other record type, or a message role not listed above, keeps the
//! raw-JSON `system` fallback: never dropped silently, never an error.
//!
//! Identity scan: `cwd` comes from the `session` record (a per-record `cwd`
//! is accepted as a fallback for omp); the agent version is the first
//! `runtime.version`. `session.version` is the FORMAT version and is never
//! used as the agent version. For files under the omp store the reported
//! version is `omp-<runtime.version>` (`omp-unknown` with no runtime
//! version); for the Pi store it is `runtime.version` as-is.
//!
//! Timestamps, in order of preference: the record's ISO `timestamp`, then
//! `updatedAt`, then the most recent timestamp already seen in this read
//! batch, and only then `fallback_ts`. In particular the leading `title`
//! record never gets "now": an imported session keeps its real timestamps so
//! the 24 h idle rule in ingest can end it.
//!
//! Public sources: Pi's session format is documented at
//! https://pi.dev/docs/latest/session-format and in the public pi-mono
//! source (badlogic/pi-mono), `packages/coding-agent/src/core/session-manager.ts`.
//! omp has no public session-format spec; its record fields above were
//! confirmed against real omp session files (field names, types, and enum
//! values only). No invented record shape remains: earlier flat records
//! (`{"type":"message","role":…,"content":…}`) are written by no real Pi or
//! omp release and are not parsed.
//!
//! Discovery attribution: a session is captured only when a non-empty `cwd`
//! inside the worktree is found; unknown/empty `cwd` is skipped (never
//! defaulted to the worktree).
//!
//! Hook story: Pi/omp have no verified JSON-config hook surface, so
//! [`Adapter::install_hooks`] is a no-op (`Ok(vec![])`). Capture happens
//! through discovery at commit/push/sync (the M1 plan allows this for
//! adapters without a hook story). [`Adapter::remove_hooks`] only cleans up
//! the legacy `<config_dir>/.config/pi/starforge.json` hook file when it
//! carries the starforge marker.

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

/// Pi adapter (unit struct; [`Adapter`] is not object-safe). Also serves omp
/// sessions, which share [`AgentName::Pi`].
pub struct PiAdapter;

/// Legacy hook path relative to `Roots.config_dir` (pre per-agent-roots
/// layout, when `config_dir` was `<home>/.config`).
const LEGACY_HOOK_REL_PATH: &str = ".config/pi/starforge.json";
/// Marker proving a hook file was written by starforge.
const MARKER: &str = "starforge";

fn valid_ts(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &Rfc3339).is_ok()
}

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

/// Join the `text` of every `{"type":"text"}` block in a content array.
fn text_blocks(blocks: &[Value]) -> String {
    let texts: Vec<&str> = blocks
        .iter()
        .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|b| b.get("text").and_then(Value::as_str))
        .collect();
    texts.join("\n")
}

/// A `content` value that is either a string or an array of text blocks,
/// rendered as readable text.
fn content_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => text_blocks(blocks),
        _ => String::new(),
    }
}

/// Render a `toolResult` message's `content` array as text: text blocks
/// joined; an image block becomes a short placeholder (never inline data).
fn tool_result_text(blocks: &[Value]) -> String {
    let mut parts = Vec::new();
    for b in blocks {
        match b.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(text) = b.get("text").and_then(Value::as_str) {
                    parts.push(text.to_string());
                }
            }
            Some("image") => {
                let mime = b
                    .get("mimeType")
                    .and_then(Value::as_str)
                    .unwrap_or("image/png");
                parts.push(format!("[image: {mime}]"));
            }
            _ => {}
        }
    }
    parts.join("\n")
}

/// Pi/omp assistant usage: `{ input, output, cacheRead, cacheWrite,
/// reasoningTokens?, … }`. Cost fields are ignored.
fn parse_usage(v: &Value) -> Usage {
    let n = |key: &str| v.get(key).and_then(Value::as_u64).unwrap_or(0);
    Usage {
        input: n("input"),
        output: n("output"),
        cache_read: n("cacheRead"),
        cache_write: n("cacheWrite"),
        reasoning: n("reasoningTokens"),
    }
}

fn is_error(v: &Value) -> bool {
    v.get("isError").and_then(Value::as_bool).unwrap_or(false)
}

/// Every `[PATH#TAG]` hashline header line in `text` (TAG is 4 hex digits).
fn hashline_paths(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('[') || !line.ends_with(']') || line.len() < 8 {
            continue;
        }
        let inner = &line[1..line.len() - 1];
        let Some(hash) = inner.rfind('#') else {
            continue;
        };
        let (path, tag) = inner.split_at(hash);
        let tag = &tag[1..];
        if path.is_empty() || tag.len() != 4 || !tag.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        out.push(path.to_string());
    }
    out
}

/// Paths carried by an `edit`/`write` tool call: the direct `path` (omp)
/// or `file_path` (Pi) argument, plus every `[PATH#TAG]` header in an
/// `edit` call's `input` (hashline), which is how omp usually names the
/// edited files when there is no `path` argument.
fn tool_paths(tool_name: &str, input: &Value) -> Vec<String> {
    let lower = tool_name.to_ascii_lowercase();
    if lower != "edit" && lower != "write" {
        return Vec::new();
    }
    let mut out = Vec::new();
    for key in ["path", "file_path"] {
        if let Some(path) = input.get(key).and_then(Value::as_str) {
            out.push(path.to_string());
        }
    }
    if lower == "edit"
        && let Some(text) = input.get("input").and_then(Value::as_str)
    {
        out.extend(hashline_paths(text));
    }
    out
}

/// Fold one parsed record into the session header accumulator.
#[derive(Default)]
struct HeaderFold {
    version: Option<String>,
    workdir: Option<String>,
    session_id: Option<String>,
    title: Option<String>,
    started_at: Option<String>,
    models: Vec<String>,
    usage: Usage,
    files_touched: Vec<String>,
}

impl HeaderFold {
    fn feed(&mut self, record: &Value, ts: &str) {
        // Agent version: first `runtime.version`. `session.version` is the
        // format version and never counts here; only `session` records carry
        // `cwd` (per-record `cwd` is an omp fallback).
        if self.version.is_none()
            && let Some(v) = record
                .get("runtime")
                .and_then(|r| r.get("version"))
                .and_then(Value::as_str)
        {
            self.version = Some(v.to_string());
        }
        if self.workdir.is_none()
            && let Some(cwd) = record.get("cwd").and_then(Value::as_str)
            && !cwd.is_empty()
        {
            self.workdir = Some(cwd.to_string());
        }
        let rtype = record.get("type").and_then(Value::as_str).unwrap_or("");
        match rtype {
            "session" => {
                if self.session_id.is_none()
                    && let Some(id) = record.get("id").and_then(Value::as_str)
                {
                    self.session_id = Some(id.to_string());
                }
                // The session title is an initial value; a later non-empty
                // `title` / `title_change` record replaces it. Empty or
                // whitespace-only titles never set or clear the title.
                if let Some(title) = record.get("title").and_then(Value::as_str)
                    && !title.trim().is_empty()
                {
                    self.title = Some(title.to_string());
                }
            }
            "title" | "title_change" => {
                // The latest non-empty title wins.
                if let Some(title) = record.get("title").and_then(Value::as_str)
                    && !title.trim().is_empty()
                {
                    self.title = Some(title.to_string());
                }
            }
            _ => {}
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

    /// Record one touched file: absolute paths inside the workdir are
    /// stored repo-relative, relative paths stay as-is, and absolute
    /// paths outside the workdir are dropped entirely — storing one
    /// verbatim would upload a path like `/home/<user>/.ssh/…` (or
    /// another repository's layout) in `files_touched`.
    fn note_file(&mut self, workdir: &str, path: &str) {
        let path = path.trim();
        if path.is_empty() {
            return;
        }
        let stored = if std::path::Path::new(path).is_absolute() {
            let Some(rel) = crate::repo_relative(std::path::Path::new(workdir), path) else {
                return;
            };
            rel
        } else {
            path.to_string()
        };
        if !stored.is_empty() && !self.files_touched.iter().any(|f| f == &stored) {
            self.files_touched.push(stored);
        }
    }
}

/// One parsed record's timestamp: the record's ISO `timestamp`, else
/// `updatedAt`, else the most recent timestamp already seen in this read
/// batch, else `fallback_ts`.
fn record_ts(record: &Value, last_seen: Option<&str>, fallback_ts: &str) -> String {
    for key in ["timestamp", "updatedAt"] {
        if let Some(ts) = record.get(key).and_then(Value::as_str)
            && valid_ts(ts)
        {
            return ts.to_string();
        }
    }
    match last_seen {
        Some(ts) => ts.to_string(),
        None => fallback_ts.to_string(),
    }
}

/// Map one parsed record to events. Mutates `fold` with header facts
/// (models, usage, files). `raw` is the record's source line: unknown record
/// types and unknown message roles fall back to `system { text: <raw JSON> }`
/// so no record is ever dropped.
fn record_events(
    raw: &str,
    record: &Value,
    fold: &mut HeaderFold,
    workdir: &str,
) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    let rtype = record.get("type").and_then(Value::as_str).unwrap_or("");
    match rtype {
        "message" => {
            let Some(msg) = record.get("message") else {
                return kinds;
            };
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
            match role {
                "user" => {
                    let text = msg.get("content").map(content_text).unwrap_or_default();
                    if !text.is_empty() {
                        kinds.push(EventKind::UserMessage(UserMessage { text }));
                    }
                }
                "assistant" => {
                    let model = msg.get("model").and_then(Value::as_str).unwrap_or("");
                    if !model.is_empty() {
                        fold.note_model(model);
                    }
                    let usage = msg.get("usage").map(parse_usage).unwrap_or_default();
                    fold.note_usage(usage);
                    kinds.extend(assistant_block_kinds(msg, model, usage, fold, workdir));
                }
                "toolResult" => {
                    let output = msg
                        .get("content")
                        .and_then(Value::as_array)
                        .map(|blocks| tool_result_text(blocks))
                        .unwrap_or_default();
                    kinds.push(EventKind::ToolResult(ToolResult {
                        result: ToolOutcome {
                            original_bytes: output.len() as u64,
                            output,
                            is_error: is_error(msg),
                            truncated: false,
                        },
                    }));
                }
                "custom" | "developer" => {
                    let text = msg.get("content").map(content_text).unwrap_or_default();
                    if !text.is_empty() {
                        kinds.push(EventKind::System(System { text }));
                    }
                }
                _ => {
                    kinds.push(EventKind::System(System {
                        text: raw.to_string(),
                    }));
                }
            }
        }
        "custom_message" => {
            let text = record.get("content").map(content_text).unwrap_or_default();
            if !text.is_empty() {
                kinds.push(EventKind::System(System { text }));
            }
        }
        "ttsr_injection" => {
            let names: Vec<&str> = record
                .get("injectedRules")
                .and_then(Value::as_array)
                .map(|rules| rules.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            kinds.push(EventKind::System(System {
                text: format!("Rules injected: {}", names.join(", ")),
            }));
        }
        "compaction" => {
            let summary = record
                .get("summary")
                .and_then(Value::as_str)
                .or_else(|| record.get("shortSummary").and_then(Value::as_str));
            kinds.push(EventKind::Compaction(Compaction {
                summary: summary.map(str::to_string),
            }));
        }
        // Header facts only (session/title/title_change), documented skips
        // (session_init, model_usage, mode/model/thinking-level changes,
        // credential_pin, custom records including session_exit): no events.
        "session"
        | "title"
        | "title_change"
        | "session_init"
        | "model_usage"
        | "mode_change"
        | "model_change"
        | "thinking_level_change"
        | "credential_pin"
        | "custom" => {}
        _ => {
            kinds.push(EventKind::System(System {
                text: raw.to_string(),
            }));
        }
    }
    kinds
}

/// Assistant content blocks in order, following the Claude adapter's
/// conventions: `thinking` → reasoning, `text` → assistant text carrying
/// `model` and `usage`, `toolCall` → tool call (input = `arguments`).
/// Unknown block types keep the raw-block system fallback, never dropped.
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
    let Some(blocks) = msg.get("content").and_then(Value::as_array) else {
        return kinds;
    };
    for b in blocks {
        let btype = b.get("type").and_then(Value::as_str).unwrap_or("");
        match btype {
            "text" => {
                if let Some(text) = b.get("text").and_then(Value::as_str) {
                    kinds.push(EventKind::AssistantMessage(AssistantMessage {
                        text: text.to_string(),
                        model: model_opt.clone(),
                        usage,
                    }));
                }
            }
            "thinking" => {
                if let Some(thinking) = b.get("thinking").and_then(Value::as_str) {
                    kinds.push(EventKind::Reasoning(Reasoning {
                        text: thinking.to_string(),
                    }));
                }
            }
            "toolCall" => {
                let name = b.get("name").and_then(Value::as_str).unwrap_or("unknown");
                let input = b.get("arguments").cloned().unwrap_or(Value::Null);
                for path in tool_paths(name, &input) {
                    fold.note_file(workdir, &path);
                }
                kinds.push(EventKind::ToolCall(ToolCall {
                    tool: ToolRef {
                        name: name.to_string(),
                        input,
                    },
                }));
            }
            _ => {
                kinds.push(EventKind::System(System {
                    text: b.to_string(),
                }));
            }
        }
    }
    kinds
}

/// Recursively collect `*.jsonl` files under `dir`, sorted for determinism.
fn collect_jsonl(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_jsonl(&path, out);
        } else if path.extension().is_some_and(|x| x == "jsonl") {
            out.push(path);
        }
    }
}

/// First non-empty `cwd` and first `runtime.version` seen in a transcript
/// (cheap identity scan). `cwd` comes from the `session` record (a
/// per-record `cwd` is accepted as the omp fallback); the version is the
/// first `runtime.version` — `session.version` is the format version and is
/// never the agent version. An empty `cwd` counts as unknown and does not
/// stop the scan.
fn scan_identity(native_path: &std::path::Path) -> (Option<String>, Option<String>) {
    let Ok(body) = std::fs::read_to_string(native_path) else {
        return (None, None);
    };
    let mut cwd = None;
    let mut version = None;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(record): Result<Value, _> = serde_json::from_str(line) else {
            continue;
        };
        if cwd.is_none()
            && let Some(c) = record.get("cwd").and_then(Value::as_str)
            && !c.is_empty()
        {
            cwd = Some(c.to_string());
        }
        if version.is_none()
            && let Some(v) = record
                .get("runtime")
                .and_then(|r| r.get("version"))
                .and_then(Value::as_str)
        {
            version = Some(v.to_string());
        }
        if cwd.is_some() && version.is_some() {
            break;
        }
    }
    (cwd, version)
}

/// Whether a native path lives under the omp store (`.omp/agent/sessions`).
fn is_omp_store(native_path: &std::path::Path) -> bool {
    native_path.components().any(|c| c.as_os_str() == ".omp")
}

/// Format a raw `runtime.version` for reporting: omp-store files report
/// `omp-<version>` (`omp-unknown` with none); Pi-store files report it as-is
/// (`unknown` with none: Pi itself records no `runtime` in its sessions).
fn format_version(raw: Option<&str>, is_omp: bool) -> String {
    match (raw, is_omp) {
        (Some(v), true) => format!("omp-{v}"),
        (None, true) => "omp-unknown".to_string(),
        (Some(v), false) => v.to_string(),
        (None, false) => "unknown".to_string(),
    }
}

impl Adapter for PiAdapter {
    fn id(&self) -> AgentName {
        AgentName::Pi
    }

    /// Pi versions only; `omp-*` versions are NEVER members (they ship
    /// unverified — see [`Adapter::version_status`]).
    const COVERED: &[&str] = &["0.5.2"];

    /// Binding: any version starting with `omp-` reports `covered: false`.
    fn version_status(&self, version: &str) -> crate::AdapterVersion {
        crate::AdapterVersion {
            covered: !version.starts_with("omp-") && Self::COVERED.contains(&version),
        }
    }

    fn detect(&self, roots: &Roots) -> bool {
        roots.data_dir.join(".pi/agent/sessions").is_dir()
            || roots.data_dir.join(".omp/agent/sessions").is_dir()
    }

    /// No verified JSON-config hook surface for Pi/omp: no-op. Capture is
    /// discovery-based (commit/push/sync).
    fn install_hooks(&self, _roots: &Roots) -> io::Result<Vec<PathBuf>> {
        Ok(vec![])
    }

    /// Remove only the legacy hook file, and only when it carries the
    /// starforge marker (top-level `starforge` key). The key is dropped,
    /// preserving unrelated keys; an emptied object deletes the file.
    fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>> {
        let path = roots.config_dir.join(LEGACY_HOOK_REL_PATH);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(vec![]);
        };
        let Ok(mut body) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(vec![]);
        };
        let Some(obj) = body.as_object_mut() else {
            return Ok(vec![]);
        };
        if obj.remove(MARKER).is_none() {
            return Ok(vec![]);
        }
        if obj.is_empty() {
            std::fs::remove_file(&path)?;
        } else {
            std::fs::write(&path, serde_json::to_string_pretty(&body).unwrap())?;
        }
        Ok(vec![path])
    }

    fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate> {
        let mut out = Vec::new();
        // Both stores are recursive; session keys are the path relative to
        // `data_dir` joined with `/` (stable and unique across stores).
        let session_key_for = |path: &std::path::Path| {
            path.strip_prefix(&roots.data_dir)
                .map(|rel| {
                    rel.components()
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .collect::<Vec<_>>()
                        .join("/")
                })
                .unwrap_or_default()
        };
        for store in [".pi/agent/sessions", ".omp/agent/sessions"] {
            let dir = roots.data_dir.join(store);
            if !dir.is_dir() {
                continue;
            }
            let mut files = Vec::new();
            collect_jsonl(&dir, &mut files);
            for native_path in files {
                let session_key = session_key_for(&native_path);
                // A subagent session lives inside a directory named after its
                // parent's file stem: the parent of `<D>/<name>.jsonl` is the
                // sibling file `<D>.jsonl`, when it exists.
                let parent_session_key = native_path
                    .parent()
                    .and_then(|parent_dir| {
                        let stem = parent_dir.file_name()?.to_string_lossy().into_owned();
                        let parent_file = parent_dir.parent()?.join(format!("{stem}.jsonl"));
                        // The parent file must live inside the scanned store
                        // dir: a file directly under the store (e.g.
                        // `<store>/x.jsonl`) must not link to a decoy
                        // `<store>/../x.jsonl` outside it.
                        if !parent_file.starts_with(&dir) {
                            return None;
                        }
                        parent_file.is_file().then(|| session_key_for(&parent_file))
                    })
                    .filter(|key| !key.is_empty() && key != &session_key);
                let (workdir, version) = scan_identity(&native_path);
                // Privacy rule: unknown cwd (missing/empty) is skipped,
                // never defaulted to this worktree.
                let Some(workdir) = workdir.filter(|cwd| !cwd.is_empty()).map(PathBuf::from) else {
                    continue;
                };
                if !workdir_inside(&roots.worktree, &workdir) {
                    continue;
                }
                if let Some(cursor) = known.get(&session_key)
                    && let Ok(meta) = std::fs::metadata(&native_path)
                    && meta.len() <= cursor.offset
                {
                    continue;
                }
                let agent_version = format_version(version.as_deref(), is_omp_store(&native_path));
                out.push(Candidate {
                    session_key,
                    native_path,
                    agent_version,
                    workdir,
                    parent_session_key,
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
        // the full session, even on incremental reads. Timestamps resolve in
        // file order, so a resumed batch inherits the most recent timestamp
        // already seen instead of "now".
        let all = complete_lines(&bytes, 0);
        let mut parsed: Vec<(String, String, Value)> = Vec::with_capacity(all.len());
        let mut last_seen: Option<String> = None;
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
            let ts = record_ts(&record, last_seen.as_deref(), fallback_ts);
            last_seen = Some(ts.clone());
            parsed.push((text.to_string(), ts, record));
        }
        let mut fold = HeaderFold::default();
        for (_, ts, record) in &parsed {
            fold.feed(record, ts);
        }
        let workdir = fold
            .workdir
            .clone()
            .unwrap_or_else(|| candidate.workdir.to_string_lossy().into_owned());
        // Event pass: now that the fold has seen every record (workdir known
        // for relativizing), map each record to its kinds.
        let mut kinds: Vec<(String, Vec<EventKind>)> = Vec::with_capacity(parsed.len());
        for (raw, ts, record) in &parsed {
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
        let version = format_version(
            fold.version.as_deref(),
            is_omp_store(&candidate.native_path),
        );
        let covered = self.version_status(&version).covered;
        let id = fold
            .session_id
            .as_deref()
            .and_then(|s| Ulid::from_str(s).ok())
            .unwrap_or(Ulid::nil());
        let header = SessionMeta {
            format: FORMAT_TAG.to_string(),
            id,
            agent: Agent {
                name: AgentName::Pi,
                version,
            },
            models: fold.models.clone(),
            title: fold.title.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_version_covers_both_stores_and_the_missing_version() {
        assert_eq!(format_version(Some("1.2.3"), true), "omp-1.2.3");
        assert_eq!(format_version(None, true), "omp-unknown");
        assert_eq!(format_version(Some("1.2.3"), false), "1.2.3");
        // Pi itself records no `runtime`; the session is still captured.
        assert_eq!(format_version(None, false), "unknown");
    }

    #[test]
    fn hashline_paths_reads_only_tagged_header_lines() {
        let text = "[src/auth.rs#a1b2]\n-old\n+new\n[README.md#00ff]\n";
        assert_eq!(
            hashline_paths(text),
            vec!["src/auth.rs".to_string(), "README.md".to_string()]
        );
        assert!(hashline_paths("[not a path]\n[src/x.rs#zzzz]\n[]").is_empty());
    }

    #[test]
    fn file_directly_under_store_does_not_link_to_decoy_parent_outside() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("data");
        let worktree = tmp.path().join("worktree");
        let store = data_dir.join(".pi/agent/sessions");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(&worktree).unwrap();
        let line = format!(
            "{{\"type\":\"session\",\"version\":3,\"id\":\"s1\",\"timestamp\":\"2026-11-04T12:00:00Z\",\"cwd\":\"{}\",\"runtime\":{{\"version\":\"0.5.2\"}}}}\n",
            worktree.to_string_lossy()
        );
        // Decoy parent file OUTSIDE the store (`<store>/../sessions.jsonl`).
        std::fs::write(data_dir.join(".pi/agent/sessions.jsonl"), &line).unwrap();
        // A file directly under the store would derive that decoy as parent.
        std::fs::write(store.join("x.jsonl"), &line).unwrap();
        let roots = Roots {
            config_dir: tmp.path().join("cfg"),
            data_dir: data_dir.clone(),
            worktree: worktree.clone(),
        };
        let found = PiAdapter.discover(&roots, &HashMap::new());
        assert_eq!(found.len(), 1, "one session discovered: {found:?}");
        assert_eq!(
            found[0].parent_session_key, None,
            "no parent link to a file outside the store dir"
        );
    }
}
