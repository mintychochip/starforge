//! Claude Code adapter: `~/.claude/projects/<slug>/<session-id>.jsonl`.
//!
//! Hook integration (`install_hooks` / `remove_hooks`) merges the
//! `SessionEnd` command `starforge hook session-end` into the user's
//! Claude Code settings file at `<config_dir>/settings.json`, in Claude
//! Code's own schema (`"hooks": { "SessionEnd": [ { "hooks": [ ... ] } ] }`).
//! Merge preserves every unrelated key and hook entry; removal deletes only
//! entries whose command is exactly ours and prunes the empty arrays or
//! objects it left behind.
//!
//! Native shape (one JSON object per line): `user` / `assistant` records
//! carrying a `message` object whose `content` array holds `text`, `thinking`,
//! `tool_use`, and `tool_result` blocks (assistant messages also carry
//! `model` and token `usage`), plus bare `summary` records holding compaction
//! context. Top-level `tool_use` / `tool_result` record shapes are accepted
//! too, for forward compatibility with hook-emitted events. Every record may
//! carry `cwd`, `sessionId`, `version`, and `timestamp`.
//!
//! Discovery attribution: a session is captured only when a record
//! carries a non-empty `cwd` inside the worktree; a session with
//! unknown/empty `cwd` is skipped (never defaulted to the worktree).

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

/// Claude Code adapter (unit struct implementing [`Adapter`]).
pub struct ClaudeAdapter;

/// Hook file path relative to `Roots.config_dir`: Claude Code's real user
/// settings file.
const HOOK_REL_PATH: &str = "settings.json";
/// The `SessionEnd` hook command starforge installs.
const HOOK_COMMAND: &str = "starforge hook session-end";
/// Write `body` to `path` atomically, following a symlinked `path` so the
/// link itself is preserved (dotfile managers): the resolved target is
/// replaced in place. A dangling symlink is an error and the file is left
/// untouched. The temp file is created exclusively (`create_new`) with a
/// random suffix and mode `0600`, synced, given the final mode (existing
/// file's mode, else `0644`) **before** the rename, so there is no
/// world-readable window.
fn write_settings(path: &std::path::Path, body: &Value) -> io::Result<()> {
    let bytes = serde_json::to_string_pretty(body).unwrap();
    let target: std::path::PathBuf = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => std::fs::canonicalize(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot resolve settings symlink {}: {e}", path.display()),
            )
        })?,
        _ => path.to_path_buf(),
    };
    #[cfg(unix)]
    let final_mode: u32 = std::fs::metadata(&target)
        .map(|m| {
            use std::os::unix::fs::PermissionsExt as _;
            m.permissions().mode() & 0o7777
        })
        .unwrap_or(0o644);
    #[cfg(not(unix))]
    let final_mode: u32 = 0;
    let parent = target.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut tmp = None;
    let mut file = None;
    for _ in 0..16 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let candidate = parent.join(format!(
            ".settings.json.tmp.{}-{n}-{nanos}",
            std::process::id()
        ));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        match opts.open(&candidate) {
            Ok(f) => {
                tmp = Some(candidate);
                file = Some(f);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    let tmp = tmp.ok_or_else(|| io::Error::other("could not create unique settings temp"))?;
    let mut file = file.expect("temp file opened");
    let result: io::Result<()> = (|| {
        use std::io::Write as _;
        file.write_all(bytes.as_bytes())?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(final_mode))?;
        }
        #[cfg(not(unix))]
        let _ = final_mode;
        std::fs::rename(&tmp, &target)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

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
            && !cwd.is_empty()
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
        if let Some(rel) = crate::repo_relative(std::path::Path::new(workdir), path)
            && !self.files_touched.iter().any(|f| f == &rel)
        {
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
/// `raw` is the record's source line: unmapped record types fall back to
/// `system { text: <raw JSON> }` so no record is ever dropped.
fn record_events(
    raw: &str,
    record: &Value,
    fold: &mut HeaderFold,
    workdir: &str,
) -> Vec<EventKind> {
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
            // Unknown record type: raw JSON into `system`. Never dropped.
            kinds.push(EventKind::System(System {
                text: raw.to_string(),
            }));
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
                    _ => {
                        // Unknown content-block type: raw block JSON into
                        // `system`. Never dropped.
                        kinds.push(EventKind::System(System {
                            text: b.to_string(),
                        }));
                    }
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
                    _ => {
                        // Unknown content-block type: raw block JSON into
                        // `system`. Never dropped.
                        kinds.push(EventKind::System(System {
                            text: b.to_string(),
                        }));
                    }
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

    /// Merge starforge's `SessionEnd` hook into `<config_dir>/settings.json`
    /// in Claude Code's schema, preserving every unrelated key and hook
    /// entry. A missing file is created with just our hooks; a present file
    /// must be a JSON object (anything else is an `InvalidData` error and the
    /// file is left untouched). Appends our group only when no existing
    /// `SessionEnd` entry already carries our command (idempotent). Writes
    /// atomically (temp file + rename, preserving the existing file mode).
    fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>> {
        let path = roots.config_dir.join(HOOK_REL_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let our_group = serde_json::json!({
            "hooks": [
                { "type": "command", "command": HOOK_COMMAND }
            ]
        });
        match std::fs::read(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut obj = serde_json::Map::new();
                let hooks = serde_json::json!({ "SessionEnd": [our_group] });
                obj.insert("hooks".to_string(), hooks);
                write_settings(&path, &Value::Object(obj))?;
                Ok(vec![path])
            }
            Err(e) => Err(e),
            Ok(bytes) => {
                let mut body: Value = serde_json::from_slice(&bytes).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("hook file is not valid JSON: {}", path.display()),
                    )
                })?;
                let obj = body.as_object_mut().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("hook file is not a JSON object: {}", path.display()),
                    )
                })?;
                if obj.contains_key("hooks") && !obj.get("hooks").is_some_and(|h| h.is_object()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("hook file has a non-object hooks value: {}", path.display()),
                    ));
                }
                let hooks = obj
                    .entry("hooks".to_string())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                let hooks_obj = hooks.as_object_mut().expect("checked object");
                if hooks_obj.contains_key("SessionEnd")
                    && !hooks_obj.get("SessionEnd").is_some_and(|s| s.is_array())
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "hook file has a non-array SessionEnd value: {}",
                            path.display()
                        ),
                    ));
                }
                let groups = hooks_obj
                    .entry("SessionEnd".to_string())
                    .or_insert_with(|| Value::Array(Vec::new()));
                let groups = groups.as_array_mut().expect("checked array");
                let already = groups.iter().any(|g| {
                    g.get("hooks")
                        .and_then(|h| h.as_array())
                        .is_some_and(|entries| {
                            entries.iter().any(|e| {
                                e.get("command").and_then(|c| c.as_str()) == Some(HOOK_COMMAND)
                            })
                        })
                });
                if already {
                    return Ok(vec![path]);
                }
                groups.push(our_group);
                write_settings(&path, &body)?;
                Ok(vec![path])
            }
        }
    }

    /// Remove only the hook entries whose command is exactly ours, then prune
    /// the empty arrays or objects left behind. Never touches anything else;
    /// reports the path only when the file changed. A missing file, an
    /// invalid file, or a file without our command is left untouched and
    /// yields nothing.
    fn remove_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>> {
        let path = roots.config_dir.join(HOOK_REL_PATH);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(vec![]);
        };
        let Ok(mut body) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(vec![]);
        };
        let Some(obj) = body.as_object_mut() else {
            return Ok(vec![]);
        };
        let Some(hooks) = obj.get_mut("hooks") else {
            return Ok(vec![]);
        };
        let Some(hooks_obj) = hooks.as_object_mut() else {
            return Ok(vec![]);
        };
        let Some(groups) = hooks_obj.get_mut("SessionEnd") else {
            return Ok(vec![]);
        };
        let Some(group_arr) = groups.as_array_mut() else {
            return Ok(vec![]);
        };
        let mut changed = false;
        group_arr.retain_mut(|g| {
            let Some(entries) = g.get_mut("hooks").and_then(|h| h.as_array_mut()) else {
                return true;
            };
            let before = entries.len();
            entries.retain(|e| e.get("command").and_then(|c| c.as_str()) != Some(HOOK_COMMAND));
            if entries.len() != before {
                changed = true;
            }
            !entries.is_empty()
        });
        if !changed {
            return Ok(vec![]);
        }
        if group_arr.is_empty() {
            hooks_obj.remove("SessionEnd");
        }
        if hooks_obj.is_empty() {
            obj.remove("hooks");
        }
        write_settings(&path, &body)?;
        Ok(vec![path])
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
            && !c.is_empty()
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
