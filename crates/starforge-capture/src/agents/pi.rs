//! Pi and omp adapters: `<data_dir>/sessions/*.jsonl` (Pi) and
//! `<data_dir>/omp/agent/sessions/**/*.jsonl` (omp).
//!
//! Native shape (one JSON object per line): `message` records carrying a `role`
//! (`user` | `assistant`), `content` text, and — assistant only — `model`,
//! `reasoning`, and token `usage`; `tool_call` records with `name` and `input`;
//! `tool_result` records with `output`; `subagent_start` / `subagent_end`
//! records with `subagent_id` and `task`; and `summary` records carrying
//! compaction context in `summary`. Every record may carry `cwd`, `session`
//! (`sessionId` is accepted too, for the omp shape), `version`, and
//! `timestamp` (`ts` is accepted as a fallback key). An assistant `message`
//! carrying `reasoning` emits two events (the multi-event record the
//! incremental test resumes across).
//!
//! omp sessions parse with the same mapper and share [`AgentName::Pi`] (the
//! five-name table has no omp entry); their versions are reported as
//! `omp-<version>`. omp-only record shapes (e.g. `extension_state`) map to
//! `system { text: <raw JSON> }`: never dropped, never an error.
//!
//! Hook story: Pi owns a single extension-event snippet under `config_dir`;
//! the omp side has no hook surface, so both directions for omp are
//! documented as `Ok(vec![])` and discovery of the session files is the only
//! omp capture path.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

use serde_json::Value;
use starforge_format::{
    Agent, AgentName, AssistantMessage, CaptureInfo, CaptureMode, Compaction, Event, EventKind,
    FORMAT_TAG, Reasoning, SessionMeta, SubagentBoundary, System, ToolCall, ToolOutcome, ToolRef,
    ToolResult, Usage, UserMessage,
};
use time::format_description::well_known::Rfc3339;
use ulid::Ulid;

use crate::{Adapter, Candidate, CaptureError, Cursor, ReadOutput, Roots, workdir_inside};

/// Pi adapter (unit struct; [`Adapter`] is not object-safe). Also serves omp
/// sessions, which share [`AgentName::Pi`].
pub struct PiAdapter;

/// Hook snippet path relative to `Roots.config_dir`.
const HOOK_REL_PATH: &str = "pi/starforge.json";
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

/// Render a tool-result `output` value (`string | scalar`) as text.
fn content_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn parse_usage(v: &Value) -> Usage {
    let n = |key: &str| v.get(key).and_then(Value::as_u64).unwrap_or(0);
    Usage {
        input: n("input_tokens"),
        output: n("output_tokens"),
        cache_read: n("cache_read_tokens"),
        cache_write: n("cache_write_tokens"),
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
        {
            self.workdir = Some(cwd.to_string());
        }
        if self.session_id.is_none() {
            let id = record
                .get("session")
                .or_else(|| record.get("sessionId"))
                .or_else(|| record.get("session_id"))
                .and_then(Value::as_str);
            if let Some(id) = id {
                self.session_id = Some(id.to_string());
            }
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
/// `raw` is the record's source line: unmapped (omp-only) shapes fall back to
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
        "message" => {
            let role = record.get("role").and_then(Value::as_str).unwrap_or("");
            match role {
                "user" => {
                    if let Some(text) = record.get("content").and_then(Value::as_str)
                        && !text.is_empty()
                    {
                        kinds.push(EventKind::UserMessage(UserMessage {
                            text: text.to_string(),
                        }));
                    }
                }
                "assistant" => {
                    let model = record.get("model").and_then(Value::as_str).unwrap_or("");
                    if !model.is_empty() {
                        fold.note_model(model);
                    }
                    let usage = record.get("usage").map(parse_usage).unwrap_or_default();
                    fold.note_usage(usage);
                    if let Some(text) = record.get("content").and_then(Value::as_str)
                        && !text.is_empty()
                    {
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
                    // An assistant message may carry its reasoning inline; it
                    // emits a second event after the message (this is the
                    // multi-event record the incremental test resumes across).
                    if let Some(reasoning) = record.get("reasoning").and_then(Value::as_str)
                        && !reasoning.is_empty()
                    {
                        kinds.push(EventKind::Reasoning(Reasoning {
                            text: reasoning.to_string(),
                        }));
                    }
                }
                _ => {
                    // Unknown role: preserve the raw record rather than drop it.
                    kinds.push(EventKind::System(System {
                        text: raw.to_string(),
                    }));
                }
            }
        }
        "tool_call" => {
            let name = record
                .get("name")
                .or_else(|| record.get("tool"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let input = record.get("input").cloned().unwrap_or(Value::Null);
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
        "tool_result" => {
            let output = record
                .get("output")
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
        "subagent_start" | "subagent_end" => {
            let boundary = SubagentBoundary {
                subagent_id: record
                    .get("subagent_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                task: record
                    .get("task")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            };
            if rtype == "subagent_start" {
                kinds.push(EventKind::SubagentStart(boundary));
            } else {
                kinds.push(EventKind::SubagentEnd(boundary));
            }
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
            // Unmapped (omp-only) record shape: raw JSON into `system`.
            // Never dropped, never an error.
            kinds.push(EventKind::System(System {
                text: raw.to_string(),
            }));
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

/// First `cwd` and `version` seen in a transcript (cheap identity scan).
fn scan_identity(native_path: &std::path::Path) -> (Option<String>, Option<String>) {
    let Ok(body) = std::fs::read_to_string(native_path) else {
        return (None, None);
    };
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(record): Result<Value, _> = serde_json::from_str(line) else {
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
        roots.data_dir.join("sessions").is_dir()
            || roots.data_dir.join("omp/agent/sessions").is_dir()
    }

    /// Merge starforge's hook fragment under the single top-level `starforge`
    /// key, preserving every unrelated key. A missing file is created; a
    /// present file must be a JSON object (anything else is an `InvalidData`
    /// error and the file is left untouched).
    fn install_hooks(&self, roots: &Roots) -> io::Result<Vec<PathBuf>> {
        let path = roots.config_dir.join(HOOK_REL_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let fragment = serde_json::json!({
            "_note": "starforge-managed extension-event hook; remove_hooks deletes this key",
            "extensionEvents": {
                "sessionEnd": [
                    {
                        "matcher": "starforge",
                        "hooks": [
                            { "type": "command", "command": "starforge hook session-end" }
                        ]
                    }
                ]
            }
        });
        match std::fs::read(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut obj = serde_json::Map::new();
                obj.insert(MARKER.to_string(), fragment);
                std::fs::write(
                    &path,
                    serde_json::to_string_pretty(&Value::Object(obj)).unwrap(),
                )?;
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
                obj.insert(MARKER.to_string(), fragment);
                std::fs::write(&path, serde_json::to_string_pretty(&body).unwrap())?;
                Ok(vec![path])
            }
        }
    }

    /// Remove only the `starforge` key, preserving every unrelated key. An
    /// emptied object deletes the file; a file without the key (or no file)
    /// is left untouched and yields nothing.
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
        // Pi store: flat `<data_dir>/sessions/*.jsonl`.
        let sessions = roots.data_dir.join("sessions");
        if sessions.is_dir() {
            let Ok(files) = std::fs::read_dir(&sessions) else {
                return out;
            };
            let mut files: Vec<_> = files
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "jsonl"))
                .collect();
            files.sort();
            for native_path in files {
                let session_key = native_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
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
        }
        // omp store: recursive `<data_dir>/omp/agent/sessions/**/*.jsonl`.
        // omp versions are reported as `omp-<version>` (the store is the
        // `<data_dir>/omp/agent/sessions/` layout, not the Pi flat layout).
        let omp_sessions = roots.data_dir.join("omp/agent/sessions");
        if omp_sessions.is_dir() {
            let mut files = Vec::new();
            collect_jsonl(&omp_sessions, &mut files);
            for native_path in files {
                let session_key = native_path
                    .strip_prefix(&roots.data_dir)
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
        let version = fold.version.clone().unwrap_or_default();
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
