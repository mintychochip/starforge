//! Gemini CLI + Antigravity adapter:
//! `<data_dir>/tmp/<hash>/chats/*.json` (Gemini CLI) and
//! `<data_dir>/antigravity/<version>/sessions/*.json` (Antigravity).
//!
//! Native shape (both stores): a single JSON chat document with `sessionId`,
//! `version`, `cwd`, `startedAt`, and a `messages` array. Message records
//! follow one `role` vocabulary: `user` records carry prompt text in
//! `content`; `model` records carry response text plus `model`, token
//! `usage`, and optional inline `reasoning`; `tool_call` records carry
//! `name` and `input`; `tool_result` records carry `output` (and
//! `is_error`); `summary` records carry compaction context in `summary`.
//!
//! Mapping: prompts → `user_message`; responses → `assistant_message`
//! (plus `reasoning` when inline reasoning is present — the multi-event
//! record the incremental test resumes across); tool records →
//! `tool_call`/`tool_result` (`Edit`/`Write` inputs carrying `file_path`
//! are noted in header `files_touched`); summaries → `compaction`.
//! Antigravity records parse with the same mapper; unmapped shapes (e.g.
//! the Antigravity-only `agent_state` record) fall back to
//! `system { text: <raw JSON> }`: never dropped, never an error.
//!
//! Antigravity layout choice: the store is keyed by version directory,
//! `<data_dir>/antigravity/<version>/sessions/*.json`, because Antigravity
//! ships its own forked chat layout that drifts per release — the directory
//! name is the source of truth for the reported version
//! (`antigravity-<version>`) rather than any in-file field, and sessions
//! from different installs never mix. That reported version ALWAYS ships
//! `adapter_version_verified == false` (binding user decision, like omp).
//! `detect` is true only when a store exists: a `chats` directory under any
//! `<data_dir>/tmp/<hash>/`, or the `<data_dir>/antigravity` directory.
//!
//! Cursor semantics: byte-offset semantics like the other file adapters —
//! `offset` is the chat file length consumed and `lines` is messages
//! consumed (`seq` still counts emitted events, so the multi-event `model`
//! record advances `events` by two). Gemini rewrites the whole chat
//! document on growth, so resume addresses records by `lines` while `offset`
//! only detects growth.
//!
//! Hook story: no hook surface is pinned for either store layout, so
//! [`Adapter::install_hooks`] and [`Adapter::remove_hooks`] both report
//! `Ok(vec![])` and discovery of the chat files is the only capture path.

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

/// Gemini adapter (unit struct; the [`Adapter`] trait is not object-safe).
/// Also serves Antigravity sessions, which share [`AgentName::Gemini`].
pub struct GeminiAdapter;

fn valid_ts(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &Rfc3339).is_ok()
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
    if let Some(b) = v
        .get("is_error")
        .or_else(|| v.get("isError"))
        .and_then(Value::as_bool)
    {
        return b;
    }
    v.get("is_error")
        .or_else(|| v.get("isError"))
        .and_then(Value::as_u64)
        .is_some_and(|n| n != 0)
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

/// Fold one parsed message into the session header accumulator.
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
    /// Document-level identity (`sessionId`, `version`, `cwd`,
    /// `startedAt`); message-level fields fill gaps below.
    fn feed_doc(&mut self, doc: &Value) {
        if self.version.is_none()
            && let Some(v) = doc.get("version").and_then(Value::as_str)
        {
            self.version = Some(v.to_string());
        }
        if self.workdir.is_none()
            && let Some(cwd) = doc.get("cwd").and_then(Value::as_str)
        {
            self.workdir = Some(cwd.to_string());
        }
        if self.session_id.is_none()
            && let Some(id) = doc.get("sessionId").and_then(Value::as_str)
        {
            self.session_id = Some(id.to_string());
        }
        if self.started_at.is_none()
            && let Some(ts) = doc.get("startedAt").and_then(Value::as_str)
            && valid_ts(ts)
        {
            self.started_at = Some(ts.to_string());
        }
    }

    /// Message-level identity gaps plus first-timestamp tracking.
    fn feed(&mut self, msg: &Value, ts: &str) {
        if self.workdir.is_none()
            && let Some(cwd) = msg.get("cwd").and_then(Value::as_str)
        {
            self.workdir = Some(cwd.to_string());
        }
        if self.session_id.is_none() {
            let id = msg
                .get("sessionId")
                .or_else(|| msg.get("session"))
                .or_else(|| msg.get("session_id"))
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
        let rel = relativize(workdir, path);
        if !self.files_touched.iter().any(|f| f == &rel) {
            self.files_touched.push(rel);
        }
    }
}

/// One message's timestamp: native `timestamp` (or `ts`) when valid
/// RFC 3339, else `fallback_ts`.
fn record_ts(msg: &Value, fallback_ts: &str) -> String {
    let ts = msg
        .get("timestamp")
        .or_else(|| msg.get("ts"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if valid_ts(ts) {
        ts.to_string()
    } else {
        fallback_ts.to_string()
    }
}

/// Map one message to events (timestamps resolved, `seq` assigned by the
/// caller). Mutates `fold` with header facts (models, usage, files).
/// `raw` is the message re-serialized: unmapped (Antigravity-only) shapes
/// fall back to `system { text: <raw JSON> }` so no message is ever dropped.
fn message_events(raw: &str, msg: &Value, fold: &mut HeaderFold, workdir: &str) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
    match role {
        "user" => {
            if let Some(text) = msg.get("content").and_then(Value::as_str)
                && !text.is_empty()
            {
                kinds.push(EventKind::UserMessage(UserMessage {
                    text: text.to_string(),
                }));
            }
        }
        "model" => {
            let model = msg.get("model").and_then(Value::as_str).unwrap_or("");
            if !model.is_empty() {
                fold.note_model(model);
            }
            let usage = msg.get("usage").map(parse_usage).unwrap_or_default();
            fold.note_usage(usage);
            if let Some(text) = msg.get("content").and_then(Value::as_str)
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
            if let Some(reasoning) = msg.get("reasoning").and_then(Value::as_str)
                && !reasoning.is_empty()
            {
                kinds.push(EventKind::Reasoning(Reasoning {
                    text: reasoning.to_string(),
                }));
            }
        }
        "tool_call" => {
            let name = msg
                .get("name")
                .or_else(|| msg.get("tool"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let input = msg.get("input").cloned().unwrap_or(Value::Null);
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
            let output = msg.get("output").map(content_to_string).unwrap_or_default();
            kinds.push(EventKind::ToolResult(ToolResult {
                result: ToolOutcome {
                    original_bytes: output.len() as u64,
                    output,
                    is_error: is_error(msg),
                    truncated: false,
                },
            }));
        }
        "summary" => {
            kinds.push(EventKind::Compaction(Compaction {
                summary: msg
                    .get("summary")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }));
        }
        _ => {
            // Unmapped (Antigravity-only) message shape: raw JSON into
            // `system`. Never dropped, never an error.
            kinds.push(EventKind::System(System {
                text: raw.to_string(),
            }));
        }
    }
    kinds
}

/// Recursively collect `*.json` files under `dir`, sorted for determinism.
fn collect_json(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_json(&path, out);
        } else if path.is_file() && path.extension().is_some_and(|x| x == "json") {
            out.push(path);
        }
    }
}

/// Document `cwd` and `version` for `discover` (cheap identity scan).
/// Returns `None`s when the file is not a chat document.
fn scan_doc(native_path: &std::path::Path) -> (Option<String>, Option<String>) {
    let Ok(bytes) = std::fs::read(native_path) else {
        return (None, None);
    };
    let Ok(doc) = serde_json::from_slice::<Value>(&bytes) else {
        return (None, None);
    };
    let cwd = doc
        .get("cwd")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            doc.get("messages")
                .and_then(Value::as_array)
                .and_then(|msgs| {
                    msgs.iter()
                        .find_map(|m| m.get("cwd").and_then(Value::as_str).map(str::to_string))
                })
        });
    let version = doc
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string);
    (cwd, version)
}

impl Adapter for GeminiAdapter {
    fn id(&self) -> AgentName {
        AgentName::Gemini
    }

    /// Gemini CLI versions only; `antigravity-*` versions are NEVER members
    /// (they ship unverified — see [`Adapter::version_status`]).
    const COVERED: &[&str] = &["0.12.0"];

    /// Binding: any version starting with `antigravity-` reports
    /// `covered: false`.
    fn version_status(&self, version: &str) -> crate::AdapterVersion {
        crate::AdapterVersion {
            covered: !version.starts_with("antigravity-") && Self::COVERED.contains(&version),
        }
    }

    fn detect(&self, roots: &Roots) -> bool {
        let tmp = roots.data_dir.join("tmp");
        if let Ok(entries) = std::fs::read_dir(&tmp)
            && entries.flatten().any(|e| e.path().join("chats").is_dir())
        {
            return true;
        }
        roots.data_dir.join("antigravity").is_dir()
    }

    /// No pinned hook story for either store layout: the installed versions
    /// expose no stable hook surface to write to, so discovery of the chat
    /// files (below) is the only capture path and both directions report
    /// nothing.
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
        // Gemini CLI store: `<data_dir>/tmp/<hash>/chats/*.json`.
        let tmp = roots.data_dir.join("tmp");
        if tmp.is_dir()
            && let Ok(hashes) = std::fs::read_dir(&tmp)
        {
            let mut hashes: Vec<PathBuf> = hashes
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            hashes.sort();
            for hash in hashes {
                let chats = hash.join("chats");
                if !chats.is_dir() {
                    continue;
                }
                let Ok(files) = std::fs::read_dir(&chats) else {
                    continue;
                };
                let mut files: Vec<PathBuf> = files
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
                    .collect();
                files.sort();
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
                    let (workdir, version) = scan_doc(&native_path);
                    let workdir = workdir
                        .filter(|cwd| !cwd.is_empty())
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
        }
        // Antigravity store: `<data_dir>/antigravity/<version>/sessions/`.
        // The version directory is the source of truth for the reported
        // `antigravity-<version>` string (see module docs).
        let ag = roots.data_dir.join("antigravity");
        if ag.is_dir()
            && let Ok(versions) = std::fs::read_dir(&ag)
        {
            let mut versions: Vec<PathBuf> = versions
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .collect();
            versions.sort();
            for vdir in versions {
                let suffix = vdir
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let mut files = Vec::new();
                collect_json(&vdir, &mut files);
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
                    let (workdir, _) = scan_doc(&native_path);
                    let workdir = workdir
                        .filter(|cwd| !cwd.is_empty())
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
                        agent_version: format!("antigravity-{suffix}"),
                        workdir,
                    });
                }
            }
        }
        out.sort_by(|a, b| a.session_key.cmp(&b.session_key));
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
        let doc: Value =
            serde_json::from_slice(&bytes).map_err(|e| CaptureError::BadNative(e.to_string()))?;
        let Some(messages) = doc.get("messages").and_then(Value::as_array) else {
            return Err(CaptureError::BadNative(
                "chat document has no messages array".to_string(),
            ));
        };
        for msg in messages {
            if !msg.is_object() {
                return Err(CaptureError::BadNative(
                    "message is not an object".to_string(),
                ));
            }
        }
        // Header pass: fold the whole document so the header always reflects
        // the full session, even on incremental reads.
        let mut fold = HeaderFold::default();
        fold.feed_doc(&doc);
        let mut parsed: Vec<(String, String, &Value)> = Vec::with_capacity(messages.len());
        for msg in messages {
            let ts = record_ts(msg, fallback_ts);
            fold.feed(msg, &ts);
            parsed.push((serde_json::to_string(msg).unwrap_or_default(), ts, msg));
        }
        let workdir = fold
            .workdir
            .clone()
            .unwrap_or_else(|| candidate.workdir.to_string_lossy().into_owned());
        // Event pass: now that the fold has seen every message (workdir
        // known for relativizing), map each message to its kinds.
        let mut kinds: Vec<(String, Vec<EventKind>)> = Vec::with_capacity(parsed.len());
        for (raw, ts, msg) in &parsed {
            let ks = message_events(raw, msg, &mut fold, &workdir);
            kinds.push((ts.clone(), ks));
        }

        // New messages are those at index >= `cursor.lines` (the whole chat
        // document is rewritten on growth, so `offset` only detects growth).
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
            Cursor {
                offset: len,
                lines: cursor.lines + fresh,
                events: cursor.events + events.len() as u64,
            }
        };
        // Antigravity candidates carry the directory-derived version; the
        // in-file field is ignored for versioning (see module docs).
        let version = if candidate.agent_version.starts_with("antigravity-") {
            candidate.agent_version.clone()
        } else {
            fold.version.clone().unwrap_or_default()
        };
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
                name: AgentName::Gemini,
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
