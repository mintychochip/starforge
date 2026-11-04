//! OpenCode adapter: `<data_dir>/opencode.db` (SQLite) or
//! `<data_dir>/opencode-sessions/*.jsonl` (file storage, by version).
//!
//! Native shape (SQLite): a `session` row per native session (`id`, `cwd`,
//! `version`, `created_at`) plus one `message` row per record (`id` rowid
//! cursor key, `session_id`, `role`, `name`, `content`, `reasoning`, token
//! counters, `is_error`, `ts`). `role` is one of `user` | `assistant` |
//! `tool_call` | `tool_result` | `summary`; `name` carries the model
//! (assistant rows) or the tool name (tool rows); `content` carries text, or
//! a JSON-encoded tool-input object for `tool_call` rows.
//!
//! Native shape (file storage): one JSON object per line with the same
//! logical columns (`role`, `name`, `content`, `reasoning`,
//! `input_tokens`, `output_tokens`, `is_error`, plus `timestamp`/`ts`,
//! `session`, `version`, `cwd` on every record).
//!
//! Mapping: `user` rows → `user_message`; `assistant` rows →
//! `assistant_message` (plus `reasoning` when inline reasoning is present —
//! the multi-event row the incremental test resumes across); `tool_call`
//! rows → `tool_call`, with `Edit`/`Write` inputs carrying `file_path`
//! additionally yielding `file_change { path, change, diff: None }` plus a
//! `files_touched` entry (the other multi-event row); `tool_result` rows →
//! `tool_result`; `summary` rows → `compaction`. Unmapped roles fall back to
//! `system { text: <raw JSON> }`: never dropped, never an error.
//!
//! Cursor semantics: for the SQLite store `offset` is the last `message`
//! rowid consumed (`0` = none) and `lines` is rows consumed; resume selects
//! `WHERE session_id = ? AND id > offset ORDER BY id`. (`id INTEGER PRIMARY
//! KEY` aliases the rowid.) For file-storage versions the cursor falls back
//! to byte-offset semantics like the other JSONL adapters; both paths share
//! `COVERED` gating.
//!
//! Reads are read-only: the adapter opens the database with
//! `SQLITE_OPEN_READ_ONLY` and issues `SELECT`s only, never `CREATE`/write.
//!
//! Hook story: no plugin-event surface is pinned for the covered versions,
//! so [`Adapter::install_hooks`] and [`Adapter::remove_hooks`] both report
//! `Ok(vec![])` and discovery of the stores is the only capture path.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use starforge_format::{
    Agent, AgentName, AssistantMessage, CaptureInfo, CaptureMode, Compaction, Event, EventKind,
    FORMAT_TAG, FileChange, FileChangeKind, Reasoning, SessionMeta, System, ToolCall, ToolOutcome,
    ToolRef, ToolResult, Usage, UserMessage,
};
use time::format_description::well_known::Rfc3339;
use ulid::Ulid;

use crate::{Adapter, Candidate, CaptureError, Cursor, ReadOutput, Roots, workdir_inside};

/// OpenCode adapter (unit struct; the [`Adapter`] trait is not object-safe).
pub struct OpencodeAdapter;

fn valid_ts(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &Rfc3339).is_ok()
}

/// One normalized message row: a SQLite `message` row or a file-storage
/// JSONL record. `ts_raw` is resolved against `fallback_ts` at read time.
#[derive(Clone)]
struct OcRow {
    role: String,
    name: String,
    content: String,
    reasoning: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
    is_error: bool,
    ts_raw: String,
}

/// Raw JSON for a SQLite row (sorted keys; the system-fallback text).
fn raw_sql(oc: &OcRow) -> String {
    let mut map = serde_json::Map::new();
    map.insert("content".to_string(), Value::String(oc.content.clone()));
    map.insert("input_tokens".to_string(), Value::from(oc.input_tokens));
    map.insert("is_error".to_string(), Value::Bool(oc.is_error));
    map.insert("name".to_string(), Value::String(oc.name.clone()));
    map.insert("output_tokens".to_string(), Value::from(oc.output_tokens));
    if let Some(reasoning) = &oc.reasoning {
        map.insert("reasoning".to_string(), Value::String(reasoning.clone()));
    }
    map.insert("role".to_string(), Value::String(oc.role.clone()));
    map.insert("ts".to_string(), Value::String(oc.ts_raw.clone()));
    Value::Object(map).to_string()
}

fn row_from_sql(row: &rusqlite::Row) -> Result<(OcRow, String), rusqlite::Error> {
    let input_raw: i64 = row.get("input_tokens")?;
    let output_raw: i64 = row.get("output_tokens")?;
    let error_raw: i64 = row.get("is_error")?;
    let oc = OcRow {
        role: row.get("role")?,
        name: row.get("name")?,
        content: row.get("content")?,
        reasoning: row.get("reasoning")?,
        input_tokens: u64::try_from(input_raw).unwrap_or(0),
        output_tokens: u64::try_from(output_raw).unwrap_or(0),
        is_error: error_raw != 0,
        ts_raw: row.get("ts")?,
    };
    let raw = raw_sql(&oc);
    Ok((oc, raw))
}

fn row_from_value(record: &Value) -> OcRow {
    let s = |key: &str| {
        record
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let n = |key: &str| record.get(key).and_then(Value::as_u64).unwrap_or(0);
    OcRow {
        role: s("role"),
        name: s("name"),
        content: s("content"),
        reasoning: record
            .get("reasoning")
            .and_then(Value::as_str)
            .map(str::to_string),
        input_tokens: n("input_tokens"),
        output_tokens: n("output_tokens"),
        is_error: record
            .get("is_error")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ts_raw: record
            .get("timestamp")
            .or_else(|| record.get("ts"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    }
}

/// Byte offset to resume from: `cursor.offset`, rounded back to the previous
/// `\n` when it lands mid-line (a foreign cursor; cursors produced by `read`
/// always sit on line starts). File-storage path only.
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
/// File-storage path only.
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

/// Fold one parsed row into the session header accumulator.
#[derive(Default)]
struct HeaderFold {
    version: Option<String>,
    session_id: Option<String>,
    started_at: Option<String>,
    models: Vec<String>,
    usage: Usage,
    files_touched: Vec<String>,
}

impl HeaderFold {
    fn feed_identity(&mut self, version: Option<&str>, session_id: Option<&str>) {
        if self.version.is_none()
            && let Some(v) = version
        {
            self.version = Some(v.to_string());
        }
        if self.session_id.is_none()
            && let Some(id) = session_id
        {
            self.session_id = Some(id.to_string());
        }
    }

    fn feed_ts(&mut self, ts: &str) {
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

/// One row's timestamp: native `ts` when valid RFC 3339, else `fallback_ts`.
fn row_ts(ts_raw: &str, fallback_ts: &str) -> String {
    if valid_ts(ts_raw) {
        ts_raw.to_string()
    } else {
        fallback_ts.to_string()
    }
}

/// Map one row to events (timestamps resolved, `seq` assigned by the
/// caller). Mutates `fold` with header facts (models, usage, files).
/// `raw` is the row's source bytes: unmapped roles fall back to
/// `system { text: <raw JSON> }` so no row is ever dropped.
fn row_events(row: &OcRow, raw: &str, fold: &mut HeaderFold, workdir: &str) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    match row.role.as_str() {
        "user" => {
            if !row.content.is_empty() {
                kinds.push(EventKind::UserMessage(UserMessage {
                    text: row.content.clone(),
                }));
            }
        }
        "assistant" => {
            if !row.name.is_empty() {
                fold.note_model(&row.name);
            }
            let usage = Usage {
                input: row.input_tokens,
                output: row.output_tokens,
                ..Usage::default()
            };
            fold.note_usage(usage);
            if !row.content.is_empty() {
                kinds.push(EventKind::AssistantMessage(AssistantMessage {
                    text: row.content.clone(),
                    model: if row.name.is_empty() {
                        None
                    } else {
                        Some(row.name.clone())
                    },
                    usage,
                }));
            }
            // Inline reasoning emits a second event after the message (this
            // is a multi-event row the incremental test resumes across).
            if let Some(reasoning) = &row.reasoning
                && !reasoning.is_empty()
            {
                kinds.push(EventKind::Reasoning(Reasoning {
                    text: reasoning.clone(),
                }));
            }
        }
        "tool_call" => {
            let input: Value =
                serde_json::from_str(&row.content).unwrap_or(Value::String(row.content.clone()));
            let call = EventKind::ToolCall(ToolCall {
                tool: ToolRef {
                    name: row.name.clone(),
                    input: input.clone(),
                },
            });
            kinds.push(call);
            if let Some(path) = edit_path(&row.name, &input) {
                fold.note_file(workdir, &path);
                // A file-write part emits a second event after the call
                // (the other multi-event row the incremental test covers).
                kinds.push(EventKind::FileChange(FileChange {
                    path: relativize(workdir, &path),
                    change: if row.name == "Write" {
                        FileChangeKind::Add
                    } else {
                        FileChangeKind::Modify
                    },
                    diff: None,
                }));
            }
        }
        "tool_result" => {
            kinds.push(EventKind::ToolResult(ToolResult {
                result: ToolOutcome {
                    original_bytes: row.content.len() as u64,
                    output: row.content.clone(),
                    is_error: row.is_error,
                    truncated: false,
                },
            }));
        }
        "summary" => {
            kinds.push(EventKind::Compaction(Compaction {
                summary: if row.content.is_empty() {
                    None
                } else {
                    Some(row.content.clone())
                },
            }));
        }
        _ => {
            // Unmapped (file-storage-era) row shape: raw JSON into `system`.
            // Never dropped, never an error.
            kinds.push(EventKind::System(System {
                text: raw.to_string(),
            }));
        }
    }
    kinds
}

/// Largest `message.id` for `session_id` (the rowid cursor space), or `None`
/// when the session holds no rows.
fn max_rowid(conn: &Connection, session_id: &str) -> Result<Option<i64>, CaptureError> {
    conn.query_row(
        "SELECT MAX(id) FROM message WHERE session_id = ?1",
        rusqlite::params![session_id],
        |row| row.get(0),
    )
    .map_err(|e| CaptureError::Sqlite(e.to_string()))
}

fn open_ro(path: &std::path::Path) -> Result<Connection, CaptureError> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| CaptureError::Sqlite(e.to_string()))
}

/// First `cwd` and `version` seen in a file-storage transcript (cheap
/// identity scan).
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

impl Adapter for OpencodeAdapter {
    fn id(&self) -> AgentName {
        AgentName::Opencode
    }

    /// Pinned SQLite-store versions. File-storage versions share this gate:
    /// anything not listed ships unverified.
    const COVERED: &[&str] = &["0.9.0"];

    fn detect(&self, roots: &Roots) -> bool {
        roots.data_dir.join("opencode.db").is_file()
            || roots.data_dir.join("opencode-sessions").is_dir()
    }

    /// No pinned plugin-event story: the covered versions expose no stable
    /// plugin surface to write to, so discovery of the stores (below) is
    /// the only capture path and both directions report nothing.
    fn install_hooks(&self, _roots: &Roots) -> io::Result<Vec<PathBuf>> {
        Ok(vec![])
    }

    /// No pinned plugin-event story (see [`Adapter::install_hooks`]):
    /// nothing to remove, so this also reports nothing.
    fn remove_hooks(&self, _roots: &Roots) -> io::Result<Vec<PathBuf>> {
        Ok(vec![])
    }

    fn discover(&self, roots: &Roots, known: &HashMap<String, Cursor>) -> Vec<Candidate> {
        let mut out = Vec::new();
        // SQLite store: one candidate per session row-set newer than known.
        let db = roots.data_dir.join("opencode.db");
        if db.is_file()
            && let Ok(conn) = open_ro(&db)
            && let Ok(mut stmt) = conn.prepare("SELECT id, cwd, version FROM session ORDER BY id")
            && let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
        {
            for row in rows.flatten() {
                let (id, cwd, version) = row;
                let workdir = if cwd.is_empty() {
                    roots.worktree.clone()
                } else {
                    PathBuf::from(&cwd)
                };
                if !workdir_inside(&roots.worktree, &workdir) {
                    continue;
                }
                let max = max_rowid(&conn, &id).unwrap_or(None).unwrap_or(0).max(0) as u64;
                if let Some(cursor) = known.get(&id)
                    && max <= cursor.offset
                {
                    continue;
                }
                out.push(Candidate {
                    session_key: id,
                    native_path: db.clone(),
                    agent_version: version,
                    workdir,
                });
            }
        }
        // File-storage store: one candidate per session file newer than known.
        let dir = roots.data_dir.join("opencode-sessions");
        if dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&dir)
        {
            let mut files: Vec<PathBuf> = entries
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
        if candidate
            .native_path
            .extension()
            .is_some_and(|x| x == "jsonl")
        {
            return self.read_files(candidate, cursor, fallback_ts);
        }
        self.read_db(candidate, cursor, fallback_ts)
    }
}

impl OpencodeAdapter {
    /// Read from the SQLite store with rowid cursor semantics.
    fn read_db(
        &self,
        candidate: &Candidate,
        cursor: &Cursor,
        fallback_ts: &str,
    ) -> Result<ReadOutput, CaptureError> {
        let conn = open_ro(&candidate.native_path)?;
        let (version, cwd, created_at): (String, String, String) = conn
            .query_row(
                "SELECT version, cwd, created_at FROM session WHERE id = ?1",
                rusqlite::params![candidate.session_key],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
        let workdir = if cwd.is_empty() {
            candidate.workdir.to_string_lossy().into_owned()
        } else {
            cwd
        };
        // Header pass: fold every row so the header always reflects the full
        // session, even on incremental reads.
        let mut all: Vec<(OcRow, String)> = Vec::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT role, name, content, reasoning, input_tokens, output_tokens, is_error, ts \
                     FROM message WHERE session_id = ?1 ORDER BY id",
                )
                .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params![candidate.session_key], row_from_sql)
                .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
            for row in rows {
                all.push(row.map_err(|e| CaptureError::Sqlite(e.to_string()))?);
            }
        }
        let mut fold = HeaderFold::default();
        fold.feed_identity(None, Some(&candidate.session_key));
        for (row, _) in &all {
            fold.feed_ts(&row_ts(&row.ts_raw, fallback_ts));
        }
        // Event pass: now that the fold holds the session identity, map
        // each row to its kinds (workdir known for relativizing).
        let mut kinds: Vec<(String, Vec<EventKind>)> = Vec::with_capacity(all.len());
        for (row, raw) in &all {
            let ts = row_ts(&row.ts_raw, fallback_ts);
            let ks = row_events(row, raw, &mut fold, &workdir);
            kinds.push((ts, ks));
        }
        // New rows are those with `id > cursor.offset`, in rowid order.
        let max = max_rowid(&conn, &candidate.session_key)?
            .unwrap_or(0)
            .max(0) as u64;
        if cursor.offset > max {
            return Err(CaptureError::CursorBeyondEnd(cursor.offset, max));
        }
        let new_ids: Vec<i64> = {
            let mut stmt = conn
                .prepare("SELECT id FROM message WHERE session_id = ?1 AND id > ?2 ORDER BY id")
                .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
            let ceiling = cursor.offset.min(i64::MAX as u64) as i64;
            let rows = stmt
                .query_map(rusqlite::params![candidate.session_key, ceiling], |row| {
                    row.get(0)
                })
                .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
            let mut ids = Vec::new();
            for id in rows {
                ids.push(id.map_err(|e| CaptureError::Sqlite(e.to_string()))?);
            }
            ids
        };
        // Rows come back in the same `ORDER BY id` as `all`, so the new rows
        // are the trailing `new_ids.len()` kinds entries.
        let skip = all.len().saturating_sub(new_ids.len());
        let mut events = Vec::new();
        let mut seq = cursor.next_seq();
        for (ts, ks) in kinds.iter().skip(skip) {
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
        let next = if new_ids.is_empty() {
            // Empty growth: events empty, cursor unchanged.
            *cursor
        } else {
            Cursor {
                offset: new_ids.last().copied().unwrap_or(0).max(0) as u64,
                lines: cursor.lines + new_ids.len() as u64,
                events: cursor.events + events.len() as u64,
            }
        };
        let covered = Self::COVERED.contains(&version.as_str());
        let started_at = fold.started_at.clone().or(if valid_ts(&created_at) {
            Some(created_at)
        } else {
            None
        });
        let header = SessionMeta {
            format: FORMAT_TAG.to_string(),
            id: Ulid::from_str(&candidate.session_key)
                .ok()
                .unwrap_or(Ulid::nil()),
            agent: Agent {
                name: AgentName::Opencode,
                version,
            },
            models: fold.models.clone(),
            title: None,
            started_at: started_at.unwrap_or_else(|| fallback_ts.to_string()),
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

    /// Read from the file-storage JSONL store with byte-offset semantics.
    fn read_files(
        &self,
        candidate: &Candidate,
        cursor: &Cursor,
        fallback_ts: &str,
    ) -> Result<ReadOutput, CaptureError> {
        let bytes = std::fs::read(&candidate.native_path)?;
        let len = bytes.len() as u64;
        if cursor.offset > len {
            return Err(CaptureError::CursorBeyondEnd(cursor.offset, len));
        }
        // Header pass: fold every complete line so the header always reflects
        // the full session, even on incremental reads.
        let all = complete_lines(&bytes, 0);
        let mut parsed: Vec<(String, OcRow, Value)> = Vec::with_capacity(all.len());
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
            parsed.push((text.to_string(), row_from_value(&record), record));
        }
        let mut fold = HeaderFold::default();
        for (raw, row, record) in &parsed {
            let _ = raw;
            fold.feed_identity(
                record.get("version").and_then(Value::as_str),
                record.get("session").and_then(Value::as_str).or(
                    if candidate.session_key.is_empty() {
                        None
                    } else {
                        Some(candidate.session_key.as_str())
                    },
                ),
            );
            fold.feed_ts(&row_ts(&row.ts_raw, fallback_ts));
        }
        let workdir = parsed
            .iter()
            .find_map(|(_, _, record)| {
                record
                    .get("cwd")
                    .and_then(Value::as_str)
                    .filter(|cwd| !cwd.is_empty())
            })
            .map(str::to_string)
            .unwrap_or_else(|| candidate.workdir.to_string_lossy().into_owned());
        // Event pass: now that the fold holds the session identity (workdir
        // known for relativizing), map each record to its kinds.
        let mut kinds: Vec<(String, Vec<EventKind>)> = Vec::with_capacity(parsed.len());
        for (raw, row, _) in &parsed {
            let ts = row_ts(&row.ts_raw, fallback_ts);
            let ks = row_events(row, raw, &mut fold, &workdir);
            kinds.push((ts, ks));
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
        let session_id = fold.session_id.clone();
        let started_at = fold.started_at.clone();
        let header = SessionMeta {
            format: FORMAT_TAG.to_string(),
            id: session_id
                .as_deref()
                .and_then(|s| Ulid::from_str(s).ok())
                .unwrap_or(Ulid::nil()),
            agent: Agent {
                name: AgentName::Opencode,
                version,
            },
            models: fold.models.clone(),
            title: None,
            started_at: started_at.unwrap_or_else(|| fallback_ts.to_string()),
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
