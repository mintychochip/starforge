//! OpenCode adapter: `<data_dir>/opencode.db` (SQLite, current schema).
//!
//! Modeled on OpenCode v2.0.29 (tag `v2.0.29`, repo `anomalyco/opencode`):
//! - tables: `packages/core/src/session/sql.ts` — `session_v2` (sessions),
//!   `session_message` (one row per message, ordered by `seq`), and
//!   `session_part` (one row per content part, keyed by `(message_id,
//!   ordinal)`), plus `project` (`packages/core/src/project/sql.ts`) for
//!   the `worktree` fallback.
//! - message payloads: `packages/schema/src/session-message.ts` —
//!   `session_message.data` is the message JSON minus `id`/`type` (the
//!   `type` and `seq` live in dedicated columns); `session_part.data` is
//!   one assistant content part (`text` | `reasoning` | `tool`). The
//!   assistant message carries the step's model and token totals
//!   (`model {id, providerID, variant?}`, `tokens {input, output, reasoning,
//!   cache {read, write}}`); a tool part carries its call `id`, tool `name`,
//!   and a `state` (`streaming` | `running` | `completed` | `error`) with
//!   the input and, when finished, the result content.
//!
//! The workdir is `session_v2.directory`, falling back to the project's
//! `worktree`. Archived sessions (`time_archived IS NOT NULL`) and child
//! sessions (`parent_id IS NOT NULL`) are skipped: upstream treats both as
//! non-user sessions — child sessions do not appear in session listings
//! (anomalyco/opencode#27620, #29175) and the TUI picker needs root
//! sessions only (#34936); archival hides a session from the list.
//! The session key is the session id, and the agent version is
//! `session_v2.version`.
//!
//! Mapping: `user` messages → `user_message`; `assistant` messages → one
//! event per part (`text` → `assistant_message` with the step model and
//! usage, `reasoning` → `reasoning`, `tool` → `tool_call` plus, when the
//! state finished, a `tool_result` immediately after it — pairs ordered by
//! the part's `call_id`/ordinal); `compaction` messages → `compaction`.
//! Every other message or part type (including v1-era part types that
//! survive in `data` such as `step-start`/`step-finish`) falls back to
//! `system { text: <raw JSON> }`: never dropped, never an error.
//!
//! Cursor semantics: `offset` is the largest `session_message.seq` consumed
//! (`seq` starts at 0 upstream — the v1→v2 migration numbers migrated
//! messages from 0), `lines` is messages consumed, `events` is events
//! emitted; resume selects `WHERE session_id = ? AND seq > offset ORDER BY
//! seq`. A fresh [`Cursor::start`] cursor reads from the beginning, which
//! is the only way to include a `seq = 0` first message. A session counts
//! as grown when it holds more messages than `known` has consumed.
//!
//! Reads are read-only: the adapter opens the database with
//! `SQLITE_OPEN_READ_ONLY` and issues `SELECT`s only, never `CREATE`/write.
//! A database whose `session_v2`/`session_message`/`session_part` tables
//! are absent (older or unrelated schema) is reported as not detected
//! instead of panicking.
//!
//! Legacy stores: OpenCode ≤ 1.x kept a real SQLite store with
//! `session`/`message`/`part` tables (same `opencode.db` file) whose
//! `message.data` held v1 message JSON. OpenCode itself migrates those
//! rows into `session_v2`/`session_message`/`session_part` exactly once
//! (`packages/core/src/database/v1-migration.bun.ts`), so after the user
//! runs v2 the v1 history is reachable through the current schema; this
//! adapter does not parse the v1 tables separately. The earlier
//! `opencode-sessions/*.jsonl` file store and the old adapter's
//! `session(id, cwd, version, created_at)` / `message(role, name, ...)`
//! column shapes were never used by any release and have been deleted.
//!
//! Hook story: no plugin-event surface is pinned for the covered versions,
//! so [`Adapter::install_hooks`] and [`Adapter::remove_hooks`] both report
//! `Ok(vec![])` and discovery of the store is the only capture path.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::PathBuf;
use std::str::FromStr;

use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use starforge_format::{
    Agent, AgentName, AssistantMessage, CaptureInfo, CaptureMode, Compaction, Event, EventKind,
    FORMAT_TAG, Reasoning, SessionMeta, System, ToolCall, ToolOutcome, ToolRef, ToolResult, Usage,
    UserMessage,
};
use time::format_description::well_known::Rfc3339;
use ulid::Ulid;

use crate::{Adapter, Candidate, CaptureError, Cursor, ReadOutput, Roots, workdir_inside};

/// OpenCode adapter (unit struct; the [`Adapter`] trait is not object-safe).
pub struct OpencodeAdapter;

fn valid_ts(s: &str) -> bool {
    time::OffsetDateTime::parse(s, &Rfc3339).is_ok()
}

/// Epoch-millis → RFC 3339 (UTC), or `None` outside the representable range.
fn ms_to_rfc3339(ms: i64) -> Option<String> {
    time::OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
}

/// One message's timestamp: native `time_created` when representable,
/// else `fallback_ts`.
fn msg_ts(time_created: i64, fallback_ts: &str) -> String {
    ms_to_rfc3339(time_created).unwrap_or_else(|| fallback_ts.to_string())
}

/// `model` struct (`{id, providerID}`) → OpenCode's `provider/model` string.
fn model_ref(data: &Value) -> String {
    let Some(m) = data.get("model") else {
        return String::new();
    };
    let id = m.get("id").and_then(Value::as_str).unwrap_or("");
    let provider = m.get("providerID").and_then(Value::as_str).unwrap_or("");
    if id.is_empty() {
        String::new()
    } else if provider.is_empty() {
        id.to_string()
    } else {
        format!("{provider}/{id}")
    }
}

/// Step usage from an assistant message's `tokens` (`{input, output,
/// reasoning, cache {read, write}}`).
fn parse_usage(data: &Value) -> Usage {
    let Some(tokens) = data.get("tokens") else {
        return Usage::default();
    };
    let n = |key: &str| tokens.get(key).and_then(Value::as_u64).unwrap_or(0);
    let cache = tokens.get("cache");
    Usage {
        input: n("input"),
        output: n("output"),
        reasoning: n("reasoning"),
        cache_read: cache
            .and_then(|c| c.get("read"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_write: cache
            .and_then(|c| c.get("write"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
    }
}

/// Render a tool-result `content` value (`string | [{type, text} | …]`) as text.
fn content_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(|item| match item.get("text").and_then(Value::as_str) {
                Some(text) => text.to_string(),
                None => item.to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.to_string(),
    }
}

/// `file_path` carried by an `edit`/`write` tool input, if any.
fn edit_path(tool_name: &str, input: &Value) -> Option<String> {
    let lowered = tool_name.to_lowercase();
    if lowered != "edit" && lowered != "write" {
        return None;
    }
    input
        .get("file_path")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Fold one parsed message into the session header accumulator.
#[derive(Default)]
struct HeaderFold {
    models: Vec<String>,
    usage: Usage,
    files_touched: Vec<String>,
}

impl HeaderFold {
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

/// One native message row.
#[derive(Clone)]
struct OcMessage {
    id: String,
    mtype: String,
    seq: i64,
    time_created: i64,
    data: Value,
}

/// One native content part row.
#[derive(Clone)]
struct OcPart {
    ptype: String,
    data: Value,
}

/// One `session_v2` row: (id, directory, version, project_id, parent_id,
/// time_archived).
type SessionRow = (String, String, String, String, Option<String>, Option<i64>);

/// Raw JSON for a message (the system-fallback text).
fn raw_message(msg: &OcMessage) -> String {
    let mut value = msg.data.clone();
    if let Some(obj) = value.as_object_mut() {
        obj.insert("id".to_string(), Value::String(msg.id.clone()));
        obj.insert("type".to_string(), Value::String(msg.mtype.clone()));
    } else {
        value = serde_json::json!({
            "data": value,
            "id": msg.id,
            "type": msg.mtype,
        });
    }
    value.to_string()
}

/// Map one part to events, in ordinal order. Unknown part types fall back
/// to `system { text: <raw JSON> }` so no part is ever dropped.
fn part_events(
    part: &OcPart,
    model: &str,
    usage: Usage,
    fold: &mut HeaderFold,
    workdir: &str,
) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    let ptype = part
        .data
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or(&part.ptype);
    match ptype {
        "text" => {
            if let Some(text) = part.data.get("text").and_then(Value::as_str)
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
        }
        "reasoning" => {
            if let Some(text) = part.data.get("text").and_then(Value::as_str)
                && !text.is_empty()
            {
                kinds.push(EventKind::Reasoning(Reasoning {
                    text: text.to_string(),
                }));
            }
        }
        "tool" => {
            let name = part
                .data
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let state = part.data.get("state");
            let input = state
                .and_then(|s| s.get("input"))
                .cloned()
                .unwrap_or(Value::Null);
            if let Some(path) = edit_path(name, &input) {
                fold.note_file(workdir, &path);
            }
            // The call half of the pair, keyed by the part's `call_id`/id.
            kinds.push(EventKind::ToolCall(ToolCall {
                tool: ToolRef {
                    name: name.to_string(),
                    input,
                },
            }));
            // The result half, only once the state is terminal.
            let status = state
                .and_then(|s| s.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if status == "completed" || status == "error" {
                let output = state
                    .and_then(|s| s.get("content"))
                    .map(content_to_string)
                    .unwrap_or_default();
                let output = if output.is_empty() {
                    state
                        .and_then(|s| s.get("error"))
                        .map(|e| e.to_string())
                        .unwrap_or_default()
                } else {
                    output
                };
                kinds.push(EventKind::ToolResult(ToolResult {
                    result: ToolOutcome {
                        original_bytes: output.len() as u64,
                        output,
                        is_error: status == "error",
                        truncated: false,
                    },
                }));
            }
        }
        _ => {
            // Unknown part type: raw JSON into `system`. Never dropped.
            kinds.push(EventKind::System(System {
                text: part.data.to_string(),
            }));
        }
    }
    kinds
}

/// Map one message (with its parts) to events. Mutates `fold` with header
/// facts (models, usage, files). Unmapped message types fall back to
/// `system { text: <raw JSON> }` so no message is ever dropped.
fn message_events(
    msg: &OcMessage,
    parts: &[OcPart],
    fold: &mut HeaderFold,
    workdir: &str,
) -> Vec<EventKind> {
    let mut kinds = Vec::new();
    match msg.mtype.as_str() {
        "user" => {
            if let Some(text) = msg.data.get("text").and_then(Value::as_str)
                && !text.is_empty()
            {
                kinds.push(EventKind::UserMessage(UserMessage {
                    text: text.to_string(),
                }));
            }
        }
        "assistant" => {
            let model = model_ref(&msg.data);
            fold.note_model(&model);
            let usage = parse_usage(&msg.data);
            fold.note_usage(usage);
            // Fall back to `data.content` when the part rows are absent
            // (e.g. a session projected before `session_part` existed).
            let parts_data: Vec<OcPart>;
            let parts_ref: &[OcPart] = if parts.is_empty() {
                parts_data = msg
                    .data
                    .get("content")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .map(|item| OcPart {
                                ptype: item
                                    .get("type")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_string(),
                                data: item.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                &parts_data
            } else {
                parts
            };
            for part in parts_ref {
                kinds.extend(part_events(part, &model, usage, fold, workdir));
            }
        }
        "compaction" => {
            kinds.push(EventKind::Compaction(Compaction {
                summary: msg
                    .data
                    .get("summary")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }));
        }
        _ => {
            // Unmapped message type (system, synthetic, skill, shell, idle,
            // *-switched, or unknown): raw JSON into `system`.
            // Never dropped, never an error.
            kinds.push(EventKind::System(System {
                text: raw_message(msg),
            }));
        }
    }
    kinds
}

fn open_ro(path: &std::path::Path) -> Result<Connection, CaptureError> {
    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| CaptureError::Sqlite(e.to_string()))
}

/// True when the current `opencode.db` schema tables exist. A database
/// without them is not our store (not detected, never a panic).
fn tables_present(conn: &Connection) -> bool {
    const TABLES: [&str; 3] = ["session_v2", "session_message", "session_part"];
    for table in TABLES {
        let present: Result<i64, _> = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            rusqlite::params![table],
            |row| row.get(0),
        );
        if present.unwrap_or(0) == 0 {
            return false;
        }
    }
    true
}

/// Workdir for one session row: `directory` when non-empty, else the
/// project's `worktree`, else the caller's worktree.
fn resolve_workdir(
    conn: &Connection,
    directory: &str,
    project_id: &str,
    fallback_worktree: &std::path::Path,
) -> PathBuf {
    if !directory.is_empty() {
        return PathBuf::from(directory);
    }
    let worktree: Result<Option<String>, _> = conn.query_row(
        "SELECT worktree FROM project WHERE id = ?1",
        rusqlite::params![project_id],
        |row| row.get(0),
    );
    match worktree {
        Ok(Some(w)) if !w.is_empty() => PathBuf::from(w),
        _ => fallback_worktree.to_path_buf(),
    }
}

/// Messages per session (`(count, max seq)`), `(-1)` when the session
/// holds no messages yet.
fn session_growth(conn: &Connection, session_id: &str) -> Result<(i64, Option<i64>), CaptureError> {
    conn.query_row(
        "SELECT COUNT(*), MAX(seq) FROM session_message WHERE session_id = ?1",
        rusqlite::params![session_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .map_err(|e| CaptureError::Sqlite(e.to_string()))
}

impl Adapter for OpencodeAdapter {
    fn id(&self) -> AgentName {
        AgentName::Opencode
    }

    /// Pinned v2-store version. Anything else is parsed by the same reader
    /// but ships unverified.
    const COVERED: &[&str] = &["2.0.29"];

    fn detect(&self, roots: &Roots) -> bool {
        let db = roots.data_dir.join("opencode.db");
        db.is_file() && open_ro(&db).is_ok_and(|conn| tables_present(&conn))
    }

    /// No pinned plugin-event story: the covered version exposes no stable
    /// plugin surface to write to, so discovery of the store (below) is
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
        let db = roots.data_dir.join("opencode.db");
        let Ok(conn) = open_ro(&db) else {
            return out;
        };
        if !tables_present(&conn) {
            return out;
        }
        let sessions: Vec<SessionRow> = {
            let Ok(mut stmt) = conn.prepare(
                "SELECT id, directory, version, project_id, parent_id, time_archived \
                 FROM session_v2 ORDER BY id",
            ) else {
                return out;
            };
            let Ok(rows) = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            }) else {
                return out;
            };
            rows.flatten().collect()
        };
        for (id, directory, version, project_id, parent_id, time_archived) in sessions {
            // Archived and child sessions are hidden from upstream
            // session listings, so they are not user sessions.
            if time_archived.is_some() || parent_id.is_some() {
                continue;
            }
            let workdir = resolve_workdir(&conn, &directory, &project_id, &roots.worktree);
            if !workdir_inside(&roots.worktree, &workdir) {
                continue;
            }
            if let Some(cursor) = known.get(&id) {
                let (count, _) = session_growth(&conn, &id).unwrap_or((0, None));
                // Grown when the store holds more messages than known.
                if count <= cursor.lines as i64 {
                    continue;
                }
            }
            out.push(Candidate {
                session_key: id,
                native_path: db.clone(),
                agent_version: version,
                workdir,
            });
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
        let conn = open_ro(&candidate.native_path)?;
        let (directory, version, project_id, title, time_created): (
            String,
            String,
            String,
            Option<String>,
            i64,
        ) = conn
            .query_row(
                "SELECT directory, version, project_id, title, time_created \
                 FROM session_v2 WHERE id = ?1",
                rusqlite::params![candidate.session_key],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
        let workdir = resolve_workdir(&conn, &directory, &project_id, &candidate.workdir)
            .to_string_lossy()
            .into_owned();
        // All messages and parts: the header pass folds the whole session,
        // the event pass emits only messages newer than the cursor.
        let mut messages: Vec<OcMessage> = Vec::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT id, type, seq, time_created, data \
                     FROM session_message WHERE session_id = ?1 ORDER BY seq",
                )
                .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params![candidate.session_key], |row| {
                    let raw: String = row.get(4)?;
                    let data: Value = serde_json::from_str(&raw).map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            4,
                            "data".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })?;
                    Ok(OcMessage {
                        id: row.get(0)?,
                        mtype: row.get(1)?,
                        seq: row.get(2)?,
                        time_created: row.get(3)?,
                        data,
                    })
                })
                .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
            for row in rows {
                messages.push(row.map_err(|e| CaptureError::Sqlite(e.to_string()))?);
            }
        }
        let mut parts_by_message: HashMap<String, Vec<OcPart>> = HashMap::new();
        {
            let mut stmt = conn
                .prepare(
                    "SELECT message_id, type, data FROM session_part \
                     WHERE session_id = ?1 ORDER BY message_id, ordinal",
                )
                .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params![candidate.session_key], |row| {
                    let raw: String = row.get(2)?;
                    let data: Value = serde_json::from_str(&raw).map_err(|_| {
                        rusqlite::Error::InvalidColumnType(
                            2,
                            "data".to_string(),
                            rusqlite::types::Type::Text,
                        )
                    })?;
                    Ok((
                        row.get::<_, String>(0)?,
                        OcPart {
                            ptype: row.get(1)?,
                            data,
                        },
                    ))
                })
                .map_err(|e| CaptureError::Sqlite(e.to_string()))?;
            for row in rows {
                let (message_id, part) = row.map_err(|e| CaptureError::Sqlite(e.to_string()))?;
                parts_by_message.entry(message_id).or_default().push(part);
            }
        }
        let mut fold = HeaderFold::default();
        let mut with_ts: Vec<(String, OcMessage, Vec<EventKind>)> =
            Vec::with_capacity(messages.len());
        for msg in messages {
            let ts = msg_ts(msg.time_created, fallback_ts);
            let parts = parts_by_message.remove(&msg.id).unwrap_or_default();
            let kinds = message_events(&msg, &parts, &mut fold, &workdir);
            with_ts.push((ts, msg, kinds));
        }
        // New messages are those with `seq > cursor.offset`; a fresh cursor
        // reads everything (upstream seqs start at 0).
        let fresh = *cursor == Cursor::start();
        let max_seq = with_ts
            .iter()
            .map(|(_, msg, _)| msg.seq)
            .max()
            .unwrap_or(0)
            .max(0) as u64;
        if !fresh && cursor.offset > max_seq {
            return Err(CaptureError::CursorBeyondEnd(cursor.offset, max_seq));
        }
        let mut events = Vec::new();
        let mut seq = cursor.next_seq();
        let mut new_count: u64 = 0;
        let mut new_offset = cursor.offset;
        for (ts, msg, kinds) in &with_ts {
            if !fresh && (msg.seq as u64) <= cursor.offset {
                continue;
            }
            new_count += 1;
            new_offset = msg.seq.max(0) as u64;
            for kind in kinds {
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
        let next = if new_count == 0 {
            // Empty growth: events empty, cursor unchanged.
            *cursor
        } else {
            Cursor {
                offset: new_offset,
                lines: cursor.lines + new_count,
                events: cursor.events + events.len() as u64,
            }
        };
        let covered = Self::COVERED.contains(&version.as_str());
        let started_at = if time_created > 0 {
            msg_ts(time_created, fallback_ts)
        } else {
            fallback_ts.to_string()
        };
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
            title: title.filter(|t| !t.is_empty()),
            started_at,
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
