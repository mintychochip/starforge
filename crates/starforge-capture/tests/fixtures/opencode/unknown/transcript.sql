-- Synthesized OpenCode session store (see SYNTHESIZED.txt).
-- Shape: a `session` row per native session plus one `message` row per
-- record. `message.role` is one of `user` | `assistant` | `tool_call` |
-- `tool_result` | `summary`; `message.name` carries the model (assistant) or
-- the tool name (tool rows); `message.content` carries text, or a
-- JSON-encoded tool-input object for `tool_call` rows. `message.id` is the
-- rowid the adapter cursors over (`WHERE id > offset ORDER BY id`).
CREATE TABLE session(
  id TEXT PRIMARY KEY,
  cwd TEXT NOT NULL,
  version TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE message(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  role TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  content TEXT NOT NULL DEFAULT '',
  reasoning TEXT,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  is_error INTEGER NOT NULL DEFAULT 0,
  ts TEXT NOT NULL
);
INSERT INTO session(id, cwd, version, created_at)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAY', '/repo', '0.0.0-unknown', '2026-11-04T12:00:00Z');
INSERT INTO message(session_id, role, name, content, ts)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAY', 'user', '', 'Help me refactor the auth module.', '2026-11-04T12:00:00Z');
INSERT INTO message(session_id, role, name, content, reasoning, input_tokens, output_tokens, ts)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAY', 'assistant', 'opencode-medium', 'I will start by reading the auth module.', 'The auth module has tangled session logic; check src/auth.rs first.', 1200, 60, '2026-11-04T12:00:05Z');
INSERT INTO message(session_id, role, name, content, ts)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAY', 'tool_call', 'Edit', '{"file_path":"/repo/src/auth.rs"}', '2026-11-04T12:00:09Z');
INSERT INTO message(session_id, role, name, content, is_error, ts)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAY', 'tool_result', 'Edit', 'Edited /repo/src/auth.rs', 0, '2026-11-04T12:00:10Z');
INSERT INTO message(session_id, role, name, content, ts)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAY', 'summary', '', 'Refactored the auth module.', '2026-11-04T12:00:15Z');
