-- Synthesized OpenCode v2 session store (see SYNTHESIZED.txt).
-- Shape follows `packages/core/src/session/sql.ts` at v2.0.29
-- (anomalyco/opencode): `session_v2` one row per session, `project` for
-- the worktree fallback, `session_message` ordered by `seq`,
-- `session_part` keyed by (message_id, ordinal).
CREATE TABLE project(
  id TEXT PRIMARY KEY,
  worktree TEXT NOT NULL,
  vcs TEXT,
  name TEXT,
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL,
  time_initialized INTEGER,
  time_active INTEGER NOT NULL DEFAULT 0,
  sandboxes TEXT NOT NULL DEFAULT '[]',
  commands TEXT
);
CREATE TABLE session_v2(
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES project(id),
  workspace_id TEXT,
  parent_id TEXT,
  fork_session_id TEXT,
  fork_boundary TEXT,
  slug TEXT NOT NULL DEFAULT '',
  directory TEXT NOT NULL DEFAULT '',
  path TEXT,
  title TEXT,
  version TEXT NOT NULL DEFAULT '',
  share_url TEXT,
  summary_additions INTEGER,
  summary_deletions INTEGER,
  summary_files INTEGER,
  summary_diffs TEXT,
  metadata TEXT,
  cost REAL NOT NULL DEFAULT 0,
  tokens_input INTEGER NOT NULL DEFAULT 0,
  tokens_output INTEGER NOT NULL DEFAULT 0,
  tokens_reasoning INTEGER NOT NULL DEFAULT 0,
  tokens_cache_read INTEGER NOT NULL DEFAULT 0,
  tokens_cache_write INTEGER NOT NULL DEFAULT 0,
  revert TEXT,
  permission TEXT,
  agent TEXT,
  model TEXT,
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL,
  time_busy INTEGER,
  time_idle INTEGER,
  time_viewed INTEGER,
  idle_outcome TEXT,
  time_compacting INTEGER,
  time_archived INTEGER,
  time_suspended INTEGER,
  resume_attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE session_message(
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES session_v2(id),
  type TEXT NOT NULL,
  seq INTEGER NOT NULL,
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL,
  data TEXT NOT NULL
);
CREATE TABLE session_part(
  message_id TEXT NOT NULL REFERENCES session_message(id),
  session_id TEXT NOT NULL REFERENCES session_v2(id),
  ordinal INTEGER NOT NULL,
  type TEXT NOT NULL,
  call_id TEXT,
  time_created INTEGER NOT NULL,
  time_updated INTEGER NOT NULL,
  data TEXT NOT NULL,
  PRIMARY KEY (message_id, ordinal)
);
INSERT INTO project(id, worktree, time_created, time_updated)
  VALUES('proj_1', '/repo', 1793793600000, 1793793600000);
INSERT INTO project(id, worktree, time_created, time_updated)
  VALUES('proj_2', '/other', 1793793600000, 1793793600000);
-- The captured session: a user message, one assistant message whose parts
-- cover text + reasoning + a completed tool call (call/result pair) + an
-- unknown future part type, then a completed compaction.
INSERT INTO session_v2(id, project_id, directory, slug, version, time_created, time_updated)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5FAY', 'proj_1', '/repo', 'noble-planet', '9.9.9', 1793793600000, 1793793615000);
-- A child (subtask) session: hidden from upstream session listings.
INSERT INTO session_v2(id, project_id, directory, slug, version, parent_id, time_created, time_updated)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5GAZ', 'proj_1', '/repo', 'child-session', '9.9.9', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 1793793600000, 1793793615000);
-- An archived session: hidden from upstream session listings.
INSERT INTO session_v2(id, project_id, directory, slug, version, time_created, time_updated, time_archived)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5GB1', 'proj_1', '/repo', 'archived-session', '9.9.9', 1793793600000, 1793793615000, 1793793615000);
-- A session in another worktree: filtered by workdir.
INSERT INTO session_v2(id, project_id, directory, slug, version, time_created, time_updated)
  VALUES('01ARZ3NDEKTSV4RRFFQ69G5GB2', 'proj_2', '/other', 'other-tree', '9.9.9', 1793793600000, 1793793615000);
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_user_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'user', 0, 1793793600000, 1793793600000, '{"text":"Help me refactor the auth module.","files":[],"agents":[],"skills":[],"time":{"created":1793793600000}}');
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_asst_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'assistant', 1, 1793793605000, 1793793610000, '{"agent":"build","model":{"id":"claude-sonnet-4-5","providerID":"anthropic"},"content":[{"type":"text","text":"I will start by reading the auth module."},{"type":"reasoning","text":"The auth module has tangled session logic; check src/auth.rs first."},{"type":"tool","id":"call_abc","name":"edit","state":{"status":"completed","input":{"file_path":"/repo/src/auth.rs"},"content":[{"type":"text","text":"Edited /repo/src/auth.rs"}]}}],"tokens":{"input":1200,"output":60,"reasoning":0,"cache":{"read":0,"write":0}},"cost":0.01,"time":{"created":1793793605000}}');
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_comp_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'compaction', 2, 1793793615000, 1793793615000, '{"status":"completed","reason":"auto","summary":"Refactored the auth module.","recent":"","time":{"created":1793793615000}}');
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_synth_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'synthetic', 3, 1793793620000, 1793793620000, '{"text":"Synthetic retry hint.","description":"Retry","time":{"created":1793793620000}}');
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_sys_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'system', 4, 1793793625000, 1793793625000, '{"description":"Notice","text":"Engine restarted.","metadata":{},"time":{"created":1793793625000}}');
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_sw_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'agent-switched', 5, 1793793630000, 1793793630000, '{"agent":"plan","previous":"build","time":{"created":1793793630000}}');
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_idle_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'idle', 6, 1793793635000, 1793793635000, '{"outcome":"completed","time":{"created":1793793635000}}');
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_asst_2', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 'assistant', 7, 1793793640000, 1793793645000, '{"agent":"plan","model":{"id":"claude-sonnet-4-5","providerID":"anthropic"},"content":[{"type":"tool","id":"call_path","name":"edit","state":{"status":"completed","input":{"path":"/repo/src/modern.rs"},"content":[{"type":"text","text":"Edited /repo/src/modern.rs"}]}},{"type":"tool","id":"call_legacy","name":"edit","state":{"status":"completed","input":{"filePath":"/repo/src/legacy.rs"},"content":[{"type":"text","text":"Edited /repo/src/legacy.rs"}]}}],"tokens":{"input":0,"output":0,"reasoning":0,"cache":{"read":0,"write":0}},"cost":0,"time":{"created":1793793640000}}');
INSERT INTO session_part(message_id, session_id, ordinal, type, call_id, time_created, time_updated, data)
  VALUES('msg_asst_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 0, 'text', NULL, 1793793605000, 1793793610000, '{"type":"text","text":"I will start by reading the auth module."}');
INSERT INTO session_part(message_id, session_id, ordinal, type, call_id, time_created, time_updated, data)
  VALUES('msg_asst_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 1, 'reasoning', NULL, 1793793605000, 1793793610000, '{"type":"reasoning","text":"The auth module has tangled session logic; check src/auth.rs first."}');
INSERT INTO session_part(message_id, session_id, ordinal, type, call_id, time_created, time_updated, data)
  VALUES('msg_asst_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 2, 'tool', 'call_abc', 1793793605000, 1793793610000, '{"type":"tool","id":"call_abc","name":"edit","state":{"status":"completed","input":{"file_path":"/repo/src/auth.rs"},"content":[{"type":"text","text":"Edited /repo/src/auth.rs"}]}}');
INSERT INTO session_part(message_id, session_id, ordinal, type, call_id, time_created, time_updated, data)
  VALUES('msg_asst_1', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 3, 'future-part', NULL, 1793793605000, 1793793610000, '{"type":"future-part","weird":true}');
INSERT INTO session_part(message_id, session_id, ordinal, type, call_id, time_created, time_updated, data)
  VALUES('msg_asst_2', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 0, 'tool', 'call_path', 1793793640000, 1793793645000, '{"type":"tool","id":"call_path","name":"edit","state":{"status":"completed","input":{"path":"/repo/src/modern.rs"},"content":[{"type":"text","text":"Edited /repo/src/modern.rs"}]}}');
INSERT INTO session_part(message_id, session_id, ordinal, type, call_id, time_created, time_updated, data)
  VALUES('msg_asst_2', '01ARZ3NDEKTSV4RRFFQ69G5FAY', 1, 'tool', 'call_legacy', 1793793640000, 1793793645000, '{"type":"tool","id":"call_legacy","name":"edit","state":{"status":"completed","input":{"filePath":"/repo/src/legacy.rs"},"content":[{"type":"text","text":"Edited /repo/src/legacy.rs"}]}}');
-- Each filtered session still holds a message, so discovery filtering
-- (not emptiness) is what excludes them.
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_child_1', '01ARZ3NDEKTSV4RRFFQ69G5GAZ', 'user', 0, 1793793600000, 1793793600000, '{"text":"Child prompt, never captured.","files":[],"agents":[],"skills":[],"time":{"created":1793793600000}}');
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_arch_1', '01ARZ3NDEKTSV4RRFFQ69G5GB1', 'user', 0, 1793793600000, 1793793600000, '{"text":"Archived prompt, never captured.","files":[],"agents":[],"skills":[],"time":{"created":1793793600000}}');
INSERT INTO session_message(id, session_id, type, seq, time_created, time_updated, data)
  VALUES('msg_out_1', '01ARZ3NDEKTSV4RRFFQ69G5GB2', 'user', 0, 1793793600000, 1793793600000, '{"text":"Other-tree prompt, never captured.","files":[],"agents":[],"skills":[],"time":{"created":1793793600000}}');
