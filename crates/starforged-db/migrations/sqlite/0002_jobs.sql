-- Starforge M0.5: the background jobs queue (forge-basics design §8).
-- Keep in lockstep with ../postgres/0002_jobs.sql.

CREATE TABLE jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'failed')),
    dedupe_key TEXT,
    run_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    last_error TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX jobs_due ON jobs (state, run_at);
-- At most one queued or running job per deduplication key (recurring jobs).
CREATE UNIQUE INDEX jobs_dedupe ON jobs (dedupe_key) WHERE state IN ('queued', 'running');
