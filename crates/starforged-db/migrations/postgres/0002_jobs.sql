-- Starforge M0.5: the background jobs queue (forge-basics design §8).
-- Keep in lockstep with ../sqlite/0002_jobs.sql.

CREATE TABLE jobs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'done', 'failed')),
    dedupe_key TEXT,
    run_at BIGINT NOT NULL,
    attempts BIGINT NOT NULL DEFAULT 0,
    locked_until BIGINT,
    last_error TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
CREATE INDEX jobs_due ON jobs (state, run_at);
-- At most one queued or running job per deduplication key (recurring jobs).
CREATE UNIQUE INDEX jobs_dedupe ON jobs (dedupe_key) WHERE state IN ('queued', 'running');
