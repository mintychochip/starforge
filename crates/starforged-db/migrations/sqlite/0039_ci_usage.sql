-- Starforge M6: CI usage metering and CI supplier links.
-- Keep in lockstep with ../postgres/0039_ci_usage.sql.
--
-- `ci_jobs.claimed_at` is when the current attempt was claimed (every claim
-- sets it); native usage is metered per attempt from it.
-- `ci_usage` holds one row per ended attempt of a job run by a native
-- (Starforge-registered) runner: the attempt's runner wall-clock seconds.
-- `(job_id, attempt)` is unique, so every transition that ends an attempt
-- may record it and only the first write counts. Rows outlive their job
-- (`job_id` is set to NULL when the job row goes) so a period's usage stays.
-- `ci_supplier_links` connects a repository to an external CI supplier
-- whose usage Starforge reads from the supplier's own API; `external_ref` is
-- the supplier's name for the repository ("owner/name" for Depot).

ALTER TABLE ci_jobs ADD COLUMN claimed_at INTEGER;

CREATE TABLE ci_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    job_id INTEGER REFERENCES ci_jobs (id) ON DELETE SET NULL,
    attempt INTEGER NOT NULL,
    runner_id INTEGER REFERENCES runners (id) ON DELETE SET NULL,
    user_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
    started_at INTEGER NOT NULL,
    ended_at INTEGER NOT NULL,
    seconds INTEGER NOT NULL CHECK (seconds >= 0),
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX ci_usage_job_attempt ON ci_usage (job_id, attempt);
CREATE INDEX ci_usage_repo_ended ON ci_usage (repo_id, ended_at);

CREATE TABLE ci_supplier_links (
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    supplier TEXT NOT NULL CHECK (supplier IN ('depot')),
    external_ref TEXT NOT NULL,
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (repo_id, supplier)
);
