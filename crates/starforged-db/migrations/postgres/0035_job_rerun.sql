-- Starforge: rerun requests for deduplicated jobs (the queue lost-update fix).
-- Keep in lockstep with ../sqlite/0035_job_rerun.sql.
-- rerun_at: a request for this job arrived while it was running, so run it again at this time after it finishes.
ALTER TABLE jobs ADD COLUMN rerun_at BIGINT;
