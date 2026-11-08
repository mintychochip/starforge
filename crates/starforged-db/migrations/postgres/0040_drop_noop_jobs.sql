-- Starforge: delete queued rows of the two removed no-op job kinds.
-- Keep in lockstep with ../sqlite/0040_drop_noop_jobs.sql.
--
-- `resolve_commit_links` and `session_webhook_outbox` were no-op markers:
-- their workers did nothing. Leftover queued or running rows of those
-- kinds would run as unreadable payloads, so the migration deletes them.

DELETE FROM jobs WHERE kind IN ('resolve_commit_links', 'session_webhook_outbox');
