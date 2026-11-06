-- M5a: index backing the per-account login rate limit (count of
-- `auth.login_failed` rows by `login:<normalized name>` in the last hour)
-- and the audit log filters.
CREATE INDEX IF NOT EXISTS audit_log_action_target_created_at_idx
    ON audit_log (action, target, created_at);
