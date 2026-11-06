-- Starforge M3b: branch protection on gate rules.
-- Keep in lockstep with ../sqlite/0022_protection.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
--
-- `block_direct_push` means changes must go through a Trail; the per-rule
-- allow-list bypasses only that block. `block_force_push` and
-- `block_deletion` have no bypass. `gate_rule_push_allowlist` holds exactly
-- one of `user_id`/`team_id` per row (team entries are validated in core to
-- org-owned repositories for teams of that org).

ALTER TABLE gate_rules ADD COLUMN block_direct_push BIGINT NOT NULL DEFAULT 0;
ALTER TABLE gate_rules ADD COLUMN block_force_push BIGINT NOT NULL DEFAULT 0;
ALTER TABLE gate_rules ADD COLUMN block_deletion BIGINT NOT NULL DEFAULT 0;

CREATE TABLE gate_rule_push_allowlist (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id BIGINT NOT NULL REFERENCES gate_rules (id) ON DELETE CASCADE,
    user_id BIGINT REFERENCES users (id) ON DELETE CASCADE,
    team_id BIGINT REFERENCES teams (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    CHECK (
        (user_id IS NOT NULL AND team_id IS NULL)
        OR (user_id IS NULL AND team_id IS NOT NULL)
    )
);
CREATE INDEX gate_rule_push_allowlist_rule ON gate_rule_push_allowlist (rule_id);
CREATE UNIQUE INDEX gate_rule_push_allowlist_rule_user
    ON gate_rule_push_allowlist (rule_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX gate_rule_push_allowlist_rule_team
    ON gate_rule_push_allowlist (rule_id, team_id) WHERE team_id IS NOT NULL;
