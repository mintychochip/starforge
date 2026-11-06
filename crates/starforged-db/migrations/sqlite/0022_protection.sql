-- Starforge M3b: branch protection on gate rules.
-- Keep in lockstep with ../postgres/0022_protection.sql.
--
-- `block_direct_push` means changes must go through a Trail; the per-rule
-- allow-list bypasses only that block. `block_force_push` and
-- `block_deletion` have no bypass. `gate_rule_push_allowlist` holds exactly
-- one of `user_id`/`team_id` per row (team entries are validated in core to
-- org-owned repositories for teams of that org).

ALTER TABLE gate_rules ADD COLUMN block_direct_push INTEGER NOT NULL DEFAULT 0;
ALTER TABLE gate_rules ADD COLUMN block_force_push INTEGER NOT NULL DEFAULT 0;
ALTER TABLE gate_rules ADD COLUMN block_deletion INTEGER NOT NULL DEFAULT 0;

CREATE TABLE gate_rule_push_allowlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES gate_rules (id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users (id) ON DELETE CASCADE,
    team_id INTEGER REFERENCES teams (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
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
