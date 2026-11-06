-- Starforge M3a A1/A2: orgs, org membership, teams, team membership, team repos.
-- Keep in lockstep with ../sqlite/0021_orgs_teams.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.

CREATE TABLE orgs (
    id BIGINT PRIMARY KEY REFERENCES owners (id) ON DELETE CASCADE,
    display_name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    base_permission TEXT NOT NULL DEFAULT 'none' CHECK (base_permission IN ('none', 'read', 'write')),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE org_members (
    org_id BIGINT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'member')),
    created_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX org_members_user ON org_members (user_id);

CREATE TABLE teams (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id BIGINT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    lower_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    permission TEXT NOT NULL CHECK (permission IN ('read', 'triage', 'write', 'maintain', 'admin')),
    all_repos BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE (org_id, lower_name)
);
CREATE INDEX teams_org ON teams (org_id);

CREATE TABLE team_members (
    team_id BIGINT NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (team_id, user_id)
);
CREATE INDEX team_members_user ON team_members (user_id);

CREATE TABLE team_repos (
    team_id BIGINT NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    repo_id BIGINT NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (team_id, repo_id)
);
CREATE INDEX team_repos_repo ON team_repos (repo_id);
