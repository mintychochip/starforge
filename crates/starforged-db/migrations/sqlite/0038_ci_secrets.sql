-- Starforge M6c C3: sealed CI secrets and per-job secret resolution.
-- Keep in lockstep with ../postgres/0038_ci_secrets.sql.
--
-- `ci_secrets.sealed_value` is XChaCha20-Poly1305 ciphertext (`c1:` +
-- base64(nonce‖ciphertext)) under the HKDF `ci-secrets-v1` key derived from
-- `security.secret_key`; the plaintext never reaches the database, the job
-- spec (names only), logs, or the audit trail. `ci_job_secrets` records
-- which secrets a job resolved so the server can decrypt them in memory for
-- dynamic session redaction; the values themselves are not stored here.
-- `ci_artifact_tokens` holds the SHA-256 of outstanding one-time artifact
-- upload tokens: authorize inserts the hash, the first successful upload
-- marks the row used, and replays are refused.

CREATE TABLE ci_secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repos (id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    sealed_value TEXT NOT NULL,
    redact_in_sessions INTEGER NOT NULL DEFAULT 1,
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (repo_id, name)
);
CREATE INDEX ci_secrets_repo ON ci_secrets (repo_id);

CREATE TABLE ci_job_secrets (
    job_id INTEGER NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    secret_id INTEGER NOT NULL REFERENCES ci_secrets (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (job_id, secret_id)
);
CREATE INDEX ci_job_secrets_secret ON ci_job_secrets (secret_id);

CREATE TABLE ci_artifact_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL,
    job_id INTEGER NOT NULL REFERENCES ci_jobs (id) ON DELETE CASCADE,
    artifact_name TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    sha256 TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX ci_artifact_tokens_hash ON ci_artifact_tokens (token_hash);
CREATE INDEX ci_artifact_tokens_job ON ci_artifact_tokens (job_id);
