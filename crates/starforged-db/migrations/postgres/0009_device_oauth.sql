-- Starforge M1d: OAuth device-flow one-time codes (RFC 8628).
-- Keep in lockstep with ../sqlite/0009_device_oauth.sql.
-- Every integer is BIGINT so it decodes as i64 through sqlx's Any driver.
-- Only the SHA-256 hash of the device code is stored, never the raw code.

CREATE TABLE device_codes (
    device_code_hash TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    user_id BIGINT REFERENCES users (id) ON DELETE CASCADE,
    interval_secs BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    last_poll_at BIGINT,
    created_at BIGINT NOT NULL
);
CREATE INDEX device_codes_user_code ON device_codes (user_code);
CREATE INDEX device_codes_expires ON device_codes (expires_at);
