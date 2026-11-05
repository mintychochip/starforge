-- Starforge M2e K3: per-attempt delivery-log columns.
-- Keep in lockstep with ../sqlite/0015_webhook_delivery_log.sql.
-- All nullable (or NOT NULL with a default) so existing rows survive.

ALTER TABLE webhook_deliveries ADD COLUMN delivery_id TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN attempt INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN action TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN request_headers TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN response_headers TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN response_body TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN duration_ms INTEGER;
ALTER TABLE webhook_deliveries ADD COLUMN redelivery INTEGER NOT NULL DEFAULT 0;
