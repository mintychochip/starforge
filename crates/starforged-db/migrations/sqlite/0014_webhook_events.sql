-- Starforge M2e K1: rewrite stored webhook subscriptions to the spec §10.4
-- event types. Keep in lockstep with ../postgres/0014_webhook_events.sql.
-- The read path de-duplicates, so collapsed duplicates need no cleanup here.

UPDATE webhooks SET events = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(events,
    '"trail.opened"', '"trail"'), '"trail.closed"', '"trail"'), '"change.opened"', '"trail"'),
    '"revision.pushed"', '"trail"'), '"change.merged"', '"trail"'), '"review.submitted"', '"review"'),
    '"status.updated"', '"check"');
