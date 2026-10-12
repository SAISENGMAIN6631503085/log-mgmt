-- The alert worker looks for failed logins that *arrived* recently (ingested_at), whatever
-- their event time, so late or uploaded logs are still checked. This index keeps that fast.
CREATE INDEX events_ingested_at_idx ON events (ingested_at);
