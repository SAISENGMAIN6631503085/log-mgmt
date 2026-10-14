-- Events (logs) now live only in ClickHouse (see app/ch_schema.py): a column store fits data that
-- is huge, written once and summarized all the time. Postgres keeps what is small and changes:
-- users, api_keys, alerts, rule_settings, login_failures.
-- Dropping the partitioned parent drops every daily partition, its indexes and its trigger.
DROP TABLE IF EXISTS events;
DROP FUNCTION IF EXISTS ensure_event_partition(date);
DROP FUNCTION IF EXISTS events_set_fingerprint();
