-- Duplicate protection: re-uploading a file, or Vector retrying a batch, must not store
-- the same event twice.
--
-- fingerprint = sha256 of (tenant, source, original payload). jsonb::text is canonical
-- (key order and whitespace normalized), so the same JSON always gives the same hash.
-- Uniqueness is on (fingerprint, ts): Postgres requires the partition key in unique indexes,
-- and it also means an event that only *looks* the same at a different time is kept.
ALTER TABLE events ADD COLUMN fingerprint bytea;

-- Computed by the database on every insert, so every write path (API, tests, manual SQL)
-- gets the same value and a client can't supply its own.
CREATE FUNCTION events_set_fingerprint() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.fingerprint := sha256(convert_to(jsonb_build_array(NEW.tenant, NEW.source, NEW.raw)::text, 'UTF8'));
    RETURN NEW;
END;
$$;

-- Backfill rows stored before this migration, then remove duplicates already present
-- (keep the first copy) so the unique index can be built.
UPDATE events SET fingerprint = sha256(convert_to(jsonb_build_array(tenant, source, raw)::text, 'UTF8'));
DELETE FROM events a USING events b
WHERE a.fingerprint = b.fingerprint AND a.ts = b.ts AND a.id > b.id;

ALTER TABLE events ALTER COLUMN fingerprint SET NOT NULL;
CREATE UNIQUE INDEX events_fingerprint_ts_key ON events (fingerprint, ts);

CREATE TRIGGER events_fingerprint BEFORE INSERT ON events
FOR EACH ROW EXECUTE FUNCTION events_set_fingerprint();
