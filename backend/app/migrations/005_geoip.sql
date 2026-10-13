-- Country of src_ip (two-letter ISO code), looked up at ingest from the DB-IP database
-- (app/geoip.py). NULL for private/reserved IPs, events without an IP, and older rows.
-- Stored, not computed at query time, so "top countries" and the country filter are plain SQL.
ALTER TABLE events ADD COLUMN src_country text;
