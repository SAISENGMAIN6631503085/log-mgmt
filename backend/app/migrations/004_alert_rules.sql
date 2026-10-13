-- More alert rules, each tunable per tenant.
--
-- Rules can group by IP (brute force, firewall scan) or by host (malware), so alerts get a
-- text group_key used for de-duplication. src_ip is still filled for IP-based rules, so the
-- API and webhook payloads stay the same.
ALTER TABLE alerts ADD COLUMN group_key text;
UPDATE alerts SET group_key = host(src_ip) WHERE group_key IS NULL AND src_ip IS NOT NULL;
CREATE INDEX alerts_group_idx ON alerts (tenant, rule_id, group_key, window_end DESC);

-- Per-tenant overrides of the defaults in app/alerting.py. No row = rule on, default threshold.
-- Only enabled + threshold are tunable: the window is part of each rule's SQL (a window
-- function's frame size can't differ per row), and it's shown in the UI.
CREATE TABLE rule_settings (
    tenant      text    NOT NULL,
    rule_id     text    NOT NULL,
    enabled     boolean NOT NULL DEFAULT true,
    threshold   integer NOT NULL CHECK (threshold BETWEEN 1 AND 10000),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, rule_id)
);
