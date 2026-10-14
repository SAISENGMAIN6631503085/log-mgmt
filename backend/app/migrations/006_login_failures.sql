-- Failed sign-ins, to slow down password guessing against our own login page.
-- Counted per typed username (whether or not that account exists, so a lockout never reveals
-- which usernames are real) and per client address. Rows older than a day are deleted by the
-- hourly retention job.
CREATE TABLE login_failures (
    id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username  text NOT NULL,                 -- lowercased, as typed
    ip        text NOT NULL,                 -- client address (text: test clients aren't IPs)
    ts        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_failures_user_idx ON login_failures (username, ts DESC);
CREATE INDEX login_failures_ip_idx ON login_failures (ip, ts DESC);
