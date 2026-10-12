import { FormEvent, useEffect, useState } from "react";
import { api, LogEvent, SOURCES } from "../api";
import { SeverityBadge } from "../components/Badge";
import { fmtTime, go, RangeKey, RANGES, rangeParams, Route } from "../util";

// Filters live in the URL hash (#/events?src_ip=...), so links from the dashboard and
// alerts pages land on a ready-made search, and a search can be bookmarked or shared.
const FILTER_KEYS = ["range", "source", "severity_min", "src_ip", "user", "host", "event_type", "tag", "q"] as const;
type Filters = Partial<Record<(typeof FILTER_KEYS)[number], string>>;

function filtersFrom(params: URLSearchParams): Filters {
  const f: Filters = {};
  for (const k of FILTER_KEYS) {
    const v = params.get(k);
    if (v) f[k] = v;
  }
  return f;
}

type Page = { events: LogEvent[]; next_cursor: string | null };

export function Events({ route, tenant }: { route: Route; tenant: string | undefined }) {
  const applied = filtersFrom(route.params);
  const appliedKey = route.params.toString();
  const [draft, setDraft] = useState<Filters>(applied);
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<LogEvent | null>(null);

  function fetchPage(after: string | null) {
    const { range = "24h", ...rest } = applied;
    setLoading(true);
    setError(null);
    return api<Page>("/api/events", {
      params: { ...rangeParams(range as RangeKey), ...rest, tenant, cursor: after ?? undefined, limit: 100 },
    })
      .then((p) => {
        setEvents((prev) => (after ? [...prev, ...p.events] : p.events));
        setCursor(p.next_cursor);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }

  // New search whenever the URL filters or the tenant change.
  useEffect(() => {
    setDraft(applied);
    setSelected(null);
    fetchPage(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appliedKey, tenant]);

  function submit(e: FormEvent) {
    e.preventDefault();
    const clean = Object.fromEntries(Object.entries(draft).filter(([, v]) => v)) as Record<string, string>;
    go("events", clean); // updating the URL triggers the search
  }

  const set = (k: keyof Filters) => (e: { target: { value: string } }) => setDraft({ ...draft, [k]: e.target.value });

  return (
    <>
      <h1>Search events</h1>
      <form className="filters" onSubmit={submit}>
        <label>
          Time range
          <select value={draft.range ?? "24h"} onChange={set("range")}>
            {RANGES.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
          </select>
        </label>
        <label>
          Source
          <select value={draft.source ?? ""} onChange={set("source")}>
            <option value="">All</option>
            {SOURCES.map((s) => <option key={s}>{s}</option>)}
          </select>
        </label>
        <label>
          Min severity
          <select value={draft.severity_min ?? ""} onChange={set("severity_min")}>
            <option value="">Any</option>
            {[3, 5, 7, 9].map((n) => <option key={n} value={n}>{n}+</option>)}
          </select>
        </label>
        <label>
          Tag
          <select value={draft.tag ?? ""} onChange={set("tag")}>
            <option value="">Any</option>
            {["auth_failure", "blocked", "edr_detection", "quarantined", "access_denied", "root_activity",
              "account_lockout", "mail_forwarding_rule"].map((t) => <option key={t}>{t}</option>)}
          </select>
        </label>
        <label>
          Source IP / CIDR
          <input value={draft.src_ip ?? ""} onChange={set("src_ip")} placeholder="10.0.0.0/8" size={14} />
        </label>
        <label>
          User
          <input value={draft.user ?? ""} onChange={set("user")} size={12} />
        </label>
        <label>
          Event type
          <input value={draft.event_type ?? ""} onChange={set("event_type")} size={12} />
        </label>
        <label>
          Text
          <input value={draft.q ?? ""} onChange={set("q")} placeholder="mimikatz" size={14} />
        </label>
        <button className="primary" type="submit">Search</button>
        <button type="button" onClick={() => go("events")}>Clear</button>
      </form>

      {error && <p className="error" role="alert">{error}</p>}

      <section className="card">
        <div className="card-head">
          <h2>{events.length} event{events.length === 1 ? "" : "s"}{cursor ? "+" : ""}</h2>
          <span className="muted">Times shown in your local time zone</span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th><th>Source</th><th>Severity</th><th>Action</th><th>Event type</th>
                <th>Source IP</th><th>User</th><th>Host</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} className={`clickable ${selected?.id === e.id ? "selected" : ""}`}
                    onClick={() => setSelected(selected?.id === e.id ? null : e)}>
                  <td>{fmtTime(e["@timestamp"])}</td>
                  <td>{e.source}</td>
                  <td><SeverityBadge severity={e.severity} /></td>
                  <td>{e.action ?? ""}</td>
                  <td>{e.event_type ?? ""}</td>
                  <td>{e.src_ip ? <code>{e.src_ip}</code> : ""}</td>
                  <td>{e.user ?? ""}</td>
                  <td>{e.host ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!loading && events.length === 0 && !error && <p className="muted">No events match these filters.</p>}
        {loading && <p className="muted">Loading…</p>}
        {cursor && !loading && (
          <p><button onClick={() => fetchPage(cursor)}>Load more</button></p>
        )}
      </section>

      {selected && <EventDetail event={selected} />}
    </>
  );
}

function EventDetail({ event }: { event: LogEvent }) {
  // Show every non-empty normalized field (time and identity first), then the original
  // payload exactly as received.
  const first = ["@timestamp", "source", "vendor", "product", "event_type", "severity", "action", "user"];
  const order = (k: string) => (first.includes(k) ? first.indexOf(k) : first.length);
  const fields = Object.entries(event)
    .filter(([k, v]) => k !== "raw" && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0))
    .sort(([a], [b]) => order(a) - order(b));
  return (
    <section className="card detail">
      <div className="card-head"><h2>Event {event.id}</h2></div>
      <dl className="kv">
        {fields.map(([k, v]) => (
          <div key={k} style={{ display: "contents" }}>
            <dt>{k}</dt>
            <dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd>
          </div>
        ))}
      </dl>
      <h2 style={{ marginBottom: 8 }}>Original log (raw)</h2>
      <pre className="raw">{JSON.stringify(event.raw, null, 2)}</pre>
    </section>
  );
}
