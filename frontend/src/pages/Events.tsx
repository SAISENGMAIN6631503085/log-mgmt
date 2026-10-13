import { FormEvent, useEffect, useState } from "react";
import { api, LogEvent, SOURCES } from "../api";
import { Empty, SeverityBadge } from "../components/Badge";
import { Country } from "../components/Country";
import { Icon } from "../components/Icon";
import { fmtTime, go, humanize, ipKind, RangeKey, RANGES, rangeParams, Route, SOURCE_LABELS } from "../util";

// Filters live in the URL hash (#/events?src_ip=...), so links from the dashboard and
// alerts pages land on a ready-made search, and a search can be bookmarked or shared.
const FILTER_KEYS = ["range", "source", "severity_min", "src_ip", "country", "user", "host", "event_type", "tag", "q"] as const;
type Filters = Partial<Record<(typeof FILTER_KEYS)[number], string>>;

// Tags in plain words. The value sent to the API stays the technical tag.
export const TAG_LABELS: Record<string, string> = {
  auth_failure: "Failed sign-in",
  blocked: "Blocked by firewall",
  edr_detection: "Malware / threat detected",
  quarantined: "File quarantined",
  access_denied: "Access denied",
  root_activity: "Root account used",
  account_lockout: "Account locked out",
  mail_forwarding_rule: "Email forwarding rule",
};


function filtersFrom(params: URLSearchParams): Filters {
  const f: Filters = {};
  for (const k of FILTER_KEYS) {
    const v = params.get(k);
    if (v) f[k] = v;
  }
  return f;
}

type Page = { events: LogEvent[]; next_cursor: string | null };

export function Events({ route, tenant, tenantName }: { route: Route; tenant: string | undefined; tenantName: string }) {
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
  const activeCount = Object.keys(applied).filter((k) => k !== "range").length;
  const rangeLong = RANGES.find((r) => r.key === (applied.range ?? "24h"))!.long;

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Search events</h1>
          <p>Find any event in <strong>{tenantName}</strong>, from all sources. Click a row to see everything about it.</p>
        </div>
      </header>
      <div className="page-body">
        <form className="card filterbar" onSubmit={submit}>
          <label className="field">
            When
            <select value={draft.range ?? "24h"} onChange={set("range")}>
              {RANGES.map((r) => <option key={r.key} value={r.key}>{r.long[0].toUpperCase() + r.long.slice(1)}</option>)}
            </select>
          </label>
          <label className="field">
            Source
            <select value={draft.source ?? ""} onChange={set("source")}>
              <option value="">All sources</option>
              {SOURCES.map((s) => <option key={s} value={s}>{SOURCE_LABELS[s]}</option>)}
            </select>
          </label>
          <label className="field">
            How serious
            <select value={draft.severity_min ?? ""} onChange={set("severity_min")}>
              <option value="">Any</option>
              <option value="4">Medium and above (4+)</option>
              <option value="7">High and above (7+)</option>
              <option value="9">Critical only (9+)</option>
            </select>
          </label>
          <label className="field">
            Kind of event
            <select value={draft.tag ?? ""} onChange={set("tag")}>
              <option value="">Any</option>
              {Object.entries(TAG_LABELS).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </label>
          <label className="field">
            IP address or range
            <input value={draft.src_ip ?? ""} onChange={set("src_ip")} placeholder="203.0.113.50 or 10.0.0.0/8" />
          </label>
          <label className="field">
            User
            <input value={draft.user ?? ""} onChange={set("user")} placeholder="administrator" />
          </label>
          <label className="field">
            Country
            <input value={draft.country ?? ""} onChange={set("country")} placeholder="2 letters, e.g. TH" maxLength={2} />
          </label>
          <label className="field">
            Event name
            <input value={draft.event_type ?? ""} onChange={set("event_type")} placeholder="e.g. logon_failure" />
          </label>
          <label className="field">
            Contains text
            <input value={draft.q ?? ""} onChange={set("q")} placeholder="Any word, e.g. mimikatz" />
          </label>
          <div className="actions">
            <button className="primary" type="submit"><Icon name="search" size={16} />Search</button>
            <button type="button" className="ghost" onClick={() => go("events")}>Reset</button>
          </div>
        </form>

        {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}

        <section className="card">
          <div className="results-head">
            <div>
              <h2>{cursor ? `Showing the newest ${events.length} events` : `${events.length} event${events.length === 1 ? "" : "s"}`}</h2>
              <div className="sub" style={{ color: "var(--text-2)", fontSize: 12.5 }}>
                {rangeLong[0].toUpperCase() + rangeLong.slice(1)}{activeCount ? ` · ${activeCount} filter${activeCount > 1 ? "s" : ""} on` : ""} · times shown in your time zone
              </div>
            </div>
          </div>
          {events.length > 0 && (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th><th>Severity</th><th>Event</th><th>IP address</th><th>User or device</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id} className={`clickable ${selected?.id === e.id ? "selected" : ""}`} onClick={() => setSelected(e)}>
                      <td className="time-cell">
                        {new Date(e["@timestamp"]).toLocaleTimeString()}
                        <span>{new Date(e["@timestamp"]).toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>
                      </td>
                      <td><SeverityBadge severity={e.severity} /></td>
                      <td className="event-cell">
                        <span className="event-name" title={e.event_type ?? undefined}>{e.event_type ? humanize(e.event_type) : "(no event name)"}</span>
                        {/* Second line: where it came from, plus any flags in plain words */}
                        <span>{[SOURCE_LABELS[e.source] ?? e.source, ...e._tags.map((t) => TAG_LABELS[t] ?? t)].join(" · ")}</span>
                      </td>
                      <td className="ip-col">
                        {e.src_ip && (
                          <>
                            <code>{e.src_ip}</code>
                            <span className="cell-sub">{e.src_country ? <Country code={e.src_country} /> : ipKind(e.src_ip)}</span>
                          </>
                        )}
                      </td>
                      <td className="clip">{e.user ?? e.host ?? ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {!loading && events.length === 0 && !error && (
            <Empty icon={<Icon name="filter" />} title="No matching events">Try a longer time range, or remove a filter.</Empty>
          )}
          {loading && events.length === 0 && <div className="skeleton" style={{ height: 240, margin: 16 }} />}
          {cursor && (
            <div className="results-foot">
              <button onClick={() => fetchPage(cursor)} disabled={loading}>{loading ? "Loading…" : "Show 100 older events"}</button>
            </div>
          )}
        </section>
      </div>

      {selected && <EventDrawer event={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

const FIELD_LABELS: Partial<Record<keyof LogEvent, string>> = {
  "@timestamp": "Time", source: "Source", vendor: "Vendor", product: "Product", event_type: "Event",
  event_subtype: "Detail", action: "Action", rule_name: "Rule", rule_id: "Rule ID",
  src_ip: "From IP", src_country: "From country", src_port: "From port", dst_ip: "To IP", dst_port: "To port", protocol: "Protocol",
  url: "URL", http_method: "HTTP method", status_code: "HTTP status", user: "User", host: "Device",
  process: "Program", cloud_account_id: "Account", cloud_region: "Region", cloud_service: "Service",
};

// Fields grouped the way an analyst reads an event; empty fields are hidden.
const SECTIONS: { title: string; fields: (keyof LogEvent)[] }[] = [
  { title: "What happened", fields: ["@timestamp", "source", "vendor", "product", "event_type", "event_subtype", "action", "rule_name", "rule_id"] },
  { title: "Network", fields: ["src_ip", "src_country", "src_port", "dst_ip", "dst_port", "protocol", "url", "http_method", "status_code"] },
  { title: "Who and where", fields: ["user", "host", "process"] },
  { title: "Cloud", fields: ["cloud_account_id", "cloud_region", "cloud_service"] },
];

function EventDrawer({ event, onClose }: { event: LogEvent; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const show = (v: unknown) => v !== null && v !== undefined && v !== "";
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`Event ${event.id}`}>
        <div className="drawer-head">
          <div>
            <div className="title">{event.event_type ?? "Event"}</div>
            <div className="meta">
              <SeverityBadge severity={event.severity} />
              <span>{SOURCE_LABELS[event.source] ?? event.source}</span>·<span>{fmtTime(event["@timestamp"])}</span>·<span className="mono">#{event.id}</span>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><Icon name="x" /></button>
        </div>
        <div className="drawer-body">
          {event._tags.length > 0 && (
            <>
              <div className="section-title">Flags</div>
              <div>{event._tags.map((t) => <span key={t} className="chip" title={t}>{TAG_LABELS[t] ?? t}</span>)}</div>
            </>
          )}
          {SECTIONS.map((s) => {
            const fields = s.fields.filter((f) => show(event[f]));
            if (!fields.length) return null;
            return (
              <div key={s.title}>
                <div className="section-title">{s.title}</div>
                <dl className="kv">
                  {fields.map((f) => (
                    <div key={f} style={{ display: "contents" }}>
                      <dt title={f}>{FIELD_LABELS[f] ?? f}</dt>
                      <dd>{f.endsWith("_ip") ? <code>{String(event[f])}</code>
                        : f === "@timestamp" ? fmtTime(String(event[f]))
                        : f === "source" ? SOURCE_LABELS[event.source] ?? event.source
                        : f === "src_country" ? <Country code={event.src_country} />
                        : String(event[f])}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            );
          })}
          {event.src_ip && (
            <p style={{ margin: "16px 0 0" }}>
              <button className="sm" onClick={() => go("events", { range: "7d", src_ip: event.src_ip! })}>
                <Icon name="search" size={14} />All events from {event.src_ip}
              </button>
            </p>
          )}
          <div className="section-title">Original log, exactly as received</div>
          <pre className="raw">{JSON.stringify(event.raw, null, 2)}</pre>
        </div>
      </aside>
    </>
  );
}
