import { useEffect, useState } from "react";
import { api, SOURCES, Stats } from "../api";
import { Empty } from "../components/Badge";
import { ChartCard } from "../components/ChartCard";
import { Country } from "../components/Country";
import { Delta, Donut, DonutSlice, EventsOverTime } from "../components/Charts";
import { Icon, IconName } from "../components/Icon";
import { Segmented } from "../components/Segmented";
import { fitToOptions, fmtNum, go, humanize, ipKind, RangeKey, rangeParams, RANGES, sourceLabel, useTokens } from "../util";

/** Every tile has the same three rows: label + icon, the number, one line of context. */
function Kpi({ icon, label, value, footer, onClick, attention }: {
  icon: IconName; label: string; value: number; footer: React.ReactNode; onClick: () => void; attention?: boolean;
}) {
  return (
    <button className={`kpi ${attention ? "attention" : ""}`} onClick={onClick}>
      <span className="kpi-top"><span className="kpi-icon"><Icon name={icon} size={15} /></span>{label}</span>
      <span className="kpi-value">{fmtNum(value)}</span>
      {footer}
    </button>
  );
}

/** The one-sentence takeaway shown above a chart, so nobody has to decode the chart to get the point. */
function Insight({ children }: { children: React.ReactNode }) {
  return <p className="insight">{children}</p>;
}

/** "erin@contoso.com" -> erin + contoso.com; "demo\eve" (Windows DOMAIN\user) -> eve + demo; "alice" -> alice. */
function splitUser(user: string): { name: string; domain?: string } {
  const at = user.indexOf("@");
  if (at > 0) return { name: user.slice(0, at), domain: user.slice(at + 1) };
  const slash = user.lastIndexOf("\\");
  if (slash > 0) return { name: user.slice(slash + 1), domain: user.slice(0, slash) };
  return { name: user };
}

type RankRow = { key: string; n: number; failed?: number; label?: React.ReactNode; sub?: React.ReactNode };

/** A ranked "top N" list. Each row: rank, a readable name with one line of context under it, a thin
 *  bar for its share of all events, the count with its %, and failed sign-ins as a badge only when
 *  there are any (so red only appears where something actually failed). */
function RankTable({ title, subtitle, head, rows, total, showFailed, onRow, emptyText }: {
  title: string; subtitle: string; head: string; rows: RankRow[]; total: number; showFailed?: boolean;
  onRow: (key: string) => void; emptyText?: string;
}) {
  const max = Math.max(1, ...rows.map((r) => r.n));
  return (
    <section className="card">
      <div className="card-head"><div><h2>{title}</h2><div className="sub">{subtitle}</div></div></div>
      {rows.length === 0 ? <Empty icon={<Icon name="inbox" />} title="No data">{emptyText ?? "Nothing in this time range."}</Empty> : (
        <div className="card-body flush table-wrap">
          <table className="rank-table">
            <thead>
              <tr>
                <th className="rank">#</th><th>{head}</th>
                <th className="num">Events</th>
                {showFailed && <th className="num"><span className="long">Failed sign-ins</span><span className="short">Failed</span></th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={r.key} className="clickable" onClick={() => onRow(r.key)} title="See these events">
                  <td className="rank">{i + 1}</td>
                  <td className="rank-main">
                    <div className="rank-name">{r.label ?? r.key}</div>
                    {r.sub && <div className="rank-sub">{r.sub}</div>}
                    <div className="rank-bar" aria-hidden="true"><span style={{ width: `${(r.n / max) * 100}%` }} /></div>
                  </td>
                  <td className="num">
                    <div className="rank-count">{fmtNum(r.n)}</div>
                    <div className="rank-share">{total ? `${pct(r.n, total) || "<1"}%` : ""}</div>
                  </td>
                  {showFailed && (
                    <td className="num">
                      {r.failed ? <span className="fail-badge">{fmtNum(r.failed)}</span> : <span className="none">–</span>}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

// Colours: red only where it means something. Critical/high/medium are one red ramp (strongest =
// most serious, validated as an ordered ramp); routine "low" is neutral grey, like the rest of the UI.
const SEVERITY_ROWS = [
  { key: "critical", label: "Critical (9–10)", min: "9", color: "--sev-1" },
  { key: "high", label: "High (7–8)", min: "7", color: "--sev-2" },
  { key: "medium", label: "Medium (4–6)", min: "4", color: "--sev-3" },
  { key: "low", label: "Low (0–3)", min: "", color: "--neutral" },
  { key: "unknown", label: "Not rated", min: "", color: "--sev-none" },
] as const;

// Sources: the biggest four keep their own slice, the rest become "Other" (neutral grey), so the
// donut never has more than 5 slices. Shades of teal by share (strongest = biggest); the legend names each one.
const INK = ["--ink-1", "--ink-2", "--ink-3", "--ink-4", "--ink-5"] as const;
const OTHER = "__other";

const pct = (part: number, whole: number) => (whole ? Math.round((part / whole) * 100) : 0);

export function Dashboard({ tenant, tenantName }: { tenant: string | undefined; tenantName: string }) {
  const [range, setRange] = useState<RangeKey>("24h");
  const [source, setSource] = useState("");  // "" = all sources
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const t = useTokens();

  useEffect(() => {
    let cancelled = false;
    setError(null);
    api<Stats>("/api/stats", { params: { ...rangeParams(range), tenant, source: source || undefined } })
      .then((s) => !cancelled && setStats(s))
      .catch((e) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [range, tenant, source]);

  // Links into the search page carry the same time range and source filter.
  const search = (params: Record<string, string>) => go("events", { range, ...(source ? { source } : {}), ...params });
  const rangeLong = RANGES.find((r) => r.key === range)!.long;

  let body = null;
  if (stats) {
    const total = stats.totals.events;
    const unit = stats.bucket_seconds >= 86400 ? "day" : stats.bucket_seconds >= 3600 ? "hour" : "15 minutes";
    const peak = stats.timeline.reduce((a, b) => (b.n > a.n ? b : a), stats.timeline[0]);
    const peakWhen = peak && new Date(peak.t).toLocaleString(undefined, unit === "day"
      ? { weekday: "long", month: "short", day: "numeric" }
      : { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
    const topSource = stats.by_source[0];
    const sevCount = (k: string) => stats.by_severity.find((r) => r.key === k)?.n ?? 0;
    const serious = sevCount("critical") + sevCount("high");
    const sources = stats.by_source.map((r) => ({ key: r.key, label: sourceLabel(r.key), n: r.n }));
    const top = sources.length > 5 ? sources.slice(0, 4) : sources;
    const rest = sources.slice(top.length).reduce((sum, r) => sum + r.n, 0);
    const sourceSlices: DonutSlice[] = [
      ...top.map((r, i) => ({ ...r, color: t[INK[i]] })),
      ...(rest > 0 ? [{ key: OTHER, label: `Other (${sources.length - top.length} sources)`, n: rest, color: t["--neutral"], clickable: false }] : []),
    ];
    const severities = SEVERITY_ROWS
      .filter((r) => r.key !== "unknown" || sevCount("unknown") > 0)
      .map((r) => ({ key: r.key, label: r.label, n: sevCount(r.key) }));
    const severitySlices: DonutSlice[] = SEVERITY_ROWS
      .filter((r) => r.key !== "unknown" || sevCount("unknown") > 0)
      .map((r) => ({ key: r.key, label: r.label, n: sevCount(r.key), color: t[r.color], clickable: !!r.min }));

    body = (
      <>
        {total === 0 && (
          <div className="note">
            <Icon name="inbox" size={16} />
            <span style={{ flex: 1 }}>No logs in the {rangeLong}{source ? ` from ${sourceLabel(source)}` : ""} yet.</span>
            <button className="sm" onClick={() => go("add")}><Icon name="upload" size={14} />Add logs</button>
          </div>
        )}
        <div className="kpis">
          <Kpi icon="activity" label="Total events" value={total} onClick={() => search({})}
               footer={<Delta current={total} previous={stats.previous.events} period={range} />} />
          <Kpi icon="lock" label="Failed sign-ins" value={stats.totals.auth_failures} onClick={() => search({ tag: "auth_failure" })}
               footer={<Delta current={stats.totals.auth_failures} previous={stats.previous.auth_failures} period={range} />} />
          <Kpi icon="flame" label="Serious events" value={stats.totals.high_severity} onClick={() => search({ severity_min: "7" })}
               footer={<Delta current={stats.totals.high_severity} previous={stats.previous.high_severity} period={range} />} />
          <Kpi icon="bell" label="Open alerts" value={stats.totals.open_alerts} onClick={() => go("alerts")}
               attention={stats.totals.open_alerts > 0}
               footer={<span className="kpi-sub">{stats.totals.open_alerts > 0 ? "Possible attacks to review" : "Nothing to review"}</span>} />
        </div>

        <ChartCard title="Events over time" subtitle={`Number of events per ${unit}. Hover a bar for details.`}
                   rows={stats.timeline} empty={total === 0}
                   columns={[{ key: "t", label: "Time", format: (v) => new Date(String(v)).toLocaleString() },
                             { key: "n", label: "Events", num: true }, { key: "auth_failures", label: "Failed sign-ins", num: true }]}>
          {peak && peak.n > 0 && (
            <Insight>Busiest {unit}: <strong>{peakWhen}</strong>, with <strong>{fmtNum(peak.n)}</strong> events ({pct(peak.n, total)}% of the total).</Insight>
          )}
          <EventsOverTime data={stats.timeline} bucketSeconds={stats.bucket_seconds} t={t} />
        </ChartCard>

        <div className="grid-2">
          <ChartCard title="Where events come from" subtitle="Share of all events. Click a slice or a row to see that source's events"
                     rows={sources} empty={sources.length === 0}
                     columns={[{ key: "label", label: "Source" }, { key: "n", label: "Events", num: true }]}>
            {topSource && (
              <Insight><strong>{sourceLabel(topSource.key)}</strong> sends the most: {fmtNum(topSource.n)} of {fmtNum(total)} events ({pct(topSource.n, total)}%).</Insight>
            )}
            <Donut slices={sourceSlices} t={t} centerLabel="events" onClick={(source) => search({ source })} />
          </ChartCard>

          <ChartCard title="How serious are they?" subtitle="Severity from 0 (routine) to 10 (act now). Click a slice or a row to see those events."
                     rows={severities} empty={total === 0}
                     columns={[{ key: "label", label: "Severity" }, { key: "n", label: "Events", num: true }]}>
            <Insight>
              {serious > 0
                ? <><strong>{fmtNum(serious)}</strong> events ({pct(serious, total)}%) are high or critical and worth a look.</>
                : <>No high or critical events in the {rangeLong}.</>}
            </Insight>
            <Donut slices={severitySlices} t={t} centerLabel="events" onClick={(key) => {
              const min = SEVERITY_ROWS.find((r) => r.key === key)?.min;
              if (min) search({ severity_min: min });
            }} />
            <div className="card-foot">
              <button className="sm" onClick={() => search({ severity_min: "7" })}>
                <Icon name="search" size={14} />See high and critical events
              </button>
            </div>
          </ChartCard>
        </div>

        <div className="grid-2">
          <RankTable title="Busiest IP addresses" subtitle="Click a row to see its events" head="IP address" total={total} showFailed
                     rows={stats.top_src_ips.map((r) => ({
                       key: r.key, n: r.n, failed: r.auth_failures,
                       label: <code>{r.key}</code>,
                       sub: r.country ? <Country code={r.country} /> : ipKind(r.key),
                     }))}
                     onRow={(ip) => search({ src_ip: ip })} />
          <RankTable title="Top countries" subtitle="Where outside traffic comes from. Click a row to see its events" head="Country" total={total} showFailed
                     rows={stats.top_countries.map((r) => ({ key: r.key, n: r.n, failed: r.auth_failures, label: <Country code={r.key} /> }))}
                     emptyText="No public IP addresses in this time range (private and example addresses have no country)."
                     onRow={(country) => search({ country })} />
          <RankTable title="Most active users" subtitle="Click a row to see their events" head="User" total={total} showFailed
                     rows={stats.top_users.map((r) => {
                       const { name, domain } = splitUser(r.key);
                       return { key: r.key, n: r.n, failed: r.auth_failures, label: name, sub: domain };
                     })}
                     onRow={(user) => search({ user })} />
          <RankTable title="Most common activity" subtitle="Click a row to see those events" head="Event" total={total}
                     rows={stats.top_event_types.map((r) => ({ key: r.key, n: r.n, label: humanize(r.key), sub: <code>{r.key}</code> }))}
                     onRow={(et) => search({ event_type: et })} />
        </div>
      </>
    );
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Overview</h1>
          <p>
            What happened in <strong>{tenantName}</strong> in the {rangeLong}
            {source ? <> from <strong>{sourceLabel(source)}</strong></> : null}. Click anything to see the events behind it.
          </p>
          {stats?.engine && (
            <p className="engine-note" title="Logs are stored and summarized in ClickHouse; users, keys and alerts live in PostgreSQL.">
              <Icon name="activity" size={13} />
              Summarized by {stats.engine.name === "clickhouse" ? "ClickHouse" : "PostgreSQL"} in {stats.engine.ms} ms
            </p>
          )}
        </div>
        <div className="header-controls">
          <label className="inline-select">
            <span>Source</span>
            <select ref={fitToOptions} value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source filter">
              <option value="">All sources</option>
              {SOURCES.map((s) => <option key={s} value={s}>{sourceLabel(s)}</option>)}
            </select>
          </label>
          <Segmented label="Time range" value={range} options={RANGES} onChange={setRange} />
        </div>
      </header>
      <div className="page-body">
        {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}
        {!stats && !error && (
          <>
            <div className="kpis">{[0, 1, 2, 3].map((i) => <div key={i} className="skeleton" style={{ height: 112 }} />)}</div>
            <div className="skeleton" style={{ height: 300 }} />
          </>
        )}
        {body}
      </div>
    </>
  );
}
