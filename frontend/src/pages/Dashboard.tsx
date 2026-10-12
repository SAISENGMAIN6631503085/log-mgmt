import { useEffect, useState } from "react";
import { api, Stats } from "../api";
import { Empty } from "../components/Badge";
import { ChartCard } from "../components/ChartCard";
import { Delta, EventsOverTime, HBars } from "../components/Charts";
import { Icon, IconName } from "../components/Icon";
import { Segmented } from "../components/Segmented";
import { fmtNum, go, RangeKey, RANGES, rangeParams, sourceLabel, useTokens } from "../util";

/** Every tile has the same three rows: label + icon, the number, one line of context. */
function Kpi({ icon, label, value, footer, onClick, attention }: {
  icon: IconName; label: string; value: number; footer: React.ReactNode; onClick: () => void; attention?: boolean;
}) {
  return (
    <button className={`kpi ${attention ? "attention" : ""}`} onClick={onClick}>
      <span className="kpi-top">{label}<span className="kpi-icon"><Icon name={icon} size={16} /></span></span>
      <span className="kpi-value">{fmtNum(value)}</span>
      {footer}
    </button>
  );
}

/** The one-sentence takeaway shown above a chart, so nobody has to decode the chart to get the point. */
function Insight({ children }: { children: React.ReactNode }) {
  return <p className="insight">{children}</p>;
}

/** Ranked list with an inline magnitude bar, scaled to the largest row. */
function RankTable({ title, subtitle, head, rows, extra, onRow, mono }: {
  title: string; subtitle: string; head: string; rows: { key: string; n: number; extra?: number }[];
  extra?: string; onRow: (key: string) => void; mono?: boolean;
}) {
  const max = Math.max(1, ...rows.map((r) => r.n));
  return (
    <section className="card">
      <div className="card-head"><div><h2>{title}</h2><div className="sub">{subtitle}</div></div></div>
      {rows.length === 0 ? <Empty icon={<Icon name="inbox" />} title="No data">Nothing in this time range.</Empty> : (
        <div className="card-body flush table-wrap">
          <table>
            <thead><tr><th>{head}</th>{extra && <th className="num">{extra}</th>}<th className="num">Events</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.key} className="clickable" onClick={() => onRow(r.key)} title="See these events">
                  <td>{mono ? <code>{r.key}</code> : r.key}</td>
                  {extra && <td className="num">{r.extra ? <span className="warn-num">{fmtNum(r.extra)}</span> : <span className="dim">0</span>}</td>}
                  <td className="num">
                    <div className="bar-cell">
                      {fmtNum(r.n)}
                      <span className="track"><span className="fill" style={{ width: `${(r.n / max) * 100}%` }} /></span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

const SEVERITY_ROWS = [
  { key: "critical", label: "Critical (9–10)", min: "9" },
  { key: "high", label: "High (7–8)", min: "7" },
  { key: "medium", label: "Medium (4–6)", min: "4" },
  { key: "low", label: "Low (0–3)", min: "" },
  { key: "unknown", label: "Not rated", min: "" },
];

const pct = (part: number, whole: number) => (whole ? Math.round((part / whole) * 100) : 0);

export function Dashboard({ tenant, tenantName }: { tenant: string | undefined; tenantName: string }) {
  const [range, setRange] = useState<RangeKey>("24h");
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const t = useTokens();

  useEffect(() => {
    let cancelled = false;
    setError(null);
    api<Stats>("/api/stats", { params: { ...rangeParams(range), tenant } })
      .then((s) => !cancelled && setStats(s))
      .catch((e) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [range, tenant]);

  // Links into the search page carry the same time range.
  const search = (params: Record<string, string>) => go("events", { range, ...params });
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
    const severities = SEVERITY_ROWS
      .filter((r) => r.key !== "unknown" || sevCount("unknown") > 0)
      .map((r) => ({ key: r.key, label: r.label, n: sevCount(r.key) }));

    body = (
      <>
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
          <ChartCard title="Where events come from" subtitle="Click a bar to see that source's events"
                     rows={sources} empty={sources.length === 0}
                     columns={[{ key: "label", label: "Source" }, { key: "n", label: "Events", num: true }]}>
            {topSource && (
              <Insight><strong>{sourceLabel(topSource.key)}</strong> sends the most: {fmtNum(topSource.n)} of {fmtNum(total)} events ({pct(topSource.n, total)}%).</Insight>
            )}
            <HBars rows={sources} t={t} onClick={(source) => search({ source })} />
          </ChartCard>

          <ChartCard title="How serious are they?" subtitle="Severity from 0 (routine) to 10 (act now). Click a bar to see those events."
                     rows={severities} empty={total === 0}
                     columns={[{ key: "label", label: "Severity" }, { key: "n", label: "Events", num: true }]}>
            <Insight>
              {serious > 0
                ? <><strong>{fmtNum(serious)}</strong> events ({pct(serious, total)}%) are high or critical and worth a look.</>
                : <>No high or critical events in the {rangeLong}.</>}
            </Insight>
            <HBars rows={severities} t={t} onClick={(key) => {
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
          <RankTable title="Busiest IP addresses" subtitle="Click a row to see its events" head="IP address" mono extra="Failed sign-ins"
                     rows={stats.top_src_ips.map((r) => ({ key: r.key, n: r.n, extra: r.auth_failures }))}
                     onRow={(ip) => search({ src_ip: ip })} />
          <RankTable title="Most common activity" subtitle="Click a row to see those events" head="Event"
                     rows={stats.top_event_types} onRow={(et) => search({ event_type: et })} />
        </div>
      </>
    );
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Overview</h1>
          <p>What happened in <strong>{tenantName}</strong> in the {rangeLong}. Click anything to see the events behind it.</p>
        </div>
        <Segmented label="Time range" value={range} options={RANGES} onChange={setRange} />
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
