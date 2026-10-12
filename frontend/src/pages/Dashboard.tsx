import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api, Stats } from "../api";
import { ChartCard } from "../components/ChartCard";
import { fmtNum, go, RangeKey, RANGES, rangeParams, Tokens, useTokens } from "../util";

// Every chart here is a single series, so all use the one accent hue: no legend needed,
// the card title names the series. Categories (sources, severities) are on the axis as text.

function ChartTip({ active, payload, label, fmt }: { active?: boolean; payload?: { value: number }[]; label?: string; fmt?: (l: string) => string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="tip">
      <div className="t">{fmt ? fmt(String(label)) : label}</div>
      <div className="v">{fmtNum(payload[0].value)} events</div>
    </div>
  );
}

function axisProps(t: Tokens) {
  return { stroke: t["--axis"], tick: { fill: t["--muted"], fontSize: 12 }, tickLine: false };
}

function Timeline({ stats, t }: { stats: Stats; t: Tokens }) {
  // Columns, not a smooth line: each value is a count for a fixed bucket, and a curve would
  // suggest values between buckets that don't exist.
  const daily = stats.bucket_seconds >= 86400;
  const fmtTick = (iso: string) =>
    new Date(iso).toLocaleString(undefined, daily ? { month: "short", day: "numeric" } : { hour: "2-digit", minute: "2-digit" });
  const fmtFull = (iso: string) =>
    new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={stats.timeline} margin={{ top: 8, right: 8, bottom: 0, left: -16 }} barCategoryGap={2}>
        <CartesianGrid stroke={t["--grid"]} vertical={false} />
        <XAxis dataKey="t" tickFormatter={fmtTick} minTickGap={40} {...axisProps(t)} />
        <YAxis allowDecimals={false} {...axisProps(t)} axisLine={false} />
        {/* Hover any column (or the gap above it) for the exact count */}
        <Tooltip content={<ChartTip fmt={fmtFull} />} cursor={{ fill: t["--grid"], fillOpacity: 0.5 }} />
        <Bar dataKey="n" fill={t["--accent"]} radius={[4, 4, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

function HBars({ rows, t, onClick }: { rows: { key: string; n: number }[]; t: Tokens; onClick?: (key: string) => void }) {
  return (
    <ResponsiveContainer width="100%" height={Math.max(120, rows.length * 32 + 24)}>
      <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 8 }} barCategoryGap={4}>
        <CartesianGrid stroke={t["--grid"]} horizontal={false} />
        <XAxis type="number" allowDecimals={false} {...axisProps(t)} />
        <YAxis type="category" dataKey="key" width={84} {...axisProps(t)} axisLine={false} />
        <Tooltip content={<ChartTip />} cursor={{ fill: t["--grid"], fillOpacity: 0.5 }} />
        <Bar dataKey="n" fill={t["--accent"]} radius={[0, 4, 4, 0]} maxBarSize={22} isAnimationActive={false}
             cursor={onClick ? "pointer" : undefined} onClick={onClick ? (d: { key: string }) => onClick(d.key) : undefined} />
      </BarChart>
    </ResponsiveContainer>
  );
}

export function Dashboard({ tenant }: { tenant: string | undefined }) {
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

  return (
    <>
      <div className="filters">
        <h1 style={{ margin: 0, flex: 1 }}>Dashboard</h1>
        <label>
          Time range
          <select value={range} onChange={(e) => setRange(e.target.value as RangeKey)}>
            {RANGES.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
          </select>
        </label>
      </div>
      {error && <p className="error">{error}</p>}
      {stats && (
        <>
          <div className="kpis">
            <button className="tile clickable" onClick={() => search({})}>
              <div className="label">Events</div>
              <div className="value">{fmtNum(stats.totals.events)}</div>
            </button>
            <button className="tile clickable" onClick={() => search({ tag: "auth_failure" })}>
              <div className="label">Failed logins</div>
              <div className="value">{fmtNum(stats.totals.auth_failures)}</div>
            </button>
            <button className="tile clickable" onClick={() => search({ severity_min: "7" })}>
              <div className="label">High severity (7+)</div>
              <div className="value">{fmtNum(stats.totals.high_severity)}</div>
            </button>
            <button className="tile clickable" onClick={() => go("alerts")}>
              <div className="label">Open alerts</div>
              <div className="value">{fmtNum(stats.totals.open_alerts)}</div>
            </button>
          </div>

          <div className="grid">
            <ChartCard title="Events over time" rows={stats.timeline} empty={stats.totals.events === 0}
                       columns={[{ key: "t", label: "Time", format: (v) => new Date(String(v)).toLocaleString() },
                                 { key: "n", label: "Events", num: true }]}>
              <Timeline stats={stats} t={t} />
            </ChartCard>
            <ChartCard title="Events by source" rows={stats.by_source} empty={stats.by_source.length === 0}
                       columns={[{ key: "key", label: "Source" }, { key: "n", label: "Events", num: true }]}>
              <HBars rows={stats.by_source} t={t} onClick={(source) => search({ source })} />
            </ChartCard>
          </div>

          <div className="grid">
            <ChartCard title="Events by severity" rows={stats.by_severity} empty={stats.totals.events === 0}
                       columns={[{ key: "key", label: "Severity" }, { key: "n", label: "Events", num: true }]}>
              <HBars rows={stats.by_severity.filter((r) => r.key !== "unknown" || r.n > 0)} t={t} />
            </ChartCard>
            <section className="card">
              <div className="card-head"><h2>Top source IPs</h2></div>
              {stats.top_src_ips.length === 0 ? <p className="muted">No events with a source IP.</p> : (
                <div className="table-wrap">
                  <table>
                    <thead><tr><th>Source IP</th><th className="num">Events</th><th className="num">Failed logins</th></tr></thead>
                    <tbody>
                      {stats.top_src_ips.map((r) => (
                        <tr key={r.key} className="clickable" onClick={() => search({ src_ip: r.key })}>
                          <td><code>{r.key}</code></td>
                          <td className="num">{fmtNum(r.n)}</td>
                          <td className="num">{fmtNum(r.auth_failures)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>

          <section className="card">
            <div className="card-head"><h2>Top event types</h2></div>
            {stats.top_event_types.length === 0 ? <p className="muted">No events.</p> : (
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Event type</th><th className="num">Events</th></tr></thead>
                  <tbody>
                    {stats.top_event_types.map((r) => (
                      <tr key={r.key} className="clickable" onClick={() => search({ event_type: r.key })}>
                        <td>{r.key}</td>
                        <td className="num">{fmtNum(r.n)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </>
  );
}
