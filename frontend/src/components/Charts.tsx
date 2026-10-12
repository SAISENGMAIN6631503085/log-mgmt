import { Bar, BarChart, CartesianGrid, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { TimelinePoint } from "../api";
import { fmtNum, Tokens } from "../util";
import { Icon } from "./Icon";

// Charts are deliberately simple: plain bars in one colour, a value printed on each bar,
// a one-sentence takeaway above (see Dashboard), hover for detail, and a "Show table" view.

const axisProps = (t: Tokens) => ({ stroke: t["--axis"], tick: { fill: t["--muted"], fontSize: 12 }, tickLine: false });

const PERIOD_WORDS: Record<string, string> = { "1h": "hour", "24h": "24 hours", "7d": "7 days" };

/** "▲ 12% more than the 24 hours before". Neutral ink: more events isn't automatically good or bad. */
export function Delta({ current, previous, period }: { current: number; previous: number; period: string }) {
  const words = PERIOD_WORDS[period] ?? period;
  if (previous === 0) {
    // No baseline to compare with: say so plainly instead of an infinite percentage.
    return <span className="kpi-sub">Nothing in the {words} before</span>;
  }
  const pct = ((current - previous) / previous) * 100;
  const rounded = Math.abs(pct) < 10 ? Math.abs(pct).toFixed(1) : Math.round(Math.abs(pct)).toString();
  return (
    <span className="delta" title={`${fmtNum(previous)} in the previous ${words}`}>
      {pct === 0 ? "No change" : <><Icon name={pct > 0 ? "up" : "down"} size={13} />{rounded}% {pct > 0 ? "more" : "fewer"}</>}
      <span className="muted">than the {words} before</span>
    </span>
  );
}

// ---------------------------------------------------------------------------
// Events over time: one bar per hour (or day)
// ---------------------------------------------------------------------------

function TimeTip({ active, payload, fmt }: { active?: boolean; payload?: { payload: TimelinePoint }[]; fmt: (iso: string) => string }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  const serious = p.critical + p.high;
  return (
    <div className="tip">
      <div className="t">{fmt(p.t)}</div>
      <div className="v">{fmtNum(p.n)} events</div>
      {p.n > 0 && (
        <div className="t" style={{ marginTop: 2 }}>
          {fmtNum(serious)} serious · {fmtNum(p.auth_failures)} failed sign-ins
        </div>
      )}
    </div>
  );
}

export function EventsOverTime({ data, bucketSeconds, t }: { data: TimelinePoint[]; bucketSeconds: number; t: Tokens }) {
  const daily = bucketSeconds >= 86400;
  const fmtTick = (iso: string) =>
    new Date(iso).toLocaleString(undefined, daily ? { month: "short", day: "numeric" } : { hour: "numeric" });
  const fmtFull = (iso: string) =>
    new Date(iso).toLocaleString(undefined, daily
      ? { weekday: "short", month: "short", day: "numeric" }
      : { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: -12 }} barCategoryGap={3}>
        <CartesianGrid stroke={t["--grid"]} vertical={false} />
        <XAxis dataKey="t" tickFormatter={fmtTick} minTickGap={36} {...axisProps(t)} />
        <YAxis allowDecimals={false} tickFormatter={(v: number) => fmtNum(v)} {...axisProps(t)} axisLine={false} />
        <Tooltip content={<TimeTip fmt={fmtFull} />} cursor={{ fill: t["--grid"], fillOpacity: 0.6 }} />
        <Bar dataKey="n" fill={t["--chart"]} radius={[4, 4, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ---------------------------------------------------------------------------
// Ranked horizontal bars with the value at the end (sources, severity levels)
// ---------------------------------------------------------------------------

type Row = { key: string; label: string; n: number };

function RowTip({ active, payload, total }: { active?: boolean; payload?: { payload: Row }[]; total: number }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="tip">
      <div className="t">{p.label}</div>
      <div className="v">{fmtNum(p.n)} events · {total ? ((p.n / total) * 100).toFixed(1) : 0}% of all</div>
    </div>
  );
}

export function HBars({ rows, t, onClick }: { rows: Row[]; t: Tokens; onClick?: (key: string) => void }) {
  const total = rows.reduce((s, r) => s + r.n, 0);
  const labelWidth = Math.min(150, Math.max(70, ...rows.map((r) => r.label.length * 7.2)));
  return (
    <ResponsiveContainer width="100%" height={Math.max(120, rows.length * 38 + 8)}>
      <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 56, bottom: 0, left: 0 }} barCategoryGap={9}>
        <XAxis type="number" hide domain={[0, "dataMax"]} />
        <YAxis type="category" dataKey="label" width={labelWidth} {...axisProps(t)}
               tick={{ fill: t["--text-2"], fontSize: 13 }} axisLine={false} />
        <Tooltip content={<RowTip total={total} />} cursor={{ fill: t["--grid"], fillOpacity: 0.6 }} />
        <Bar dataKey="n" fill={t["--chart"]} radius={[0, 4, 4, 0]} maxBarSize={22} minPointSize={2} isAnimationActive={false}
             background={{ fill: t["--grid"], fillOpacity: 0.4, radius: 4 } as object}
             cursor={onClick ? "pointer" : undefined} onClick={onClick ? (d: Row) => onClick(d.key) : undefined}>
          {/* The number at the end of each bar, so nobody has to read the bar length. */}
          <LabelList dataKey="n" position="right" formatter={(v: number) => fmtNum(v)}
                     style={{ fill: t["--text"], fontSize: 13, fontWeight: 600 }} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
