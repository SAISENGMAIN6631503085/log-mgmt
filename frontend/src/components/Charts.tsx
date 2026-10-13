import { Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { TimelinePoint } from "../api";
import { fmtNum, Tokens } from "../util";
import { Icon } from "./Icon";

// Charts are deliberately simple: one-colour bars over time, donuts for shares (<= 5 slices, with a
// labelled legend), a one-sentence takeaway above (see Dashboard), hover for detail, and a "Show table" view.

const axisProps = (t: Tokens) => ({ stroke: t["--axis"], tick: { fill: t["--muted"], fontSize: 12 }, tickLine: false });

const PERIOD_WORDS: Record<string, string> = { "1h": "hour", "24h": "24 hours", "7d": "7 days" };
const PERIOD_SHORT: Record<string, string> = { "1h": "previous hour", "24h": "previous 24 h", "7d": "previous 7 days" };

/** "↑ 12% more vs. previous 24 h", or "↑ 72× more" when it grew a lot: a 7,132% rise reads better as 72×.
 *  Neutral ink: more events isn't automatically good or bad. Exact numbers are in the tooltip. */
export function Delta({ current, previous, period }: { current: number; previous: number; period: string }) {
  const short = PERIOD_SHORT[period] ?? `previous ${period}`;
  if (previous === 0) {
    // No baseline to compare with: say so plainly instead of an infinite percentage.
    return <span className="kpi-sub">Nothing in the {PERIOD_WORDS[period] ?? period} before</span>;
  }
  const title = `${fmtNum(current)} now, ${fmtNum(previous)} in the ${short}`;
  if (current === previous) return <span className="delta" title={title}>Same as {short}</span>;
  const ratio = current / previous;
  const up = ratio > 1;
  const amount = ratio >= 2
    ? `${ratio >= 10 ? Math.round(ratio) : ratio.toFixed(1)}× more`
    : `${Math.max(1, Math.round(Math.abs(ratio - 1) * 100))}% ${up ? "more" : "fewer"}`;
  return (
    <span className="delta" title={title}>
      <Icon name={up ? "up" : "down"} size={13} />
      <span className="delta-amount">{amount}</span>{" "}
      <span className="muted">vs. {short}</span>
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
// Donut: part of a whole, for at most ~6 slices (severity levels, top sources + "Other").
// The legend beside it names every slice with its count and share, so nothing relies on
// colour alone, and the total sits in the middle.
// ---------------------------------------------------------------------------

export type DonutSlice = { key: string; label: string; n: number; color: string; clickable?: boolean };

function SliceTip({ active, payload, total }: { active?: boolean; payload?: { payload: DonutSlice }[]; total: number }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="tip">
      <div className="t">{p.label}</div>
      <div className="v">{fmtNum(p.n)} events · {total ? ((p.n / total) * 100).toFixed(1) : 0}%</div>
    </div>
  );
}

export function Donut({ slices, t, centerLabel, onClick }: {
  slices: DonutSlice[]; t: Tokens; centerLabel: string; onClick?: (key: string) => void;
}) {
  const total = slices.reduce((s, x) => s + x.n, 0);
  const shown = slices.filter((x) => x.n > 0);
  const pct = (n: number) => (total ? (n / total) * 100 : 0);
  return (
    <div className="donut">
      <div className="donut-chart">
        <ResponsiveContainer width="100%" height={200}>
          <PieChart>
            <Tooltip content={<SliceTip total={total} />} />
            <Pie data={shown} dataKey="n" nameKey="label" innerRadius="68%" outerRadius="96%"
                 startAngle={90} endAngle={-270} isAnimationActive={false}
                 // 2px surface-coloured edges = the gap between slices
                 stroke={t["--surface"]} strokeWidth={2}
                 cursor={onClick ? "pointer" : undefined}
                 onClick={onClick ? (d: DonutSlice) => d.clickable !== false && onClick(d.key) : undefined}>
              {shown.map((x) => <Cell key={x.key} fill={x.color} />)}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-center" aria-hidden="true">
          <strong>{fmtNum(total)}</strong>
          <span>{centerLabel}</span>
        </div>
      </div>
      <ul className="donut-legend">
        {slices.map((x) => (
          <li key={x.key}>
            <button type="button" className="legend-row" disabled={!onClick || x.n === 0 || x.clickable === false}
                    onClick={() => onClick?.(x.key)} title={onClick ? `See ${x.label} events` : undefined}>
              <span className="swatch" style={{ background: x.color }} />
              <span className="legend-label">{x.label}</span>
              <span className="legend-n">{fmtNum(x.n)}</span>
              <span className="legend-pct">{pct(x.n) < 1 && x.n > 0 ? "<1" : Math.round(pct(x.n))}%</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
