import { useEffect, useMemo, useState } from "react";
import { Alert, api, User } from "../api";
import { Empty } from "../components/Badge";
import { Country } from "../components/Country";
import { Icon, IconName } from "../components/Icon";
import { Segmented } from "../components/Segmented";
import { fmtNum, go, severityLevel, sourceLabel } from "../util";

// A triage queue: what happened (the headline), how serious (the coloured rail), when and where
// (the facts), and what to do (Investigate / Acknowledge). Grouped by day, newest first.

type StatusFilter = "open" | "acknowledged" | "all";
const STATUS_OPTIONS = [
  { key: "open", label: "Open" },
  { key: "acknowledged", label: "Acknowledged" },
  { key: "all", label: "All" },
] as const;

const RULES: Record<string, { name: string; icon: IconName }> = {
  brute_force_login: { name: "Brute-force login", icon: "lock" },
  firewall_scan: { name: "Firewall scan", icon: "router" },
  malware_detected: { name: "Malware detected", icon: "bug" },
};
const ruleOf = (a: Alert) => RULES[a.rule_id] ?? { name: a.rule_name.split(":")[0], icon: "alert" as IconName };

/** "alice, bob and carol" / "alice, bob, carol and 4 more". */
function listNames(names: string[]) {
  const shown = names.slice(0, 3);
  const rest = names.length - shown.length;
  return <>{shown.map((u, i) => <strong key={u}>{i > 0 ? ", " : ""}{u}</strong>)}{rest > 0 ? ` and ${rest} more` : ""}</>;
}

function ago(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

function waited(iso: string): string {
  const m = Math.max(1, Math.round((Date.now() - new Date(iso).getTime()) / 60000));
  if (m < 60) return `${m} minute${m === 1 ? "" : "s"}`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} hour${h === 1 ? "" : "s"}`;
  return `${Math.round(h / 24)} days`;
}

function duration(a: Alert): string {
  const s = (new Date(a.window_end).getTime() - new Date(a.window_start).getTime()) / 1000;
  if (s < 60) return "under a minute";
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

function dayLabel(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86400000);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
  return d.toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" });
}

/** The headline says what happened, in plain words. */
function Headline({ a }: { a: Alert }) {
  const target = a.group_key ?? a.src_ip ?? "";
  const country = a.details.country ? <> <Country code={a.details.country} /></> : null;
  if (a.rule_id === "firewall_scan") {
    return <>{fmtNum(a.event_count)} blocked connections from <code>{target}</code>{country}</>;
  }
  if (a.rule_id === "malware_detected") {
    return <>{a.event_count === 1 ? "A serious threat" : `${fmtNum(a.event_count)} serious threats`} found on <code>{target}</code></>;
  }
  return <>{fmtNum(a.event_count)} failed sign-ins from <code>{target}</code>{country}</>;
}

/** One line of "so what" under the headline. */
function Detail({ a }: { a: Alert }) {
  const users = a.details.users ?? [];
  if (a.rule_id === "firewall_scan") return <>Someone may be scanning this network for open ports.</>;
  if (a.rule_id === "malware_detected") {
    return users.length ? <>Signed-in user: {listNames(users)}. Check the computer and the account.</> : <>Check the computer.</>;
  }
  return users.length ? <>Accounts tried: {listNames(users)}. Someone may be guessing passwords.</> : <>Someone may be guessing passwords.</>;
}

export function Alerts({ user, tenant, tenantName, onChange }: {
  user: User; tenant: string | undefined; tenantName: string; onChange?: (openCount: number) => void;
}) {
  const [status, setStatus] = useState<StatusFilter>("open");
  const [rule, setRule] = useState<string>("all");
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setError(null);
    api<{ alerts: Alert[] }>("/api/alerts", { params: { tenant, status: status === "all" ? undefined : status } })
      .then((r) => {
        setAlerts(r.alerts);
        if (status === "open") onChange?.(r.alerts.length);
      })
      .catch((e) => setError(e.message));
  }

  useEffect(load, [status, tenant]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => setRule("all"), [status]);

  async function ack(id: number) {
    try {
      await api(`/api/alerts/${id}/ack`, { method: "POST", params: { tenant } });
      const open = await api<{ alerts: Alert[] }>("/api/alerts", { params: { tenant, status: "open" } });
      onChange?.(open.alerts.length);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  // Open the search page on exactly the events behind the alert (each rule matches different events).
  const investigate = (a: Alert) => {
    const target = a.group_key ?? a.src_ip ?? "";
    if (a.rule_id === "firewall_scan") go("events", { range: "7d", source: "firewall", src_ip: target, tag: "blocked" });
    else if (a.rule_id === "malware_detected") go("events", { range: "7d", source: "crowdstrike", host: target, severity_min: "7" });
    else go("events", { range: "7d", src_ip: target, tag: "auth_failure" });
  };

  const counts = useMemo(() => {
    const byRule: Record<string, number> = {};
    for (const a of alerts ?? []) byRule[a.rule_id] = (byRule[a.rule_id] ?? 0) + 1;
    return byRule;
  }, [alerts]);
  const shown = (alerts ?? []).filter((a) => rule === "all" || a.rule_id === rule);

  // Group by the day the alert was raised; the list is already newest first.
  const groups: { day: string; items: Alert[] }[] = [];
  for (const a of shown) {
    const day = dayLabel(a.created_at);
    if (groups.at(-1)?.day !== day) groups.push({ day, items: [] });
    groups.at(-1)!.items.push(a);
  }

  const open = status === "open" ? alerts ?? [] : [];
  const bySeverity = (lvl: string) => open.filter((a) => severityLevel(a.severity) === lvl).length;
  const oldest = open.length ? open.reduce((o, a) => (a.created_at < o.created_at ? a : o)) : null;
  const severityParts = (["critical", "high", "medium"] as const)
    .map((lvl) => [lvl, bySeverity(lvl)] as const).filter(([, n]) => n > 0)
    .map(([lvl, n]) => `${n} ${lvl}`);

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Alerts</h1>
          {status === "open" && alerts && alerts.length > 0 ? (
            <p className="triage">
              <strong>{alerts.length} open {alerts.length === 1 ? "alert" : "alerts"}</strong> in {tenantName}
              {severityParts.length ? `: ${severityParts.join(", ")}` : ""}.
              {oldest && <> The oldest has waited {waited(oldest.created_at)}.</>}
            </p>
          ) : (
            <p>Possible attacks found in <strong>{tenantName}</strong>. The <button className="link" onClick={() => go("rules")}>detection rules</button> run every minute.</p>
          )}
        </div>
        <Segmented label="Status" value={status} options={STATUS_OPTIONS} onChange={setStatus} />
      </header>

      <div className="page-body">
        {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}

        {alerts && alerts.length > 0 && (
          <div className="rule-filter" role="group" aria-label="Filter by rule">
            <button className={rule === "all" ? "on" : ""} aria-pressed={rule === "all"} onClick={() => setRule("all")}>
              All rules <span className="n">{alerts.length}</span>
            </button>
            {Object.entries(RULES).filter(([id]) => counts[id]).map(([id, r]) => (
              <button key={id} className={rule === id ? "on" : ""} aria-pressed={rule === id} onClick={() => setRule(id)}>
                <Icon name={r.icon} size={14} />{r.name} <span className="n">{counts[id]}</span>
              </button>
            ))}
            <button className="link rules-link" onClick={() => go("rules")}>Manage rules</button>
          </div>
        )}

        {!alerts && !error && <div className="skeleton" style={{ height: 240 }} />}

        {alerts && alerts.length === 0 && (
          <section className="card">
            {status === "open"
              ? <Empty icon={<Icon name="check" />} title="Nothing to review">No open alerts in {tenantName}. The rules check new logs every minute.</Empty>
              : <Empty icon={<Icon name="inbox" />} title="No alerts">Nothing matches this filter.</Empty>}
          </section>
        )}

        {groups.map((g) => (
          <section key={g.day} className="alert-day" aria-label={g.day}>
            <h2 className="alert-day-label">{g.day}</h2>
            <ol className="queue">
              {g.items.map((a) => {
                const r = ruleOf(a);
                const level = severityLevel(a.severity);
                const handled = a.status === "acknowledged";
                return (
                  <li key={a.id} className={`queue-item sev-${level} ${handled ? "handled" : ""}`}>
                    <span className="rail" aria-hidden="true" />
                    <span className="queue-icon" aria-hidden="true"><Icon name={r.icon} size={18} /></span>
                    <div className="queue-body">
                      <div className="queue-kicker">
                        <span className={`sev-word ${level}`}>{level[0].toUpperCase() + level.slice(1)}</span>
                        <span>{r.name}</span>
                        {handled && <span className="handled-tag"><Icon name="check" size={13} />Acknowledged</span>}
                      </div>
                      <h3 className="queue-title"><Headline a={a} /></h3>
                      <p className="queue-detail"><Detail a={a} /></p>
                      <dl className="queue-facts">
                        <div><dt>Started</dt><dd title={new Date(a.window_start).toLocaleString()}>
                          {new Date(a.window_start).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}</dd></div>
                        <div><dt>Lasted</dt><dd>{duration(a)}</dd></div>
                        {a.details.sources?.length ? <div><dt>Seen in</dt><dd>{a.details.sources.map(sourceLabel).join(", ")}</dd></div> : null}
                        <div><dt>Notified</dt><dd>{a.webhook_sent_at ? "Webhook sent" : "In app only"}</dd></div>
                      </dl>
                    </div>
                    <div className="queue-side">
                      <time dateTime={a.created_at} title={new Date(a.created_at).toLocaleString()}>{ago(a.created_at)}</time>
                      <div className="queue-actions">
                        <button className="sm" onClick={() => investigate(a)}><Icon name="search" size={14} />Investigate</button>
                        {/* Viewers are read-only; the API enforces this too (403). */}
                        {user.role === "admin" && !handled && (
                          <button className="sm ghost" onClick={() => ack(a.id)}><Icon name="check" size={14} />Acknowledge</button>
                        )}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ol>
          </section>
        ))}
      </div>
    </>
  );
}
