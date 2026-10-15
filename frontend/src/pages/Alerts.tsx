import { KeyboardEvent as ReactKeyboardEvent, useEffect, useMemo, useState } from "react";
import { Alert, api, User } from "../api";
import { Empty } from "../components/Badge";
import { Country } from "../components/Country";
import { Icon, IconName } from "../components/Icon";
import { Segmented } from "../components/Segmented";
import { fmtNum, go, severityLevel, sourceLabel } from "../util";

// An alert table, like the triage views of SIEM tools: one alert per row (severity, what happened,
// how many events, when, where it was seen, status), newest first, so many alerts can be scanned
// and compared at once. A row opens a side panel with every detail and the actions; admins can
// tick rows and acknowledge them together.

type StatusFilter = "open" | "acknowledged" | "all";
const STATUS_OPTIONS = [
  { key: "open", label: "Open" },
  { key: "acknowledged", label: "Acknowledged" },
  { key: "all", label: "All" },
] as const;

// `means` is the few-word "so what" shown in the table; the side panel has the full sentence.
const RULES: Record<string, { name: string; icon: IconName; means: string }> = {
  brute_force_login: { name: "Brute-force login", icon: "lock", means: "someone may be guessing passwords" },
  firewall_scan: { name: "Firewall scan", icon: "router", means: "someone may be scanning for open ports" },
  malware_detected: { name: "Malware detected", icon: "bug", means: "check the computer and the account" },
};
const ruleOf = (a: Alert) =>
  RULES[a.rule_id] ?? { name: a.rule_name.split(":")[0], icon: "alert" as IconName, means: "" };

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
  return d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
}

const clock = (iso: string) => new Date(iso).toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
const capital = (s: string) => s[0].toUpperCase() + s.slice(1);

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

  const open = status === "open" ? alerts ?? [] : [];
  const bySeverity = (lvl: string) => open.filter((a) => severityLevel(a.severity) === lvl).length;
  const oldest = open.length ? open.reduce((o, a) => (a.created_at < o.created_at ? a : o)) : null;
  const severityParts = (["critical", "high", "medium"] as const)
    .map((lvl) => [lvl, bySeverity(lvl)] as const).filter(([, n]) => n > 0)
    .map(([lvl, n]) => `${n} ${lvl}`);

  const [openId, setOpenId] = useState<number | null>(null);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const [busy, setBusy] = useState(false);
  useEffect(() => setPicked(new Set()), [status, rule, tenant]);

  const isAdmin = user.role === "admin";
  const pickable = shown.filter((a) => a.status === "open");
  const allPicked = pickable.length > 0 && pickable.every((a) => picked.has(a.id));
  const toggle = (id: number) => setPicked((p) => {
    const next = new Set(p);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });

  async function ackPicked() {
    setBusy(true);
    try {
      // One request per alert, a few at a time; the API checks each one belongs to this tenant.
      const ids = [...picked];
      for (let i = 0; i < ids.length; i += 6) {
        await Promise.all(ids.slice(i, i + 6).map((id) => api(`/api/alerts/${id}/ack`, { method: "POST", params: { tenant } })));
      }
      setPicked(new Set());
      const open = await api<{ alerts: Alert[] }>("/api/alerts", { params: { tenant, status: "open" } });
      onChange?.(open.alerts.length);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const openAlert = shown.find((a) => a.id === openId) ?? (alerts ?? []).find((a) => a.id === openId) ?? null;
  const rowKey = (a: Alert) => (e: ReactKeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setOpenId(a.id); }
  };

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

        {shown.length > 0 && (
          <section className="card alert-table-card">
            <div className="results-head">
              {isAdmin && picked.size > 0 ? (
                <div className="bulk-bar" role="status">
                  <strong>{picked.size} selected</strong>
                  <button className="sm primary" onClick={ackPicked} disabled={busy}>
                    <Icon name="check" size={14} />{busy ? "Acknowledging…" : "Acknowledge selected"}
                  </button>
                  <button className="link" onClick={() => setPicked(new Set())}>Clear</button>
                </div>
              ) : (
                <span className="dim">{fmtNum(shown.length)} {shown.length === 1 ? "alert" : "alerts"}, newest first. Click one for details.</span>
              )}
            </div>
            <div className="table-wrap">
              <table className="alert-table">
                <thead>
                  <tr>
                    {isAdmin && (
                      <th className="pick">
                        <input type="checkbox" aria-label="Select all open alerts shown" checked={allPicked}
                               disabled={!pickable.length}
                               onChange={() => setPicked(allPicked ? new Set() : new Set(pickable.map((a) => a.id)))} />
                      </th>
                    )}
                    <th>Severity</th>
                    <th>Alert</th>
                    <th className="num">Events</th>
                    <th>Started</th>
                    <th>Seen in</th>
                    {/* On the Open / Acknowledged tabs every row has the same status, so it's shown only under All. */}
                    {status === "all" && <th>Status</th>}
                  </tr>
                </thead>
                <tbody>
                  {shown.map((a) => {
                    const r = ruleOf(a);
                    const level = severityLevel(a.severity);
                    const handled = a.status === "acknowledged";
                    return (
                      <tr key={a.id} className={`clickable sev-row-${level}${handled ? " handled" : ""}${openId === a.id ? " selected" : ""}`}
                          tabIndex={0} onClick={() => setOpenId(a.id)} onKeyDown={rowKey(a)}>
                        {isAdmin && (
                          <td className="pick" onClick={(e) => e.stopPropagation()}>
                            {!handled && <input type="checkbox" aria-label={`Select alert ${a.id}`}
                                                checked={picked.has(a.id)} onChange={() => toggle(a.id)} />}
                          </td>
                        )}
                        <td><span className={`pill sev-${level}`}><span className="dot" />{capital(level)}</span></td>
                        <td className="alert-cell">
                          <div className="alert-what"><Headline a={a} /></div>
                          <div className="alert-why">
                            <Icon name={r.icon} size={13} /><span><strong>{r.name}</strong>{r.means && `: ${r.means}`}</span>
                          </div>
                        </td>
                        <td className="num">{fmtNum(a.event_count)}</td>
                        <td className="time-cell"
                            title={`Started ${new Date(a.window_start).toLocaleString()}\nAlert raised ${ago(a.created_at)}`}>
                          {clock(a.window_start)}<span>{dayLabel(a.window_start)}</span>
                        </td>
                        <td className="dim">{(a.details.sources ?? []).map(sourceLabel).join(", ") || "–"}</td>
                        {status === "all" && (
                          <td><span className={`pill status-${a.status}`}><span className="dot" />{handled ? "Acknowledged" : "Open"}</span></td>
                        )}
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {openAlert && (
          <AlertDrawer a={openAlert} canAck={isAdmin && openAlert.status === "open"} onClose={() => setOpenId(null)}
                       onInvestigate={() => investigate(openAlert)} onAck={() => ack(openAlert.id)} />
        )}
      </div>
    </>
  );
}

/** Every detail of one alert, with its actions. */
function AlertDrawer({ a, canAck, onClose, onInvestigate, onAck }: {
  a: Alert; canAck: boolean; onClose: () => void; onInvestigate: () => void; onAck: () => void;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const r = ruleOf(a);
  const level = severityLevel(a.severity);
  const target = a.group_key ?? a.src_ip ?? "";
  const facts: [string, React.ReactNode][] = [
    [a.rule_id === "malware_detected" ? "Computer" : "IP address",
      <><code>{target}</code>{a.details.country ? <> <Country code={a.details.country} /></> : null}</>],
    ["Events", <>{fmtNum(a.event_count)} {a.event_count === 1 ? "event" : "events"}
      {a.details.threshold ? <span className="dim"> (the rule fires at {fmtNum(a.details.threshold)})</span> : null}</>],
    ["Started", new Date(a.window_start).toLocaleString()],
    ["Last event", new Date(a.window_end).toLocaleString()],
    ["Lasted", duration(a)],
    ["Seen in", (a.details.sources ?? []).map(sourceLabel).join(", ") || "–"],
    ...(a.details.users?.length ? [["Accounts", a.details.users.join(", ")] as [string, React.ReactNode]] : []),
    // The computer list repeats the target for malware alerts, so it's shown only when it adds something.
    ...(a.details.hosts?.length && a.details.hosts.join() !== target
      ? [["Computers", a.details.hosts.join(", ")] as [string, React.ReactNode]] : []),
    ["Raised", `${new Date(a.created_at).toLocaleString()} (${ago(a.created_at)})`],
    ["Notified", a.webhook_sent_at ? "Webhook sent" : "In the app only"],
  ];
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`Alert ${a.id}`}>
        <div className="drawer-head">
          <div>
            <div className="title"><Headline a={a} /></div>
            <div className="meta">
              <span className={`pill sev-${level}`}><span className="dot" />{capital(level)}</span>
              <span className="alert-why"><Icon name={r.icon} size={13} />{r.name}</span>
              <span className={`pill status-${a.status}`}><span className="dot" />{a.status === "acknowledged" ? "Acknowledged" : "Open"}</span>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><Icon name="x" /></button>
        </div>
        <div className="drawer-body">
          <div className="section-title">What it means</div>
          <p className="alert-meaning"><Detail a={a} /></p>
          <div className="drawer-actions">
            <button className="sm primary" onClick={onInvestigate}><Icon name="search" size={14} />Investigate the events</button>
            {/* Viewers are read-only; the API enforces this too (403). */}
            {canAck && <button className="sm" onClick={onAck}><Icon name="check" size={14} />Acknowledge</button>}
          </div>
          <div className="section-title">Details</div>
          <dl className="kv">
            {facts.map(([k, v]) => (
              <div key={k} style={{ display: "contents" }}><dt>{k}</dt><dd>{v}</dd></div>
            ))}
          </dl>
        </div>
      </aside>
    </>
  );
}
