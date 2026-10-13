import { useEffect, useState } from "react";
import { Alert, api, User } from "../api";
import { Empty, SeverityBadge, StatusPill } from "../components/Badge";
import { Country } from "../components/Country";
import { Icon } from "../components/Icon";
import { Segmented } from "../components/Segmented";
import { fmtTime, go } from "../util";

/** "alice, bob and carol" / "alice, bob, carol and 4 more", so long lists don't take over the row. */
function listUsers(users: string[]) {
  const shown = users.slice(0, 3);
  const rest = users.length - shown.length;
  const names = shown.map((u, i) => <strong key={u}>{i > 0 ? ", " : ""}{u}</strong>);
  return <>{names}{rest > 0 ? ` and ${rest} more` : ""}</>;
}

/** One plain sentence per rule: what happened, from where, to whom. */
function AlertWhat({ a }: { a: Alert }) {
  const target = a.group_key ?? a.src_ip;
  if (a.rule_id === "firewall_scan") {
    return <><strong>{a.event_count}</strong> blocked connections from <code>{target}</code>{a.details.country ? <> <Country code={a.details.country} /></> : null}: possibly scanning for open ports</>;
  }
  if (a.rule_id === "malware_detected") {
    return (
      <>
        <strong>{a.event_count}</strong> high-severity {a.event_count === 1 ? "threat" : "threats"} on computer <code>{target}</code>
        {a.details.users?.length ? <> (user {listUsers(a.details.users)})</> : null}
      </>
    );
  }
  return (
    <>
      <strong>{a.event_count}</strong> failed sign-ins from <code>{target}</code>{a.details.country ? <> <Country code={a.details.country} /></> : null}
      {a.details.users?.length ? <> for {listUsers(a.details.users)}</> : null}
    </>
  );
}

type StatusFilter = "open" | "acknowledged" | "all";
const STATUS_OPTIONS = [
  { key: "open", label: "Open" },
  { key: "acknowledged", label: "Acknowledged" },
  { key: "all", label: "All" },
] as const;

export function Alerts({ user, tenant, tenantName, onChange }: {
  user: User; tenant: string | undefined; tenantName: string; onChange?: (openCount: number) => void;
}) {
  const [status, setStatus] = useState<StatusFilter>("open");
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
  const showEvents = (a: Alert) => {
    const target = a.group_key ?? a.src_ip ?? "";
    if (a.rule_id === "firewall_scan") go("events", { range: "7d", source: "firewall", src_ip: target, tag: "blocked" });
    else if (a.rule_id === "malware_detected") go("events", { range: "7d", source: "crowdstrike", host: target, severity_min: "7" });
    else go("events", { range: "7d", src_ip: target, tag: "auth_failure" });
  };

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Alerts</h1>
          <p>Possible attacks found in <strong>{tenantName}</strong>. Checked every minute.</p>
        </div>
        <Segmented label="Status" value={status} options={STATUS_OPTIONS} onChange={setStatus} />
      </header>
      <div className="page-body">
        {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}
        <div className="rule-note">
          <Icon name="alert" size={16} />
          <span>
            Alerts come from <strong>detection rules</strong>, such as many failed sign-ins from one IP address, a
            firewall scan, or malware on a computer. Check the events, then acknowledge the alert once it's handled.{" "}
            <button className="link" onClick={() => go("rules")}>See the rules</button>
          </span>
        </div>
        <section className="card">
          {!alerts && !error && <div className="skeleton" style={{ height: 160, margin: 16 }} />}
          {alerts && alerts.length === 0 && (
            status === "open"
              ? <Empty icon={<Icon name="check" />} title="All clear">No open alerts for {tenantName}.</Empty>
              : <Empty icon={<Icon name="inbox" />} title="No alerts">Nothing to show for this filter.</Empty>
          )}
          {alerts && alerts.length > 0 && (
            <div className="alert-list">
              {alerts.map((a) => (
                <article key={a.id} className="alert-row">
                  <SeverityBadge severity={a.severity} />
                  <div>
                    <div className="alert-title">
                      {/* "Brute-force login: 5+ failed logins..." -> short title; the full rule is the tooltip */}
                      <span title={a.rule_name}>{a.rule_name.split(":")[0]}</span>
                      <StatusPill status={a.status} />
                    </div>
                    <div className="alert-what"><AlertWhat a={a} /></div>
                    <div className="alert-meta">
                      <span>Attack: {fmtTime(a.window_start)}{a.window_end !== a.window_start ? ` – ${new Date(a.window_end).toLocaleTimeString()}` : ""}</span>
                      <span>Found: {fmtTime(a.created_at)}</span>
                      {a.details.sources?.length ? <span>Seen in: {a.details.sources.join(", ")}</span> : null}
                      {a.webhook_sent_at && <span>Notification sent</span>}
                    </div>
                  </div>
                  <div className="alert-actions">
                    <button className="sm" onClick={() => showEvents(a)}><Icon name="search" size={14} />See events</button>
                    {/* Viewers are read-only; the API enforces this too (403). */}
                    {user.role === "admin" && a.status === "open" && (
                      <button className="sm primary" onClick={() => ack(a.id)}><Icon name="check" size={14} />Acknowledge</button>
                    )}
                  </div>
                </article>
              ))}
            </div>
          )}
        </section>
      </div>
    </>
  );
}
