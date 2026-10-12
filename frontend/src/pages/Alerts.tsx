import { useEffect, useState } from "react";
import { Alert, api, User } from "../api";
import { SeverityBadge } from "../components/Badge";
import { fmtTime, go } from "../util";

type StatusFilter = "open" | "acknowledged" | "all";

export function Alerts({ user, tenant }: { user: User; tenant: string | undefined }) {
  const [status, setStatus] = useState<StatusFilter>("open");
  const [alerts, setAlerts] = useState<Alert[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setError(null);
    api<{ alerts: Alert[] }>("/api/alerts", { params: { tenant, status: status === "all" ? undefined : status } })
      .then((r) => setAlerts(r.alerts))
      .catch((e) => setError(e.message));
  }

  useEffect(load, [status, tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  async function ack(id: number) {
    try {
      await api(`/api/alerts/${id}/ack`, { method: "POST", params: { tenant } });
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  // Open the search page on exactly the events behind the alert.
  function showEvents(a: Alert) {
    go("events", { range: "7d", src_ip: a.src_ip ?? "", tag: "auth_failure" });
  }

  return (
    <>
      <div className="filters">
        <h1 style={{ margin: 0, flex: 1 }}>Alerts</h1>
        <label>
          Status
          <select value={status} onChange={(e) => setStatus(e.target.value as StatusFilter)}>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="all">All</option>
          </select>
        </label>
      </div>
      {error && <p className="error" role="alert">{error}</p>}
      <section className="card">
        {alerts && alerts.length === 0 && <p className="muted">No {status === "all" ? "" : status} alerts.</p>}
        {alerts && alerts.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Created</th><th>Severity</th><th>Rule</th><th>Source IP</th><th className="num">Failures</th>
                  <th>Attack window</th><th>Users targeted</th><th>Status</th><th></th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id}>
                    <td className="wrap">{fmtTime(a.created_at)}</td>
                    <td><SeverityBadge severity={a.severity} /></td>
                    <td className="wrap" style={{ minWidth: 180 }}>{a.rule_name}</td>
                    <td>{a.src_ip ? <code>{a.src_ip}</code> : ""}</td>
                    <td className="num">{a.event_count}</td>
                    <td className="wrap">{fmtTime(a.window_start)} –<br />{new Date(a.window_end).toLocaleTimeString()}</td>
                    <td>{(a.details.users ?? []).join(", ")}</td>
                    <td>{a.status}{a.webhook_sent_at ? " · sent" : ""}</td>
                    <td>
                      <div style={{ display: "flex", gap: 8 }}>
                        <button onClick={() => showEvents(a)}>Events</button>
                        {/* Viewers are read-only; the API enforces this too (403). */}
                        {user.role === "admin" && a.status === "open" && <button onClick={() => ack(a.id)}>Acknowledge</button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
