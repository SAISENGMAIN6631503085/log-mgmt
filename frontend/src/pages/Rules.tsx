import { useEffect, useState } from "react";
import { api, Rule, User } from "../api";
import { SeverityBadge } from "../components/Badge";
import { Icon } from "../components/Icon";
import { go } from "../util";

// Everyone can see which rules watch their tenant; only admins can change them. The API
// enforces the same split (PUT /api/rules/{id} is admin only).

const GROUP_WORDS = { src_ip: "from one IP address", host: "on one computer" } as const;

function RuleCard({ rule, canEdit, tenant, onSaved }: {
  rule: Rule; canEdit: boolean; tenant: string | undefined; onSaved: (r: Rule) => void;
}) {
  const [threshold, setThreshold] = useState(String(rule.threshold));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const value = Number(threshold);
  const valid = Number.isInteger(value) && value >= 1 && value <= 10000;
  const dirty = valid && value !== rule.threshold;

  async function save(enabled: boolean, newThreshold: number) {
    setBusy(true);
    setError(null);
    try {
      const r = await api<Rule>(`/api/rules/${rule.id}`, { method: "PUT", body: { enabled, threshold: newThreshold }, params: { tenant } });
      onSaved(r);
      setThreshold(String(r.threshold));
      setSaved(true);
      window.setTimeout(() => setSaved(false), 1500);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className={`card rule-card ${rule.enabled ? "" : "off"}`}>
      <div className="card-head">
        <div>
          <h2>{rule.name}</h2>
          <div className="sub">{rule.description}</div>
        </div>
        <label className={`switch ${canEdit ? "" : "readonly"}`} title={canEdit ? "Turn this rule on or off" : "Only admins can change rules"}>
          <input type="checkbox" checked={rule.enabled} disabled={!canEdit || busy}
                 onChange={(e) => save(e.target.checked, rule.threshold)} aria-label={`${rule.name}: on or off`} />
          <span className="switch-track"><span className="switch-knob" /></span>
          <span className="switch-label">{rule.enabled ? "On" : "Off"}</span>
        </label>
      </div>
      <div className="card-body">
        <div className="rule-condition">
          <span>Alert when</span>
          {canEdit ? (
            <input type="number" min={1} max={10000} value={threshold} disabled={!rule.enabled || busy}
                   onChange={(e) => setThreshold(e.target.value)} aria-label="Threshold" className="threshold-input" />
          ) : (
            <strong>{rule.threshold}</strong>
          )}
          <span>or more events happen {GROUP_WORDS[rule.group_by]} within <strong>{rule.window_minutes} minutes</strong></span>
          {canEdit && dirty && (
            <button className="sm primary" onClick={() => save(rule.enabled, value)} disabled={busy}>Save</button>
          )}
          {saved && <span className="saved"><Icon name="check" size={14} />Saved</span>}
        </div>
        {canEdit && !valid && <div className="field-error">Enter a whole number from 1 to 10,000.</div>}
        {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}
        <div className="rule-foot">
          <span className="rule-foot-item">Alert severity <SeverityBadge severity={rule.severity} /></span>
          {rule.threshold !== rule.default_threshold && <span className="rule-foot-item">Default: {rule.default_threshold}</span>}
          <button className="link" onClick={() => go("alerts")}>
            {rule.open_alerts > 0 ? `${rule.open_alerts} open ${rule.open_alerts === 1 ? "alert" : "alerts"}` : "No open alerts"}
          </button>
        </div>
      </div>
    </section>
  );
}

export function Rules({ user, tenant, tenantName }: { user: User; tenant: string | undefined; tenantName: string }) {
  const [rules, setRules] = useState<Rule[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const canEdit = user.role === "admin";

  useEffect(() => {
    api<{ rules: Rule[] }>("/api/rules", { params: { tenant } })
      .then((r) => setRules(r.rules))
      .catch((e) => setError(e.message));
  }, [tenant]);

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Detection rules</h1>
          <p>
            What the system watches for in <strong>{tenantName}</strong>. Rules are checked every minute.
            {canEdit ? " Changes apply from the next check." : " Only admins can change them."}
          </p>
        </div>
      </header>
      <div className="page-body">
        {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}
        {!rules && !error && <div className="skeleton" style={{ height: 200 }} />}
        {rules?.map((r) => (
          <RuleCard key={r.id} rule={r} canEdit={canEdit} tenant={tenant}
                    onSaved={(updated) => setRules((list) => list?.map((x) => (x.id === updated.id ? updated : x)) ?? null)} />
        ))}
      </div>
    </>
  );
}
