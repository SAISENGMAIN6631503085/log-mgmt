import { useEffect, useState } from "react";
import { api } from "../api";
import { CodeBlock } from "../components/CodeBlock";
import { Icon } from "../components/Icon";
import { fmtNum, go } from "../util";

// Admin only (the menu hides it from viewers, and the API returns 403 for them anyway).
// Onboarding a customer: add the tenant (which creates its first API key, so it can send logs at
// once), then give their staff viewer sign-ins that can only ever see this tenant.

type TenantRow = { tenant: string; viewers: string[]; active_keys: number };

export function Tenants({ current, onView, onChanged }: {
  current: string; onView: (tenant: string) => void; onChanged: () => void;
}) {
  const [rows, setRows] = useState<TenantRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<{ tenant: string; key: string } | null>(null);
  const [addingTo, setAddingTo] = useState<string | null>(null); // the row with the open "add viewer" form

  const load = () => api<TenantRow[]>("/api/admin/tenants").then(setRows).catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  async function addTenant(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setCreated(await api<{ tenant: string; key: string }>("/api/admin/tenants", { method: "POST", body: { name: name.trim() } }));
      setName("");
      await load();
      onChanged(); // the tenant menu in the top bar lists it too
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Tenants</h1>
          <p>Each tenant is one customer. Their logs and alerts are kept apart, and their viewers only ever see their own.</p>
        </div>
      </header>
      <div className="page-body">
        {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}

        <section className="card">
          <div className="card-head">
            <div>
              <h2>Add a tenant</h2>
              <div className="sub">It gets its first API key straight away, so it can start sending logs.</div>
            </div>
          </div>
          <div className="card-body">
            <form className="key-form" onSubmit={addTenant}>
              <input value={name} onChange={(e) => setName(e.target.value)} maxLength={32} pattern="[A-Za-z][A-Za-z0-9_\-]{1,31}"
                     title="2 to 32 letters, digits, - or _, starting with a letter"
                     placeholder='Customer name, e.g. "acme"' aria-label="Tenant name" />
              <button className="primary" type="submit" disabled={busy || !name.trim()}>
                <Icon name="building" size={16} />{busy ? "Adding…" : "Add tenant"}
              </button>
            </form>
            <div className="muted small form-hint">Letters, digits, - and _, starting with a letter. It can't be renamed later.</div>

            {created && (
              <div className="new-key" role="status">
                <div className="new-key-head">
                  <span className="ok-mark"><Icon name="check" size={16} /></span>
                  <div>
                    <strong>Tenant {created.tenant} added</strong>
                    <div className="muted small">Copy its API key now; it can't be shown again. Next, add a viewer below so their staff can sign in.</div>
                  </div>
                  <button className="sm ghost" onClick={() => setCreated(null)} aria-label="Hide key"><Icon name="x" size={14} /></button>
                </div>
                <CodeBlock label={`API key for ${created.tenant} (send it in the X-API-Key header)`} code={created.key} />
              </div>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h2>All tenants</h2>
              <div className="sub">{rows ? `${fmtNum(rows.length)} ${rows.length === 1 ? "tenant" : "tenants"}` : "Loading…"}</div>
            </div>
          </div>
          <div className="card-body flush table-wrap">
            <table className="tenants-table">
              <thead><tr><th>Tenant</th><th>Viewers (can sign in)</th><th className="num">Active API keys</th><th /></tr></thead>
              <tbody>
                {(rows ?? []).map((t) => (
                  <TenantRowView key={t.tenant} t={t} viewing={t.tenant === current} adding={addingTo === t.tenant}
                                 onAdd={() => setAddingTo(addingTo === t.tenant ? null : t.tenant)}
                                 onAdded={() => { setAddingTo(null); load(); }}
                                 onView={() => { onView(t.tenant); go("dashboard"); }} />
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  );
}

function TenantRowView({ t, viewing, adding, onAdd, onAdded, onView }: {
  t: TenantRow; viewing: boolean; adding: boolean; onAdd: () => void; onAdded: () => void; onView: () => void;
}) {
  return (
    <>
      <tr>
        <td><strong>{t.tenant}</strong>{viewing && <span className="menu-tag inline-tag">viewing</span>}</td>
        <td className="wrap">
          {t.viewers.length ? t.viewers.map((v) => <span key={v} className="chip">{v}</span>)
            : <span className="muted">None yet</span>}
        </td>
        <td className="num">{t.active_keys}</td>
        <td className="num">
          <div className="row-actions">
            <button className="sm" onClick={onAdd} aria-expanded={adding}><Icon name="user" size={14} />Add viewer</button>
            {!viewing && <button className="sm ghost" onClick={onView}>View data</button>}
          </div>
        </td>
      </tr>
      {adding && (
        <tr className="form-row">
          <td colSpan={4}><AddViewer tenant={t.tenant} onAdded={onAdded} onCancel={onAdd} /></td>
        </tr>
      )}
    </>
  );
}

function AddViewer({ tenant, onAdded, onCancel }: { tenant: string; onAdded: () => void; onCancel: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api(`/api/admin/tenants/${encodeURIComponent(tenant)}/viewers`, { method: "POST", body: { username: username.trim(), password } });
      onAdded();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="add-viewer" onSubmit={submit}>
      <div className="add-viewer-title">New viewer for <strong>{tenant}</strong>: read-only, and only this tenant.</div>
      <div className="add-viewer-fields">
        <label className="field">Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="off"
                 maxLength={32} pattern="[A-Za-z][A-Za-z0-9_\-]{1,31}" title="2 to 32 letters, digits, - or _, starting with a letter" />
        </label>
        <label className="field">Password (at least 12 characters)
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={12} />
        </label>
        <div className="add-viewer-buttons">
          <button className="primary sm" type="submit" disabled={busy || !username.trim() || password.length < 12}>
            {busy ? "Adding…" : "Add viewer"}
          </button>
          <button className="sm ghost" type="button" onClick={onCancel}>Cancel</button>
        </div>
      </div>
      {error && <div className="field-error" role="alert">{error}</div>}
      <div className="muted small">Give them the password in person or another safe way. It's stored scrambled and can't be shown again.</div>
    </form>
  );
}
