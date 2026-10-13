import { useEffect, useState } from "react";
import { api } from "../api";
import { Empty } from "../components/Badge";
import { CodeBlock } from "../components/CodeBlock";
import { Icon } from "../components/Icon";
import { go } from "../util";

// Admin only (the menu hides it from viewers, and the API returns 403 for them anyway).
// A key decides which tenant its logs go into, so keys are listed and created per tenant.

type ApiKey = { id: number; name: string; prefix: string; created_at: string; revoked_at: string | null };

const fmtDate = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

export function ApiKeys({ tenant, tenantName }: { tenant: string | undefined; tenantName: string }) {
  const [keys, setKeys] = useState<ApiKey[] | null>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<(ApiKey & { key: string }) | null>(null);

  const load = () =>
    api<{ keys: ApiKey[] }>("/api/keys", { params: { tenant } })
      .then((r) => setKeys(r.keys))
      .catch((e) => setError(e.message));
  useEffect(() => { load(); }, [tenant]); // eslint-disable-line react-hooks/exhaustive-deps

  async function create(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setCreated(await api<ApiKey & { key: string }>("/api/keys", { method: "POST", body: { name: name.trim() }, params: { tenant } }));
      setName("");
      await load();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(k: ApiKey) {
    if (!window.confirm(`Revoke "${k.name}"? Anything using this key will stop sending logs right away.`)) return;
    setError(null);
    try {
      await api(`/api/keys/${k.id}/revoke`, { method: "POST", params: { tenant } });
      if (created?.id === k.id) setCreated(null);
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  }

  const active = keys?.filter((k) => !k.revoked_at).length ?? 0;

  return (
    <>
      <header className="page-header">
        <div>
          <h1>API keys</h1>
          <p>
            Apps and log senders use a key to send logs into <strong>{tenantName}</strong>. The key decides the tenant,
            so give each one only to the system that needs it.
          </p>
        </div>
      </header>
      <div className="page-body">
        {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}

        <section className="card">
          <div className="card-head">
            <div>
              <h2>Create a key</h2>
              <div className="sub">Name it after what will use it, so you know which one to revoke later.</div>
            </div>
          </div>
          <div className="card-body">
            <form className="key-form" onSubmit={create}>
              <input value={name} onChange={(e) => setName(e.target.value)} maxLength={60}
                     placeholder='e.g. "shop website" or "firewall-01"' aria-label="Key name" />
              <button className="primary" type="submit" disabled={busy || !name.trim()}>
                <Icon name="key" size={16} />{busy ? "Creating…" : "Create key"}
              </button>
            </form>

            {created && (
              <div className="new-key" role="status">
                <div className="new-key-head">
                  <span className="ok-mark"><Icon name="check" size={16} /></span>
                  <div>
                    <strong>Key "{created.name}" created for {tenantName}</strong>
                    <div className="muted small">Copy it now. For safety it's stored scrambled, so it can't be shown again.</div>
                  </div>
                  <button className="sm ghost" onClick={() => setCreated(null)} aria-label="Hide key"><Icon name="x" size={14} /></button>
                </div>
                <CodeBlock label="API key (send it in the X-API-Key header)" code={created.key} />
                <button className="link small" onClick={() => go("add")}>How do I send logs with it?</button>
              </div>
            )}
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h2>Keys for {tenantName}</h2>
              <div className="sub">{keys ? `${active} active${keys.length > active ? ` · ${keys.length - active} revoked` : ""}` : "Loading…"}</div>
            </div>
          </div>
          {keys && keys.length === 0 ? (
            <Empty icon={<Icon name="key" />} title="No keys yet">Create one above to start sending logs.</Empty>
          ) : (
            <div className="card-body flush table-wrap">
              <table className="keys-table">
                <thead><tr><th>Name</th><th>Key</th><th>Created</th><th>Status</th><th /></tr></thead>
                <tbody>
                  {(keys ?? []).map((k) => (
                    <tr key={k.id} className={k.revoked_at ? "revoked" : ""}>
                      <td>{k.name}</td>
                      <td><code>{k.prefix}…</code></td>
                      <td>{fmtDate(k.created_at)}</td>
                      <td>
                        <span className={`pill ${k.revoked_at ? "status-revoked" : "status-active"}`}
                              title={k.revoked_at ? `Revoked on ${fmtDate(k.revoked_at)}` : undefined}>
                          <span className="dot" />{k.revoked_at ? "Revoked" : "Active"}
                        </span>
                      </td>
                      <td className="num">
                        {!k.revoked_at && <button className="sm" onClick={() => revoke(k)}>Revoke</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </>
  );
}
