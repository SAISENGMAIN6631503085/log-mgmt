import { FormEvent, useState } from "react";
import { api, saveSession, User } from "../api";
import { Icon } from "../components/Icon";

export function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ access_token: string; user: User }>("/api/auth/login", {
        method: "POST",
        body: { username, password },
      });
      saveSession(res.access_token, res.user);
      onLogin(res.user);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <div className="card login-card">
        <div className="brand">
          <span className="brand-mark"><Icon name="logo" /></span>
          <div>
            <div className="brand-name">Log Management</div>
            <div className="brand-sub">Security events</div>
          </div>
        </div>
        <h1>Sign in</h1>
        <p className="lead">Use your account to view your organization's events.</p>
        <form onSubmit={submit}>
          <label className="field">
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
          </label>
          <label className="field">
            Password
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          </label>
          {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}
          <button className="primary" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
        </form>
        <p className="hint">Demo accounts: admin, viewerA, viewerB</p>
      </div>
    </div>
  );
}
