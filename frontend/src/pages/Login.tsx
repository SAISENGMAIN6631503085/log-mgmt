import { FormEvent, useState } from "react";
import { api, saveSession, User } from "../api";
import { Icon } from "../components/Icon";

// Split layout: a dark product panel (what the tool does, shown with log lines like the ones it
// handles) and a plain sign-in form. The log lines are decoration only (aria-hidden).
const STREAM: { sev: "crit" | "high" | "med" | "low"; src: string; text: string }[] = [
  { sev: "crit", src: "crowdstrike", text: "malware_detected  host=WS-071  process=mimikatz.exe  action=quarantine" },
  { sev: "high", src: "ad", text: "logon_failure  user=administrator  ip=88.198.10.118  ×6 in 1 min" },
  { sev: "low", src: "firewall", text: "allow  10.0.1.24:52144 → 10.0.2.10:443  proto=tcp" },
  { sev: "med", src: "firewall", text: "deny  113.160.10.118 → 10.0.1.10:22  policy=Block-SSH" },
  { sev: "low", src: "m365", text: "UserLoggedIn  user=erin@contoso.com  ip=1.46.10.5" },
  { sev: "low", src: "aws", text: "RunInstances  region=ap-southeast-1  user=deploy-bot" },
  { sev: "med", src: "network", text: "link_down  core-sw01  interface=Gi1/0/17" },
  { sev: "high", src: "api", text: "login_failed  service=payments-api  user=dave  status=401" },
  { sev: "low", src: "ad", text: "logon_success  user=carol  host=DC01" },
  { sev: "low", src: "firewall", text: "allow  10.0.3.45:61022 → 8.8.8.8:53  proto=udp" },
];

export function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
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
      <aside className="login-hero">
        <div className="login-hero-brand">
          <span className="brand-mark"><Icon name="logo" /></span>
          <span>Log Management</span>
        </div>

        <div className="login-hero-copy">
          <h2>Every security event,<br />one place to look.</h2>
          <p>Firewalls, servers, cloud and endpoints, collected and searchable in seconds, with alerts when something looks wrong.</p>
        </div>

        <div className="log-stream" aria-hidden="true">
          {/* Listed twice so the slow scroll loops without a jump */}
          <div className="log-stream-track">
            {[...STREAM, ...STREAM].map((l, i) => (
              <div key={i} className="log-line">
                <span className={`log-sev ${l.sev}`} />
                <span className="log-src">{l.src}</span>
                <span className="log-text">{l.text}</span>
              </div>
            ))}
          </div>
        </div>

        <ul className="login-hero-facts">
          <li><strong>7</strong> log sources</li>
          <li><strong>60 s</strong> alert checks</li>
          <li><strong>7 days</strong> searchable</li>
        </ul>
      </aside>

      <main className="login-main">
        <form className="login-form" onSubmit={submit}>
          <div className="login-mobile-brand">
            <span className="brand-mark"><Icon name="logo" /></span>
            <span>Log Management</span>
          </div>
          <h1>Sign in</h1>
          <p className="lead">to see your organization's security events.</p>

          <label className="field">
            Username
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
          </label>
          <label className="field">
            Password
            <span className="password-wrap">
              <input type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)}
                     autoComplete="current-password" required />
              <button type="button" className="icon-btn reveal" onClick={() => setShowPassword((v) => !v)}
                      aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword}>
                <Icon name={showPassword ? "eyeOff" : "eye"} size={16} />
              </button>
            </span>
          </label>

          {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}
          <button className="primary login-submit" disabled={busy}>
            {busy ? "Signing in…" : <>Sign in<Icon name="arrowRight" size={16} /></>}
          </button>

          <p className="login-foot">
            <Icon name="lock" size={13} />Encrypted connection. Each organization sees only its own data.
          </p>
          <p className="login-demo">Demo accounts: <code>admin</code>, <code>viewerA</code>, <code>viewerB</code></p>
        </form>
      </main>
    </div>
  );
}
