import { FormEvent, KeyboardEvent, useEffect, useState } from "react";
import { api, ApiError, saveSession, User } from "../api";
import { Icon } from "../components/Icon";
import { IngestPreview } from "../components/IngestPreview";

// Split layout: a dark product panel showing what the tool does (logs from many systems turned
// into one format, and an alert when they add up to an attack) and a plain sign-in form.
// The headline types itself once when the page opens; the line under it fades in when the typing
// is done, and the cursor keeps blinking softly at the end. The whole sentence is always laid out,
// with the part not typed yet invisible, so lines break in the same places from the first letter
// and nothing jumps. The cursor is glued to the last typed letter (spaces wait until the next
// letter), so it never floats after a space or drops to a line of its own. Screen readers get the
// whole sentence at once; with reduced motion everything is shown complete.
function useTyping(text: string) {
  const still = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const [count, setCount] = useState(still ? text.length : 0);
  useEffect(() => {
    if (still || count >= text.length) return;
    // A person's rhythm: a beat before starting, ~85 ms a letter, a little longer between words
    // and after the comma.
    const prev = text[count - 1];
    const delay = count === 0 ? 600 : prev === "," ? 420 : prev === " " ? 150 : 85;
    const id = window.setTimeout(() => setCount((n) => n + 1), delay);
    return () => window.clearTimeout(id);
  }, [count, still, text]);
  return { count, done: count >= text.length, still };
}

function TypedHeading({ text, count, still }: { text: string; count: number; still: boolean }) {
  const typed = text.slice(0, count).trimEnd(); // trailing spaces are shown with the next letter
  const caret = <span className={`typed-caret${still ? " is-still" : ""}`} />;
  return (
    <h2 aria-label={text}>
      <span aria-hidden="true">
        {typed.length === 0 ? caret : (
          <>
            {typed.slice(0, -1)}
            <span className="typed-tail">{typed.slice(-1)}{caret}</span>
          </>
        )}
        <span className="typed-rest">{text.slice(typed.length)}</span>
      </span>
    </h2>
  );
}

const mmss = (s: number) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;

const HEADLINE = "Logs from every system, read as one";

export function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const typing = useTyping(HEADLINE);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [capsLock, setCapsLock] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // Seconds until sign-in is allowed again, after too many failed attempts (server says how long).
  const [lockedFor, setLockedFor] = useState(0);

  useEffect(() => {
    if (lockedFor <= 0) return;
    const id = window.setTimeout(() => setLockedFor((s) => s - 1), 1000);
    return () => window.clearTimeout(id);
  }, [lockedFor]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (lockedFor > 0) return;
    if (!username.trim() || !password) {
      setError("Enter your username and password.");
      return;
    }
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
      if (err instanceof ApiError && err.status === 429) {
        setLockedFor(err.retryAfter ?? 60);
      } else if (err instanceof ApiError && err.status === 401) {
        setError("That username and password don't match. Check them and try again.");
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setBusy(false);
    }
  }

  const watchCaps = (e: KeyboardEvent<HTMLInputElement>) => setCapsLock(e.getModifierState("CapsLock"));

  return (
    <div className="login-page">
      <aside className="login-hero">
        <div className="login-hero-brand">
          <span className="brand-mark"><Icon name="logo" size={21} /></span>
          <span>Log Management</span>
        </div>

        <div className="login-hero-copy">
          <TypedHeading text={HEADLINE} count={typing.count} still={typing.still} />
          <p className={`after-typing${typing.done ? " is-shown" : ""}`}>
            Firewalls, Windows, AWS, Microsoft 365 and CrowdStrike, searched together and watched for attacks.
          </p>
        </div>

        <IngestPreview />
      </aside>

      <main className="login-main">
        <form className="login-form" onSubmit={submit} noValidate>
          <div className="login-mobile-brand">
            <span className="brand-mark"><Icon name="logo" size={21} /></span>
            <span>Log Management</span>
          </div>
          <div>
            <h1>Sign in</h1>
            <p className="lead">Use the account your administrator gave you.</p>
          </div>

          <label className="field">
            Username
            <span className="input-icon">
              <Icon name="user" size={16} />
              <input value={username} onChange={(e) => setUsername(e.target.value)} onKeyUp={watchCaps}
                     autoComplete="username" autoFocus required spellCheck={false} autoCapitalize="none" />
            </span>
          </label>
          <label className="field">
            Password
            <span className="input-icon">
              <Icon name="lock" size={16} />
              <input type={showPassword ? "text" : "password"} value={password} onChange={(e) => setPassword(e.target.value)}
                     onKeyUp={watchCaps} onKeyDown={watchCaps} autoComplete="current-password" required />
              <button type="button" className="icon-btn reveal" onClick={() => setShowPassword((v) => !v)}
                      aria-label={showPassword ? "Hide password" : "Show password"} aria-pressed={showPassword}>
                <Icon name={showPassword ? "eyeOff" : "eye"} size={16} />
              </button>
            </span>
            {capsLock && <span className="caps-warning" role="status"><Icon name="alert" size={13} />Caps Lock is on</span>}
          </label>

          {lockedFor > 0 ? (
            <div className="login-locked" role="alert">
              <Icon name="lock" size={16} />
              <div>
                <strong>Too many failed sign-ins</strong>
                <span>For safety, this account is paused. Try again in <b>{mmss(lockedFor)}</b>.</span>
              </div>
            </div>
          ) : error && (
            <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>
          )}

          <button className="primary login-submit" disabled={busy || lockedFor > 0}>
            {busy ? <><span className="spinner" aria-hidden="true" />Signing in</> : "Sign in"}
          </button>

          <p className="login-foot">
            <Icon name="lock" size={13} />Encrypted connection. Each organization sees only its own data.
          </p>
          <div className="login-demo">
            <span>Demo accounts</span>
            <code>admin</code><code>viewerA</code><code>viewerB</code>
          </div>
        </form>
      </main>
    </div>
  );
}
