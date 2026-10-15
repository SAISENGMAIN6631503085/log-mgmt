import { useEffect, useRef, useState } from "react";
import { User } from "../api";
import { Theme } from "../util";
import { Icon } from "./Icon";

/** Two-state switch: the knob slides to the sun (light) or the moon (dark). */
export function ThemeSwitch({ theme, onChange }: { theme: Theme; onChange: (t: Theme) => void }) {
  const dark = theme === "dark";
  return (
    <button type="button" role="switch" aria-checked={dark} className={`theme-switch ${dark ? "is-dark" : ""}`}
            onClick={() => onChange(dark ? "light" : "dark")} title={dark ? "Switch to light mode" : "Switch to dark mode"}
            aria-label="Dark mode">
      <span className="theme-switch-icon sun"><Icon name="sun" size={14} /></span>
      <span className="theme-switch-icon moon"><Icon name="moon" size={14} /></span>
      <span className="theme-switch-knob" aria-hidden="true">
        <Icon name={dark ? "moon" : "sun"} size={14} />
      </span>
    </button>
  );
}

/** Avatar button that opens a small menu with the account details and Sign out. */
export function UserMenu({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const role = user.role === "admin" ? "Administrator" : "Viewer";
  return (
    <div className="user-menu" ref={ref}>
      <button type="button" className="user-button" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        <span className="avatar">{user.sub.slice(0, 2)}</span>
        <span className="user-button-text">
          <span className="user-name">{user.sub}</span>
          <span className="user-role">{role}</span>
        </span>
        <Icon name="chevron" size={16} />
      </button>
      {open && (
        <div className="menu" role="menu">
          <div className="menu-head">
            <span className="avatar lg">{user.sub.slice(0, 2)}</span>
            <div>
              <div className="user-name">{user.sub}</div>
              <div className="user-role">
                {role} · {user.role === "admin" ? "all tenants" : `tenant ${user.tenant}`}
              </div>
            </div>
          </div>
          {user.role === "viewer" && <div className="menu-note">Read-only access: you can view events and alerts.</div>}
          <button type="button" role="menuitem" className="menu-item" onClick={onSignOut}>
            <Icon name="logout" size={16} />Sign out
          </button>
        </div>
      )}
    </div>
  );
}

/** Admin tenant switcher: a menu (not a bare <select>) so the current tenant, the admin's
 *  default (the one that opens after sign-in, which they can change here), and the choices are all
 *  explicit. Viewers get a fixed label instead. */
export function TenantSwitcher({ current, home, tenants, onChange, onMakeDefault }: {
  current: string; home: string; tenants: string[]; onChange: (t: string) => void;
  onMakeDefault: (t: string) => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setError(null), [open, current]);

  async function makeDefault() {
    setSaving(true);
    try {
      await onMakeDefault(current);
      setOpen(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const list = tenants.length ? tenants : [home];
  return (
    <div className="user-menu" ref={ref}>
      <button type="button" className={`tenant-picker ${current !== home ? "is-switched" : ""}`}
              aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}
              title="Choose which customer's data to view">
        <Icon name="building" size={16} />
        <span className="tenant-picker-label">Viewing</span>
        <strong>{current}</strong>
        <Icon name="chevron" size={14} />
      </button>
      {open && (
        <div className="menu tenant-menu" role="menu">
          <div className="menu-title">Switch tenant</div>
          {list.map((t) => (
            <button key={t} type="button" role="menuitemradio" aria-checked={t === current}
                    className={`menu-item ${t === current ? "is-current" : ""}`}
                    onClick={() => { onChange(t); setOpen(false); }}>
              <span className="check">{t === current && <Icon name="check" size={16} />}</span>
              <span className="tenant-name">{t}</span>
              {t === home && <span className="menu-tag" title="Opens after you sign in">default</span>}
            </button>
          ))}
          {current !== home && (
            <button type="button" role="menuitem" className="menu-item make-default" onClick={makeDefault} disabled={saving}>
              <span className="check" />
              <span>{saving ? "Saving…" : <>Make <strong>{current}</strong> my default</>}</span>
            </button>
          )}
          {error && <div className="menu-note error-text" role="alert">{error}</div>}
          <div className="menu-note">As an administrator you can view every tenant. Viewers only ever see their own.</div>
        </div>
      )}
    </div>
  );
}
