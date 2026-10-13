import { useEffect, useState } from "react";
import { Alert, api, clearSession, loadSession, User } from "./api";
import { Icon, IconName } from "./components/Icon";
import { TenantSwitcher, ThemeSwitch, UserMenu } from "./components/TopBar";
import { AddLogs } from "./pages/AddLogs";
import { Alerts } from "./pages/Alerts";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { Login } from "./pages/Login";
import { applyTheme, loadTheme, Theme, useRoute } from "./util";

const PAGES: { key: string; label: string; icon: IconName }[] = [
  { key: "dashboard", label: "Overview", icon: "dashboard" },
  { key: "events", label: "Search", icon: "search" },
  { key: "alerts", label: "Alerts", icon: "bell" },
  { key: "add", label: "Add logs", icon: "upload" },
];

export default function App() {
  const [user, setUser] = useState<User | null>(() => loadSession()?.user ?? null);
  // Admin only: which tenant to view. Viewers never send a tenant; the server uses their JWT.
  // Kept for this browser tab, so a reload doesn't silently jump back to the default tenant.
  const [tenant, setTenantState] = useState<string | undefined>(() => {
    try {
      return sessionStorage.getItem("lm_tenant") ?? undefined;
    } catch {
      return undefined;
    }
  });
  const setTenant = (t: string | undefined) => {
    setTenantState(t);
    try {
      if (t) sessionStorage.setItem("lm_tenant", t);
      else sessionStorage.removeItem("lm_tenant");
    } catch {
      /* per-tab convenience only */
    }
  };
  const [tenants, setTenants] = useState<string[]>([]);
  const [openAlerts, setOpenAlerts] = useState(0);
  const [theme, setTheme] = useState<Theme>(loadTheme);
  const route = useRoute();

  useEffect(() => applyTheme(theme, false), []); // eslint-disable-line react-hooks/exhaustive-deps
  const changeTheme = (t: Theme) => {
    setTheme(t);
    applyTheme(t, true); // an explicit choice is remembered
  };

  // Any 401 (expired/invalid token) sends us back to the login page.
  useEffect(() => {
    const onLogout = () => setUser(null);
    window.addEventListener("lm:logout", onLogout);
    return () => window.removeEventListener("lm:logout", onLogout);
  }, []);

  useEffect(() => {
    if (!user) return;
    if (user.role !== "admin") {
      setTenant(undefined); // a viewer's tenant always comes from their token
      return;
    }
    api<string[]>("/api/tenants")
      .then((list) => {
        setTenants(list);
        // A remembered tenant that no longer exists falls back to the admin's default.
        if (tenant && !list.includes(tenant)) setTenant(undefined);
      })
      .catch(() => setTenants([]));
  }, [user]); // eslint-disable-line react-hooks/exhaustive-deps

  // Open-alert count for the sidebar badge; refreshed on the alert worker's cadence.
  useEffect(() => {
    if (!user) return;
    const load = () =>
      api<{ alerts: Alert[] }>("/api/alerts", { params: { tenant, status: "open" } })
        .then((r) => setOpenAlerts(r.alerts.length))
        .catch(() => {});
    load();
    const id = window.setInterval(load, 60_000);
    return () => window.clearInterval(id);
  }, [user, tenant, route.page]);

  if (!user) return <Login onLogin={(u) => { setTenant(undefined); setUser(u); }} />;

  function logout() {
    clearSession();
    setTenant(undefined);
    setUser(null);
  }

  const page = PAGES.some((p) => p.key === route.page) ? route.page : "dashboard";
  const activeTenant = tenant ?? user.tenant;
  // Remount pages when the tenant changes so no data from the previous tenant lingers.
  const key = `${page}:${activeTenant}`;

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><Icon name="logo" /></span>
          <div>
            <div className="brand-name">Log Management</div>
            <div className="brand-sub">Security events</div>
          </div>
        </div>
        <nav className="nav" aria-label="Main">
          {PAGES.map((p) => (
            <a key={p.key} href={`#/${p.key}`} className={page === p.key ? "active" : ""}
               aria-current={page === p.key ? "page" : undefined}>
              <Icon name={p.icon} />
              {p.label}
              {p.key === "alerts" && openAlerts > 0 && <span className="count" aria-label={`${openAlerts} open`}>{openAlerts}</span>}
            </a>
          ))}
        </nav>
      </aside>

      <div className="content">
        <header className="topbar">
          {user.role === "admin" ? (
            <TenantSwitcher current={activeTenant} home={user.tenant} tenants={tenants}
                            onChange={(t) => setTenant(t === user.tenant ? undefined : t)} />
          ) : (
            <span className="tenant-picker static" title="Your organization (fixed for your account)">
              <Icon name="building" size={16} />
              <span className="tenant-picker-label">Tenant</span>
              <strong>{user.tenant}</strong>
            </span>
          )}
          <span className="topbar-divider" aria-hidden="true" />
          <ThemeSwitch theme={theme} onChange={changeTheme} />
          <UserMenu user={user} onSignOut={logout} />
        </header>

        {page === "dashboard" && <Dashboard key={key} tenant={tenant} tenantName={activeTenant} />}
        {page === "events" && <Events key={key} route={route} tenant={tenant} tenantName={activeTenant} />}
        {page === "add" && <AddLogs key={key} user={user} tenant={tenant} tenantName={activeTenant} />}
        {page === "alerts" && <Alerts key={key} user={user} tenant={tenant} tenantName={activeTenant} onChange={setOpenAlerts} />}
      </div>
    </div>
  );
}
