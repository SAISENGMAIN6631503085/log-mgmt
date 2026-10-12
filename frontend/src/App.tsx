import { useEffect, useState } from "react";
import { api, clearSession, loadSession, User } from "./api";
import { Alerts } from "./pages/Alerts";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { Login } from "./pages/Login";
import { useRoute } from "./util";

const PAGES = [
  { key: "dashboard", label: "Dashboard" },
  { key: "events", label: "Search" },
  { key: "alerts", label: "Alerts" },
];

export default function App() {
  const [user, setUser] = useState<User | null>(() => loadSession()?.user ?? null);
  // Admin only: which tenant to view. Viewers never send a tenant; the server uses their JWT.
  const [tenant, setTenant] = useState<string | undefined>(undefined);
  const [tenants, setTenants] = useState<string[]>([]);
  const route = useRoute();

  // Any 401 (expired/invalid token) sends us back to the login page.
  useEffect(() => {
    const onLogout = () => setUser(null);
    window.addEventListener("lm:logout", onLogout);
    return () => window.removeEventListener("lm:logout", onLogout);
  }, []);

  useEffect(() => {
    if (user?.role !== "admin") return;
    api<string[]>("/api/tenants").then(setTenants).catch(() => setTenants([]));
  }, [user]);

  if (!user) return <Login onLogin={(u) => { setUser(u); setTenant(undefined); }} />;

  function logout() {
    clearSession();
    setUser(null);
  }

  const page = PAGES.some((p) => p.key === route.page) ? route.page : "dashboard";
  // Remount pages when the tenant changes so no data from the previous tenant lingers.
  const key = `${page}:${tenant ?? user.tenant}`;

  return (
    <>
      <header className="topbar">
        <span className="brand">Log Management</span>
        <nav className="nav">
          {PAGES.map((p) => (
            <a key={p.key} href={`#/${p.key}`} className={page === p.key ? "active" : ""}>{p.label}</a>
          ))}
        </nav>
        <span className="spacer" />
        <span className="who">
          {user.role === "admin" ? (
            <label>
              Tenant{" "}
              <select value={tenant ?? user.tenant} onChange={(e) => setTenant(e.target.value)}>
                {(tenants.length ? tenants : [user.tenant]).map((t) => <option key={t}>{t}</option>)}
              </select>
            </label>
          ) : (
            <span>Tenant <strong>{user.tenant}</strong></span>
          )}
          <span>· {user.sub} ({user.role})</span>
          <button onClick={logout}>Sign out</button>
        </span>
      </header>
      <main>
        {page === "dashboard" && <Dashboard key={key} tenant={tenant} />}
        {page === "events" && <Events key={key} route={route} tenant={tenant} />}
        {page === "alerts" && <Alerts key={key} user={user} tenant={tenant} />}
      </main>
    </>
  );
}
