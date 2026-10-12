import { useEffect, useState } from "react";

// --- time ranges (shared by dashboard and search) ---
export const RANGES = [
  { key: "1h", label: "1h", long: "last hour", ms: 3600e3 },
  { key: "24h", label: "24h", long: "last 24 hours", ms: 24 * 3600e3 },
  { key: "7d", label: "7d", long: "last 7 days", ms: 7 * 24 * 3600e3 },
] as const;
export type RangeKey = (typeof RANGES)[number]["key"];

export function rangeParams(key: RangeKey) {
  const ms = RANGES.find((r) => r.key === key)!.ms;
  const to = new Date();
  return { from: new Date(to.getTime() - ms).toISOString(), to: to.toISOString() };
}

// Times are stored in UTC and shown in the viewer's local time.
export const fmtTime = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });

export const fmtNum = (n: number) => n.toLocaleString();

export function severityLevel(sev: number | null): "critical" | "high" | "medium" | "low" | "unknown" {
  if (sev === null) return "unknown";
  if (sev >= 9) return "critical";
  if (sev >= 7) return "high";
  if (sev >= 4) return "medium";
  return "low";
}

// --- hash routing: "#/events?src_ip=1.2.3.4" -> { page: "events", params } ---
export type Route = { page: string; params: URLSearchParams };

function parseHash(): Route {
  const [path, query] = window.location.hash.replace(/^#\/?/, "").split("?");
  return { page: path || "dashboard", params: new URLSearchParams(query ?? "") };
}

export function useRoute(): Route {
  const [route, setRoute] = useState(parseHash);
  useEffect(() => {
    const onChange = () => setRoute(parseHash());
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return route;
}

export function go(page: string, params: Record<string, string> = {}) {
  const q = new URLSearchParams(params).toString();
  window.location.hash = `/${page}${q ? `?${q}` : ""}`;
}

// --- theme tokens for SVG charts ---
// Recharts writes colours as SVG attributes, where var(--x) doesn't resolve, so read the
// computed token values and re-read them when the OS theme changes.
const TOKENS = ["--chart", "--text", "--text-2", "--muted", "--grid", "--axis", "--surface"] as const;
export type Tokens = Record<(typeof TOKENS)[number], string>;

function readTokens(): Tokens {
  const s = getComputedStyle(document.documentElement);
  return Object.fromEntries(TOKENS.map((t) => [t, s.getPropertyValue(t).trim()])) as Tokens;
}

export function useTokens(): Tokens {
  const [tokens, setTokens] = useState(readTokens);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const update = () => setTokens(readTokens());
    mq.addEventListener("change", update);
    const obs = new MutationObserver(update); // data-theme toggles
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => {
      mq.removeEventListener("change", update);
      obs.disconnect();
    };
  }, []);
  return tokens;
}

// --- theme: light or dark. First visit follows the OS; after that the viewer's choice sticks. ---
export type Theme = "light" | "dark";

export function loadTheme(): Theme {
  try {
    const t = localStorage.getItem("lm_theme");
    if (t === "light" || t === "dark") return t;
  } catch {
    /* storage blocked: fall through to the OS setting */
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function applyTheme(theme: Theme, remember: boolean) {
  document.documentElement.dataset.theme = theme;
  if (!remember) return;
  try {
    localStorage.setItem("lm_theme", theme);
  } catch {
    /* per-viewer convenience only */
  }
}

// Plain names for the source codes used in the API (?source=ad etc.)
export const SOURCE_LABELS: Record<string, string> = {
  firewall: "Firewall", network: "Network device", api: "Application", crowdstrike: "CrowdStrike",
  aws: "AWS", m365: "Microsoft 365", ad: "Active Directory",
};
export const sourceLabel = (s: string) => SOURCE_LABELS[s] ?? s;
