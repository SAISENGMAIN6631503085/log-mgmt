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
const TOKENS = [
  "--chart", "--text", "--text-2", "--muted", "--grid", "--axis", "--surface",
  "--sev-1", "--sev-2", "--sev-3", "--sev-4", "--sev-none", "--ink-1", "--ink-2", "--ink-3", "--ink-4", "--ink-5",
] as const;
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

// --- readable names for codes from the logs ---
const KEEP_UPPER = new Set(["ip", "api", "aws", "id", "ssh", "dns", "mfa", "iam", "ec2", "s3", "url"]);
/** "logon_success" -> "Logon success", "UserLoggedIn" -> "User logged in", "RunInstances" -> "Run instances".
 *  Only for display: the raw value is still what search and the API use. */
export function humanize(code: string): string {
  const words = code
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")   // camelCase / PascalCase
    .replace(/[_\-.]+/g, " ")                  // snake_case, kebab-case
    .trim().toLowerCase().split(/\s+/)
    .map((w) => (KEEP_UPPER.has(w) ? w.toUpperCase() : w));
  const text = words.join(" ");
  return text ? text[0].toUpperCase() + text.slice(1) : code;
}

/** For IPs without a country: say why, instead of leaving a blank. */
export function ipKind(ip: string): string {
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(ip)) return "Private network";
  if (/^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/.test(ip)) return "Example address";
  return "Country unknown";
}

// --- countries (src_country, from the backend's DB-IP lookup) ---
/** "TH" -> 🇹🇭: a flag emoji is two "regional indicator" letters. (Windows shows the letters instead.) */
export function countryFlag(code: string): string {
  return /^[A-Za-z]{2}$/.test(code)
    ? String.fromCodePoint(...code.toUpperCase().split("").map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
    : "";
}

let countryNames: Intl.DisplayNames | null = null;
/** "TH" -> "Thailand", in English like the rest of the UI. */
export function countryName(code: string): string {
  try {
    countryNames ??= new Intl.DisplayNames(["en"], { type: "region" });
    return countryNames.of(code.toUpperCase()) ?? code;
  } catch {
    return code;
  }
}
