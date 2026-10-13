// Thin fetch wrapper: adds the JWT, turns errors into exceptions, and logs out on 401.

export type Role = "admin" | "viewer";
export type User = { sub: string; role: Role; tenant: string };

const TOKEN_KEY = "lm_token";
const USER_KEY = "lm_user";

// localStorage keeps you logged in across reloads. Trade-off: any XSS could read the token;
// an httpOnly cookie would avoid that but needs CSRF protection. Fine for this demo, noted in the README.
export function loadSession(): { token: string; user: User } | null {
  try {
    const token = localStorage.getItem(TOKEN_KEY);
    const user = localStorage.getItem(USER_KEY);
    return token && user ? { token, user: JSON.parse(user) as User } : null;
  } catch {
    return null;
  }
}

export function saveSession(token: string, user: User) {
  try {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
  } catch {
    /* private mode etc.: session lasts until reload */
  }
  memoryToken = token;
}

export function clearSession() {
  try {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  } catch {
    /* ignore */
  }
  memoryToken = null;
}

let memoryToken: string | null = loadSession()?.token ?? null;

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

type Params = Record<string, string | number | string[] | undefined | null>;

export async function api<T>(path: string, opts: { method?: string; body?: unknown; params?: Params } = {}): Promise<T> {
  const url = new URL(path, window.location.origin);
  for (const [k, v] of Object.entries(opts.params ?? {})) {
    if (v === undefined || v === null || v === "") continue;
    for (const item of Array.isArray(v) ? v : [v]) url.searchParams.append(k, String(item));
  }
  const res = await fetch(url, {
    method: opts.method ?? "GET",
    headers: {
      ...(memoryToken ? { Authorization: `Bearer ${memoryToken}` } : {}),
      ...(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    let message = res.statusText;
    try {
      const data = await res.json();
      message = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
    } catch {
      /* not JSON */
    }
    if (res.status === 401 && path !== "/api/auth/login") {
      clearSession();
      window.dispatchEvent(new Event("lm:logout")); // App listens and shows the login page
    }
    throw new ApiError(res.status, message);
  }
  return res.json() as Promise<T>;
}

// --- API types (mirror the backend responses) ---

export type LogEvent = {
  id: number;
  "@timestamp": string;
  tenant: string;
  source: string;
  vendor: string | null;
  product: string | null;
  event_type: string | null;
  event_subtype: string | null;
  severity: number | null;
  action: string | null;
  src_ip: string | null;
  src_port: number | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: string | null;
  user: string | null;
  host: string | null;
  process: string | null;
  url: string | null;
  http_method: string | null;
  status_code: number | null;
  rule_name: string | null;
  rule_id: string | null;
  cloud_account_id: string | null;
  cloud_region: string | null;
  cloud_service: string | null;
  raw: unknown;
  _tags: string[];
};

export type Alert = {
  id: number;
  tenant: string;
  rule_id: string;
  rule_name: string;
  severity: number;
  src_ip: string | null;
  event_count: number;
  window_start: string;
  window_end: string;
  details: { users?: string[]; sources?: string[] };
  status: "open" | "acknowledged";
  created_at: string;
  webhook_sent_at: string | null;
};

export type Stats = {
  tenant: string;
  from: string;
  to: string;
  bucket_seconds: number;
  totals: { events: number; auth_failures: number; high_severity: number; unique_src_ips: number; open_alerts: number };
  previous: { events: number; auth_failures: number; high_severity: number };
  timeline: TimelinePoint[];
  source_timeline: { source: string; t: string; n: number }[];
  by_source: { key: string; n: number }[];
  by_severity: { key: string; n: number }[];
  top_src_ips: { key: string; n: number; auth_failures: number }[];
  top_users: { key: string; n: number; auth_failures: number }[];
  top_event_types: { key: string; n: number }[];
};

export type TimelinePoint = {
  t: string;
  n: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  auth_failures: number;
};

export const SOURCES = ["firewall", "network", "api", "crowdstrike", "aws", "m365", "ad"] as const;
