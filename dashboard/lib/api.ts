/**
 * Typed REST client for the Sentinel control-plane API.
 * All paths are relative so Next.js rewrites proxy them to the control plane.
 */
import { getToken, logout, refreshToken } from "./auth";

const BASE = "/api/v1";

// ---------------------------------------------------------------------------
// Core fetch with auth + auto-refresh
// ---------------------------------------------------------------------------

async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res = await fetch(`${BASE}${path}`, { ...init, headers });

  // Attempt one token refresh on 401.
  if (res.status === 401) {
    const refreshed = await refreshToken();
    if (refreshed) {
      const newToken = getToken();
      if (newToken) headers["Authorization"] = `Bearer ${newToken}`;
      res = await fetch(`${BASE}${path}`, { ...init, headers });
    } else {
      logout();
      if (typeof window !== "undefined") window.location.href = "/login";
      throw new Error("Session expired — redirecting to login");
    }
  }

  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${path}: ${res.status} ${text}`);
  }
  return res.json() as Promise<T>;
}

// ---------------------------------------------------------------------------
// Types (mirrors control-plane REST API responses)
// ---------------------------------------------------------------------------

export interface DashboardStats {
  total_sites:     number;
  active_sites:    number;
  total_rules:     number;
  enabled_rules:   number;
  open_alerts:     number;
  critical_alerts: number;
}

export interface Site {
  id:         string;
  tenant_id:  string;
  name:       string;
  domains:    string[];
  upstream:   Record<string, unknown>;
  waf_policy: { mode: string; paranoia_level: number; anomaly_threshold: number };
  status:     "active" | "paused" | "draft";
  created_at: string;
  updated_at: string;
}

export interface Rule {
  id:         string;
  tenant_id:  string;
  name:       string;
  source:     "custom" | "crs" | "community" | "virtual_patch" | "ai_generated";
  phase:      number;
  severity:   "info" | "low" | "medium" | "high" | "critical";
  dsl:        string;
  enabled:    boolean;
  tags:       string[];
  created_at: string;
  updated_at: string;
}

export interface Alert {
  id:          string;
  tenant_id:   string;
  site_id:     string | null;
  severity:    "info" | "low" | "medium" | "high" | "critical";
  kind:        string;
  summary:     string;
  details:     Record<string, unknown>;
  state:       "open" | "acked" | "resolved" | "closed";
  created_at:  string;
  resolved_at: string | null;
}

export interface AuditEntry {
  id:            string;
  tenant_id:     string;
  actor_user_id: string | null;
  action:        string;
  target_kind:   string;
  target_id:     string | null;
  ip:            string | null;
  created_at:    string;
}

export interface MetricsSnapshot {
  rps:               number;
  p99_latency_ms:    number;
  total_requests:    number;
  blocked_requests:  number;
  ml_anomalies:      number;
  error_count:       number;
  ebpf_drops:        number;
  connected_clients: number;
}

export interface TrafficBucket {
  ts:      number;
  reqs:    number;
  blocked: number;
  p99_ms:  number;
}

export interface MLModel {
  name:         string;
  version:      string;
  precision:    number;
  recall:       number;
  status:       string;
  latency_ms:   number;
  last_updated: string;
}

export interface MLStats {
  precision:             number;
  recall:                number;
  fp_rate:               number;
  total_analyzed:        number;
  anomalies_detected:    number;
  block_rate:            number;
  model_status:          string;
  models:                MLModel[];
  false_positives_today: number;
  true_positives_today:  number;
}

export interface UserRow {
  id:         string;
  email:      string;
  name:       string;
  role:       string;
  status:     string;
  twofa:      boolean;
  last_login: string | null;
}

export interface APIKeyRow {
  id:         string;
  name:       string;
  preview:    string;
  scope:      string;
  created_at: string;
  expires_at: string;
  last_used:  string;
}

export interface RuleTestResult {
  verdict:       string;
  matched:       boolean;
  detail:        string;
  anomaly_score: number;
  phases_run:    string[];
}

// ---------------------------------------------------------------------------
// API methods
// ---------------------------------------------------------------------------

export const api = {
  auth: {
    login: (email: string, password: string) =>
      apiFetch<{ access_token: string; user: { id: string; email: string; role: string } }>(
        "/auth/login",
        { method: "POST", body: JSON.stringify({ email, password }) }
      ),
  },

  dashboard: {
    stats: () =>
      apiFetch<{ tenant_id: string; stats: DashboardStats }>("/dashboard/stats"),
  },

  sites: {
    list: () => apiFetch<{ sites: Site[]; tenant_id: string }>("/sites"),
    create: (body: { name: string; domains: string[]; upstream?: object; waf_policy?: object }) =>
      apiFetch<{ site: Site }>("/sites", { method: "POST", body: JSON.stringify(body) }),
    delete: (id: string) =>
      apiFetch<{ ok: boolean }>(`/sites/${id}`, { method: "DELETE" }),
    updateStatus: (id: string, status: "active" | "paused") =>
      apiFetch<{ ok: boolean; status: string }>(`/sites/${id}/status`, {
        method: "PATCH", body: JSON.stringify({ status }),
      }),
  },

  rules: {
    list:   () => apiFetch<{ rules: Rule[]; tenant_id: string }>("/rules"),
    create: (body: Partial<Rule>) =>
      apiFetch<{ rule: Rule }>("/rules", { method: "POST", body: JSON.stringify(body) }),
    toggle: (id: string, enabled: boolean) =>
      apiFetch<{ ok: boolean; id: string; enabled: boolean }>(
        `/rules/${id}`, { method: "PATCH", body: JSON.stringify({ enabled }) }
      ),
    delete: (id: string) =>
      apiFetch<{ ok: boolean }>(`/rules/${id}`, { method: "DELETE" }),
    test: (dsl: string, payload: string, method?: string, path?: string) =>
      apiFetch<RuleTestResult>("/rules/test", {
        method: "POST",
        body: JSON.stringify({ dsl, payload, method: method ?? "GET", path: path ?? "/" }),
      }),
  },

  ml: {
    stats: () => apiFetch<MLStats>("/ml/stats"),
  },

  traffic: {
    history: () => apiFetch<{ buckets: TrafficBucket[] }>("/traffic/history"),
  },

  admin: {
    users: {
      list:   () => apiFetch<{ users: UserRow[]; tenant_id: string }>("/admin/users"),
      create: (body: { email: string; name: string; role: string }) =>
        apiFetch<{ user: UserRow; message: string }>("/admin/users", { method: "POST", body: JSON.stringify(body) }),
    },
    apikeys: {
      list:   () => apiFetch<{ api_keys: APIKeyRow[]; tenant_id: string }>("/admin/apikeys"),
      create: (body: { name: string; scope?: string }) =>
        apiFetch<{ api_key: APIKeyRow & { key: string }; warning: string }>(
          "/admin/apikeys", { method: "POST", body: JSON.stringify(body) }
        ),
      revoke: (id: string) =>
        apiFetch<{ ok: boolean }>(`/admin/apikeys/${id}`, { method: "DELETE" }),
    },
  },

  alerts: {
    list: (state?: string) =>
      apiFetch<{ alerts: Alert[]; tenant_id: string }>(
        `/alerts${state ? `?state=${state}` : ""}`
      ),
    ack:     (id: string) => apiFetch<{ ok: boolean }>(`/alerts/${id}/ack`,     { method: "POST" }),
    resolve: (id: string) => apiFetch<{ ok: boolean }>(`/alerts/${id}/resolve`, { method: "POST" }),
  },

  audit: {
    list: () => apiFetch<{ entries: AuditEntry[]; tenant_id: string }>("/audit"),
  },

  metrics: {
    snapshot: () => apiFetch<MetricsSnapshot>("/metrics/snapshot"),
  },

  /** Returns the EventSource URL for the log stream (SSE).
   *  The token is appended as a query param because EventSource cannot set headers.
   *  We bypass the Next.js production proxy (which buffers SSE) by pointing
   *  directly at the Go control plane. NEXT_PUBLIC_CONTROL_PLANE_URL must be
   *  set at build time, e.g. NEXT_PUBLIC_CONTROL_PLANE_URL=http://localhost:9501 */
  logs: {
    streamURL: (kind?: string): string => {
      const token = getToken() ?? "";
      const params = new URLSearchParams({ token });
      if (kind) params.set("kind", kind);
      const goBase =
        process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? "http://localhost:9501";
      return `${goBase}/api/v1/logs/stream?${params}`;
    },
  },
};
