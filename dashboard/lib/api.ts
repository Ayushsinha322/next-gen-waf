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

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ChannelType = "webhook" | "slack" | "syslog" | "cef";

/** Type-specific settings for a notification channel (superset; only the
 *  relevant subset is used per channel type). */
export interface ChannelConfig {
  // webhook / slack
  url?:      string;
  method?:   string;
  headers?:  Record<string, string>;
  secret?:   string;
  // syslog / cef
  host?:     string;
  port?:     number;
  protocol?: "udp" | "tcp";
  facility?: number;
  tag?:      string;
}

export interface NotificationChannel {
  id:           string;
  tenant_id:    string;
  name:         string;
  type:         ChannelType;
  config:       ChannelConfig;
  min_severity: Severity;
  enabled:      boolean;
  last_status?: string | null;
  last_sent_at?: string | null;
  created_at:   string;
  updated_at:   string;
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
  // Real aggregates derived from the proxy NDJSON stream.
  unique_blocked_ips: number;
  status_2xx:         number;
  status_3xx:         number;
  status_4xx:         number;
  status_5xx:         number;
  attack_breakdown:   Record<string, number>;
  by_country:         Record<string, number>;
  geoip_loaded:       boolean;
  mem_used_bytes:     number;
  mem_total_bytes:    number;
}

export interface TrafficBucket {
  ts:      number;
  reqs:    number;
  blocked: number;
  p99_ms:  number;
}

/** Cumulative per-site counters (keyed by site label) from /metrics/sites. */
export interface SiteStat {
  total:      number;
  blocked:    number;
  status_4xx: number;
  status_5xx: number;
}

/** A rule's would-have-blocked aggregation while a site runs in Learning mode. */
export interface LearningStat {
  rule_id:   string;
  category:  string;
  severity:  string;
  message:   string;
  count:     number;
  last_seen: string;
  samples:   string[];
}

/** A ClickHouse-stored WAF event (searchable history). */
export interface WafEvent {
  ts:       number;  // unix seconds
  ip:       string;
  country:  string;
  site:     string;
  method:   string;
  path:     string;
  rule:     string;
  attack:   string;
  action:   string;  // BLOCK | DETECT
  severity: string;
  score:    number;
  status:   number;
  protocol?: string; // h1 | h2 | h3
}

export interface TimelineBucket { ts: number; total: number; blocked: number }

export interface EventQuery {
  site?: string; country?: string; rule?: string; action?: string;
  ip?: string; protocol?: string; q?: string; from?: number; to?: number; limit?: number;
}

// --- Threat Intelligence -----------------------------------------------------
// Mirrors the control-plane threat_intel_iocs schema. IOCs are node-global; the
// tier (block/watch) is derived from confidence vs the block threshold.

export type IOCType = "ip" | "cidr" | "user_agent" | "domain" | "url_substring";
export type IOCTier = "block" | "watch";

/** A single Indicator of Compromise. */
export interface IOC {
  id:         number;
  type:       IOCType;
  value:      string;      // 1.2.3.4 · 10.0.0.0/8 · sqlmap · evil.example · /wp-admin/x
  source:     string;      // tor · feodo · urlhaus · stix · builtin_bad_ua · manual
  category:   string;
  confidence: number;      // 0..100
  tier:       IOCTier;     // derived: confidence >= threshold ? "block" : "watch"
  first_seen: string;
  last_seen:  string;
  expires_at: string | null;
}

/** KPI/summary counters that drive the top stat row + facet bars. */
export interface ThreatIntelSummary {
  total_active: number;
  block_tier:   number;
  watch_tier:   number;
  threshold:    number;
  by_type:      Record<string, number>;
  by_source:    Record<string, number>;
  by_category:  Record<string, number>;
  newest_seen:  string | null;
  oldest_seen:  string | null;
}

export interface IOCPage { items: IOC[]; total: number; limit: number; offset: number }

/** Filters for the IOC browse table (all optional). */
export interface IOCQuery {
  q?: string; type?: string; tier?: string; source?: string; limit?: number; offset?: number;
}

/** A recent threat-intel-driven enforcement hit (from ClickHouse waf_events). */
export interface TIBlock {
  ts: number; ip: string; country: string; site: string; path: string; reason: string;
}

/** A per-site rule exclusion stored in waf_policy.rule_exclusions. */
export interface RuleExclusion {
  rule_id:          number;
  exclude_targets?: string[];
  disable?:         boolean;
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

/** Certificate source as reported by the data plane. */
export type CertSource =
  | "self_signed"
  | { acme: { provider: string; email: string } }
  | "manual";

export interface Certificate {
  domain:      string;
  name?:       string; // operator-assigned friendly profile label (empty = use domain)
  san:         string[];
  issued_at:   number; // UNIX seconds
  expires_at:  number; // UNIX seconds (0 = unknown)
  fingerprint: string;
  source:      CertSource;
}

export type AcmeProvider = "letsencrypt" | "letsencrypt_staging" | "zerossl";
export type AcmeChallenge = "http_01" | "tls_alpn_01";

/** Current management-console TLS cert (or the self-signed default). */
export interface ManagementTLSInfo {
  self_signed:  boolean;
  domain?:      string;
  name?:        string;  // operator profile label, or the cert subject when none set
  issuer?:      string;
  san?:         string[];
  issued_at?:   number;  // UNIX seconds
  expires_at?:  number;  // UNIX seconds
  fingerprint?: string;
  key_type?:    string;
}

/** Validated metadata returned after a successful management-cert upload. */
export interface CertValidationResult {
  subject:        string;
  issuer:         string;
  san:            string[];
  not_before:     number;
  not_after:      number;
  days_remaining: number;
  fingerprint:    string;
  key_type:       string;
  self_signed:    boolean;
  warnings:       string[];
}

// ---------------------------------------------------------------------------
// API methods
// ---------------------------------------------------------------------------

/** Build a query string from a filter object, dropping empty values. */
function eventQS(f: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  return p.toString();
}

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
    get:  (id: string) => apiFetch<{ site: Site }>(`/sites/${id}`),
    create: (body: { name: string; domains: string[]; upstream?: object; waf_policy?: object }) =>
      apiFetch<{ site: Site }>("/sites", { method: "POST", body: JSON.stringify(body) }),
    update: (id: string, body: { name?: string; domains?: string[]; upstream?: object; waf_policy?: object }) =>
      apiFetch<{ site: Site }>(`/sites/${id}`, { method: "PUT", body: JSON.stringify(body) }),
    delete: (id: string) =>
      apiFetch<{ ok: boolean }>(`/sites/${id}`, { method: "DELETE" }),
    updateStatus: (id: string, status: "active" | "paused") =>
      apiFetch<{ ok: boolean; status: string }>(`/sites/${id}/status`, {
        method: "PATCH", body: JSON.stringify({ status }),
      }),
    /** Add (or update) a rule exclusion on a site — learning-report tuning.
     *  Omit exclude_targets to disable the whole rule (the common case). */
    addExclusion: (id: string, body: { rule_id: number; exclude_targets?: string[]; disable?: boolean }) =>
      apiFetch<{ site: Site; rule_exclusions: RuleExclusion[] }>(`/sites/${id}/exclusions`, {
        method: "POST", body: JSON.stringify(body),
      }),
    /** Remove the exclusion for a rule (re-enable it). */
    removeExclusion: (id: string, ruleId: number) =>
      apiFetch<{ site: Site; rule_exclusions: RuleExclusion[] }>(`/sites/${id}/exclusions/${ruleId}`, {
        method: "DELETE",
      }),
    /** Returns the full site catalogue as a YAML string (Config-as-Code). */
    exportYaml: async (): Promise<string> => {
      const token = getToken();
      const res = await fetch(`${BASE}/sites/export`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error(`export failed: ${res.status}`);
      return res.text();
    },
    /** Upserts sites from a YAML document (Config-as-Code). */
    importYaml: (yaml: string) =>
      apiFetch<{ ok: boolean; created: number; updated: number; total: number }>(
        "/sites/import", { method: "POST", body: JSON.stringify({ yaml }) }
      ),
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

  notifications: {
    list: () => apiFetch<{ channels: NotificationChannel[] }>("/notifications/channels"),
    create: (body: { name: string; type: ChannelType; config: ChannelConfig; min_severity?: Severity; enabled?: boolean }) =>
      apiFetch<{ channel: NotificationChannel }>("/notifications/channels", {
        method: "POST", body: JSON.stringify(body),
      }),
    update: (id: string, body: { name?: string; config?: ChannelConfig; min_severity?: Severity; enabled?: boolean }) =>
      apiFetch<{ channel: NotificationChannel }>(`/notifications/channels/${id}`, {
        method: "PUT", body: JSON.stringify(body),
      }),
    delete: (id: string) =>
      apiFetch<{ ok: boolean }>(`/notifications/channels/${id}`, { method: "DELETE" }),
    test: (id: string) =>
      apiFetch<{ ok: boolean; message?: string }>(`/notifications/channels/${id}/test`, { method: "POST" }),
  },

  plugins: {
    list: () => apiFetch<{ plugins: unknown[]; tenant_id: string }>("/plugins"),
  },

  cluster: {
    status: () =>
      apiFetch<{ enabled: boolean; leader?: string; status?: { node_id?: string; state?: string; peers?: unknown[] } }>(
        "/cluster/status"
      ),
  },

  audit: {
    list: () => apiFetch<{ entries: AuditEntry[]; tenant_id: string }>("/audit"),
  },

  waf: {
    status: () =>
      apiFetch<{ waf_running: boolean; uptime_secs?: number; sites?: number; listeners?: string[]; upstreams_healthy?: number; upstreams_total?: number; http3?: { enabled: boolean; listener?: string; bind?: string; advertise_port?: number }; error?: string }>("/waf/status"),
  },

  certs: {
    list: () => apiFetch<{ certs: Certificate[]; waf_running: boolean }>("/certs"),
    /** Metadata for the WAF's internal Root CA (drives the "Download Root CA" UI). */
    rootCAInfo: () =>
      apiFetch<{ available: boolean; subject?: string; not_after?: number; fingerprint?: string; filename?: string }>(
        "/certs/root-ca/info"),
    /** Download the public Root CA PEM as a file (so users can import it as a trusted root). */
    downloadRootCA: async (): Promise<void> => {
      const token = getToken();
      const res = await fetch(`${BASE}/certs/root-ca`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error(`root CA download failed: ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "sentinel-root-ca.crt";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    },
    uploadManual: (body: { domain: string; name?: string; cert_pem: string; key_pem: string }) =>
      apiFetch<{ installed: string }>("/certs/manual", {
        method: "POST", body: JSON.stringify(body),
      }),
    rename: (domain: string, name: string) =>
      apiFetch<{ renamed: string; name: string }>(`/certs/${encodeURIComponent(domain)}`, {
        method: "PATCH", body: JSON.stringify({ name }),
      }),
    requestAcme: (body: {
      domains: string[];
      email: string;
      provider?: AcmeProvider;
      challenge?: AcmeChallenge;
      renew_before_days?: number;
    }) =>
      apiFetch<{ issued: string[] }>("/certs/acme", {
        method: "POST", body: JSON.stringify(body),
      }),
    renew: (domain: string) =>
      apiFetch<{ issued: string[] }>(`/certs/${encodeURIComponent(domain)}/renew`, {
        method: "POST",
      }),
    delete: (domain: string) =>
      apiFetch<{ removed: string }>(`/certs/${encodeURIComponent(domain)}`, {
        method: "DELETE",
      }),
  },

  /** Management-console TLS — the cert the admin UI itself is served with. */
  managementTls: {
    get: () => apiFetch<ManagementTLSInfo>("/management-tls"),
    /** Validate + install. Throws with the server's validation message on failure. */
    upload: async (body: {
      cert_pem: string;
      key_pem: string;
      ca_bundle_pem?: string;
      name?: string;
      expected_host?: string;
    }): Promise<{ ok: boolean; info: CertValidationResult; warnings: string[] }> => {
      const token = getToken();
      const res = await fetch(`${BASE}/management-tls`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => ({} as Record<string, unknown>));
      if (!res.ok) throw new Error((data as { error?: string }).error || `upload failed: ${res.status}`);
      return data as { ok: boolean; info: CertValidationResult; warnings: string[] };
    },
    revert: () => apiFetch<{ ok: boolean; reverted: boolean }>("/management-tls", { method: "DELETE" }),
  },

  events: {
    /** ClickHouse reachability + row counts (drives the empty state). */
    status: () => apiFetch<{ configured: boolean; reachable: boolean; events?: number; traffic_buckets?: number; error?: string }>("/events/status"),
    /** Search waf_events with optional filters; from/to are unix seconds. */
    search: (f: EventQuery) =>
      apiFetch<{ events: WafEvent[]; clickhouse: boolean }>(`/events/search?${eventQS(f)}`),
    timeline: (from?: number, to?: number, bucket = 60) =>
      apiFetch<{ buckets: TimelineBucket[]; clickhouse: boolean }>(
        `/events/timeline?${eventQS({ from, to })}&bucket=${bucket}`),
    facets: (column: string, from?: number, to?: number, limit = 10) =>
      apiFetch<{ facets: { key: string; count: number }[]; column: string; clickhouse: boolean }>(
        `/events/facets?column=${encodeURIComponent(column)}&${eventQS({ from, to })}&limit=${limit}`),
  },

  threatIntel: {
    /** Summary counters + facet maps for the KPI row. */
    stats: () => apiFetch<ThreatIntelSummary>("/threat-intel/stats"),
    /** Filtered, paginated IOC list. */
    list: (f: IOCQuery = {}) => apiFetch<IOCPage>(`/threat-intel/iocs?${eventQS(f)}`),
    /** Add a manual indicator (block-tier by default). */
    create: (body: { type: IOCType; value: string; tier?: IOCTier; source?: string; category?: string; confidence?: number; expires_at?: string | null }) =>
      apiFetch<{ ioc: IOC }>("/threat-intel/iocs", { method: "POST", body: JSON.stringify(body) }),
    /** Remove an indicator by id (re-allows matching traffic). */
    remove: (id: number) => apiFetch<{ ok: boolean }>(`/threat-intel/iocs/${id}`, { method: "DELETE" }),
    /** Recent threat-intel-driven blocks (ClickHouse-backed; empty when absent). */
    recentBlocks: (limit = 100) =>
      apiFetch<{ blocks: TIBlock[]; clickhouse: boolean }>(`/threat-intel/recent-blocks?limit=${limit}`),
  },

  geoip: {
    /** Union of blocked ISO country codes across all sites. */
    listBlocked: () => apiFetch<{ countries: string[] }>("/geoip/blocked"),
    /** Block a country across all active sites (hot-applies in ~5s). */
    block: (code: string) =>
      apiFetch<{ ok: boolean; country: string; sites_changed: number; countries: string[] }>(
        "/geoip/block", { method: "POST", body: JSON.stringify({ country: code }) }
      ),
    /** Remove a country block across all sites. */
    unblock: (code: string) =>
      apiFetch<{ ok: boolean; country: string; sites_changed: number; countries: string[] }>(
        `/geoip/block/${encodeURIComponent(code)}`, { method: "DELETE" }
      ),
  },

  metrics: {
    snapshot: () => apiFetch<MetricsSnapshot>("/metrics/snapshot"),
    sites: () => apiFetch<{ sites: Record<string, SiteStat> }>("/metrics/sites"),
    /** Learning-mode would-have-blocked aggregation. Pass a site label to scope
     *  it; omit for all sites. Rules sorted by detection count desc. */
    learning: (site?: string) =>
      apiFetch<{ site: string; rules: LearningStat[] }>(
        `/metrics/learning${site ? `?site=${encodeURIComponent(site)}` : ""}`
      ),
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
