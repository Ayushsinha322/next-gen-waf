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

/**
 * Fetch for endpoints that are reachable WITHOUT a session.
 *
 * apiFetch is wrong for these in two ways. It attaches whatever token is in
 * localStorage — and the people using password recovery are exactly the ones
 * whose stored token is stale — and it treats the resulting 401 as an expired
 * session, so it calls logout() and redirects to /login. The effect was that a
 * locked-out user with an old token could never reach the reset form: the page
 * bounced them to the login screen they could not get past.
 *
 * This sends no credentials, follows no refresh path, and surfaces the server's
 * own error text so the caller can show something useful.
 */
async function publicFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init.headers as Record<string, string>) },
  });
  if (!res.ok) {
    let message = res.statusText;
    try {
      const body = await res.json();
      if (body && typeof body.error === "string") message = body.error;
    } catch { /* non-JSON error body — fall back to the status text */ }
    throw new Error(message);
  }
  return res.json() as Promise<T>;
}

/**
 * Multipart upload with the same auth + one-shot refresh behaviour as apiFetch.
 *
 * Separate because apiFetch hardcodes `Content-Type: application/json`. For a
 * FormData body the header MUST be left unset so the browser can generate the
 * multipart boundary; setting it by hand produces a body the server cannot parse.
 *
 * Also unwraps the server's `{"error": "..."}` payload into the thrown message.
 * For plugin upload that text IS the user experience — "plugin.wasm is not a
 * WebAssembly module (missing the \0asm preamble)" tells the uploader exactly
 * what to fix, and wrapping it in `API /plugins: 400 {...}` would bury it.
 */
async function apiUpload<T>(path: string, form: FormData): Promise<T> {
  const send = async (): Promise<Response> => {
    const token = getToken();
    const headers: Record<string, string> = {};
    if (token) headers["Authorization"] = `Bearer ${token}`;
    return fetch(`${BASE}${path}`, { method: "POST", body: form, headers });
  };

  let res = await send();
  if (res.status === 401) {
    const refreshed = await refreshToken();
    if (refreshed) {
      res = await send();
    } else {
      logout();
      if (typeof window !== "undefined") window.location.href = "/login";
      throw new Error("Session expired — redirecting to login");
    }
  }
  if (!res.ok) {
    const raw = await res.text().catch(() => "");
    let msg = raw || res.statusText;
    try {
      const parsed = JSON.parse(raw) as { error?: string };
      if (parsed.error) msg = parsed.error;
    } catch {
      /* not JSON — use the raw text */
    }
    throw new Error(msg);
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

/** How the fleet reports a rule, as opposed to what the database stores.
 *
 * "enabled" only ever meant "stored". These come from the data plane, which owns
 * the SRL compiler and is the only component that knows whether a rule actually
 * compiled — so a rule can be enabled and NOT be protecting anything. */
export type RuleEnforcement =
  | "enforced"      // a data-plane node confirms it is compiled and live
  | "not_enforced"  // a node compiled the config and rejected it
  | "disabled"      // operator switched it off; nothing to observe
  | "not_deployed"  // excluded from delivery by design (crs/community)
  | "unknown";      // no node has reported recently

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
  /** Empty/absent means the rule applies to every site in the deployment. */
  site_id?:   string;
  enforcement?:       RuleEnforcement;
  /** Why it is not enforced — the parse error, verbatim from the compiler. */
  enforcement_error?: string;
  /** Why it is not deployed, for states that are correct-by-design. */
  enforcement_note?:  string;
  nodes_enforcing?:   number;
  nodes_reporting?:   number;
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
  /** Chain position. Also the pagination cursor (created_at is not unique). */
  seq?:          number;
  /** Resolved from users; absent for system actions or a deleted actor. */
  actor_email?:  string | null;
  user_agent?:   string | null;
  /** Signed before/after payload, and the outcome. */
  diff?:         unknown;
  /** SUCCESS | FAILURE, lifted out of diff by the API. */
  result?:       string;
}

/** Result of recomputing the audit hash chain. `verified` is the only field
 *  that may be used to make a compliance claim, and it is false whenever the
 *  check could not complete. */
export interface AuditVerifyResult {
  verified:       boolean;
  checked:        number;
  altered:        string[];
  chain_broken:   string[];
  seq_gaps:       string[];
  unchained_rows: number;
  note?:          string;
  error?:         string;
}

export interface MetricsSnapshot {
  rps:               number;
  /** End-to-end request latency (upstream included), p99 of recent samples. */
  p99_latency_ms:    number;
  /** Samples behind that p99. 0 = no measurement, NOT a fast one. */
  p99_samples?:      number;
  /** p99 of the WAF's OWN processing time (end-to-end minus the wait on the
   *  origin). This is what the badge shows: a slow or long-polling upstream
   *  cannot distort it. */
  p99_waf_ms?:       number;
  p99_waf_samples?:  number;
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

/** WAF phases a plugin runs in, from its sentinel-plugin.toml [plugin.hooks]. */
export interface PluginHooks {
  request_headers?:  boolean;
  request_body?:     boolean;
  response_headers?: boolean;
  response_body?:    boolean;
}

/**
 * Host functions a plugin DECLARES it needs, from [plugin.permissions].
 *
 * Declared intent, not enforcement: the runtime does not currently gate host
 * calls on these flags, so any loaded plugin can call any host function the ABI
 * exposes. Shown in the UI so an operator can see what a plugin claims it will do
 * before enabling it — never presented as a sandbox guarantee.
 */
export interface PluginPermissions {
  host_log?:            boolean;
  host_get_req_header?: boolean;
  host_set_decision?:   boolean;
  host_add_score?:      boolean;
  host_set_header?:     boolean;
  host_kv_get?:         boolean;
  host_kv_set?:         boolean;
  host_http_callout?:   boolean;
}

/** An installed WASM plugin (module bytes are never sent to the browser). */
export interface Plugin {
  id:          string;
  tenant_id:   string;
  name:        string;
  version:     string;
  description: string;
  author:      string;
  hooks:       PluginHooks;
  permissions: PluginPermissions;
  sha256:      string;
  size_bytes:  number;
  enabled:     boolean;
  uploaded_by: string;
  created_at:  string;
  updated_at:  string;
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
  /** Query string (capped by the data plane). Empty/absent on older rows. */
  query?:   string;
  /** Referer header — for SPA traffic, which screen fired the request. */
  referer?: string;
  /** The text the rule actually matched (credential targets arrive redacted). */
  matched?: string;
  rule:     string;
  attack:   string;
  action:   string;  // BLOCK | DETECT
  severity: string;
  score:    number;
  status:   number;
  protocol?: string; // h1 | h2 | h3
  /** Correlation id shared with the NDJSON access/waf logs. */
  request_id?: string;
  /** Which part of the request tripped the rule; empty for multi-target rules. */
  target?: string;
  /** blocking | learning | off | node — whether the verdict was ENFORCED. */
  mode?: string;
  threshold?: number;
  /** Plain-English explanation written when the event was recorded. Absent on
   *  rows stored before the explain-the-verdict change. */
  explanation?: string;
  /** JA4 TLS fingerprint of the client (`t…` TCP, `q…` QUIC). The value that
   *  drove the malicious-JA4 bot signal and the JA4 blocklist — the field that
   *  makes a JA4-based block explainable. Absent on rows stored before it was
   *  recorded, and for plaintext requests. */
  ja4?: string;
}

/** One configuration rollback point (control-plane db.ConfigVersionSummary). */
export interface ConfigVersionSummary {
  id:         number;
  generation: number;
  reason:     string;   // e.g. "site.update", "site.delete"
  site_count: number;
  created_by?: string;
  created_at: string;   // RFC3339
}

/** One reason a site configuration would not survive conversion to the
 *  data-plane shape (control-plane SiteConfigProblem). */
export interface SiteConfigProblem {
  field:   string;      // JSON path, e.g. "upstream.servers"
  problem: string;
}

export interface TimelineBucket { ts: number; total: number; blocked: number }

/** One time bucket of the threat-detection trend, split by severity band
 *  (High folds CRITICAL + HIGH together). */
export interface SeverityBucket {
  ts:     number; // unix seconds (bucket start)
  high:   number;
  medium: number;
  low:    number;
  info:   number;
}

/** One source IP rolled up over the query window (Top Attacker IPs card). */
export interface Attacker {
  ip:        string;
  country:   string;  // ISO-3166 alpha-2, or "" when GeoIP hasn't tagged it
  requests:  number;  // total WAF events attributed to this IP
  blocked:   number;  // subset actively blocked (action = BLOCK)
  last_seen: number;  // unix seconds
}

export interface EventQuery {
  site?: string; country?: string; rule?: string; action?: string;
  ip?: string; protocol?: string; severity?: string; q?: string;
  from?: number; to?: number; limit?: number;
  // Query-param bag: also indexable so it can be fed to eventQS().
  [key: string]: string | number | undefined;
}

// --- Log profiles ------------------------------------------------------------
// A saved, named log view scoped to one web application. Exists for the support
// workflow "the customer wants their app's logs for 3 August": the filters are
// saved once per application, and only the date changes call to call.

export type ExportFormat = "csv" | "ndjson" | "json";

export interface LogProfile {
  id: string;
  tenant_id: string;
  name: string;
  description: string;
  site: string;
  rule: string;
  action: string;
  ip: string;
  country: string;
  protocol: string;
  severity: string;
  q: string;
  /** Window the UI pre-selects when the profile is opened (seconds). */
  default_range_secs: number;
  default_format: ExportFormat;
  created_by?: string;
  created_at: string;
  updated_at: string;
}

/** Create/update payload. Every field but `name` is optional so a PATCH-style
 *  update can leave stored filters untouched. */
export interface LogProfileInput {
  name: string;
  description?: string;
  site?: string;
  rule?: string;
  action?: string;
  ip?: string;
  country?: string;
  protocol?: string;
  severity?: string;
  q?: string;
  default_range_secs?: number;
  default_format?: ExportFormat;
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
  // Query-param bag: also indexable so it can be fed to eventQS().
  [key: string]: string | number | undefined;
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
  name:          string;
  kind:          string;
  buckets:       number;
  status:        string;
  metrics_note:  string;
}

// Deliberately carries NO precision/recall/fp_rate/true_positives fields.
//
// The API used to return them as hardcoded literals (0.953/0.891/0.003) with
// three invented models, and this page rendered them as live gauges. They are
// not computable without labelled ground truth, so the contract now reports
// `quality_measured: false` and the UI says so instead of drawing a number.
export interface MLStats {
  total_analyzed:      number;
  anomalies_detected:  number;
  block_rate:          number;
  // Real enablement state ("enabled", "disabled on all sites",
  // "enabled on N of M sites", "no sites configured") — not the old constant "active".
  model_status:        string;
  ml_enabled_sites:    number;
  total_sites:         number;
  quality_measured:    boolean;
  quality_note:        string;
  models:              MLModel[];
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

/** One rule as the compiler actually understood it. */
export interface CompiledRuleSummary {
  id:       number;
  phase:    string;
  action:   string;
  severity: string;
}

export interface RuleTestResult {
  verdict:       string;
  matched:       boolean;
  detail:        string;
  anomaly_score: number;
  phases_run:    string[];
  /** false when the DSL does not compile. Absent on responses from a control
   *  plane older than 2026-07-28, which could not tell valid from invalid. */
  valid?:            boolean;
  /** Verdict from the real rule VM: Allow | Block | Limit | Challenge | Log. */
  decision?:         string;
  matched_rule_ids?: string[];
  /** What the DSL compiled to — surfaces a rule that parses but defines nothing. */
  rules?:            CompiledRuleSummary[];
  error?:            string;
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

// --- Cluster & Node Health ---------------------------------------------------
// Mirrors GET /cluster/health: a fleet-wide roll-up of every data-plane node
// plus the control-plane (Raft) quorum, used by the Cluster health dashboard.

/** A single data-plane (WAF) node in the fleet. */
export interface DataPlaneNode {
  id:               string;
  hostname:         string;
  role:             string;
  version:          string;
  status:           "healthy" | "degraded" | "down";
  last_seen:        number; // unix seconds
  seconds_since_seen: number;
  uptime_secs:      number;
  sites:            number;
  upstreams_healthy: number;
  upstreams_total:  number;
}

/** A single control-plane (Raft) node. */
export interface ControlPlaneNode {
  // A stable node name (pod name / hostname), not a Raft integer ID.
  node_id:      string;
  // "candidate" no longer occurs: there is no election protocol with candidate
  // states, only "holds the advisory lock" or "does not".
  role:         "leader" | "follower" | "unknown";
  is_leader:    boolean;
  is_self:      boolean;
  reachable:    boolean;
  last_seen_sec: number;
  addr:         string;
}

/** Fleet-wide health roll-up (data plane + control plane). */
export interface ClusterHealth {
  generated_at:      number; // unix seconds
  overall:           "healthy" | "degraded" | "critical";
  protection_active: boolean;
  data_plane: {
    total:            number;
    healthy:          number;
    degraded:         number;
    down:             number;
    resilience_budget: number;
    nodes:            DataPlaneNode[];
  };
  control_plane: {
    enabled:          boolean;
    // "leader" | "follower" | "standalone".
    role:             string | null;
    total:            number;
    healthy:          number;
    // Whether a write leader is in view. This replaced quorum_size/quorum_ok/term:
    // leadership is a Postgres advisory lock, so writes survive on a single node
    // and there is no control-plane majority to maintain. Node IDs are now stable
    // names (pod names), not Raft integers.
    write_available:  boolean;
    leader_id:        string | null;
    leader_addr?:     string;
    resilience_budget: number;
    nodes:            ControlPlaneNode[];
  };
}

// ---------------------------------------------------------------------------
// API methods
// ---------------------------------------------------------------------------

/** Build a query string from a filter object, dropping empty values. */
export function eventQS(f: Record<string, unknown>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  return p.toString();
}

/** Pull the filename out of a Content-Disposition header.
 *
 *  The server names the file after the application and the exact window it
 *  covers, so preserving that name matters: the commonest support failure with
 *  exported logs is nobody being able to tell, later, what period a file held.
 *  Falls back to the caller's name if the header is missing or unparseable. */
function filenameFromDisposition(header: string | null, fallback: string): string {
  if (!header) return fallback;
  const m = /filename\*?=(?:UTF-8'')?"?([^\";]+)"?/i.exec(header);
  return m?.[1] ? decodeURIComponent(m[1]) : fallback;
}

/** Download a server-generated export and hand it to the browser.
 *
 *  Deliberately not apiFetch: the success path is a file body plus headers, the
 *  failure path is JSON, and the server streams the full match set rather than
 *  the page the UI happens to be showing — so the operator gets every event in
 *  the window, not the 300 rows on screen.
 *
 *  Returns the row count the server reported so the caller can tell the operator
 *  exactly what they are about to hand a customer. */
async function downloadExport(path: string, fallbackName: string): Promise<{ filename: string; rows: number }> {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res = await fetch(`${BASE}${path}`, { headers });
  if (res.status === 401) {
    const refreshed = await refreshToken();
    if (!refreshed) {
      logout();
      if (typeof window !== "undefined") window.location.href = "/login";
      throw new Error("Session expired — redirecting to login");
    }
    const newToken = getToken();
    if (newToken) headers["Authorization"] = `Bearer ${newToken}`;
    res = await fetch(`${BASE}${path}`, { headers });
  }
  if (!res.ok) {
    // Errors on this endpoint are JSON and carry the actionable detail — the
    // real row count when an export is refused as too large, for instance.
    const data = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(data.error || `export failed: ${res.status}`);
  }

  const filename = filenameFromDisposition(res.headers.get("Content-Disposition"), fallbackName);
  const rows = Number(res.headers.get("X-Sentinel-Export-Rows") ?? 0);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return { filename, rows };
}

export const api = {
  auth: {
    login: (email: string, password: string) =>
      apiFetch<{ access_token: string; user: { id: string; email: string; role: string } }>(
        "/auth/login",
        { method: "POST", body: JSON.stringify({ email, password }) }
      ),

    /** Start a self-service password reset.
     *
     * Always resolves with the same message whether or not the address has an
     * account — the backend deliberately gives no signal, and the UI must not
     * invent one by branching on anything here. */
    forgotPassword: (email: string) =>
      publicFetch<{ ok: boolean; message: string }>("/auth/password/forgot", {
        method: "POST", body: JSON.stringify({ email }),
      }),

    /** Redeem a reset link and set the new password. */
    resetPassword: (token: string, password: string) =>
      publicFetch<{ ok: boolean; message: string }>("/auth/password/reset", {
        method: "POST", body: JSON.stringify({ token, password }),
      }),

    /** Rotate your own password. Requires the current one; on success every
     *  session — including this one — has been signed out, which is why the
     *  response carries reauth_required. */
    changePassword: (current_password: string, new_password: string) =>
      apiFetch<{ ok: boolean; reauth_required: boolean; message: string }>(
        "/auth/password/change",
        { method: "POST", body: JSON.stringify({ current_password, new_password }) }
      ),
  },

  mail: {
    /** SMTP status for the settings screen. The password is reported only as
     *  password_set — the value is never sent to the browser. */
    status: () =>
      apiFetch<{ mail: {
        configured: boolean; password_reset_ready: boolean;
        host: string; port: number; security: string; from: string;
        from_name: string; username: string; password_set: boolean;
        skip_verify: boolean; notify_email: string; public_url: string;
        auth_required: boolean; public_url_hint?: string;
      } }>("/admin/mail"),

    sendTest: (to?: string) =>
      apiFetch<{ ok: boolean; message: string }>("/admin/mail/test", {
        method: "POST", body: JSON.stringify(to ? { to } : {}),
      }),
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
    /** Dry-run a site configuration.
     *
     * Runs the same conversion the config sync runs, so a green result means the
     * site will actually reach the proxy rather than silently vanish at sync
     * time. Pass site_id to validate a partial update against the stored site. */
    validate: (body: Record<string, unknown>) =>
      apiFetch<{ valid: boolean; problems: SiteConfigProblem[]; resolved: { name: string; domains: string[] } }>(
        "/sites/validate", { method: "POST", body: JSON.stringify(body) }),

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
    /** Enable/disable only. PATCH is a full partial-update now, so the toggle
     *  lives on its own route to keep the two intentions apart. */
    toggle: (id: string, enabled: boolean) =>
      apiFetch<{ ok: boolean; id: string; enabled: boolean }>(
        `/rules/${id}/enabled`, { method: "PUT", body: JSON.stringify({ enabled }) }
      ),
    /** Partial update. An omitted field is left alone. A dsl change is validated
     *  against the real engine and refused if it would not run — so a failed call
     *  here means the EXISTING rule is still in place, not that it was replaced
     *  with something broken. */
    update: (id: string, body: {
      dsl?: string; severity?: string; phase?: number;
      tags?: string[]; enabled?: boolean;
      site_id?: string; clear_site_id?: boolean;
    }) =>
      apiFetch<{ rule: Rule; warning?: string }>(
        `/rules/${id}`, { method: "PATCH", body: JSON.stringify(body) }
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
      // `password` is REQUIRED by the API — handleCreateUserReal binds it with
      // `binding:"required,min=12"`. It was missing from this signature, so every
      // "Invite User" request was rejected 400 before it reached the database.
      create: (body: { email: string; name: string; role: string; password: string }) =>
        apiFetch<{ user: UserRow; message: string }>("/admin/users", { method: "POST", body: JSON.stringify(body) }),

      /** Email the user a reset link.
       *
       * Returns only a confirmation message. There is deliberately no password
       * in the response: an administrator who could read a colleague's new
       * password could then act as them, and the audit trail would show the
       * colleague. */
      sendResetLink: (id: string) =>
        apiFetch<{ ok: boolean; message: string }>(`/admin/users/${id}/reset-password`, { method: "POST" }),
    },
    apikeys: {
      list:   () => apiFetch<{ api_keys: APIKeyRow[]; tenant_id: string }>("/admin/apikeys"),
      // The API reads `scopes` (a string array) and `role`. This previously
      // declared `scope` — singular, and a name the backend never looks at — so
      // the field was silently dropped and every key was created with whatever
      // the server defaulted to.
      create: (body: { name: string; role?: string; scopes?: string[] }) =>
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
    list: () =>
      apiFetch<{ plugins: Plugin[]; tenant_id?: string; database?: boolean }>("/plugins"),
    /** Install (or upgrade) from a .zip containing sentinel-plugin.toml + the module. */
    upload: (file: File) => {
      const form = new FormData();
      form.append("file", file);
      return apiUpload<{ plugin: Plugin; note?: string }>("/plugins", form);
    },
    setEnabled: (name: string, enabled: boolean) =>
      apiFetch<{ name: string; enabled: boolean; note?: string }>(
        `/plugins/${encodeURIComponent(name)}`,
        { method: "PATCH", body: JSON.stringify({ enabled }) },
      ),
    remove: (name: string) =>
      apiFetch<{ deleted: string }>(`/plugins/${encodeURIComponent(name)}`, {
        method: "DELETE",
      }),
  },

  cluster: {
    status: () =>
      apiFetch<{ enabled: boolean; leader?: string; status?: { node_id?: string; state?: string; peers?: unknown[] } }>(
        "/cluster/status"
      ),
    /** Fleet-wide health roll-up: data-plane nodes + control-plane (Raft) quorum. */
    health: () => apiFetch<ClusterHealth>("/cluster/health"),
  },

  audit: {
    /** Server-side filtered. Passing nothing preserves the previous behaviour
     *  (newest 100), so existing callers are unaffected. */
    list: (p: { limit?: number; action?: string; action_prefix?: string;
                result?: "SUCCESS" | "FAILURE"; from?: number; to?: number;
                before_seq?: number } = {}) => {
      const q = new URLSearchParams();
      Object.entries(p).forEach(([k, v]) => { if (v !== undefined && v !== "") q.set(k, String(v)); });
      const qs = q.toString();
      return apiFetch<{ entries: AuditEntry[]; tenant_id: string; next_before_seq: number }>(
        "/audit" + (qs ? `?${qs}` : ""));
    },
    /** Recompute the hash chain. Returns 409 with a populated report when the
     *  chain does not verify, which apiFetch surfaces as a thrown error — so
     *  callers must treat a throw as "not verified", never as "unknown". */
    verify: () => apiFetch<AuditVerifyResult>("/audit/verify"),
  },

  /** Configuration rollback points.
   *
   * The control plane has been writing a snapshot before every site mutation
   * since config_versions landed, and exposing list + rollback endpoints, with
   * no client ever calling them — the storage cost was already being paid for a
   * feature nobody could reach. "What happens when a config change breaks
   * production" is the first question an enterprise buyer asks. */
  config: {
    versions: (limit?: number) =>
      apiFetch<{ versions: ConfigVersionSummary[] }>(
        `/config/versions${limit ? `?limit=${limit}` : ""}`),
    /** Restore a snapshot. Returns what it could and could not put back:
     *  sites created after the snapshot are left alone, sites deleted since are
     *  not re-created — both surfaced in `skipped` and `note`. */
    rollback: (id: number) =>
      apiFetch<{ restored_sites: number; skipped: string[]; version_id: number; note: string }>(
        `/config/versions/${id}/rollback`, { method: "POST" }),
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
    /** Top source IPs by WAF-event volume, each with blocked count + country.
     *  ClickHouse-backed; returns `clickhouse:false` + empty list when the event
     *  store is not configured. */
    topAttackers: (limit = 8, from?: number, to?: number) =>
      apiFetch<{ attackers: Attacker[]; clickhouse: boolean }>(
        `/events/top-attackers?${eventQS({ from, to, limit })}`),
    /** Threat-detection trend: waf_events bucketed by time + severity band.
     *  ClickHouse-backed; empty + `clickhouse:false` when the store is off. */
    severityTimeline: (from?: number, to?: number, bucket = 60) =>
      apiFetch<{ buckets: SeverityBucket[]; clickhouse: boolean }>(
        `/events/severity-timeline?${eventQS({ from, to })}&bucket=${bucket}`),
    /** Resolve a Support ID (from a block page) to the request that produced it.
     *  Ignores the selected time range on purpose — a customer often calls days
     *  after the block, and applying the UI's window would read as "not found". */
    bySupportID: (id: string) =>
      apiFetch<{ events: WafEvent[]; clickhouse: boolean }>(
        `/events/support/${encodeURIComponent(id.trim())}`),
    /** Download the current ad-hoc view as a file. Streams the FULL match set
     *  from the server, not the rows the table happens to have loaded. */
    exportDownload: (f: EventQuery, format: ExportFormat = "csv") =>
      downloadExport(`/events/export?${eventQS({ ...f, format })}`, `waf-events.${format}`),
  },

  /** Saved per-application log views + the export handed to a customer. */
  logProfiles: {
    list: () => apiFetch<{ profiles: LogProfile[] }>("/logs/profiles"),
    create: (body: LogProfileInput) =>
      apiFetch<{ profile: LogProfile }>("/logs/profiles", { method: "POST", body: JSON.stringify(body) }),
    update: (id: string, body: LogProfileInput) =>
      apiFetch<{ profile: LogProfile }>(`/logs/profiles/${encodeURIComponent(id)}`, {
        method: "PUT", body: JSON.stringify(body),
      }),
    remove: (id: string) =>
      apiFetch<{ deleted: boolean }>(`/logs/profiles/${encodeURIComponent(id)}`, { method: "DELETE" }),
    /** Export a saved profile over an explicit window. The profile supplies
     *  WHICH events, from/to supply WHEN — that split is the point. */
    exportDownload: (id: string, from: number, to: number, format: ExportFormat) =>
      downloadExport(
        `/logs/profiles/${encodeURIComponent(id)}/export?${eventQS({ from, to, format })}`,
        `waf-events.${format}`),
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
   *
   *  SAME-ORIGIN BY DEFAULT, and that is the important property. The management
   *  console (:9443) reverse-proxies `/api/*` straight to the control plane —
   *  Next.js is not in that path — so a relative URL reaches the Go server
   *  unbuffered, which is the reason this used to be absolute.
   *
   *  Being relative makes the stream work under ANY origin the console is
   *  reached by: an SSH tunnel (https://127.0.0.1:9443), the host itself, a
   *  management VLAN address, or a real hostname later. The previous absolute
   *  form baked ONE deployment's IP into the image at build time
   *  (NEXT_PUBLIC_* is inlined by Next at build, not read at runtime), so the
   *  dashboard image only worked on the box it was built for — and it broke
   *  outright once :9443 was bound to loopback, because the browser was still
   *  told to reach a host-IP that no longer answers.
   *
   *  The token rides as a query param because EventSource cannot set headers.
   *
   *  Override only if the console is served from an origin that does NOT proxy
   *  /api to the control plane — notably the cleartext :3000 break-glass path,
   *  where Next.js rewrites DO buffer SSE. Set NEXT_PUBLIC_CONTROL_PLANE_URL to
   *  a browser-reachable control-plane base in that case. */
  logs: {
    streamURL: (kind?: string): string => {
      const token = getToken() ?? "";
      const params = new URLSearchParams({ token });
      if (kind) params.set("kind", kind);
      const override = process.env.NEXT_PUBLIC_CONTROL_PLANE_URL?.trim();
      const base = override ? override.replace(/\/+$/, "") : "";
      return `${base}/api/v1/logs/stream?${params}`;
    },
  },
};
