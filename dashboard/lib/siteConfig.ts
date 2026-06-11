/**
 * Rich per-site configuration model shared by the Add/Edit Site wizard and the
 * site detail page. This is the single source of truth that translates the
 * friendly UI form into the JSON the control-plane stores (and the data plane
 * consumes), and back again for editing.
 *
 * The control-plane stores `upstream` and `waf_policy` as opaque JSON blobs, so
 * we can carry the full rich shape without any DB migration.
 */
import type { Site } from "./api";

/**
 * Reduce arbitrary user input to a bare Host-header value.
 * A "domain" is a hostname the WAF matches on — never a URL — so we strip any
 * scheme, userinfo, port, path, query and fragment. e.g.
 *   "http://localhost:7000/"  -> "localhost"
 *   "https://app.example.com" -> "app.example.com"
 *   "App.Example.com:8443/x"  -> "app.example.com"
 */
export function normalizeDomain(input: string): string {
  let d = (input || "").trim();
  if (!d) return "";
  d = d.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, ""); // scheme
  d = d.replace(/^[^@/]*@/, "");                       // userinfo
  d = d.split(/[/?#]/)[0];                             // path/query/fragment
  d = d.replace(/:\d+$/, "");                          // port
  return d.toLowerCase();
}

/* ── Upstream ──────────────────────────────────────────────────── */
export interface UpstreamServer {
  host:   string;
  port:   number;
  weight: number;
  tls:    boolean;
}

export type LoadBalancer =
  | "round_robin" | "least_conn" | "ip_hash" | "random" | "adaptive";

export interface HealthCheck {
  enabled:  boolean;
  path:     string;
  interval: string;
  timeout:  string;
}

/* ── WAF ───────────────────────────────────────────────────────── */
export type WafMode = "blocking" | "learning" | "off";

export interface RuleExclusion {
  rule_id:         number;
  exclude_targets: string[];
}

export interface RateWindow { rps: number; burst: number }

/* ── Full form state ───────────────────────────────────────────── */
export interface SiteForm {
  // basics
  name:    string;
  domains: string[];
  preset:  PresetKey;

  // upstream / reverse proxy
  lb:           LoadBalancer;
  servers:      UpstreamServer[];
  health:       HealthCheck;

  // waf core
  mode:              WafMode;
  paranoia_level:    number;
  anomaly_threshold: number;
  rule_categories:   string[];
  rule_exclusions:   RuleExclusion[];

  // request limits
  max_body_size_mb: number;
  max_uri_length:   number;
  max_header_count: number;

  // rate limiting + anti-ddos
  rate_limit_enabled: boolean;
  rl_global:          RateWindow;
  rl_per_ip:          RateWindow;
  antiddos_enabled:   boolean;
  antiddos_conn_rate: number;
  antiddos_burst:     number;
  antiddos_block_secs: number;

  // bots + geo + ip reputation
  bot_ja4:        boolean;
  bot_challenge:  "off" | "native_pow" | "hcaptcha" | "turnstile";
  geo_mode:       "off" | "block" | "allow";
  geo_countries:  string[];
  ip_allow:       string[];
  ip_block:       string[];

  // ml + advanced
  ml_enabled:     boolean;
  ml_sensitivity: number;
  api_discovery:  boolean;
}

/* ── OWASP CRS categories (UI-friendly toggles) ───────────────────
 * Keys mirror crsCategoryFiles in the control-plane handlers.
 */
export const CRS_CATEGORIES: { key: string; label: string; desc: string; core?: boolean }[] = [
  { key: "sqli",            label: "SQL Injection",       desc: "SQLi payloads in args, body, headers, cookies" },
  { key: "xss",             label: "Cross-Site Scripting",desc: "Reflected / stored / DOM XSS vectors" },
  { key: "rce",             label: "Remote Code Exec",    desc: "Unix/Windows command injection" },
  { key: "lfi",             label: "Local File Inclusion",desc: "Path traversal & local file disclosure" },
  { key: "rfi",             label: "Remote File Inclusion",desc: "Remote URL inclusion attacks" },
  { key: "php",             label: "PHP Injection",       desc: "PHP-specific code & wrapper attacks" },
  { key: "java",            label: "Java Attacks",        desc: "Java deserialization & expression injection" },
  { key: "generic",         label: "Generic Attacks",     desc: "Generic injection & evasion patterns" },
  { key: "protocol_attack", label: "Protocol Attacks",    desc: "Request smuggling, response splitting" },
  { key: "protocol",        label: "Protocol Enforcement",desc: "HTTP protocol hygiene", core: true },
  { key: "method",          label: "Method Enforcement",  desc: "Allowed HTTP methods", core: true },
  { key: "scanner",         label: "Scanner Detection",   desc: "Block nikto, sqlmap, nmap, etc.", core: true },
  { key: "session",         label: "Session Fixation",    desc: "Session fixation protection" },
];

export const ALL_CRS_KEYS = CRS_CATEGORIES.map(c => c.key);

/* ── Security presets ─────────────────────────────────────────── */
export type PresetKey = "essential" | "balanced" | "strict" | "custom";

export const PRESETS: Record<Exclude<PresetKey, "custom">, {
  label: string; icon: string; desc: string;
  paranoia_level: number; anomaly_threshold: number;
  rl_per_ip: RateWindow; bot_ja4: boolean;
}> = {
  essential: {
    label: "Essential", icon: "🟢",
    desc: "Low false-positives. Blocks the OWASP Top-10. Best for most apps.",
    paranoia_level: 1, anomaly_threshold: 10,
    rl_per_ip: { rps: 200, burst: 100 }, bot_ja4: false,
  },
  balanced: {
    label: "Balanced", icon: "🔵",
    desc: "Recommended. Stronger detection with sensible thresholds.",
    paranoia_level: 2, anomaly_threshold: 5,
    rl_per_ip: { rps: 100, burst: 50 }, bot_ja4: false,
  },
  strict: {
    label: "Strict", icon: "🔴",
    desc: "Maximum protection. Higher false-positive risk — tune with Learning first.",
    paranoia_level: 4, anomaly_threshold: 3,
    rl_per_ip: { rps: 50, burst: 25 }, bot_ja4: true,
  },
};

/* ── Country list for GeoIP filtering (common subset) ─────────── */
export const COUNTRIES: { code: string; name: string }[] = [
  { code: "US", name: "United States" }, { code: "CN", name: "China" },
  { code: "RU", name: "Russia" },        { code: "IN", name: "India" },
  { code: "BR", name: "Brazil" },        { code: "DE", name: "Germany" },
  { code: "FR", name: "France" },        { code: "GB", name: "United Kingdom" },
  { code: "NL", name: "Netherlands" },   { code: "KP", name: "North Korea" },
  { code: "IR", name: "Iran" },          { code: "UA", name: "Ukraine" },
  { code: "JP", name: "Japan" },         { code: "KR", name: "South Korea" },
  { code: "SG", name: "Singapore" },     { code: "CA", name: "Canada" },
  { code: "AU", name: "Australia" },     { code: "VN", name: "Vietnam" },
  { code: "TR", name: "Turkey" },        { code: "ID", name: "Indonesia" },
];

/* ── Defaults / empty form ────────────────────────────────────── */
export function emptyForm(): SiteForm {
  return {
    name: "", domains: [], preset: "balanced",
    lb: "round_robin",
    servers: [{ host: "127.0.0.1", port: 8080, weight: 1, tls: false }],
    health: { enabled: true, path: "/", interval: "10s", timeout: "3s" },
    mode: "blocking", paranoia_level: 2, anomaly_threshold: 5,
    rule_categories: [...ALL_CRS_KEYS], rule_exclusions: [],
    max_body_size_mb: 10, max_uri_length: 8192, max_header_count: 100,
    rate_limit_enabled: true,
    rl_global: { rps: 5000, burst: 10000 },
    rl_per_ip: { rps: 100, burst: 50 },
    antiddos_enabled: false, antiddos_conn_rate: 200, antiddos_burst: 50, antiddos_block_secs: 300,
    bot_ja4: false, bot_challenge: "off",
    geo_mode: "off", geo_countries: [],
    ip_allow: [], ip_block: [],
    ml_enabled: false, ml_sensitivity: 0.85,
    api_discovery: false,
  };
}

/** Apply a security preset's tuned values onto the form (non-destructive to identity/upstream). */
export function applyPreset(form: SiteForm, preset: PresetKey): SiteForm {
  if (preset === "custom") return { ...form, preset };
  const p = PRESETS[preset];
  return {
    ...form,
    preset,
    paranoia_level: p.paranoia_level,
    anomaly_threshold: p.anomaly_threshold,
    rl_per_ip: { ...p.rl_per_ip },
    bot_ja4: p.bot_ja4,
    rule_categories: [...ALL_CRS_KEYS],
  };
}

/* ── Form → API payload ───────────────────────────────────────── */
export function formToPayload(f: SiteForm): {
  name: string; domains: string[]; upstream: object; waf_policy: object;
} {
  const upstream: Record<string, unknown> = {
    lb: f.lb,
    load_balancer: f.lb,
    servers: f.servers.map(s => ({
      host: s.host, port: Number(s.port) || 80,
      weight: Number(s.weight) || 1, tls: !!s.tls,
    })),
  };
  if (f.health.enabled) {
    upstream.health_check = { path: f.health.path, interval: f.health.interval, timeout: f.health.timeout };
  }

  const waf_policy: Record<string, unknown> = {
    mode: f.mode,
    paranoia_level: Number(f.paranoia_level) || 2,
    anomaly_threshold: Number(f.anomaly_threshold) || 5,
    rule_categories: f.rule_categories,
    rule_exclusions: f.rule_exclusions,
    max_body_size: Math.round((Number(f.max_body_size_mb) || 10) * 1024 * 1024),
    max_uri_length: Number(f.max_uri_length) || 8192,
    max_header_count: Number(f.max_header_count) || 100,
    api_discovery: f.api_discovery,
  };

  if (f.rate_limit_enabled) {
    waf_policy.rate_limit = { global: f.rl_global, per_ip: f.rl_per_ip };
  }
  if (f.antiddos_enabled) {
    waf_policy.anti_ddos = {
      enabled: true, conn_rate_limit: Number(f.antiddos_conn_rate) || 200,
      burst: Number(f.antiddos_burst) || 50, block_duration_secs: Number(f.antiddos_block_secs) || 300,
    };
  }
  if (f.bot_ja4 || f.bot_challenge !== "off") {
    waf_policy.bot_detection = { ja4: f.bot_ja4, challenge: f.bot_challenge };
  }
  if (f.geo_mode !== "off" && f.geo_countries.length > 0) {
    waf_policy.geoip = f.geo_mode === "allow"
      ? { allow_countries: f.geo_countries, block_countries: [] }
      : { block_countries: f.geo_countries, allow_countries: [] };
  }
  if (f.ip_allow.length > 0 || f.ip_block.length > 0) {
    waf_policy.ip_reputation = { allow: f.ip_allow, block: f.ip_block };
  }
  if (f.ml_enabled) {
    waf_policy.ml = { enable: true, models: [], sensitivity: Number(f.ml_sensitivity) || 0.85 };
  }

  return { name: f.name.trim(), domains: f.domains, upstream, waf_policy };
}

/* ── API Site → Form (for editing) ────────────────────────────── */
type AnyRec = Record<string, unknown>;
const num = (v: unknown, d: number) => (typeof v === "number" ? v : Number(v) || d);
const arr = <T,>(v: unknown): T[] => (Array.isArray(v) ? (v as T[]) : []);

export function siteToForm(site: Site): SiteForm {
  const f = emptyForm();
  f.name = site.name;
  f.domains = site.domains ?? [];

  const up = (site.upstream ?? {}) as AnyRec;
  f.lb = (up.load_balancer as LoadBalancer) ?? (up.lb as LoadBalancer) ?? "round_robin";
  const rawServers = up.servers;
  if (Array.isArray(rawServers) && rawServers.length) {
    f.servers = rawServers.map((s): UpstreamServer => {
      if (typeof s === "string") {
        const [host, port] = s.split(":");
        return { host, port: Number(port) || 80, weight: 1, tls: false };
      }
      const o = s as AnyRec;
      return { host: String(o.host ?? "127.0.0.1"), port: num(o.port, 80), weight: num(o.weight, 1), tls: !!o.tls };
    });
  }
  const hc = up.health_check as AnyRec | undefined;
  if (hc) {
    f.health = { enabled: true, path: String(hc.path ?? "/"), interval: String(hc.interval ?? "10s"), timeout: String(hc.timeout ?? "3s") };
  } else {
    f.health.enabled = false;
  }

  const w = (site.waf_policy ?? {}) as AnyRec;
  f.mode = (w.mode as WafMode) ?? "blocking";
  f.paranoia_level = num(w.paranoia_level, 2);
  f.anomaly_threshold = num(w.anomaly_threshold, 5);
  const cats = arr<string>(w.rule_categories);
  f.rule_categories = cats.length ? cats : [...ALL_CRS_KEYS];
  f.rule_exclusions = arr<RuleExclusion>(w.rule_exclusions);
  if (typeof w.max_body_size === "number") f.max_body_size_mb = Math.round((w.max_body_size as number) / (1024 * 1024));
  f.max_uri_length = num(w.max_uri_length, 8192);
  f.max_header_count = num(w.max_header_count, 100);
  f.api_discovery = !!w.api_discovery;

  const rl = w.rate_limit as AnyRec | undefined;
  if (rl) {
    f.rate_limit_enabled = true;
    const g = rl.global as AnyRec | undefined;
    const pi = rl.per_ip as AnyRec | undefined;
    if (g) f.rl_global = { rps: num(g.rps, 5000), burst: num(g.burst, 10000) };
    if (pi) f.rl_per_ip = { rps: num(pi.rps, 100), burst: num(pi.burst, 50) };
  } else f.rate_limit_enabled = false;

  const ad = w.anti_ddos as AnyRec | undefined;
  if (ad && ad.enabled) {
    f.antiddos_enabled = true;
    f.antiddos_conn_rate = num(ad.conn_rate_limit, 200);
    f.antiddos_burst = num(ad.burst, 50);
    f.antiddos_block_secs = num(ad.block_duration_secs, 300);
  }

  const bot = w.bot_detection as AnyRec | undefined;
  if (bot) {
    f.bot_ja4 = !!bot.ja4;
    f.bot_challenge = (bot.challenge as SiteForm["bot_challenge"]) ?? "off";
  }

  const geo = w.geoip as AnyRec | undefined;
  if (geo) {
    const allow = arr<string>(geo.allow_countries);
    const block = arr<string>(geo.block_countries);
    if (allow.length) { f.geo_mode = "allow"; f.geo_countries = allow; }
    else if (block.length) { f.geo_mode = "block"; f.geo_countries = block; }
  }

  const ipr = w.ip_reputation as AnyRec | undefined;
  if (ipr) { f.ip_allow = arr<string>(ipr.allow); f.ip_block = arr<string>(ipr.block); }

  const ml = w.ml as AnyRec | undefined;
  if (ml && ml.enable) { f.ml_enabled = true; f.ml_sensitivity = num(ml.sensitivity, 0.85); }

  f.preset = "custom";
  return f;
}
