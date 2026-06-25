/**
 * Rich per-site configuration model shared by the Add/Edit Site wizard and the
 * site detail page. This is the single source of truth that translates the
 * friendly UI form into the JSON the control-plane stores (and the data plane
 * consumes), and back again for editing.
 *
 * The control-plane stores `upstream` and `waf_policy` as opaque JSON blobs, so
 * we can carry the full rich shape without any DB migration. The data plane
 * enforces the WAF core (mode/paranoia/threshold/CRS), rule exclusions,
 * rate-limit, anti-DDoS, bot_detection, geoip, ML, ip_reputation and request
 * limits today; `bot_detection` and `ip_reputation` are passed through verbatim
 * so provider keys / blacklist sources reach the data plane and are honoured
 * where supported. TLS certificates are managed through the dedicated /certs
 * API (real ACME + manual upload).
 */
import type { Site, AcmeProvider } from "./api";

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
  /** When true the whole rule is dropped (learning-report one-click disable). */
  disable?:        boolean;
}

export interface RateWindow { rps: number; burst: number }

/* ── TLS / Certificates ───────────────────────────────────────── */
export type TlsMode = "auto" | "existing" | "manual" | "off";

/**
 * Does a certificate (by its primary domain + SANs) cover `host`?
 * Matches exact names and one-level wildcards (`*.example.com` → `a.example.com`),
 * mirroring the data plane's SNI resolver. Used to show "this cert protects
 * these sites" without re-uploading per site.
 */
export function certCoversHost(certNames: string[], host: string): boolean {
  const h = (host || "").toLowerCase();
  return certNames.some(n => {
    const name = (n || "").toLowerCase();
    if (name === h) return true;
    if (name.startsWith("*.")) {
      const parent = name.slice(2);
      const idx = h.indexOf(".");
      return idx > 0 && h.slice(idx + 1) === parent;
    }
    return false;
  });
}

/** ACME challenge type. http_01 + tls_alpn_01 are enforced by our ACME engine;
 *  dns_01 (for wildcards) is roadmap — carried for round-trip, not yet issued. */
export type ChallengeType = "http_01" | "tls_alpn_01" | "dns_01";

/** How a custom certificate is supplied: pasted PEM data, or a path on the node. */
export type CustomCertPriority = "data" | "file";

/* ── Custom response header ───────────────────────────────────── */
export interface CustomHeader { name: string; value: string }

/* ── Full form state ───────────────────────────────────────────── */
export interface SiteForm {
  // basics
  name:    string;
  domains: string[];
  preset:  PresetKey;

  // front service / public exposure
  front_https:  boolean;   // terminate HTTPS on the public listener
  force_https:  boolean;   // redirect HTTP → HTTPS
  http2:        boolean;
  http3:        boolean;

  // upstream / reverse proxy
  lb:                  LoadBalancer;
  servers:             UpstreamServer[];
  health:              HealthCheck;
  proxy_host_header:   string;   // override Host sent upstream ("" = pass-through)
  proxy_ssl_sni:       boolean;  // send SNI to a TLS upstream
  proxy_ssl_sni_name:  string;
  proxy_websocket:     boolean;  // allow Upgrade/WebSocket
  proxy_keepalive:     boolean;
  proxy_connect_timeout: string;
  proxy_read_timeout:  string;

  // tls / certificates — automatic (ACME) + manual, full BunkerWeb parity
  tls_mode:       TlsMode;
  acme_provider:  AcmeProvider;
  acme_email:     string;
  acme_challenge: ChallengeType;
  acme_staging:   boolean;
  acme_wildcard:  boolean;
  acme_ca_server: string;          // override ACME directory URL ("" = provider default)  [stored]
  // ZeroSSL API tuning (only relevant when provider = zerossl)  [stored]
  zerossl_api_key:         string;
  zerossl_retries:         number;
  zerossl_retry_delay:     number;
  zerossl_connect_timeout: number;
  zerossl_max_time:        number;
  // DNS-01 automation (for wildcard certs)  [stored — roadmap]
  dns_provider:    string;
  dns_propagation: string;
  dns_credential:  string;
  // manual certificate
  tls_existing_cert: string;  // selected repository cert (primary domain) when mode = existing
  custom_priority: CustomCertPriority; // "data" = paste PEM (enforced) · "file" = path on node [stored]
  cert_pem:        string;  // manual PEM data (installed via /certs API)
  key_pem:         string;  // manual PEM data (installed via /certs API)
  cert_path:       string;  // path on the WAF node (when priority = file) [stored]
  key_path:        string;  // path on the WAF node (when priority = file) [stored]
  hsts:            boolean;
  hsts_max_age:    number;

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
  allowed_methods:  string[];

  // rate limiting + anti-ddos
  rate_limit_enabled: boolean;
  rl_global:          RateWindow;
  rl_per_ip:          RateWindow;
  antiddos_enabled:   boolean;
  antiddos_conn_rate: number;
  antiddos_burst:     number;
  antiddos_block_secs: number;

  // bots / antibot
  bot_ja4:        boolean;
  bot_challenge:  "off" | "native_pow" | "hcaptcha" | "turnstile" | "recaptcha";
  bot_recaptcha_sitekey: string;
  bot_recaptcha_secret:  string;
  bot_recaptcha_score:   number;
  bot_hcaptcha_sitekey:  string;
  bot_hcaptcha_secret:   string;
  bot_turnstile_sitekey: string;
  bot_turnstile_secret:  string;

  // geo + ip reputation + blacklists
  geo_mode:       "off" | "block" | "allow";
  geo_countries:  string[];
  ip_allow:       string[];
  ip_block:       string[];
  dnsbl_enabled:  boolean;
  dnsbl_servers:  string[];
  blacklist_user_agents: string[];
  blacklist_uris: string[];

  // http response headers
  csp:               string;
  referrer_policy:   string;
  permissions_policy: string;
  cors_enabled:      boolean;
  cors_origins:      string;
  cookie_flags:      string;
  custom_headers:    CustomHeader[];

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

/* ── HTTP methods (for method enforcement) ────────────────────── */
export const HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"];

/* ── ACME / Let's Encrypt providers ───────────────────────────── */
export const ACME_PROVIDERS: { key: AcmeProvider; label: string; desc: string }[] = [
  { key: "letsencrypt",         label: "Let's Encrypt",          desc: "Free, trusted, 90-day certs (production)" },
  { key: "letsencrypt_staging", label: "Let's Encrypt (Staging)",desc: "Untrusted test certs — no rate limits" },
  { key: "zerossl",             label: "ZeroSSL",                desc: "Free ACME CA, EAB optional" },
];

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

    front_https: true, force_https: true, http2: true, http3: false,

    lb: "round_robin",
    servers: [{ host: "127.0.0.1", port: 8080, weight: 1, tls: false }],
    health: { enabled: true, path: "/", interval: "10s", timeout: "3s" },
    proxy_host_header: "", proxy_ssl_sni: false, proxy_ssl_sni_name: "",
    proxy_websocket: false, proxy_keepalive: true,
    proxy_connect_timeout: "5s", proxy_read_timeout: "60s",

    tls_mode: "auto", acme_provider: "letsencrypt", acme_email: "",
    acme_challenge: "http_01", acme_staging: false, acme_wildcard: false,
    acme_ca_server: "",
    zerossl_api_key: "", zerossl_retries: 3, zerossl_retry_delay: 2,
    zerossl_connect_timeout: 5, zerossl_max_time: 20,
    dns_provider: "", dns_propagation: "default", dns_credential: "",
    tls_existing_cert: "",
    custom_priority: "data", cert_pem: "", key_pem: "", cert_path: "", key_path: "",
    hsts: true, hsts_max_age: 31536000,

    mode: "blocking", paranoia_level: 2, anomaly_threshold: 5,
    rule_categories: [...ALL_CRS_KEYS], rule_exclusions: [],

    max_body_size_mb: 10, max_uri_length: 8192, max_header_count: 100,
    allowed_methods: ["GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"],

    rate_limit_enabled: true,
    rl_global: { rps: 5000, burst: 10000 },
    rl_per_ip: { rps: 100, burst: 50 },
    antiddos_enabled: false, antiddos_conn_rate: 200, antiddos_burst: 50, antiddos_block_secs: 300,

    bot_ja4: false, bot_challenge: "off",
    bot_recaptcha_sitekey: "", bot_recaptcha_secret: "", bot_recaptcha_score: 0.7,
    bot_hcaptcha_sitekey: "", bot_hcaptcha_secret: "",
    bot_turnstile_sitekey: "", bot_turnstile_secret: "",

    geo_mode: "off", geo_countries: [],
    ip_allow: [], ip_block: [],
    dnsbl_enabled: false, dnsbl_servers: [], blacklist_user_agents: [], blacklist_uris: [],

    csp: "", referrer_policy: "strict-origin-when-cross-origin",
    permissions_policy: "geolocation=(), microphone=(), camera=()",
    cors_enabled: false, cors_origins: "*", cookie_flags: "* HttpOnly SameSite=Lax",
    custom_headers: [],

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
  // Reverse-proxy options (passed through; honoured where supported by the data plane).
  const proxy: Record<string, unknown> = {
    websocket: f.proxy_websocket,
    keepalive: f.proxy_keepalive,
    connect_timeout: f.proxy_connect_timeout,
    read_timeout: f.proxy_read_timeout,
  };
  if (f.proxy_host_header.trim()) proxy.host_header = f.proxy_host_header.trim();
  if (f.proxy_ssl_sni) { proxy.ssl_sni = true; if (f.proxy_ssl_sni_name.trim()) proxy.ssl_sni_name = f.proxy_ssl_sni_name.trim(); }
  upstream.proxy = proxy;

  const waf_policy: Record<string, unknown> = {
    mode: f.mode,
    paranoia_level: Number(f.paranoia_level) || 2,
    anomaly_threshold: Number(f.anomaly_threshold) || 5,
    rule_categories: f.rule_categories,
    rule_exclusions: f.rule_exclusions,
    max_body_size: Math.round((Number(f.max_body_size_mb) || 10) * 1024 * 1024),
    max_uri_length: Number(f.max_uri_length) || 8192,
    max_header_count: Number(f.max_header_count) || 100,
    allowed_methods: f.allowed_methods,
    api_discovery: f.api_discovery,
    // front-service exposure (informational round-trip; listener is global today)
    frontend: {
      https: f.front_https, force_https: f.force_https,
      http2: f.http2, http3: f.http3,
    },
    // tls intent (cert material is issued via the /certs API, not stored here)
    tls: {
      mode: f.tls_mode,
      provider: f.acme_provider,
      email: f.acme_email,
      challenge: f.acme_challenge,
      staging: f.acme_staging,
      wildcard: f.acme_wildcard,
      existing_cert: f.tls_existing_cert,
      ca_server: f.acme_ca_server,
      zerossl: {
        api_key: f.zerossl_api_key,
        retries: Number(f.zerossl_retries) || 3,
        retry_delay: Number(f.zerossl_retry_delay) || 2,
        connect_timeout: Number(f.zerossl_connect_timeout) || 5,
        max_time: Number(f.zerossl_max_time) || 20,
      },
      dns: { provider: f.dns_provider, propagation: f.dns_propagation, credential: f.dns_credential },
      custom: { priority: f.custom_priority, cert_path: f.cert_path, key_path: f.key_path },
    },
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
    const bot: Record<string, unknown> = { ja4: f.bot_ja4, challenge: f.bot_challenge };
    if (f.bot_challenge === "recaptcha") {
      bot.recaptcha = { sitekey: f.bot_recaptcha_sitekey, secret: f.bot_recaptcha_secret, score: Number(f.bot_recaptcha_score) || 0.7 };
    } else if (f.bot_challenge === "hcaptcha") {
      bot.hcaptcha = { sitekey: f.bot_hcaptcha_sitekey, secret: f.bot_hcaptcha_secret };
    } else if (f.bot_challenge === "turnstile") {
      bot.turnstile = { sitekey: f.bot_turnstile_sitekey, secret: f.bot_turnstile_secret };
    }
    waf_policy.bot_detection = bot;
  }
  if (f.geo_mode !== "off" && f.geo_countries.length > 0) {
    waf_policy.geoip = f.geo_mode === "allow"
      ? { allow_countries: f.geo_countries, block_countries: [] }
      : { block_countries: f.geo_countries, allow_countries: [] };
  }
  // IP reputation + blacklist sources (passed through verbatim to the data plane).
  if (f.ip_allow.length > 0 || f.ip_block.length > 0 || f.dnsbl_enabled ||
      f.blacklist_user_agents.length > 0 || f.blacklist_uris.length > 0) {
    const ipr: Record<string, unknown> = { allow: f.ip_allow, block: f.ip_block };
    if (f.dnsbl_enabled) ipr.dnsbl = { enabled: true, servers: f.dnsbl_servers };
    if (f.blacklist_user_agents.length) ipr.block_user_agents = f.blacklist_user_agents;
    if (f.blacklist_uris.length) ipr.block_uris = f.blacklist_uris;
    waf_policy.ip_reputation = ipr;
  }
  // Response headers (secure defaults are always injected by the proxy; these
  // are per-site overrides carried for round-trip and future enforcement).
  const headers: Record<string, unknown> = {};
  if (f.csp.trim()) headers.content_security_policy = f.csp.trim();
  if (f.referrer_policy.trim()) headers.referrer_policy = f.referrer_policy.trim();
  if (f.permissions_policy.trim()) headers.permissions_policy = f.permissions_policy.trim();
  if (f.cors_enabled) headers.cors = { enabled: true, allow_origin: f.cors_origins };
  if (f.cookie_flags.trim()) headers.cookie_flags = f.cookie_flags.trim();
  if (f.hsts) headers.hsts = { enabled: true, max_age: Number(f.hsts_max_age) || 31536000 };
  const custom = f.custom_headers.filter(h => h.name.trim());
  if (custom.length) headers.custom = custom.map(h => ({ name: h.name.trim(), value: h.value }));
  if (Object.keys(headers).length) waf_policy.security_headers = headers;

  if (f.ml_enabled) {
    waf_policy.ml = { enable: true, models: [], sensitivity: Number(f.ml_sensitivity) || 0.85 };
  }

  return { name: f.name.trim(), domains: f.domains, upstream, waf_policy };
}

/* ── API Site → Form (for editing) ────────────────────────────── */
type AnyRec = Record<string, unknown>;
const num = (v: unknown, d: number) => (typeof v === "number" ? v : Number(v) || d);
const str = (v: unknown, d = "") => (typeof v === "string" ? v : d);
const bool = (v: unknown) => v === true;
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
  const proxy = up.proxy as AnyRec | undefined;
  if (proxy) {
    f.proxy_websocket = bool(proxy.websocket);
    f.proxy_keepalive = proxy.keepalive === undefined ? true : bool(proxy.keepalive);
    f.proxy_connect_timeout = str(proxy.connect_timeout, "5s");
    f.proxy_read_timeout = str(proxy.read_timeout, "60s");
    f.proxy_host_header = str(proxy.host_header);
    f.proxy_ssl_sni = bool(proxy.ssl_sni);
    f.proxy_ssl_sni_name = str(proxy.ssl_sni_name);
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
  const methods = arr<string>(w.allowed_methods);
  if (methods.length) f.allowed_methods = methods;
  f.api_discovery = !!w.api_discovery;

  const fe = w.frontend as AnyRec | undefined;
  if (fe) {
    f.front_https = fe.https === undefined ? true : bool(fe.https);
    f.force_https = fe.force_https === undefined ? true : bool(fe.force_https);
    f.http2 = fe.http2 === undefined ? true : bool(fe.http2);
    f.http3 = bool(fe.http3);
  }

  const tls = w.tls as AnyRec | undefined;
  if (tls) {
    f.tls_mode = (tls.mode as TlsMode) ?? "auto";
    f.acme_provider = (tls.provider as AcmeProvider) ?? "letsencrypt";
    f.acme_email = str(tls.email);
    f.acme_challenge = (tls.challenge as ChallengeType) ?? "http_01";
    f.acme_staging = bool(tls.staging);
    f.acme_wildcard = bool(tls.wildcard);
    f.tls_existing_cert = str(tls.existing_cert);
    f.acme_ca_server = str(tls.ca_server);
    const z = tls.zerossl as AnyRec | undefined;
    if (z) {
      f.zerossl_api_key = str(z.api_key);
      f.zerossl_retries = num(z.retries, 3);
      f.zerossl_retry_delay = num(z.retry_delay, 2);
      f.zerossl_connect_timeout = num(z.connect_timeout, 5);
      f.zerossl_max_time = num(z.max_time, 20);
    }
    const dns = tls.dns as AnyRec | undefined;
    if (dns) { f.dns_provider = str(dns.provider); f.dns_propagation = str(dns.propagation, "default"); f.dns_credential = str(dns.credential); }
    const cust = tls.custom as AnyRec | undefined;
    if (cust) { f.custom_priority = (cust.priority as CustomCertPriority) ?? "data"; f.cert_path = str(cust.cert_path); f.key_path = str(cust.key_path); }
  }

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
    const rc = bot.recaptcha as AnyRec | undefined;
    if (rc) { f.bot_recaptcha_sitekey = str(rc.sitekey); f.bot_recaptcha_secret = str(rc.secret); f.bot_recaptcha_score = num(rc.score, 0.7); }
    const hc2 = bot.hcaptcha as AnyRec | undefined;
    if (hc2) { f.bot_hcaptcha_sitekey = str(hc2.sitekey); f.bot_hcaptcha_secret = str(hc2.secret); }
    const ts = bot.turnstile as AnyRec | undefined;
    if (ts) { f.bot_turnstile_sitekey = str(ts.sitekey); f.bot_turnstile_secret = str(ts.secret); }
  }

  const geo = w.geoip as AnyRec | undefined;
  if (geo) {
    const allow = arr<string>(geo.allow_countries);
    const block = arr<string>(geo.block_countries);
    if (allow.length) { f.geo_mode = "allow"; f.geo_countries = allow; }
    else if (block.length) { f.geo_mode = "block"; f.geo_countries = block; }
  }

  const ipr = w.ip_reputation as AnyRec | undefined;
  if (ipr) {
    f.ip_allow = arr<string>(ipr.allow);
    f.ip_block = arr<string>(ipr.block);
    const dnsbl = ipr.dnsbl as AnyRec | undefined;
    if (dnsbl && dnsbl.enabled) { f.dnsbl_enabled = true; f.dnsbl_servers = arr<string>(dnsbl.servers); }
    f.blacklist_user_agents = arr<string>(ipr.block_user_agents);
    f.blacklist_uris = arr<string>(ipr.block_uris);
  }

  const sh = w.security_headers as AnyRec | undefined;
  if (sh) {
    f.csp = str(sh.content_security_policy);
    if (sh.referrer_policy) f.referrer_policy = str(sh.referrer_policy);
    if (sh.permissions_policy) f.permissions_policy = str(sh.permissions_policy);
    if (sh.cookie_flags) f.cookie_flags = str(sh.cookie_flags);
    const cors = sh.cors as AnyRec | undefined;
    if (cors && cors.enabled) { f.cors_enabled = true; f.cors_origins = str(cors.allow_origin, "*"); }
    const hsts = sh.hsts as AnyRec | undefined;
    if (hsts) { f.hsts = bool(hsts.enabled); f.hsts_max_age = num(hsts.max_age, 31536000); }
    else { f.hsts = false; }
    f.custom_headers = arr<AnyRec>(sh.custom).map(h => ({ name: str(h.name), value: str(h.value) }));
  }

  const ml = w.ml as AnyRec | undefined;
  if (ml && ml.enable) { f.ml_enabled = true; f.ml_sensitivity = num(ml.sensitivity, 0.85); }

  f.preset = "custom";
  return f;
}
