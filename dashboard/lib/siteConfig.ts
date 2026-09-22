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
import Icon from "@/components/ui/Icon";

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

/** Per-path policy override. Longest matching prefix wins, so /api/admin/ beats
 *  /api/ regardless of the order rows were added.
 *
 *  Only mode and anomaly_threshold can vary by path: paranoia_level and
 *  rule_exclusions are applied when the rule engine is COMPILED, so the API
 *  rejects them here rather than accepting and ignoring them. */
export interface PathOverride {
  path_prefix:        string;
  mode?:              WafMode | "";
  anomaly_threshold?: number | "";
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

/**
 * The certificate-store keys the data plane tries for `host`, in order.
 *
 * Mirrors `resolve_live` in crates/sentinel-proxy/src/tls/cert_store.rs: the
 * exact key first, then the same name with its first label replaced by `*`.
 *
 * ⚠ The resolver matches on the key a certificate was STORED under (its
 * `domain`), and never reads the certificate's SANs. So this must not either —
 * a lookup that consulted SANs would name a certificate the WAF would never
 * actually serve, which is worse than showing nothing.
 */
export function certStoreKeysFor(host: string): string[] {
  const h = (host || "").trim().toLowerCase().replace(/\.$/, "");
  if (!h) return [];
  const keys = [h];
  const dot = h.indexOf(".");
  // `a.example.com` -> `*.example.com`. A bare `example.com` has no parent to
  // wildcard, and `*.` + "" would match everything, so it is not offered.
  if (dot > 0 && dot < h.length - 1) keys.push(`*.${h.slice(dot + 1)}`);
  return keys;
}

/**
 * Which stored certificate the data plane would serve for `host` right now, or
 * null — in which case it generates a self-signed one on demand and browsers
 * warn.
 *
 * This exists because a site can already be served a perfectly good certificate
 * while the site record names none: an upload through the Certificates page is
 * bound to the DOMAIN in the shared store, not to the site row, and SNI does
 * the rest. The site form showed an empty selector for exactly that state,
 * which reads as "no certificate" and sent an operator looking for a fault that
 * was not there.
 */
export function servingCertFor<T extends { domain: string }>(certs: T[], host: string): T | null {
  for (const key of certStoreKeysFor(host)) {
    const hit = certs.find(c => (c.domain || "").trim().toLowerCase().replace(/\.$/, "") === key);
    if (hit) return hit;
  }
  return null;
}

/** ACME challenge type. http_01 + tls_alpn_01 are enforced by our ACME engine;
 *  dns_01 (for wildcards) is roadmap — carried for round-trip, not yet issued. */
export type ChallengeType = "http_01" | "tls_alpn_01" | "dns_01";

/** How a custom certificate is supplied: pasted PEM data, or a path on the node. */
export type CustomCertPriority = "data" | "file";

/* ── Custom response header ───────────────────────────────────── */
export interface CustomHeader { name: string; value: string }

/* ── External IP-reputation feed (ip_reputation.feeds) ─────────── */
export interface IpFeed { url: string; interval: string; format: "cidr" | "json" }

/* ── DLP action (response data-loss prevention) ───────────────── */
export type DlpAction = "block" | "mask" | "detect";

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
  path_overrides:    PathOverride[];

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
  /** Names of installed plugins THIS site runs. Opt-in: empty = none. */
  site_plugins:   string[];
  /** Mirror the block-list into the kernel (XDP). Node-wide: blocks those sources for EVERY site on the node. */
  ip_block_xdp:   boolean;
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

  // block page — what a blocked visitor sees, and the Support ID they quote
  block_page_enabled: boolean;
  block_page_title:   string;
  block_page_message: string;
  block_page_contact: string;
  block_page_logo:    string;
  /** Off by default: the reason names which control fired, which is an attacker
   *  tuning oracle. Only for internal/staging sites. */
  block_page_show_reason: boolean;

  // ml + advanced
  ml_enabled:     boolean;
  ml_sensitivity: number;
  ml_models:      string[];   // specific bundled models ([] = all)
  api_discovery:  boolean;

  // api security — edge JWT / OAuth2 validation (waf_policy.jwt)
  jwt_enabled:         boolean;
  jwt_required:        boolean;   // reject missing/invalid token vs. verify-if-present
  jwt_issuer:          string;
  jwt_audience:        string;
  jwt_algorithms:      string[];  // e.g. ["RS256"]
  jwt_hs_secret:       string;    // HS256 shared secret
  jwt_public_key_pem:  string;    // RSA/EC public key PEM
  jwt_jwks_url:        string;    // JWKS endpoint (rotated by kid)
  jwt_required_scopes: string[];
  jwt_scope_claim:     string;    // default "scope"

  // api security — GraphQL firewall (waf_policy.graphql)
  graphql_enabled:             boolean;
  graphql_max_depth:           number;
  graphql_max_complexity:      number;
  graphql_block_introspection: boolean;

  // api security — gRPC firewall (waf_policy.grpc)
  grpc_enabled:          boolean;
  grpc_max_message_kb:   number;   // UI in KB → bytes on emit
  grpc_max_frames:       number;
  grpc_block_reflection: boolean;
  grpc_allowed_methods:  string[];
  grpc_blocked_methods:  string[];

  // response data-loss prevention (waf_policy.dlp)
  dlp_enabled:  boolean;
  dlp_action:   DlpAction;
  dlp_patterns: string[];   // extra regexes on top of built-ins ([] = built-ins only)

  // weighted verdict fusion (waf_policy.fusion)
  fusion_enabled:          boolean;
  fusion_weights:          Record<string, number>;  // engine → weight
  fusion_block_thresholds: number[];  // per paranoia level PL1..PL4
  fusion_limit_thresholds: number[];  // soft-LIMIT tier per PL ([] disables)
  fusion_limit_status:     number;    // HTTP status for a LIMIT verdict

  // external ip-reputation feeds (waf_policy.ip_reputation.feeds)
  ip_feeds: IpFeed[];
}

/* ── OWASP CRS categories (UI-friendly toggles) ───────────────────
 * Keys mirror crsCategoryFiles in the control-plane handlers.
 */
export type CrsCategory = { key: string; label: string; desc: string; core?: boolean };

/* Request-phase families. These are the default set: an empty stored selection
 * means "all of these", and the Go control plane's crsFilesForCategories agrees.
 * Keep the keys identical to crsCategoryFiles in handlers.go — a key the Go map
 * does not name is accepted by the API, echoed back here, and silently dropped
 * before it reaches the data plane. */
export const CRS_REQUEST_CATEGORIES: CrsCategory[] = [
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
  { key: "multipart",       label: "Multipart Attacks",   desc: "Malformed upload part headers, deprecated transfer encodings. The stricter charset-policy rule (922110) ships disabled — it refuses us-ascii, utf-16, shift_jis and euc-kr" },
];

/* Response-phase families — data-leakage and web-shell detection in the response
 * BODY, not the request. The engine and the proxy have always supported these;
 * until now the control plane had no key for them, so the rules shipped in the
 * image and no site configuration could load them.
 *
 * Deliberately NOT part of ALL_CRS_KEYS, so they are never enabled implicitly.
 * Two reasons, both visible to the operator in the UI note:
 *   - enabling any of them makes the proxy BUFFER every text-ish response for
 *     the site (up to the scan cap) instead of streaming it through;
 *   - these rules carry `block` directly rather than adding to the anomaly
 *     score, so ONE match blocks the response — the anomaly threshold does not
 *     moderate them. A page that legitimately prints an ORA- code or a MySQL
 *     error will be blocked. */
export const CRS_RESPONSE_CATEGORIES: CrsCategory[] = [
  { key: "leak_sql",     label: "SQL Error Leakage",   desc: "Database errors disclosed in responses (MySQL, Oracle, MSSQL, DB2)" },
  { key: "leak_php",     label: "PHP Error Leakage",   desc: "PHP warnings, stack traces and source disclosure" },
  { key: "leak_java",    label: "Java Error Leakage",  desc: "Java exceptions and stack traces in responses" },
  { key: "leak_iis",     label: "IIS Error Leakage",   desc: "IIS / ASP.NET error pages and path disclosure" },
  { key: "leak_generic", label: "Generic Leakage",     desc: "Directory listings and other generic disclosure" },
  { key: "web_shells",   label: "Web Shell Detection", desc: "Responses served by known web shells (c99, r57, etc.)" },
];

/* Kept as the combined list for read-only summaries. */
export const CRS_CATEGORIES: CrsCategory[] = [...CRS_REQUEST_CATEGORIES, ...CRS_RESPONSE_CATEGORIES];

/* The default selection — request families only. Response families are opt-in;
 * see CRS_RESPONSE_CATEGORIES. */
export const ALL_CRS_KEYS = CRS_REQUEST_CATEGORIES.map(c => c.key);
export const ALL_CRS_RESPONSE_KEYS = CRS_RESPONSE_CATEGORIES.map(c => c.key);

/* ── HTTP methods (for method enforcement) ────────────────────── */
export const HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"];

/* ── JWT signature algorithms (edge JWT / OAuth2 validation) ───── */
export const JWT_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "HS256", "HS384", "HS512"];

/* ── Weighted-fusion engines (engine → weight multiplier) ─────────
 * Mirrors the recognised engines in FusionConfig (Rust). Weight 1.0 = neutral. */
export const FUSION_ENGINES: { key: string; label: string; desc: string }[] = [
  { key: "rules",        label: "Signature rules", desc: "OWASP CRS + custom DSL score" },
  { key: "ml",           label: "ML anomaly",      desc: "Behavioural model score" },
  { key: "bot",          label: "Bot detection",   desc: "JA4 + heuristic bot score" },
  { key: "threat_intel", label: "Threat intel",    desc: "IOC / reputation match" },
];

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
    label: "Essential", icon: "shield",
    desc: "Low false-positives. Blocks the OWASP Top-10. Best for most apps.",
    paranoia_level: 1, anomaly_threshold: 10,
    rl_per_ip: { rps: 200, burst: 100 }, bot_ja4: false,
  },
  balanced: {
    label: "Balanced", icon: "scale",
    desc: "Recommended. The benchmarked default configuration.",
    // PL2 / threshold 10 — deliberately identical to defaultWafPolicyJSON in
    // control-plane/cmd/controllerd/handlers.go, whose comment reads "keep the
    // two in step, or a site's stored policy and its effective policy drift".
    //
    // This was threshold 5, so the preset the operator manual recommends
    // produced a site that was HALF the benchmarked threshold — and at 5 a
    // single weak +5 heuristic blocks on its own, which is where most benign
    // false-positives came from. It also made fpr-report.sh lie: its triage
    // advice tells the operator "the threshold is already at the benchmarked
    // value of 10" and warns them off lowering it, which was false for every
    // site this wizard had ever created.
    paranoia_level: 2, anomaly_threshold: 10,
    rl_per_ip: { rps: 100, burst: 50 }, bot_ja4: false,
  },
  strict: {
    label: "Strict", icon: "lock",
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

    // Learning, not blocking. A site is created for an application whose
    // false-positive rate nobody has measured yet, and the runbook, the
    // onboarding checklist and first-site.sh all say the same thing: soak in
    // learning, measure, tune, then enforce per-site. This wizard was the one
    // path that did the opposite, so the console and the CLI shipped opposite
    // postures for the same action.
    mode: "learning",
    // Taken from the preset that is pre-SELECTED above rather than written out
    // again. applyPreset only runs when an operator CLICKS a tile, so a literal
    // here meant the Balanced tile rendered as active advertising "PL2 · thr 10"
    // while the form actually held 5 — half the benchmarked threshold, on every
    // site this wizard had ever created. Deriving it makes that drift
    // impossible rather than merely fixed.
    paranoia_level: PRESETS.balanced.paranoia_level,
    anomaly_threshold: PRESETS.balanced.anomaly_threshold,
    rule_categories: [...ALL_CRS_KEYS], rule_exclusions: [], path_overrides: [],

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
    dnsbl_enabled: false, ip_block_xdp: false, site_plugins: [], dnsbl_servers: [], blacklist_user_agents: [], blacklist_uris: [],

    csp: "", referrer_policy: "strict-origin-when-cross-origin",
    permissions_policy: "geolocation=(), microphone=(), camera=()",
    cors_enabled: false, cors_origins: "*", cookie_flags: "* HttpOnly SameSite=Lax",
    custom_headers: [],

    block_page_enabled: true, block_page_title: "", block_page_message: "",
    block_page_contact: "", block_page_logo: "", block_page_show_reason: false,

    ml_enabled: false, ml_sensitivity: 0.85, ml_models: [],
    api_discovery: false,

    jwt_enabled: false, jwt_required: true, jwt_issuer: "", jwt_audience: "",
    jwt_algorithms: ["RS256"], jwt_hs_secret: "", jwt_public_key_pem: "",
    jwt_jwks_url: "", jwt_required_scopes: [], jwt_scope_claim: "scope",

    graphql_enabled: false, graphql_max_depth: 10, graphql_max_complexity: 1000,
    graphql_block_introspection: true,

    grpc_enabled: false, grpc_max_message_kb: 4096, grpc_max_frames: 512,
    grpc_block_reflection: true, grpc_allowed_methods: [], grpc_blocked_methods: [],

    dlp_enabled: false, dlp_action: "block", dlp_patterns: [],

    fusion_enabled: false,
    fusion_weights: { rules: 1, ml: 1, bot: 1, threat_intel: 1 },
    fusion_block_thresholds: [7, 5, 4, 3], fusion_limit_thresholds: [4, 3, 2, 2],
    fusion_limit_status: 429,

    ip_feeds: [],
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

/** Parse a duration like "60s" / "2m" / "90" (bare = seconds) into whole
 *  seconds. Returns 0 for anything unparseable, which callers read as
 *  "unset — use the deployment default". */
export function durationToSecs(v: string): number {
  const m = /^(\d+)\s*(s|m|h)?$/i.exec((v ?? "").trim());
  if (!m) return 0;
  const n = Number(m[1]);
  switch ((m[2] ?? "s").toLowerCase()) {
    case "m": return n * 60;
    case "h": return n * 3600;
    default:  return n;
  }
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

  // How long the origin may take to return response headers. This is the only
  // consumer of the Read Timeout field that the data plane actually enforces —
  // `upstream.proxy.read_timeout` was never read by it, so the control looked
  // live but did nothing. 0 / unparseable = fall back to the node default.
  const readTimeoutSecs = durationToSecs(f.proxy_read_timeout);
  if (readTimeoutSecs > 0) upstream.timeout_secs = readTimeoutSecs;

  // Connect timeout follows the same shape as Read Timeout above: the duration
  // string in `proxy` is what the operator types, and this promoted seconds value
  // is what the data plane reads. 0 / unparseable = node default.
  const connectTimeoutSecs = durationToSecs(f.proxy_connect_timeout);
  if (connectTimeoutSecs > 0) upstream.connect_timeout_secs = connectTimeoutSecs;

  // Drop incomplete or no-op rows rather than sending them: the API rejects an
  // override that sets neither mode nor threshold, and a half-filled row in the
  // UI should not fail the whole save.
  const path_overrides = (f.path_overrides ?? [])
    .filter(o => o.path_prefix.trim() !== "")
    .map(o => {
      const out: Record<string, unknown> = { path_prefix: o.path_prefix.trim() };
      if (o.mode) out.mode = o.mode;
      if (o.anomaly_threshold !== "" && o.anomaly_threshold !== undefined) {
        out.anomaly_threshold = Number(o.anomaly_threshold);
      }
      return out;
    })
    .filter(o => o.mode !== undefined || o.anomaly_threshold !== undefined);

  const waf_policy: Record<string, unknown> = {
    mode: f.mode,
    paranoia_level: Number(f.paranoia_level) || 2,
    // Falls back to the benchmarked default, not to 5. An empty field must not
    // silently install a posture nobody validated.
    anomaly_threshold: Number(f.anomaly_threshold) || PRESETS.balanced.anomaly_threshold,
    rule_categories: f.rule_categories,
    rule_exclusions: f.rule_exclusions,
    max_body_size: Math.round((Number(f.max_body_size_mb) || 10) * 1024 * 1024),
    max_uri_length: Number(f.max_uri_length) || 8192,
    max_header_count: Number(f.max_header_count) || 100,
    allowed_methods: f.allowed_methods,
    api_discovery: f.api_discovery,
    // Always emitted, including empty: a site with no plugins selected runs
    // none, and sending it explicitly makes a deselection legible in the
    // effective-config diff instead of looking like an omitted key.
    enabled_plugins: f.site_plugins,
    // Always emitted, including when empty: waf_policy is REPLACED wholesale, so
    // an absent key and an empty list mean the same thing to the server — but
    // sending it explicitly keeps "cleared on purpose" legible in a request log.
    path_overrides,
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
  const ipFeeds = f.ip_feeds
    .filter(x => x.url.trim())
    .map(x => ({ url: x.url.trim(), interval: x.interval.trim() || "1h", format: x.format || "cidr" }));
  if (f.ip_allow.length > 0 || f.ip_block.length > 0 || f.dnsbl_enabled ||
      f.blacklist_user_agents.length > 0 || f.blacklist_uris.length > 0 || ipFeeds.length > 0) {
    const ipr: Record<string, unknown> = { allow: f.ip_allow, block: f.ip_block };
    if (f.ip_block_xdp) ipr.xdp_mirror = true;
    if (ipFeeds.length) ipr.feeds = ipFeeds;
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

  // Block page. Emitted whenever it differs from the built-in default, so an
  // untouched site stays absent from the config rather than carrying a block of
  // empty strings the data plane would have to treat as "unset" anyway.
  const bp: Record<string, unknown> = {};
  if (!f.block_page_enabled) bp.enabled = false;
  if (f.block_page_title.trim()) bp.title = f.block_page_title.trim();
  if (f.block_page_message.trim()) bp.message = f.block_page_message.trim();
  if (f.block_page_contact.trim()) bp.contact = f.block_page_contact.trim();
  if (f.block_page_logo.trim()) bp.logo_url = f.block_page_logo.trim();
  if (f.block_page_show_reason) bp.show_reason = true;
  if (Object.keys(bp).length) {
    // `enabled` defaults true in the data plane; send it explicitly so a config
    // that sets only, say, a title does not read as enabled:false anywhere.
    if (bp.enabled === undefined) bp.enabled = true;
    waf_policy.block_page = bp;
  }

  if (f.ml_enabled) {
    waf_policy.ml = {
      enable: true,
      models: f.ml_models.map(m => m.trim()).filter(Boolean),
      sensitivity: Number(f.ml_sensitivity) || 0.85,
    };
  }

  // ── Edge JWT / OAuth2 validation (waf_policy.jwt) ──
  if (f.jwt_enabled) {
    const jwt: Record<string, unknown> = {
      enable: true,
      required: f.jwt_required,
      algorithms: f.jwt_algorithms.length ? f.jwt_algorithms : ["RS256"],
      required_scopes: f.jwt_required_scopes,
      scope_claim: f.jwt_scope_claim.trim() || "scope",
    };
    if (f.jwt_issuer.trim()) jwt.issuer = f.jwt_issuer.trim();
    if (f.jwt_audience.trim()) jwt.audience = f.jwt_audience.trim();
    if (f.jwt_hs_secret.trim()) jwt.hs_secret = f.jwt_hs_secret.trim();
    if (f.jwt_public_key_pem.trim()) jwt.public_key_pem = f.jwt_public_key_pem.trim();
    if (f.jwt_jwks_url.trim()) jwt.jwks_url = f.jwt_jwks_url.trim();
    waf_policy.jwt = jwt;
  }

  // ── GraphQL firewall (waf_policy.graphql) ──
  if (f.graphql_enabled) {
    waf_policy.graphql = {
      enable: true,
      max_depth: Number(f.graphql_max_depth) || 10,
      max_complexity: Number(f.graphql_max_complexity) || 1000,
      block_introspection: f.graphql_block_introspection,
    };
  }

  // ── gRPC firewall (waf_policy.grpc) ──
  if (f.grpc_enabled) {
    waf_policy.grpc = {
      enable: true,
      max_message_bytes: (Number(f.grpc_max_message_kb) || 4096) * 1024,
      max_frames: Number(f.grpc_max_frames) || 512,
      block_reflection: f.grpc_block_reflection,
      allowed_methods: f.grpc_allowed_methods,
      blocked_methods: f.grpc_blocked_methods,
    };
  }

  // ── Response data-loss prevention (waf_policy.dlp) ──
  if (f.dlp_enabled) {
    waf_policy.dlp = {
      enable: true,
      action: f.dlp_action,
      patterns: f.dlp_patterns.map(p => p.trim()).filter(Boolean),
    };
  }

  // ── Weighted verdict fusion (waf_policy.fusion) ──
  if (f.fusion_enabled) {
    // Drop neutral (1.0) weights so the payload only carries operator intent.
    const weights: Record<string, number> = {};
    for (const [k, v] of Object.entries(f.fusion_weights)) {
      const n = Number(v);
      if (Number.isFinite(n) && n !== 1) weights[k] = n;
    }
    waf_policy.fusion = {
      enable: true,
      weights,
      block_thresholds: f.fusion_block_thresholds.map(n => Number(n) || 0),
      limit_thresholds: f.fusion_limit_thresholds.map(n => Number(n) || 0),
      limit_status: Number(f.fusion_limit_status) || 429,
    };
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
  // `timeout_secs` is the value the data plane actually enforces, so it wins
  // over the legacy `proxy.read_timeout` display string when both are present.
  const timeoutSecs = Number(up.timeout_secs);
  if (Number.isFinite(timeoutSecs) && timeoutSecs > 0) {
    f.proxy_read_timeout = `${timeoutSecs}s`;
  }

  const w = (site.waf_policy ?? {}) as AnyRec;
  f.mode = (w.mode as WafMode) ?? "blocking";
  f.paranoia_level = num(w.paranoia_level, 2);
  f.anomaly_threshold = num(w.anomaly_threshold, 5);
  const cats = arr<string>(w.rule_categories);
  f.rule_categories = cats.length ? cats : [...ALL_CRS_KEYS];
  f.rule_exclusions = arr<RuleExclusion>(w.rule_exclusions);
  // Read back so a round-trip preserves them. Omitting this made loading a site
  // and saving it — for any reason, e.g. flipping the mode — silently DELETE the
  // operator's per-path policy, because formToPayload writes a whole waf_policy
  // and the form had an empty list. Every field in SiteForm must be read here or
  // it is data the UI quietly discards.
  // Read as loose records: this is untrusted JSON from the API, not something
  // already shaped like a PathOverride.
  f.path_overrides = arr<AnyRec>(w.path_overrides).map(o => ({
    path_prefix:       String(o.path_prefix ?? ""),
    mode:              (o.mode as WafMode) ?? "",
    anomaly_threshold: typeof o.anomaly_threshold === "number" ? o.anomaly_threshold : "",
  }));
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

  f.site_plugins = arr<string>(w.enabled_plugins);

  const ipr = w.ip_reputation as AnyRec | undefined;
  if (ipr) {
    f.ip_allow = arr<string>(ipr.allow);
    f.ip_block = arr<string>(ipr.block);
    f.ip_block_xdp = ipr.xdp_mirror === true;
    const dnsbl = ipr.dnsbl as AnyRec | undefined;
    if (dnsbl && dnsbl.enabled) { f.dnsbl_enabled = true; f.dnsbl_servers = arr<string>(dnsbl.servers); }
    f.blacklist_user_agents = arr<string>(ipr.block_user_agents);
    f.blacklist_uris = arr<string>(ipr.block_uris);
    f.ip_feeds = arr<AnyRec>(ipr.feeds).map(x => ({
      url: str(x.url), interval: str(x.interval, "1h"),
      format: (x.format === "json" ? "json" : "cidr") as IpFeed["format"],
    }));
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

  const bp = w.block_page as AnyRec | undefined;
  if (bp) {
    // Absent `enabled` means the data-plane default (true), not false — the
    // wizard must round-trip a config that only set a title without silently
    // switching the page off.
    f.block_page_enabled = bp.enabled === undefined ? true : bool(bp.enabled);
    f.block_page_title = str(bp.title);
    f.block_page_message = str(bp.message);
    f.block_page_contact = str(bp.contact);
    f.block_page_logo = str(bp.logo_url);
    f.block_page_show_reason = bool(bp.show_reason);
  }

  const ml = w.ml as AnyRec | undefined;
  if (ml && ml.enable) { f.ml_enabled = true; f.ml_sensitivity = num(ml.sensitivity, 0.85); f.ml_models = arr<string>(ml.models); }

  const jwt = w.jwt as AnyRec | undefined;
  if (jwt && jwt.enable) {
    f.jwt_enabled = true;
    f.jwt_required = jwt.required === undefined ? true : bool(jwt.required);
    f.jwt_issuer = str(jwt.issuer);
    f.jwt_audience = str(jwt.audience);
    const algs = arr<string>(jwt.algorithms);
    if (algs.length) f.jwt_algorithms = algs;
    f.jwt_hs_secret = str(jwt.hs_secret);
    f.jwt_public_key_pem = str(jwt.public_key_pem);
    f.jwt_jwks_url = str(jwt.jwks_url);
    f.jwt_required_scopes = arr<string>(jwt.required_scopes);
    f.jwt_scope_claim = str(jwt.scope_claim, "scope");
  }

  const gql = w.graphql as AnyRec | undefined;
  if (gql && gql.enable) {
    f.graphql_enabled = true;
    f.graphql_max_depth = num(gql.max_depth, 10);
    f.graphql_max_complexity = num(gql.max_complexity, 1000);
    f.graphql_block_introspection = gql.block_introspection === undefined ? true : bool(gql.block_introspection);
  }

  const grpc = w.grpc as AnyRec | undefined;
  if (grpc && grpc.enable) {
    f.grpc_enabled = true;
    f.grpc_max_message_kb = Math.round(num(grpc.max_message_bytes, 4 * 1024 * 1024) / 1024);
    f.grpc_max_frames = num(grpc.max_frames, 512);
    f.grpc_block_reflection = grpc.block_reflection === undefined ? true : bool(grpc.block_reflection);
    f.grpc_allowed_methods = arr<string>(grpc.allowed_methods);
    f.grpc_blocked_methods = arr<string>(grpc.blocked_methods);
  }

  const dlp = w.dlp as AnyRec | undefined;
  if (dlp && dlp.enable) {
    f.dlp_enabled = true;
    f.dlp_action = (dlp.action === "mask" || dlp.action === "detect") ? dlp.action : "block";
    f.dlp_patterns = arr<string>(dlp.patterns);
  }

  const fusion = w.fusion as AnyRec | undefined;
  if (fusion && fusion.enable) {
    f.fusion_enabled = true;
    const wts = (fusion.weights as Record<string, unknown>) ?? {};
    const merged = { ...f.fusion_weights };
    for (const [k, v] of Object.entries(wts)) merged[k] = num(v, 1);
    f.fusion_weights = merged;
    const bt = arr<number>(fusion.block_thresholds);
    if (bt.length) f.fusion_block_thresholds = bt;
    const lt = arr<number>(fusion.limit_thresholds);
    if (lt.length) f.fusion_limit_thresholds = lt;
    f.fusion_limit_status = num(fusion.limit_status, 429);
  }

  f.preset = "custom";
  return f;
}
