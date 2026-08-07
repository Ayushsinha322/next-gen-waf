use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Handle type — shared cheap clone passed everywhere
// ---------------------------------------------------------------------------

/// Thread-safe config handle. Clone freely; reads are lock-free.
pub type ConfigHandle = Arc<ArcSwap<SentinelConfig>>;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SentinelConfig {
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    #[serde(default)]
    pub sites: Vec<SiteConfig>,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub ebpf: EbpfConfig,
    /// Global connection/request admission-control limits (DoS load-shedding).
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Directory where ACME certs are persisted.
    /// Defaults to `$HOME/.config/sentinel/certs` or `/var/lib/sentinel/certs`.
    pub cert_dir: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Admission-control limits
// ---------------------------------------------------------------------------

/// Global concurrency ceilings enforced by the data plane so a connection or
/// request flood sheds gracefully (connection reject / 503) instead of
/// exhausting file descriptors or memory. Both are process-wide, spanning every
/// listener and both transports (TCP h1/h2 and QUIC/h3).
///
/// Each field can be overridden at startup by an environment variable, which
/// takes precedence over the config file: `SENTINEL_MAX_CONNECTIONS` and
/// `SENTINEL_MAX_INFLIGHT_REQUESTS`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum concurrent client connections across all listeners. Connections
    /// accepted beyond this are immediately closed (rejected) at the accept
    /// loop before any per-connection task is spawned, bounding file-descriptor
    /// and memory use under a connection flood.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Maximum concurrent in-flight WAF-processed requests across all listeners.
    /// This specifically bounds HTTP/2 and HTTP/3 stream multiplexing, where a
    /// single connection may open hundreds of concurrent streams. Requests
    /// beyond this limit receive `503 Service Unavailable` with `Retry-After`.
    #[serde(default = "default_max_inflight_requests")]
    pub max_inflight_requests: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_inflight_requests: default_max_inflight_requests(),
        }
    }
}

fn default_max_connections() -> usize {
    10_000
}

fn default_max_inflight_requests() -> usize {
    8_192
}

// ---------------------------------------------------------------------------
// Cluster
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    #[serde(default = "default_cluster_name")]
    pub name: String,
    /// `"auto"` = derive from hostname + MAC; or explicit UUID
    #[serde(default = "default_node_id")]
    pub node_id: String,
    pub control_plane: Option<ControlPlaneConfig>,
    /// Control-plane REST URL for site config polling.
    /// E.g. `"http://localhost:9501"`. When set, the proxy polls
    /// `GET {sync_url}/api/v1/internal/config` every `sync_interval_secs`
    /// and hot-syncs the sites list without a SIGHUP.
    #[serde(default)]
    pub sync_url: Option<String>,
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            name: default_cluster_name(),
            node_id: default_node_id(),
            control_plane: None,
            sync_url: None,
            sync_interval_secs: default_sync_interval(),
        }
    }
}

fn default_cluster_name() -> String {
    "sentinel".to_string()
}

fn default_node_id() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    pub endpoints: Vec<String>,
    pub tls: TlsFileConfig,
}

fn default_sync_interval() -> u64 {
    5
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsFileConfig {
    pub ca: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub min_version: TlsVersion,
    #[serde(default)]
    pub post_quantum: PostQuantumMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsVersion {
    #[serde(rename = "tls1.2")]
    Tls12,
    #[default]
    #[serde(rename = "tls1.3")]
    Tls13,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PostQuantumMode {
    #[default]
    Disabled,
    Hybrid,
    Required,
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerConfig {
    pub name: String,
    pub bind: String,
    pub protocol: ProtocolSpec,
    pub tls: Option<TlsFileConfig>,
    /// When set, requests that don't match any site by Host header are routed
    /// to this site ID — enables port-based routing (e.g. :9095 → dvwa).
    #[serde(default)]
    pub default_site: Option<String>,
    /// Listener role. `normal` (default) runs the full WAF pipeline and routes
    /// to customer sites by Host. `management` turns this listener into the
    /// dedicated management endpoint: it bypasses the WAF pipeline, presents the
    /// hot-swappable management certificate, and reverse-proxies the admin UI
    /// (path `/api/*` → control plane, everything else → dashboard).
    #[serde(default)]
    pub role: ListenerRole,
}

/// What a listener is for. Mirrors the F5 "management interface vs data plane"
/// separation: customer traffic and the appliance's own admin console are
/// served by the same engine but on distinct listeners with distinct certs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListenerRole {
    /// Customer-facing WAF listener: full pipeline, Host-routed to sites.
    #[default]
    Normal,
    /// Dedicated management console listener (admin UI + API over HTTPS).
    Management,
}

impl ListenerConfig {
    pub fn protocols(&self) -> Vec<Protocol> {
        match &self.protocol {
            ProtocolSpec::Single(p) => vec![p.clone()],
            ProtocolSpec::Multiple(ps) => ps.clone(),
        }
    }

    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    pub fn is_management(&self) -> bool {
        self.role == ListenerRole::Management
    }
}

/// YAML allows: `protocol: http1`  or  `protocol: [http1, http2]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProtocolSpec {
    Single(Protocol),
    Multiple(Vec<Protocol>),
}

impl Default for ProtocolSpec {
    fn default() -> Self {
        ProtocolSpec::Single(Protocol::Http1)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[serde(rename = "http1")]
    Http1,
    #[serde(rename = "http2")]
    Http2,
    #[serde(rename = "http3")]
    Http3,
}

// ---------------------------------------------------------------------------
// Sites
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteConfig {
    pub id: String,
    /// Owning tenant, propagated from the control plane so per-request telemetry
    /// (ClickHouse waf_events / traffic) can be scoped per tenant. Empty in
    /// standalone/file-based configs.
    #[serde(default)]
    pub tenant_id: String,
    pub domains: Vec<String>,
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub waf: WafConfig,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    /// Per-site TLS certificate configuration.
    #[serde(default)]
    pub tls: SiteTlsConfig,
    /// Where this site came from. See SiteOrigin — without it a deleted site
    /// cannot be told apart from a file-declared one and is never evicted.
    #[serde(default)]
    pub origin: SiteOrigin,
}

/// Whether a site was declared on disk or delivered by the control plane.
///
/// This exists because `update_sites` has to answer one question on every sync:
/// a site is in the running config but NOT in what the control plane just sent —
/// keep it or drop it? Both a file-declared site and a site the operator has
/// just DELETED look identical from that angle, and the merge used to keep both,
/// so a deleted site was re-added on every poll and served until the process
/// restarted. Provenance is the missing fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SiteOrigin {
    /// Declared in the on-disk YAML config. The control plane does not know
    /// about these, so they survive every sync. This is the default precisely
    /// so a hand-written config file needs no new key.
    #[default]
    File,
    /// Delivered by the control plane (or restored from its on-disk cache).
    /// The control plane is authoritative for these, so each sync replaces the
    /// whole set — which is what makes a delete take effect.
    ControlPlane,
}

// ---------------------------------------------------------------------------
// Per-site TLS / ACME
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SiteTlsConfig {
    /// How to obtain the TLS cert for this site's domains.
    #[serde(default)]
    pub mode: TlsCertMode,
    /// Manual mode: path to certificate PEM file.
    pub cert: Option<PathBuf>,
    /// Manual mode: path to private key PEM file.
    pub key: Option<PathBuf>,
    /// ACME mode configuration.
    pub acme: Option<SiteAcmeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsCertMode {
    /// No TLS managed for this site (served via an HTTP listener or terminated upstream).
    #[default]
    Off,
    /// Auto-generate a self-signed cert (useful for internal / dev sites).
    SelfSigned,
    /// Operator-uploaded PEM cert + key.
    Manual,
    /// Automatic ACME (Let's Encrypt / ZeroSSL) — issues and renews automatically.
    Acme,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteAcmeConfig {
    /// Contact email for the ACME account.
    pub email: String,
    /// CA provider (default: Let's Encrypt production).
    #[serde(default)]
    pub provider: AcmeProvider,
    /// ACME challenge type (default: HTTP-01).
    #[serde(default)]
    pub challenge: AcmeChallengeType,
    /// Renew the cert this many days before expiry (default: 30).
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
}

fn default_renew_before_days() -> u32 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcmeProvider {
    /// Let's Encrypt production CA (https://acme-v02.api.letsencrypt.org/).
    #[default]
    LetsEncrypt,
    /// Let's Encrypt staging CA — free to test against, issues untrusted certs.
    LetsEncryptStaging,
    /// ZeroSSL (https://acme.zerossl.com/v2/DV90).
    ZeroSsl,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AcmeChallengeType {
    /// HTTP-01: ACME server fetches `http://<domain>/.well-known/acme-challenge/<token>`.
    /// Requires the proxy to be reachable on port 80 for the domain.
    #[default]
    Http01,
    /// TLS-ALPN-01: ACME server connects to port 443 with ALPN "acme-tls/1".
    /// Works without port 80 — great for port-80-blocked environments.
    TlsAlpn01,
}

// ---------------------------------------------------------------------------
// Upstream / load balancing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default)]
    pub load_balancer: LoadBalancerStrategy,
    pub servers: Vec<UpstreamServer>,
    pub health_check: Option<HealthCheckConfig>,
    /// How long this site's origin may take to return response *headers*
    /// (connect + send + first byte).  It does NOT bound the response body, so
    /// long downloads and Server-Sent Events streams are unaffected.
    ///
    /// Raise it for apps with slow synchronous endpoints (report generation,
    /// bulk export, some payment-gateway callbacks) that would otherwise 504.
    /// `None` or `0` falls back to the deployment-wide default
    /// (`SENTINEL_UPSTREAM_TIMEOUT_SECS`, 30s) — one slow app should not force
    /// every other site on the node to wait as long.
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerStrategy {
    #[default]
    RoundRobin,
    LeastConn,
    IpHash,
    Random,
    Adaptive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamServer {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Connect to this upstream over TLS (HTTPS).  Set to `true` when the
    /// backend runs on HTTPS and false (default) for plain HTTP.
    #[serde(default)]
    pub tls: bool,
}

impl UpstreamServer {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default = "default_health_path")]
    pub path: String,
    #[serde(default = "default_interval")]
    pub interval: String,
    #[serde(default = "default_timeout")]
    pub timeout: String,
}

fn default_health_path() -> String {
    "/healthz".to_string()
}

fn default_interval() -> String {
    "10s".to_string()
}

fn default_timeout() -> String {
    "2s".to_string()
}

// ---------------------------------------------------------------------------
// WAF
// ---------------------------------------------------------------------------

/// Weighted verdict fusion: combine per-engine anomaly contributions with
/// configurable weights, then decide the verdict against per-paranoia-level
/// thresholds — with a soft LIMIT tier below the hard BLOCK tier. When `enable`
/// is false the WAF uses the legacy flat `anomaly_threshold`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionConfig {
    #[serde(default)]
    pub enable: bool,
    /// Per-engine weight multipliers (engine name → weight). Engines not listed
    /// default to 1.0. Recognised engines: `rules`, `ml`, `bot`, `threat_intel`,
    /// `reputation`, `correlation`, `plugin`.
    #[serde(default)]
    pub weights: HashMap<String, f32>,
    /// Hard-block threshold per paranoia level (index 0 = PL1 … 3 = PL4). If the
    /// list is shorter than the site's paranoia level, the last entry is used.
    #[serde(default = "default_block_thresholds")]
    pub block_thresholds: Vec<u32>,
    /// Soft-LIMIT threshold per paranoia level (must be below block). Empty
    /// disables the LIMIT tier (fused verdict is only ever Allow or Block).
    #[serde(default = "default_limit_thresholds")]
    pub limit_thresholds: Vec<u32>,
    /// HTTP status returned for a LIMIT verdict.
    #[serde(default = "default_limit_status")]
    pub limit_status: u16,
}

fn default_block_thresholds() -> Vec<u32> {
    // Stricter (lower) at higher paranoia levels — PL1..PL4.
    vec![7, 5, 4, 3]
}

fn default_limit_thresholds() -> Vec<u32> {
    vec![4, 3, 2, 2]
}

fn default_limit_status() -> u16 {
    429
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WafConfig {
    #[serde(default)]
    pub mode: WafMode,
    #[serde(default = "default_paranoia")]
    pub paranoia_level: u8,
    #[serde(default = "default_threshold")]
    pub anomaly_threshold: u32,
    /// Weighted verdict fusion (per-engine weights + LIMIT tier + per-paranoia
    /// thresholds). When absent/disabled the flat `anomaly_threshold` is used.
    pub fusion: Option<FusionConfig>,
    #[serde(default)]
    pub rules: Vec<String>,
    /// Operator-authored rules delivered as SRL source by the control plane,
    /// rather than as a file path like `rules`.
    ///
    /// These come from the `rules` table and exist so an operator can virtual-patch
    /// a zero-day without waiting for a data-plane image rebuild: the control plane
    /// bumps the config version, the fleet re-fetches, and the rule is live.
    ///
    /// Source is shipped instead of compiled bytecode deliberately — bytecode would
    /// couple the control plane's compiler version to the data plane's and make a
    /// version skew silently mis-execute rules. Parsing here costs microseconds at
    /// reload time and keeps exactly one compiler in the system.
    #[serde(default)]
    pub inline_rules: Vec<InlineRule>,
    /// Per-path policy overrides, longest matching prefix wins. See PathOverride.
    #[serde(default)]
    pub path_overrides: Vec<PathOverride>,
    pub ml: Option<MlConfig>,
    pub ip_reputation: Option<IpReputationConfig>,
    pub rate_limit: Option<RateLimitConfig>,
    pub bot_detection: Option<BotDetectionConfig>,
    pub dlp: Option<DlpConfig>,
    #[serde(default)]
    pub api_discovery: bool,
    pub graphql: Option<GraphqlConfig>,
    pub jwt: Option<JwtConfig>,
    pub grpc: Option<GrpcConfig>,
    pub anti_ddos: Option<AntiDdosConfig>,
    pub geoip: Option<GeoIpConfig>,
    /// Paths to plugin manifests (`sentinel-plugin.toml` files).
    #[serde(default)]
    pub plugins: Vec<String>,
    /// Per-rule exclusions: remove specific targets from a rule to suppress false positives.
    #[serde(default)]
    pub rule_exclusions: Vec<RuleExclusion>,
    /// Maximum request body size in bytes (0 = unlimited, default 10 MiB).
    /// Requests with bodies exceeding this limit receive 413 Payload Too Large.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: u64,
    /// Maximum URI length in bytes (0 = unlimited, default 8192).
    #[serde(default = "default_max_uri_length")]
    pub max_uri_length: u32,
    /// Maximum number of request headers (0 = unlimited, default 100).
    #[serde(default = "default_max_header_count")]
    pub max_header_count: u32,
    /// Allowed HTTP methods. Empty = allow all; otherwise a request whose method
    /// isn't listed is rejected with 405. Case-insensitive.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Per-site response/security header policy (overrides the proxy defaults
    /// and injects operator-defined headers).
    pub security_headers: Option<SecurityHeadersConfig>,
    /// What a blocked visitor sees. Absent = the built-in default page.
    pub block_page: Option<BlockPageConfig>,
}

/// Per-site customisation of the page a blocked visitor receives.
///
/// The page exists to turn a dead end into a support path: it shows the Support
/// ID (the request id, which is the join key across access.log, waf.log and the
/// ClickHouse event store), so a caller can quote one string and the operator
/// can find the exact request that was blocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPageConfig {
    /// Serve the branded HTML page to browsers. When false, blocked browsers get
    /// the same minimal JSON an API client gets.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Heading shown to the visitor (default: "Request blocked").
    pub title: Option<String>,
    /// Body text. Keep it about what the visitor should DO, not about what the
    /// WAF detected.
    pub message: Option<String>,
    /// Who to contact — an email, phone number or URL. Rendered as a link when
    /// it parses as a mailto:/tel:/http(s) target, otherwise as plain text.
    pub contact: Option<String>,
    /// Absolute https:// (or site-relative) logo URL. Other schemes are dropped
    /// rather than rendered — see sanitize_logo_url.
    pub logo_url: Option<String>,
    /// Include the detection reason in the response.
    ///
    /// Defaults to FALSE, and that default is a security decision rather than a
    /// cosmetic one. `block_reason` names the control that fired ("IP
    /// reputation: …", "threat intel: …", a rule id and its target), which hands
    /// an attacker a free oracle: they can permute a payload and read back
    /// exactly which engine caught it and when it stopped catching it. F5 and
    /// Imperva return a support id and nothing else for the same reason. Enable
    /// only on an internal or staging site where the audience is your own
    /// developers debugging a false positive.
    #[serde(default)]
    pub show_reason: bool,
}

/// Hand-written rather than derived so the Rust default matches the serde
/// default. `#[derive(Default)]` would set `enabled: false` while
/// `#[serde(default = "default_true")]` sets it true, so a config built in code
/// would silently disable the block page while the identical config parsed from
/// YAML enabled it — the kind of disagreement nothing warns you about.
impl Default for BlockPageConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            title: None,
            message: None,
            contact: None,
            logo_url: None,
            show_reason: false,
        }
    }
}

/// Operator-configurable response headers, applied on top of the proxy's secure
/// defaults. Empty/absent fields fall back to the built-in defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecurityHeadersConfig {
    /// `Content-Security-Policy` value (omitted by default — CSP can break apps).
    pub content_security_policy: Option<String>,
    /// Override `Referrer-Policy` (default: strict-origin-when-cross-origin).
    pub referrer_policy: Option<String>,
    /// Override `Permissions-Policy`.
    pub permissions_policy: Option<String>,
    /// CORS handling (`Access-Control-Allow-Origin`).
    pub cors: Option<CorsConfig>,
    /// Arbitrary operator-defined response headers (name/value), applied last.
    #[serde(default)]
    pub custom: Vec<CustomHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CorsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allow_origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustomHeader {
    pub name: String,
    pub value: String,
}

/// Per-path policy override, so one site can enforce different strictness on
/// different parts of the application.
///
/// This is the shape F5 ASM calls URL-level enforcement: an API surface wants a
/// lower threshold than the marketing pages, a legacy endpoint needs detect-only
/// while it is being fixed, and static assets want the WAF out of the way.
/// Without it a site has exactly one policy and the operator must pick a
/// compromise that is wrong for part of the app — which is how false positives
/// and under-protection both get baked in.
///
/// MATCHING is longest-prefix-wins, not regex, deliberately. An operator reading
/// `/api/` can predict what it matches; a regex in a security control is a
/// footgun (ReDoS, and subtly wrong anchoring is easy). Ties cannot happen
/// because two identical prefixes are the same prefix.
///
/// WHAT CAN AND CANNOT BE OVERRIDDEN, and why this is not arbitrary:
/// `mode` and `anomaly_threshold` are consulted per request, so they can vary by
/// path. `paranoia_level` and `rule_exclusions` are applied when the rule engine
/// is COMPILED (see load_site_engine) — the engine physically contains a
/// different rule set — so overriding them per path would need a separate
/// compiled engine per override, which is a larger change and multiplies memory
/// by the number of overrides. They stay site-wide, and the control plane
/// rejects an attempt to set them here rather than accepting and ignoring it.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathOverride {
    /// Path prefix this applies to, e.g. `/api/`. Matched against the request
    /// path only — never the query string.
    pub path_prefix: String,
    /// Enforcement for this path. `off` lets the traffic through regardless of
    /// what the rules found; `learning` records the verdict without acting.
    #[serde(default)]
    pub mode: Option<WafMode>,
    /// Blocking threshold for this path. Lower is stricter.
    #[serde(default)]
    pub anomaly_threshold: Option<u32>,
}

/// One operator-authored rule, carried as SRL source from the control plane.
///
/// `name` is for diagnostics only: it is what gets logged when the rule fails to
/// parse, so an operator can find the offending row in the UI. Rule identity for
/// scoring and exclusions still comes from the `id:` inside the DSL.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InlineRule {
    pub name: String,
    pub dsl: String,
}

/// Removes one or more targets from a rule to suppress known false positives.
/// Mirrors the CRS `ctl:ruleRemoveTargetById` mechanism. When `disable` is set
/// the whole rule is dropped (CRS `SecRuleRemoveById`) — used by the learning
/// report's one-click "disable rule" tuning action for a confirmed false positive.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleExclusion {
    pub rule_id: u32,
    /// Target names to exclude, e.g. `["ARGS_NAMES"]`.
    #[serde(default)]
    pub exclude_targets: Vec<String>,
    /// Drop the entire rule rather than only specific targets.
    #[serde(default)]
    pub disable: bool,
}

fn default_max_body_size() -> u64 {
    10 * 1024 * 1024 // 10 MiB
}

fn default_max_uri_length() -> u32 {
    8192
}

fn default_max_header_count() -> u32 {
    100
}

fn default_paranoia() -> u8 {
    2
}

fn default_threshold() -> u32 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WafMode {
    Off,
    #[default]
    Learning,
    Blocking,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default = "default_sensitivity")]
    pub sensitivity: f32,
}

fn default_sensitivity() -> f32 {
    0.85
}

// ---------------------------------------------------------------------------
// IP Reputation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IpReputationConfig {
    /// CIDR ranges that are always allowed (overrides blocklist).
    #[serde(default)]
    pub allow: Vec<String>,
    /// CIDR ranges that are always blocked.
    #[serde(default)]
    pub block: Vec<String>,
    /// External feed URLs (AbuseIPDB, Spamhaus, etc.) — loaded at startup.
    #[serde(default)]
    pub feeds: Vec<IpFeedConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpFeedConfig {
    pub url: String,
    /// How often to refresh the feed (e.g. "1h").
    #[serde(default = "default_feed_interval")]
    pub interval: String,
    /// Feed format: "cidr" (one CIDR per line) or "json".
    #[serde(default = "default_feed_format")]
    pub format: String,
}

fn default_feed_interval() -> String {
    "1h".to_string()
}

fn default_feed_format() -> String {
    "cidr".to_string()
}

// ---------------------------------------------------------------------------
// Rate limit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub global: Option<RateWindow>,
    pub per_ip: Option<RateWindow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateWindow {
    pub rps: u32,
    pub burst: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BotDetectionConfig {
    #[serde(default)]
    pub ja4: bool,
    #[serde(default)]
    pub challenge: ChallengeMode,
    /// Interactive-CAPTCHA provider settings, used when `challenge` selects a
    /// third-party provider. Only the one matching `challenge` is consulted; the
    /// site key is public (embedded in the challenge page) and the secret is used
    /// server-side for token verification (siteverify).
    #[serde(default)]
    pub recaptcha: Option<CaptchaProvider>,
    #[serde(default)]
    pub hcaptcha: Option<CaptchaProvider>,
    #[serde(default)]
    pub turnstile: Option<CaptchaProvider>,
}

/// Credentials for a third-party CAPTCHA provider (reCAPTCHA / hCaptcha /
/// Turnstile). `sitekey` is rendered into the challenge page; `secret` is sent
/// to the provider's siteverify endpoint. `score` is the reCAPTCHA-v3 pass
/// threshold (0..1) and is ignored by pass/fail providers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaptchaProvider {
    #[serde(default)]
    pub sitekey: String,
    #[serde(default)]
    pub secret: String,
    #[serde(default = "default_captcha_score")]
    pub score: f32,
}

fn default_captcha_score() -> f32 {
    0.5
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeMode {
    #[default]
    Off,
    // `alias` keeps configs written under the old `rename_all = "lowercase"`
    // scheme ("nativepow") deserializing after the switch to snake_case.
    #[serde(alias = "nativepow")]
    NativePow,
    Recaptcha,
    Hcaptcha,
    Turnstile,
}

/// What the DLP scanner does when it finds sensitive data in a response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DlpAction {
    /// Block the entire response (default — backward compatible).
    #[default]
    Block,
    /// Redact the matched data in place and forward the sanitized response.
    Mask,
    /// Log the finding but forward the response unchanged.
    Detect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Response action when sensitive data is found: `block` (default), `mask`,
    /// or `detect` (log-only).
    #[serde(default)]
    pub action: DlpAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_gql_depth")]
    pub max_depth: u32,
    #[serde(default = "default_gql_complexity")]
    pub max_complexity: u32,
    /// Block introspection queries (`__schema` / `__type`). Defaults to `true`
    /// so schema disclosure is refused unless an operator opts out.
    #[serde(default = "default_true")]
    pub block_introspection: bool,
}

/// Per-site edge JWT / OAuth2 validation for protected customer APIs. When
/// `enable` is set, the WAF verifies the client's `Authorization: Bearer` token
/// (signature + expiry + issuer/audience + required scopes) before forwarding.
/// Key material comes from a static HS256 secret, a public-key PEM, or a JWKS
/// endpoint (fetched + cached, rotated by `kid`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    #[serde(default)]
    pub enable: bool,
    /// Reject requests whose token is missing or invalid. When false, a token
    /// is verified if present but a missing token is allowed through.
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default = "default_jwt_algorithms")]
    pub algorithms: Vec<String>,
    /// HS256 shared secret (symmetric).
    #[serde(default)]
    pub hs_secret: Option<String>,
    /// RSA / EC public key in PEM form (asymmetric static key).
    #[serde(default)]
    pub public_key_pem: Option<String>,
    /// JWKS endpoint URL — keys fetched + cached, selected by token `kid`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// All of these scopes must be present in the token to pass.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    /// Claim carrying scopes (space-delimited string or array). Default `scope`.
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
}

fn default_jwt_algorithms() -> Vec<String> {
    vec!["RS256".to_string()]
}

fn default_scope_claim() -> String {
    "scope".to_string()
}

/// gRPC firewall — protocol-aware limits for `application/grpc(+web)` traffic.
/// Enforces message/frame size caps, per-method allow/deny lists, and blocks
/// server-reflection. Applied only to requests whose content-type is gRPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrpcConfig {
    #[serde(default)]
    pub enable: bool,
    /// Per-message size cap in bytes (anti-DoS). Default 4 MiB.
    #[serde(default = "default_grpc_max_message")]
    pub max_message_bytes: usize,
    /// Max message frames allowed in one request body. Default 512.
    #[serde(default = "default_grpc_max_frames")]
    pub max_frames: usize,
    /// Block gRPC server-reflection services (schema disclosure). Default true.
    #[serde(default = "default_true")]
    pub block_reflection: bool,
    /// If non-empty, only these `/package.Service/Method` paths (or `/svc/`
    /// prefixes ending in `/`) are allowed; all others are blocked.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// These `/package.Service/Method` paths (or `/svc/` prefixes) are blocked.
    #[serde(default)]
    pub blocked_methods: Vec<String>,
}

fn default_grpc_max_message() -> usize {
    4 * 1024 * 1024
}

fn default_grpc_max_frames() -> usize {
    512
}

fn default_gql_depth() -> u32 {
    10
}

fn default_gql_complexity() -> u32 {
    1000
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Anti-DDoS
// ---------------------------------------------------------------------------

/// Connection-rate-based DDoS protection (Phase 0, before site matching).
///
/// Tracks new TCP connections per source IP in a 1-second sliding window.
/// IPs that exceed `conn_rate_limit + burst` connections/second are blocked
/// for `block_duration_secs` seconds.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AntiDdosConfig {
    /// Enable connection-rate DDoS protection.
    #[serde(default)]
    pub enabled: bool,
    /// Maximum new connections allowed per IP per second before blocking.
    #[serde(default = "default_conn_rate")]
    pub conn_rate_limit: u32,
    /// Initial burst budget (connections allowed before rate limit activates).
    #[serde(default = "default_conn_burst")]
    pub burst: u32,
    /// How long (seconds) a violating IP stays blocked.
    #[serde(default = "default_block_duration")]
    pub block_duration_secs: u64,
}

fn default_conn_rate() -> u32 {
    200
}
fn default_conn_burst() -> u32 {
    50
}
fn default_block_duration() -> u64 {
    300
}

// ---------------------------------------------------------------------------
// GeoIP
// ---------------------------------------------------------------------------

/// Country-level IP filtering via MaxMind GeoLite2-Country .mmdb.
///
/// If `allow_countries` is non-empty, ONLY those countries are allowed
/// (block-list mode ignored).  If only `block_countries` is set, all
/// listed countries are blocked and all others pass.
///
/// If the `.mmdb` file is missing or unreadable the filter degrades
/// gracefully — all IPs pass (Unknown → Allow).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpConfig {
    /// Path to the MaxMind GeoLite2-Country.mmdb file.
    pub db_path: String,
    /// ISO 3166-1 alpha-2 country codes to block (e.g. `["CN", "RU"]`).
    #[serde(default)]
    pub block_countries: Vec<String>,
    /// Allow-only country codes.  If non-empty, all other countries are
    /// blocked regardless of `block_countries`.
    #[serde(default)]
    pub allow_countries: Vec<String>,
}

// ---------------------------------------------------------------------------
// Plugins
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
    #[serde(default)]
    pub outputs: Vec<LogOutput>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
            outputs: vec![LogOutput::Stdout],
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Json,
    Text,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum LogOutput {
    Stdout,
    Stderr,
    File {
        path: PathBuf,
        #[serde(default)]
        rotate: Option<LogRotateConfig>,
    },
    Otlp {
        endpoint: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotateConfig {
    pub size: Option<String>,
    pub keep: Option<u32>,
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageConfig {
    pub cache: Option<CacheConfig>,
    pub kv: Option<KvConfig>,
    pub timeseries: Option<TimeSeriesConfig>,
}

/// ClickHouse connection for traffic-history persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesConfig {
    /// HTTP endpoint, e.g. `http://127.0.0.1:8123`.
    pub url: String,
    /// Database name (default: `sentinel_logs`).
    #[serde(default = "default_ts_database")]
    pub database: String,
    /// ClickHouse username (sent as `X-ClickHouse-User`). Required when the
    /// server has access-management enabled.
    #[serde(default)]
    pub username: Option<String>,
    /// ClickHouse password (sent as `X-ClickHouse-Key`).
    #[serde(default)]
    pub password: Option<String>,
}

fn default_ts_database() -> String {
    "sentinel_logs".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default)]
    pub backend: CacheBackend,
    pub size: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CacheBackend {
    #[default]
    Memory,
    Redis,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvConfig {
    #[serde(default)]
    pub backend: KvBackend,
    pub path: Option<PathBuf>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KvBackend {
    #[default]
    Memory,
    RocksDb,
    Redis,
}

// ---------------------------------------------------------------------------
// eBPF
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EbpfConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub programs: Vec<String>,
}

// ---------------------------------------------------------------------------
// Loader — loads from file + SIGHUP hot-reload
// ---------------------------------------------------------------------------

/// Owns the config file path and the live config handle.
///
/// Call [`ConfigLoader::load`] to get the handle to share with other
/// components; call [`ConfigLoader::watch_signals`] in a background task
/// to react to SIGHUP.
pub struct ConfigLoader {
    path: PathBuf,
    handle: ConfigHandle,
}

impl ConfigLoader {
    /// Parse config from `path` and return a loader holding the live handle.
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let cfg = read_config_file(&path)?;
        let handle: ConfigHandle = Arc::new(ArcSwap::new(Arc::new(cfg)));
        info!(path = %path.display(), "configuration loaded");
        Ok(Self { path, handle })
    }

    /// Returns the live config handle to be cloned and shared with other
    /// components.
    pub fn handle(&self) -> ConfigHandle {
        Arc::clone(&self.handle)
    }

    /// Reload config from the file on disk and atomically swap it in.
    pub fn reload(&self) -> anyhow::Result<()> {
        let cfg = read_config_file(&self.path)?;
        self.handle.store(Arc::new(cfg));
        info!(path = %self.path.display(), "configuration reloaded");
        Ok(())
    }

    /// Spawn a tokio task that listens for SIGHUP and reloads config.
    /// The task exits automatically when the handle is dropped (i.e., when
    /// no other component holds a clone).
    #[cfg(unix)]
    pub fn spawn_signal_watcher(loader: Arc<Self>) {
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut stream = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    warn!("could not register SIGHUP handler: {e}");
                    return;
                }
            };
            loop {
                stream.recv().await;
                info!("SIGHUP received — reloading configuration");
                if let Err(e) = loader.reload() {
                    warn!("config reload failed: {e}");
                }
            }
        });
    }

    #[cfg(not(unix))]
    pub fn spawn_signal_watcher(_loader: Arc<Self>) {
        // No SIGHUP on non-Unix platforms; hot-reload via control-plane gRPC only.
    }
}

// ---------------------------------------------------------------------------
// Live site update — called by the control-plane polling task
// ---------------------------------------------------------------------------

/// Merge sites received from the control plane into the live config.
///
/// DB sites are authoritative for any site they know about (same ID = full
/// replacement).  File-based sites that the DB does *not* mention are preserved
/// as bootstrap entries.  This avoids the "DB deletes your YAML sites" problem
/// while still letting the UI add/update/delete sites at runtime.
pub fn update_sites(handle: &ConfigHandle, mut db_sites: Vec<SiteConfig>) {
    let current = handle.load_full();

    // Everything arriving here came from the control plane (a live sync, or its
    // on-disk cache replayed at boot), so stamp it rather than trusting the
    // payload — the control plane does not send an origin field.
    for s in &mut db_sites {
        s.origin = SiteOrigin::ControlPlane;
    }

    // Keep ONLY the file-declared sites. Selecting by origin rather than by
    // "absent from db_sites" is the whole fix: the old predicate kept any site
    // the control plane had stopped sending, which is exactly what a DELETED
    // site looks like. It was therefore re-added on every 5s poll and kept
    // being served — with correct config everywhere else, so nothing looked
    // wrong — until the process was restarted.
    let mut file_sites: Vec<SiteConfig> = current
        .sites
        .iter()
        .filter(|s| s.origin == SiteOrigin::File)
        .cloned()
        .collect();

    let dropped = current
        .sites
        .iter()
        .filter(|s| {
            s.origin == SiteOrigin::ControlPlane && !db_sites.iter().any(|ds| ds.id == s.id)
        })
        .map(|s| s.id.as_str())
        .collect::<Vec<_>>();
    if !dropped.is_empty() {
        // Worth a line at INFO: a site vanishing from the fleet is a change an
        // operator should be able to find in the log afterwards.
        info!(sites = ?dropped, "sites removed by control plane — no longer served");
    }

    let mut merged = db_sites;
    merged.append(&mut file_sites);

    let count = merged.len();
    let mut new_cfg = (*current).clone();
    new_cfg.sites = merged;
    handle.store(Arc::new(new_cfg));
    info!(count, "sites merged from control plane (file + db)");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_config_file(path: &Path) -> anyhow::Result<SentinelConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading config file: {}", path.display()))?;
    let cfg: SentinelConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing config file: {}", path.display()))?;
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_roundtrips() {
        let cfg = SentinelConfig::default();
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let back: SentinelConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(back.cluster.node_id, cfg.cluster.node_id);
    }

    #[test]
    fn parse_example_config() {
        let yaml = include_str!("../../../../configs/examples/sentinel.yaml");
        let cfg: SentinelConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!cfg.sites.is_empty());
        assert_eq!(cfg.sites[0].id, "example");
    }

    #[test]
    fn protocol_spec_single() {
        let yaml = r#"name: test
bind: "0.0.0.0:80"
protocol: http1
"#;
        let l: ListenerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(l.protocols(), vec![Protocol::Http1]);
    }

    #[test]
    fn protocol_spec_multiple() {
        let yaml = r#"name: https
bind: "0.0.0.0:443"
protocol: [http1, http2]
tls:
  cert: /etc/tls/tls.crt
  key: /etc/tls/tls.key
"#;
        let l: ListenerConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(l.protocols(), vec![Protocol::Http1, Protocol::Http2]);
        assert!(l.is_tls());
    }
}

#[cfg(test)]
mod site_eviction_tests {
    use super::*;

    /// Built through serde rather than a struct literal so these tests also
    /// exercise the deserialization the real sync path uses.
    fn site(id: &str, origin: SiteOrigin) -> SiteConfig {
        let yaml = format!(
            r#"
id: {id}
domains: ["{id}.example"]
upstream:
  servers:
    - {{ host: "127.0.0.1", port: 8080 }}
"#
        );
        let mut s: SiteConfig = serde_yaml::from_str(&yaml).expect("parse test site");
        s.origin = origin;
        s
    }

    fn handle_with(sites: Vec<SiteConfig>) -> ConfigHandle {
        let cfg = SentinelConfig {
            sites,
            ..SentinelConfig::default()
        };
        Arc::new(ArcSwap::from(Arc::new(cfg)))
    }

    fn ids(h: &ConfigHandle) -> Vec<String> {
        let mut v: Vec<String> = h.load_full().sites.iter().map(|s| s.id.clone()).collect();
        v.sort();
        v
    }

    /// The bug: a site deleted in the dashboard kept being SERVED. The merge
    /// retained anything the control plane had stopped sending, which is
    /// indistinguishable from a file-declared site — so the deleted site was
    /// re-added on every 5s poll and only disappeared when the process
    /// restarted. Found on the deploy VM: rule count stayed at 670 (two sites)
    /// and the deleted host still answered 403, while the control plane and
    /// database both correctly listed one site.
    #[test]
    fn control_plane_delete_evicts_the_site() {
        let h = handle_with(vec![
            site("keep-me", SiteOrigin::ControlPlane),
            site("deleted-site", SiteOrigin::ControlPlane),
        ]);

        // Next sync: the control plane no longer mentions deleted-site.
        update_sites(&h, vec![site("keep-me", SiteOrigin::ControlPlane)]);

        assert_eq!(
            ids(&h),
            vec!["keep-me".to_string()],
            "a site the control plane stopped sending must stop being served"
        );
    }

    /// The reason the old predicate existed: the control plane knows nothing
    /// about sites declared in the on-disk YAML, so a sync must never delete
    /// them. Evicting by origin has to preserve that.
    #[test]
    fn file_declared_sites_survive_every_sync() {
        let h = handle_with(vec![
            site("from-yaml", SiteOrigin::File),
            site("from-db", SiteOrigin::ControlPlane),
        ]);

        // A sync that mentions neither of them.
        update_sites(&h, vec![site("brand-new", SiteOrigin::ControlPlane)]);

        assert_eq!(
            ids(&h),
            vec!["brand-new".to_string(), "from-yaml".to_string()],
            "file sites stay; control-plane sites are replaced wholesale"
        );
    }

    /// Incoming sites are stamped rather than trusted: the control plane's JSON
    /// carries no origin field, so without stamping they would deserialize as
    /// File (the default) and become un-evictable on the very next sync.
    #[test]
    fn incoming_sites_are_stamped_control_plane() {
        let h = handle_with(vec![]);
        // Deliberately pass the serde default, as a real payload would.
        update_sites(&h, vec![site("from-cp", SiteOrigin::File)]);

        let stored = h.load_full();
        assert_eq!(stored.sites[0].origin, SiteOrigin::ControlPlane);

        // And prove it is now evictable — the property the stamping buys.
        update_sites(&h, vec![]);
        assert!(
            ids(&h).is_empty(),
            "a stamped control-plane site must be removable on a later sync"
        );
    }

    /// An empty payload is a legitimate "this tenant has no sites", not a
    /// signal to keep the previous set. It must not resurrect anything.
    #[test]
    fn empty_payload_clears_control_plane_sites_but_not_file_sites() {
        let h = handle_with(vec![
            site("yaml-one", SiteOrigin::File),
            site("db-one", SiteOrigin::ControlPlane),
        ]);
        update_sites(&h, vec![]);
        assert_eq!(ids(&h), vec!["yaml-one".to_string()]);
    }

    /// A YAML-declared site with no `origin` key must default to File, or a
    /// hand-written config would start being deleted by control-plane syncs.
    #[test]
    fn yaml_without_origin_key_defaults_to_file() {
        let yaml = r#"
id: legacy-site
domains: ["legacy.example"]
upstream:
  servers:
    - { host: "127.0.0.1", port: 8080 }
"#;
        let s: SiteConfig = serde_yaml::from_str(yaml).expect("parse site");
        assert_eq!(s.origin, SiteOrigin::File);
    }
}
