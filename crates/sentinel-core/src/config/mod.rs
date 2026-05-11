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
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            name: default_cluster_name(),
            node_id: default_node_id(),
            control_plane: None,
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
    pub domains: Vec<String>,
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub waf: WafConfig,
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WafConfig {
    #[serde(default)]
    pub mode: WafMode,
    #[serde(default = "default_paranoia")]
    pub paranoia_level: u8,
    #[serde(default = "default_threshold")]
    pub anomaly_threshold: u32,
    #[serde(default)]
    pub rules: Vec<String>,
    pub ml: Option<MlConfig>,
    pub rate_limit: Option<RateLimitConfig>,
    pub bot_detection: Option<BotDetectionConfig>,
    pub dlp: Option<DlpConfig>,
    #[serde(default)]
    pub api_discovery: bool,
    pub graphql: Option<GraphqlConfig>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeMode {
    #[default]
    Off,
    NativePow,
    Hcaptcha,
    Turnstile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_gql_depth")]
    pub max_depth: u32,
    #[serde(default = "default_gql_complexity")]
    pub max_complexity: u32,
}

fn default_gql_depth() -> u32 {
    10
}

fn default_gql_complexity() -> u32 {
    1000
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
