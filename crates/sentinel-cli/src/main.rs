//! `sentinel` — node-local administration CLI for the Sentinel WAF.
//!
//! Wraps the data-plane binary (`sentinel-bin`) with a friendly UX:
//!
//! ```text
//! sentinel init                                    # one-time setup
//! sentinel site add NAME --domain D --upstream HOST:PORT
//! sentinel start                                   # daemonise the WAF
//! sentinel status                                  # what's protected
//! sentinel logs -f                                 # live request log
//! sentinel test                                    # send sample attacks
//! sentinel reload                                  # SIGHUP hot-reload
//! sentinel stop                                    # SIGTERM
//! ```

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use sentinel_core::config::{
    LoadBalancerStrategy, LogFormat, LogOutput, LoggingConfig, ListenerConfig, Protocol,
    ProtocolSpec, SentinelConfig, SiteConfig, UpstreamConfig, UpstreamServer, WafConfig, WafMode,
};
use sentinel_ml::llm_copilot::CopilotService;

const DEFAULT_BIND: &str = "127.0.0.1:8080";

// ---------------------------------------------------------------------------
// CLI definitions
// ---------------------------------------------------------------------------

/// Sentinel WAF — easy-mode admin CLI.
#[derive(Parser)]
#[command(name = "sentinel", version, about, long_about = None)]
struct Cli {
    /// Path to the Sentinel config file.
    /// Defaults to `~/.config/sentinel/sentinel.yaml`.
    #[arg(short, long, env = "SENTINEL_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Override the data-plane binary path (default: auto-detect).
    #[arg(long, env = "SENTINEL_BIN", global = true)]
    data_plane_bin: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Initialise Sentinel: create config dir, default YAML, and discover CRS rules.
    Init {
        /// Listener bind address (host:port).
        #[arg(long, default_value = DEFAULT_BIND)]
        bind: String,
    },

    /// Start the WAF in the background (detached daemon).
    Start,

    /// Stop the running WAF (SIGTERM, then SIGKILL after 5 s).
    Stop,

    /// Hot-reload config without dropping connections (SIGHUP).
    Reload,

    /// Stop then start.
    Restart,

    /// Show running state, listeners, protected sites.
    Status,

    /// Manage protected sites.
    Site {
        #[command(subcommand)]
        action: SiteCmd,
    },

    /// Manage WASM plugins (install from OCI registry).
    Plugin {
        #[command(subcommand)]
        action: PluginCmd,
    },

    /// View or follow the request log.
    Logs {
        /// Follow new lines (like `tail -f`).
        #[arg(short, long)]
        follow: bool,
        /// Number of recent lines to show.
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
        /// Print raw JSON (skip pretty-print).
        #[arg(long)]
        raw: bool,
    },

    /// Send sample attack requests through Sentinel and report which were blocked.
    Test {
        /// Site name to target (defaults to the first configured site).
        #[arg(long)]
        site: Option<String>,
    },

    /// AI-powered security assistant: explain alerts, suggest rules, generate patches.
    Copilot {
        #[command(subcommand)]
        action: CopilotCmd,
    },

    /// Print the full path of important files (config, log, pid, binary).
    Paths,
}

#[derive(Subcommand)]
enum CopilotCmd {
    /// Test the LLM copilot with a one-shot prompt.
    Chat {
        /// The prompt to send.
        #[arg(short, long)]
        prompt: String,
        /// System message / personality.
        #[arg(short, long, default_value = "You are a helpful WAF security assistant.")]
        system: String,
    },
    /// Explain why a recent request was blocked (paste log line or describe it).
    Explain {
        /// The alert details (URI, rules fired, reason).
        alert: String,
    },
    /// Generate an SRL rule from a human description.
    SuggestRule {
        /// Natural-language description of what to detect.
        description: String,
    },
    /// Generate a virtual patch for a CVE.
    Patch {
        /// CVE identifier (e.g. CVE-2024-1234).
        cve: String,
        /// Short description of the vulnerability.
        #[arg(short, long)]
        description: String,
    },
}

#[derive(Subcommand)]
enum SiteCmd {
    /// Add a site to protect.
    Add {
        /// Site identifier (e.g. "dvwa", "juice").
        name: String,

        /// Hostname clients use (Host header). Can be repeated.
        #[arg(long, required = true)]
        domain: Vec<String>,

        /// Upstream backend in `host:port` form. Can be repeated for load-balancing.
        #[arg(long, required = true)]
        upstream: Vec<String>,

        /// WAF mode: off | learning | blocking.
        #[arg(long, default_value = "blocking")]
        mode: String,

        /// CRS anomaly threshold (block when score >= this).
        #[arg(long, default_value_t = 5)]
        threshold: u32,

        /// Skip bundling the OWASP CRS rule set.
        #[arg(long)]
        no_crs: bool,
    },

    /// Remove a site.
    #[command(alias = "rm")]
    Remove {
        /// Site identifier.
        name: String,
    },

    /// List all configured sites.
    #[command(alias = "ls")]
    List,

    /// Change a site's WAF mode (off | learning | blocking).
    Mode {
        /// Site identifier.
        name: String,
        /// New mode.
        mode: String,
    },
}

#[derive(Subcommand)]
enum PluginCmd {
    /// Install a plugin from an OCI-compatible registry.
    Install {
        /// Plugin reference in `registry.example.com/namespace/name:tag` format.
        reference: String,
        /// Directory to install the plugin into.
        #[arg(long, default_value = "~/.config/sentinel/plugins")]
        dir: String,
    },
    /// List installed plugins.
    #[command(alias = "ls")]
    List {
        /// Directory containing installed plugins.
        #[arg(long, default_value = "~/.config/sentinel/plugins")]
        dir: String,
    },
    /// Remove an installed plugin.
    #[command(alias = "rm")]
    Remove {
        /// Plugin name (directory name under `--dir`).
        name: String,
        /// Directory containing installed plugins.
        #[arg(long, default_value = "~/.config/sentinel/plugins")]
        dir: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    // rustls crypto provider required for HTTPS in copilot commands.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: failed to build tokio runtime: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = rt.block_on(run()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let cfg_path = match cli.config.clone() {
        Some(p) => p,
        None => default_config_path()?,
    };

    match cli.cmd {
        Cmd::Init { bind } => cmd_init(&cfg_path, &bind),
        Cmd::Start => cmd_start(&cfg_path, cli.data_plane_bin.as_deref()),
        Cmd::Stop => cmd_stop(),
        Cmd::Reload => cmd_reload(),
        Cmd::Restart => {
            let _ = cmd_stop();
            std::thread::sleep(Duration::from_millis(500));
            cmd_start(&cfg_path, cli.data_plane_bin.as_deref())
        }
        Cmd::Status => cmd_status(&cfg_path),
        Cmd::Site { action } => match action {
            SiteCmd::Add {
                name,
                domain,
                upstream,
                mode,
                threshold,
                no_crs,
            } => cmd_site_add(&cfg_path, &name, &domain, &upstream, &mode, threshold, no_crs),
            SiteCmd::Remove { name } => cmd_site_remove(&cfg_path, &name),
            SiteCmd::List => cmd_site_list(&cfg_path),
            SiteCmd::Mode { name, mode } => cmd_site_mode(&cfg_path, &name, &mode),
        },
        Cmd::Plugin { action } => match action {
            PluginCmd::Install { reference, dir } => cmd_plugin_install(&reference, &dir),
            PluginCmd::List { dir } => cmd_plugin_list(&dir),
            PluginCmd::Remove { name, dir } => cmd_plugin_remove(&name, &dir),
        },
        Cmd::Logs { follow, lines, raw } => cmd_logs(follow, lines, raw),
        Cmd::Test { site } => cmd_test(&cfg_path, site.as_deref()),
        Cmd::Copilot { action } => cmd_copilot(action).await,
        Cmd::Paths => cmd_paths(&cfg_path, cli.data_plane_bin.as_deref()),
    }
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

fn config_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    Ok(PathBuf::from(home).join(".config/sentinel"))
}

fn default_config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("sentinel.yaml"))
}

fn pid_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("sentinel.pid"))
}

fn log_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("sentinel.log"))
}

/// Discover where `sentinel-bin` lives.
fn find_sentinel_bin(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        if p.exists() {
            return Ok(p.canonicalize()?);
        }
        bail!("--data-plane-bin not found: {}", p.display());
    }

    // 1. Sibling to the current sentinel CLI executable.
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(dir) = self_exe.parent() {
            let candidate = dir.join("sentinel-bin");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    // 2. PATH lookup via `which`.
    if let Ok(out) = Command::new("which").arg("sentinel-bin").output() {
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !p.is_empty() {
                return Ok(PathBuf::from(p));
            }
        }
    }

    // 3. Cargo target dirs relative to CWD.
    for rel in ["target/release/sentinel-bin", "target/debug/sentinel-bin"] {
        let p = PathBuf::from(rel);
        if p.exists() {
            return Ok(p.canonicalize()?);
        }
    }

    bail!(
        "sentinel-bin not found.\n\
         Install with:  cargo install --path crates/sentinel-bin --path crates/sentinel-cli\n\
         Or build it:   cargo build --release -p sentinel-bin"
    )
}

/// Discover the OWASP CRS rules directory.
///
/// Searches in priority order: env override, `~/.config/sentinel/rules/`,
/// `./rules/owasp-crs/rules/` (repo root), and a few common install paths.
/// Returns the canonical absolute path of the directory if found.
fn find_crs_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(env) = std::env::var("SENTINEL_CRS_DIR") {
        candidates.push(PathBuf::from(env));
    }
    if let Ok(d) = config_dir() {
        candidates.push(d.join("rules/owasp-crs/rules"));
    }
    candidates.push(PathBuf::from("rules/owasp-crs/rules"));
    candidates.push(PathBuf::from("/usr/share/sentinel/rules/owasp-crs/rules"));
    candidates.push(PathBuf::from("/usr/local/share/sentinel/rules/owasp-crs/rules"));

    for c in candidates {
        if c.is_dir() {
            return c.canonicalize().ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Config helpers (load / save)
// ---------------------------------------------------------------------------

fn load_config(path: &Path) -> Result<SentinelConfig> {
    let raw = fs::read_to_string(path).with_context(|| {
        format!(
            "reading config '{}'.\nRun `sentinel init` to create one.",
            path.display()
        )
    })?;
    let cfg: SentinelConfig = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing config '{}'", path.display()))?;
    Ok(cfg)
}

fn save_config(path: &Path, cfg: &SentinelConfig) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let yaml = serde_yaml::to_string(cfg)?;
    fs::write(path, yaml)
        .with_context(|| format!("writing config '{}'", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Process helpers (PID file + signals)
// ---------------------------------------------------------------------------

fn read_pid() -> Result<Option<i32>> {
    let p = pid_path()?;
    if !p.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&p)?;
    let pid: i32 = raw.trim().parse().context("invalid pid file contents")?;
    Ok(Some(pid))
}

fn write_pid(pid: u32) -> Result<()> {
    fs::write(pid_path()?, pid.to_string())?;
    Ok(())
}

fn process_alive(pid: i32) -> bool {
    // signal 0 → only checks existence/permissions, doesn't deliver.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn signal_pid(pid: i32, sig: i32) -> Result<()> {
    let r = unsafe { libc::kill(pid, sig) };
    if r < 0 {
        Err(std::io::Error::last_os_error()).context(format!("kill({pid}, {sig})"))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_init(cfg_path: &Path, bind: &str) -> Result<()> {
    fs::create_dir_all(config_dir()?)?;

    if cfg_path.exists() {
        println!("Config already exists at {}", cfg_path.display());
        println!("Delete it first if you want to start over.");
        return Ok(());
    }

    let cfg = SentinelConfig {
        listeners: vec![ListenerConfig {
            name: "http".into(),
            bind: bind.to_string(),
            protocol: ProtocolSpec::Single(Protocol::Http1),
            tls: None,
            default_site: None,
            role: Default::default(),
        }],
        sites: vec![],
        logging: LoggingConfig {
            level: "info".into(),
            format: LogFormat::Json,
            outputs: vec![LogOutput::Stdout],
        },
        ..Default::default()
    };
    save_config(cfg_path, &cfg)?;

    let crs_status = match find_crs_dir() {
        Some(d) => format!("found at {}", d.display()),
        None => "NOT FOUND (sites will start with no rules)".into(),
    };

    println!("Sentinel initialised.");
    println!();
    println!("  Config:     {}", cfg_path.display());
    println!("  Listening:  {}", bind);
    println!("  CRS rules:  {}", crs_status);
    println!();
    println!("Next steps:");
    println!("  1. Add a site:  sentinel site add NAME --domain DOMAIN --upstream HOST:PORT");
    println!("  2. Start:       sentinel start");
    println!("  3. Status:      sentinel status");
    println!("  4. Send tests:  sentinel test");
    Ok(())
}

fn cmd_start(cfg_path: &Path, override_bin: Option<&Path>) -> Result<()> {
    if !cfg_path.exists() {
        bail!(
            "config not found at {}.\nRun `sentinel init` first.",
            cfg_path.display()
        );
    }

    if let Some(pid) = read_pid()? {
        if process_alive(pid) {
            println!("sentinel is already running (pid {pid}).");
            return Ok(());
        }
        // Stale pid — overwrite below.
    }

    fs::create_dir_all(config_dir()?)?;
    let bin = find_sentinel_bin(override_bin)?;
    let log = log_path()?;
    let cfg_abs = cfg_path
        .canonicalize()
        .with_context(|| format!("resolving config path '{}'", cfg_path.display()))?;

    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .with_context(|| format!("opening log file '{}'", log.display()))?;
    let log_file_err = log_file.try_clone()?;

    let mut cmd = Command::new(&bin);
    cmd.arg("--config").arg(&cfg_abs);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::from(log_file));
    cmd.stderr(Stdio::from(log_file_err));

    // Detach from controlling tty so the daemon survives shell exit.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd.spawn().with_context(|| {
        format!("spawning data-plane binary '{}'", bin.display())
    })?;
    let pid = child.id() as i32;
    write_pid(pid as u32)?;

    // Give the data plane a moment to either bind or fail.
    std::thread::sleep(Duration::from_millis(400));
    if !process_alive(pid) {
        let last = read_last_log_lines(&log, 10).unwrap_or_default();
        println!("sentinel failed to start.");
        println!("Last log lines:\n{last}");
        bail!("startup failure (pid {pid} exited)");
    }

    let cfg = load_config(cfg_path).ok();
    let listener = cfg
        .as_ref()
        .and_then(|c| c.listeners.first())
        .map(|l| l.bind.as_str())
        .unwrap_or(DEFAULT_BIND);
    let site_count = cfg.as_ref().map(|c| c.sites.len()).unwrap_or(0);

    println!("sentinel started (pid {pid}).");
    println!();
    println!("  Listening on:    {listener}");
    println!("  Protected sites: {site_count}");
    println!("  Logs:            {}", log.display());
    println!();
    println!("  Watch traffic:   sentinel logs -f");
    println!("  Try attacks:    sentinel test");
    Ok(())
}

fn cmd_stop() -> Result<()> {
    let pid = match read_pid()? {
        Some(p) => p,
        None => {
            println!("sentinel is not running.");
            return Ok(());
        }
    };
    if !process_alive(pid) {
        println!("sentinel was not running (stale pid).");
        let _ = fs::remove_file(pid_path()?);
        return Ok(());
    }
    signal_pid(pid, libc::SIGTERM)?;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if !process_alive(pid) {
            break;
        }
    }
    if process_alive(pid) {
        eprintln!("graceful shutdown timed out — sending SIGKILL");
        signal_pid(pid, libc::SIGKILL)?;
    }
    let _ = fs::remove_file(pid_path()?);
    println!("sentinel stopped (pid {pid}).");
    Ok(())
}

fn cmd_reload() -> Result<()> {
    let pid = read_pid()?.ok_or_else(|| anyhow!("sentinel is not running"))?;
    if !process_alive(pid) {
        bail!("sentinel is not running (stale pid)");
    }
    signal_pid(pid, libc::SIGHUP)?;
    println!("config reload signalled (pid {pid}).");
    println!("Verify with:  sentinel logs -n 5");
    Ok(())
}

fn cmd_status(cfg_path: &Path) -> Result<()> {
    println!("Sentinel WAF\n");

    let pid = read_pid()?;
    let alive = pid.map(process_alive).unwrap_or(false);
    if alive {
        println!("  Status:    RUNNING (pid {})", pid.expect("pid must exist when alive"));
    } else {
        println!("  Status:    stopped");
    }
    println!("  Config:    {}", cfg_path.display());
    println!("  Logs:      {}", log_path()?.display());

    if !cfg_path.exists() {
        println!();
        println!("Config does not exist. Run:  sentinel init");
        return Ok(());
    }

    let cfg = load_config(cfg_path)?;
    println!();
    println!("  Listeners:");
    if cfg.listeners.is_empty() {
        println!("    (none)");
    } else {
        for l in &cfg.listeners {
            let tls = if l.is_tls() { "TLS" } else { "plain" };
            println!("    - {:<10} {}  ({})", l.name, l.bind, tls);
        }
    }

    println!();
    println!("  Protected sites:");
    if cfg.sites.is_empty() {
        println!("    (none)");
        println!();
        println!("  Add one:  sentinel site add NAME --domain D --upstream HOST:PORT");
    } else {
        for s in &cfg.sites {
            let upstreams = s
                .upstream
                .servers
                .iter()
                .map(|u| format!("{}:{}", u.host, u.port))
                .collect::<Vec<_>>()
                .join(", ");
            println!(
                "    - {:<14} mode={:<8} domains=[{}]  → {}  ({} rules)",
                s.id,
                fmt_mode(&s.waf.mode),
                s.domains.join(", "),
                upstreams,
                s.waf.rules.len()
            );
        }
    }
    Ok(())
}

fn cmd_site_add(
    cfg_path: &Path,
    name: &str,
    domains: &[String],
    upstreams: &[String],
    mode: &str,
    threshold: u32,
    no_crs: bool,
) -> Result<()> {
    let mut cfg = load_config(cfg_path)?;

    if cfg.sites.iter().any(|s| s.id == name) {
        bail!(
            "site '{name}' already exists. Remove it first:  sentinel site rm {name}"
        );
    }

    let waf_mode = parse_mode(mode)?;

    let parsed_upstreams: Vec<UpstreamServer> = upstreams
        .iter()
        .map(|u| {
            let (h, p) = parse_host_port(u)?;
            Ok(UpstreamServer {
                host: h,
                port: p,
                weight: 1,
                tls: false,
            })
        })
        .collect::<Result<_>>()?;

    // Resolve CRS paths to absolute file paths so the daemon can find them
    // regardless of its current working directory.
    let rules: Vec<String> = if no_crs {
        Vec::new()
    } else {
        match find_crs_dir() {
            Some(dir) => default_crs_files()
                .iter()
                .filter_map(|f| {
                    let p = dir.join(f);
                    if p.exists() {
                        Some(p.to_string_lossy().into_owned())
                    } else {
                        None
                    }
                })
                .collect(),
            None => {
                eprintln!(
                    "warning: OWASP CRS rules not found — site will start with NO rules.\n\
                     Set SENTINEL_CRS_DIR or copy CRS to ~/.config/sentinel/rules/owasp-crs/rules/"
                );
                Vec::new()
            }
        }
    };

    let site = SiteConfig {
        id: name.to_string(),
        tenant_id: String::new(),
        domains: domains.to_vec(),
        upstream: UpstreamConfig {
            load_balancer: LoadBalancerStrategy::RoundRobin,
            servers: parsed_upstreams,
            health_check: None,
        },
        waf: WafConfig {
            mode: waf_mode.clone(),
            paranoia_level: 1,
            anomaly_threshold: threshold,
            rules,
            ml: None,
            ip_reputation: None,
            rate_limit: None,
            bot_detection: None,
            dlp: None,
            api_discovery: false,
            graphql: None,
            anti_ddos: None,
            geoip: None,
            plugins: vec![],
            rule_exclusions: vec![],
            max_body_size: 10 * 1024 * 1024,
            max_uri_length: 8192,
            max_header_count: 100,
            allowed_methods: Default::default(),
            security_headers: Default::default(),
        },
        plugins: vec![],
        tls: Default::default(),
    };

    cfg.sites.push(site);
    save_config(cfg_path, &cfg)?;

    let listener_bind = cfg
        .listeners
        .first()
        .map(|l| l.bind.clone())
        .unwrap_or_else(|| DEFAULT_BIND.to_string());

    println!("Added site '{name}'.");
    println!();
    println!("  Mode:       {}", fmt_mode(&waf_mode));
    println!("  Domains:    {}", domains.join(", "));
    println!("  Upstreams:  {}", upstreams.join(", "));
    println!("  Threshold:  anomaly score >= {threshold} → block");
    println!();
    println!("Test it:");
    let test_domain = domains.first().map(String::as_str).unwrap_or("localhost");
    println!("  curl -H 'Host: {test_domain}' http://{listener_bind}/");
    println!(
        "  curl -H 'Host: {test_domain}' 'http://{listener_bind}/?id=1%27%20UNION%20SELECT%201'"
    );
    println!();
    if read_pid()?.map(process_alive).unwrap_or(false) {
        println!("Apply without restart:   sentinel reload");
    } else {
        println!("Start the WAF:           sentinel start");
    }
    Ok(())
}

fn cmd_site_remove(cfg_path: &Path, name: &str) -> Result<()> {
    let mut cfg = load_config(cfg_path)?;
    let before = cfg.sites.len();
    cfg.sites.retain(|s| s.id != name);
    if cfg.sites.len() == before {
        bail!("site '{name}' not found.");
    }
    save_config(cfg_path, &cfg)?;
    println!("Removed site '{name}'.");
    if read_pid()?.map(process_alive).unwrap_or(false) {
        println!("Apply without restart:   sentinel reload");
    }
    Ok(())
}

fn cmd_site_list(cfg_path: &Path) -> Result<()> {
    let cfg = load_config(cfg_path)?;
    if cfg.sites.is_empty() {
        println!("No sites configured.");
        println!("Add one:  sentinel site add NAME --domain D --upstream HOST:PORT");
        return Ok(());
    }
    println!(
        "{:<14} {:<10} {:<32} {:<28} {:>5}",
        "NAME", "MODE", "DOMAINS", "UPSTREAMS", "RULES"
    );
    println!("{}", "-".repeat(90));
    for s in &cfg.sites {
        let upstreams = s
            .upstream
            .servers
            .iter()
            .map(|u| format!("{}:{}", u.host, u.port))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{:<14} {:<10} {:<32} {:<28} {:>5}",
            s.id,
            fmt_mode(&s.waf.mode),
            truncate(&s.domains.join(","), 30),
            truncate(&upstreams, 26),
            s.waf.rules.len(),
        );
    }
    Ok(())
}

fn cmd_site_mode(cfg_path: &Path, name: &str, mode: &str) -> Result<()> {
    let mut cfg = load_config(cfg_path)?;
    let new_mode = parse_mode(mode)?;
    let site = cfg
        .sites
        .iter_mut()
        .find(|s| s.id == name)
        .ok_or_else(|| anyhow!("site '{name}' not found"))?;
    site.waf.mode = new_mode.clone();
    save_config(cfg_path, &cfg)?;
    println!("Site '{name}' mode set to {}", fmt_mode(&new_mode));
    if read_pid()?.map(process_alive).unwrap_or(false) {
        println!("Apply without restart:   sentinel reload");
    }
    Ok(())
}

fn cmd_logs(follow: bool, lines: usize, raw: bool) -> Result<()> {
    let log = log_path()?;
    if !log.exists() {
        println!("No logs yet at {}", log.display());
        println!("Start the WAF first: sentinel start");
        return Ok(());
    }

    if follow {
        // Pretty-print mode: tail -n N -f, then format each line.
        if raw {
            let err = Command::new("tail")
                .args(["-n", &lines.to_string(), "-f"])
                .arg(&log)
                .exec();
            return Err(anyhow!("failed to exec tail: {err}"));
        }
        // Spawn `tail -n N -f` and pretty-print lines we receive.
        let mut child = Command::new("tail")
            .args(["-n", &lines.to_string(), "-f"])
            .arg(&log)
            .stdout(Stdio::piped())
            .spawn()
            .context("spawning tail")?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("tail produced no stdout"))?;
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => print_log_line(&l),
                Err(_) => break,
            }
        }
        let _ = child.wait();
        return Ok(());
    }

    // Non-follow mode: read last N lines.
    let content = fs::read_to_string(&log)?;
    let all: Vec<&str> = content.lines().collect();
    let start = all.len().saturating_sub(lines);
    for line in &all[start..] {
        if raw {
            println!("{line}");
        } else {
            print_log_line(line);
        }
    }
    Ok(())
}

fn cmd_test(cfg_path: &Path, site_filter: Option<&str>) -> Result<()> {
    let cfg = load_config(cfg_path)?;
    let pid = read_pid()?;
    if !pid.map(process_alive).unwrap_or(false) {
        eprintln!("warning: sentinel does not appear to be running. Start it: sentinel start");
    }

    let listener = cfg
        .listeners
        .first()
        .ok_or_else(|| anyhow!("no listeners in config"))?;
    let target = format!("http://{}", listener.bind);

    let site = if let Some(name) = site_filter {
        cfg.sites
            .iter()
            .find(|s| s.id == name)
            .ok_or_else(|| anyhow!("site '{name}' not found"))?
    } else {
        cfg.sites
            .first()
            .ok_or_else(|| anyhow!("no sites configured. Add one: sentinel site add ..."))?
    };
    let host = site
        .domains
        .first()
        .map(|d| d.as_str())
        .unwrap_or("localhost");

    println!("Testing Sentinel WAF");
    println!("  Target: {target}");
    println!("  Site:   {} (Host: {host})", site.id);
    println!("  Mode:   {}", fmt_mode(&site.waf.mode));
    println!();

    let attacks: &[(&str, &str, Option<&str>, bool)] = &[
        ("Clean GET",         "/",                                                                None,                                              false),
        ("Clean query",       "/?id=42&name=alice",                                               None,                                              false),
        ("SQL injection",     "/?id=1%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users",  None,                                              true),
        ("SQLi (SLEEP)",      "/login?u=admin%27%20OR%20SLEEP(5)--%20",                           None,                                              true),
        ("XSS (script tag)",  "/?q=%3Cscript%3Ealert(1)%3C/script%3E",                            None,                                              true),
        ("XSS (img onerror)", "/?q=%3Cimg%20src=x%20onerror=alert(1)%3E",                         None,                                              true),
        ("Path traversal",    "/?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",                          None,                                              true),
        ("RCE attempt",       "/?cmd=%3Bcat%20%2Fetc%2Fpasswd",                                   None,                                              true),
        ("PHP wrapper",       "/?file=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Da", None,                                              true),
        ("Login bypass POST", "/login",                                                           Some("user=admin&pass=%27%20OR%20%271%27%3D%271"), true),
    ];

    let mut blocked = 0usize;
    let mut passed = 0usize;
    let mut errors = 0usize;

    for (name, path, body, is_attack) in attacks {
        let url = format!("{target}{path}");
        let mut args: Vec<String> = vec![
            "-s".into(),
            "-o".into(),
            "/dev/null".into(),
            "-w".into(),
            "%{http_code}".into(),
            "--max-time".into(),
            "5".into(),
            "-H".into(),
            format!("Host: {host}"),
        ];
        if let Some(b) = body {
            args.push("-X".into());
            args.push("POST".into());
            args.push("-H".into());
            args.push("Content-Type: application/x-www-form-urlencoded".into());
            args.push("-d".into());
            args.push(b.to_string());
        }
        args.push(url);

        let result = match Command::new("curl").args(&args).output() {
            Ok(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            Err(e) => {
                errors += 1;
                format!("ERR {e}")
            }
        };

        let (label, expected_ok) = match result.as_str() {
            "403" => ("BLOCKED", *is_attack),
            "200" => ("PASSED",  !*is_attack),
            "502" | "503" | "504" => ("UPSTREAM-ERR", false),
            _ => (result.as_str(), false),
        };

        let marker = if expected_ok { "  ok " } else { " WARN" };
        println!(
            "  [{marker}] {label:<13}  {name:<20} {path}",
        );

        if result == "403" {
            blocked += 1;
        } else if result == "200" {
            passed += 1;
        }
    }

    println!();
    println!("Summary: {blocked} blocked, {passed} passed, {errors} errors");
    println!();
    println!("Inspect what fired:   sentinel logs -n 30");
    Ok(())
}

fn cmd_paths(cfg_path: &Path, override_bin: Option<&Path>) -> Result<()> {
    let bin = find_sentinel_bin(override_bin).ok();
    let crs = find_crs_dir();

    println!("config_dir   : {}", config_dir()?.display());
    println!("config_file  : {}", cfg_path.display());
    println!("pid_file     : {}", pid_path()?.display());
    println!("log_file     : {}", log_path()?.display());
    println!(
        "data_plane   : {}",
        bin.map(|p| p.display().to_string()).unwrap_or_else(|| "(not found)".into())
    );
    println!(
        "crs_rules_dir: {}",
        crs.map(|p| p.display().to_string()).unwrap_or_else(|| "(not found)".into())
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Copilot commands
// ---------------------------------------------------------------------------

async fn cmd_copilot(action: CopilotCmd) -> Result<()> {
    use sentinel_ml::llm_copilot::{CopilotConfig, CopilotService};

    // Build config from env vars — defaults to company in-house AI.
    let cfg = CopilotConfig {
        endpoint: std::env::var("SENTINEL_LLM_ENDPOINT")
            .unwrap_or_else(|_| "https://ai.enlight.dev/api".into()),
        api_key: std::env::var("SENTINEL_LLM_API_KEY")
            .unwrap_or_else(|_| "sk-f87a48c6102447abb3382b596ebf51de".into()),
        model: std::env::var("SENTINEL_LLM_MODEL")
            .unwrap_or_else(|_| "deepseek-r1:8b".into()),
        timeout_secs: 30,
    };

    println!("LLM Copilot");
    println!("  Endpoint:  {}", cfg.endpoint);
    println!("  Model:     {}", cfg.model);
    println!();

    let copilot = CopilotService::new(cfg);

    match action {
        CopilotCmd::Chat { prompt, system } => {
            // Use internal chat method via a direct JSON approach.
            // CopilotService::chat is private; we'll use the public API.
            println!("Asking: {prompt}");
            println!();
            // We expose this via the explain method with a crafted context.
            // For raw chat, we send a simple JSON request.
            let client = &copilot; // borrow
            let resp = raw_chat(client, &system, &prompt).await?;
            println!("Response:\n{resp}");
        }
        CopilotCmd::Explain { alert } => {
            println!("Alert: {alert}");
            println!();
            let explanation = raw_chat(
                &copilot,
                "You are a WAF security analyst. Explain in plain English why this alert fired.",
                &format!("Explain this WAF alert: {alert}"),
            )
            .await?;
            println!("Explanation:\n{explanation}");
        }
        CopilotCmd::SuggestRule { description } => {
            println!("Generating rule for: {description}");
            println!();
            let rule = copilot.suggest_rule(&description).await?;
            println!("{rule}");
        }
        CopilotCmd::Patch { cve, description } => {
            println!("Generating virtual patch for: {cve}");
            println!();
            let patch = copilot.generate_virtual_patch(&cve, &description).await?;
            println!("{patch}");
        }
    }
    Ok(())
}

/// Raw chat: send a prompt and system message, get text back.
async fn raw_chat(copilot: &CopilotService, system: &str, user: &str) -> Result<String> {
    copilot.ask(system, user).await.map_err(|e| {
        anyhow!("LLM call failed: {e}. Check that the endpoint and API key are correct.")
    })
}

// ---------------------------------------------------------------------------
// Helpers — formatting, parsing
// ---------------------------------------------------------------------------

fn parse_host_port(s: &str) -> Result<(String, u16)> {
    let (h, p) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("upstream must be host:port (got '{s}')"))?;
    if h.is_empty() {
        bail!("upstream missing host (got '{s}')");
    }
    let port: u16 = p
        .parse()
        .with_context(|| format!("upstream port must be a number (got '{p}')"))?;
    Ok((h.to_string(), port))
}

fn parse_mode(s: &str) -> Result<WafMode> {
    match s.to_lowercase().as_str() {
        "off" => Ok(WafMode::Off),
        "learning" | "learn" | "detect" | "detection" => Ok(WafMode::Learning),
        "blocking" | "block" | "on" => Ok(WafMode::Blocking),
        _ => bail!("invalid mode '{s}'. Use: off | learning | blocking"),
    }
}

fn fmt_mode(m: &WafMode) -> &'static str {
    match m {
        WafMode::Off => "off",
        WafMode::Learning => "learning",
        WafMode::Blocking => "blocking",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

/// Default OWASP CRS request rules to bundle with a new site.
/// Order matters: 901 initialises TX vars; 949 evaluates the anomaly score.
fn default_crs_files() -> &'static [&'static str] {
    &[
        "REQUEST-901-INITIALIZATION.conf",
        "REQUEST-911-METHOD-ENFORCEMENT.conf",
        "REQUEST-913-SCANNER-DETECTION.conf",
        "REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
        "REQUEST-921-PROTOCOL-ATTACK.conf",
        "REQUEST-930-APPLICATION-ATTACK-LFI.conf",
        "REQUEST-931-APPLICATION-ATTACK-RFI.conf",
        "REQUEST-932-APPLICATION-ATTACK-RCE.conf",
        "REQUEST-933-APPLICATION-ATTACK-PHP.conf",
        "REQUEST-934-APPLICATION-ATTACK-GENERIC.conf",
        "REQUEST-941-APPLICATION-ATTACK-XSS.conf",
        "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
        "REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf",
        "REQUEST-944-APPLICATION-ATTACK-JAVA.conf",
        "REQUEST-949-BLOCKING-EVALUATION.conf",
    ]
}

fn read_last_log_lines(path: &Path, n: usize) -> Result<String> {
    let content = fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n);
    Ok(lines[start..].join("\n"))
}

/// Pretty-print a JSON tracing log line, falling back to raw output.
fn print_log_line(line: &str) {
    let v: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => {
            println!("{line}");
            return;
        }
    };
    let ts = v
        .get("timestamp")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .chars()
        .take(19)
        .collect::<String>();
    let level = v.get("level").and_then(|x| x.as_str()).unwrap_or("");
    // tracing_subscriber JSON format puts user fields under `fields` and
    // the log target/message at the top.  Prefer fields for our structured
    // request log entries.
    let fields = v.get("fields").unwrap_or(&v);
    let msg = fields
        .get("message")
        .and_then(|x| x.as_str())
        .unwrap_or("");

    if msg == "request" {
        let decision = fields
            .get("decision")
            .and_then(|x| x.as_str())
            .unwrap_or("Allow");
        let method = fields.get("method").and_then(|x| x.as_str()).unwrap_or("?");
        let uri = fields.get("uri").and_then(|x| x.as_str()).unwrap_or("?");
        let status = fields.get("status").and_then(|x| x.as_u64()).unwrap_or(0);
        let score = fields
            .get("anomaly_score")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let matches = fields
            .get("rule_matches")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        let site = fields.get("site").and_then(|x| x.as_str()).unwrap_or("-");
        let client = fields
            .get("client_ip")
            .and_then(|x| x.as_str())
            .unwrap_or("-");

        let tag = match decision {
            "Block" => "BLOCK ",
            "Challenge" => "CHALLE",
            "Log" => "DETECT",
            _ => "OK    ",
        };
        let truncated_uri = if uri.len() > 60 {
            format!("{}…", &uri[..59])
        } else {
            uri.to_string()
        };
        println!(
            "{ts}  {tag}  {client:<15} {method:<5} {site:<14} {truncated_uri}  status={status} score={score} matches={matches}"
        );
    } else {
        let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("");
        println!("{ts} {level:<5} {target} {msg}");
    }
}

// ---------------------------------------------------------------------------
// Plugin commands
// ---------------------------------------------------------------------------

fn cmd_plugin_install(reference: &str, dir: &str) -> Result<()> {
    let (registry, repo, tag) = parse_plugin_reference(reference)?;
    let plugin_dir = PathBuf::from(dir);
    fs::create_dir_all(&plugin_dir)?;

    println!("Installing plugin '{}' from {}", reference, registry);
    println!();

    let api_base = if registry.contains("://") {
        registry.clone()
    } else {
        format!("https://{}", registry)
    };

    let manifest_url = format!("{}/v2/{}/manifests/{}", api_base, repo, tag);
    println!("  → Fetching manifest: {}", manifest_url);

    let manifest_resp = ureq::get(&manifest_url)
        .set("Accept", "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json")
        .set("User-Agent", "sentinel-waf-cli/0.1")
        .call()
        .with_context(|| format!("fetching manifest from {manifest_url}"))?;

    if manifest_resp.status() != 200 {
        anyhow::bail!(
            "registry returned HTTP {} for manifest. Check the plugin reference.",
            manifest_resp.status()
        );
    }

    let manifest: serde_json::Value = manifest_resp
        .into_json()
        .context("parsing manifest JSON")?;

    let layers = manifest["layers"]
        .as_array()
        .ok_or_else(|| anyhow!("manifest has no 'layers' array — expected OCI image"))?;

    if layers.is_empty() {
        anyhow::bail!("manifest has no layers");
    }

    let plugin_name = repo.split('/').last().unwrap_or(&repo).to_string();
    let install_dir = plugin_dir.join(&plugin_name);
    fs::create_dir_all(&install_dir)?;

    let mut manifest_written = false;
    for (i, layer) in layers.iter().enumerate() {
        let digest = layer["digest"]
            .as_str()
            .ok_or_else(|| anyhow!("layer {i} missing 'digest'"))?;
        let media_type = layer["mediaType"].as_str().unwrap_or("");

        let blob_url = format!("{}/v2/{}/blobs/{}", api_base, repo, digest);
        println!("  → Downloading layer {}/{}: {}", i + 1, layers.len(), digest);

        let blob_resp = ureq::get(&blob_url)
            .set("User-Agent", "sentinel-waf-cli/0.1")
            .call()
            .with_context(|| format!("downloading blob {digest}"))?;

        let blob_status = blob_resp.status();
        if !(200..300).contains(&blob_status) {
            anyhow::bail!("download failed with HTTP {}", blob_resp.status());
        }

        let mut data = Vec::new();
        blob_resp
            .into_reader()
            .read_to_end(&mut data)
            .context("reading blob data")?;

        if media_type.contains("wasm") || digest.contains("wasm") {
            let wasm_path = install_dir.join(format!("{}.wasm", plugin_name));
            fs::write(&wasm_path, &data)?;
            println!("     → Saved {}", wasm_path.display());
        } else if data.len() > 2 && data[0] == 0x1f && data[1] == 0x8b {
            match decompress_gzip_tar(&data, &install_dir) {
                Ok(files) => {
                    for f in &files {
                        println!("     → Extracted {}", f.display());
                    }
                }
                Err(e) => {
                    let raw_path = install_dir.join(format!("layer_{}.bin", i));
                    fs::write(&raw_path, &data)?;
                    println!("     → Decompress failed ({e}), saved raw blob to {}", raw_path.display());
                }
            }
        } else {
            let raw_path = install_dir.join(format!("layer_{}.bin", i));
            fs::write(&raw_path, &data)?;
            println!("     → Saved to {}", raw_path.display());
        }

        if !manifest_written {
            let manifest_str = serde_json::to_string_pretty(&manifest)?;
            fs::write(install_dir.join("manifest.json"), manifest_str)?;
            manifest_written = true;
        }
    }

    let toml_path = install_dir.join("sentinel-plugin.toml");
    if !toml_path.exists() {
        let toml_content = format!(
            "[plugin]\nname = \"{}\"\nversion = \"{}\"\nwasm = \"{}.wasm\"\n\n[plugin.hooks]\nrequest_headers = true\n\n[plugin.permissions]\nhost_log = true\nhost_get_req_header = true\nhost_set_decision = true\nhost_add_score = true\n",
            plugin_name, tag, plugin_name
        );
        fs::write(&toml_path, toml_content)?;
        println!("     → Generated {}", toml_path.display());
    }

    println!();
    println!("Plugin installed to {}", install_dir.display());
    println!();
    println!("To use it, add this to your site's sentinel.yaml:");
    println!("  waf:");
    println!("    plugins:");
    println!("      - \"{}\"", toml_path.display());

    Ok(())
}

fn cmd_plugin_list(dir: &str) -> Result<()> {
    let plugin_dir = PathBuf::from(dir);
    if !plugin_dir.is_dir() {
        println!("No plugins installed (directory does not exist: {})", plugin_dir.display());
        return Ok(());
    }

    let mut found = false;
    for entry in fs::read_dir(&plugin_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            let manifest_path = entry.path().join("sentinel-plugin.toml");
            if manifest_path.exists() {
                let raw = fs::read_to_string(&manifest_path).unwrap_or_default();
                let version = raw
                    .lines()
                    .find(|l| l.trim().starts_with("version"))
                    .and_then(|l| l.split('=').nth(1))
                    .map(|v| v.trim().trim_matches('"').to_string())
                    .unwrap_or_else(|| "?".to_string());
                let wasm_path = entry.path().join(format!("{}.wasm", name));
                let wasm_size = if wasm_path.exists() {
                    fs::metadata(&wasm_path).map(|m| m.len()).unwrap_or(0)
                } else {
                    0
                };
                println!("{:<24} {}  ({})", name, version, fmt_bytes(wasm_size));
                found = true;
            } else {
                println!("{:<24} (no manifest)", name);
                found = true;
            }
        }
    }

    if !found {
        println!("No plugins found in {}", plugin_dir.display());
    }

    Ok(())
}

fn cmd_plugin_remove(name: &str, dir: &str) -> Result<()> {
    let target = PathBuf::from(dir).join(name);
    if !target.exists() {
        anyhow::bail!("plugin '{}' not found at {}", name, target.display());
    }
    fs::remove_dir_all(&target)
        .with_context(|| format!("removing plugin directory '{}'", target.display()))?;
    println!("Removed plugin '{}'", name);
    Ok(())
}

fn parse_plugin_reference(reference: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = reference.rsplitn(2, ':').collect();
    let (rest, tag) = if parts.len() == 2 {
        (parts[1], parts[0])
    } else {
        (reference, "latest")
    };

    let parts: Vec<&str> = rest.splitn(2, '/').collect();
    if parts.len() < 2 {
        anyhow::bail!(
            "invalid plugin reference '{}'. Expected format: [registry/]namespace/name:tag",
            reference
        );
    }

    let first = parts[0];
    let remainder = parts[1];

    if first.contains('.') || first.contains(':') || first == "localhost" {
        Ok((first.to_string(), remainder.to_string(), tag.to_string()))
    } else {
        Ok((
            "registry-1.docker.io".to_string(),
            format!("{}/{}", first, remainder),
            tag.to_string(),
        ))
    }
}

fn decompress_gzip_tar(data: &[u8], dest: &Path) -> Result<Vec<PathBuf>> {
    use std::io::Read;

    let gz = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(gz);

    let mut files = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        let dest_path = dest.join(&path);

        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&dest_path)?;
        } else {
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;
            fs::write(&dest_path, &data)?;
            files.push(dest_path);
        }
    }

    Ok(files)
}

fn fmt_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
