//! Sentinel WAF — data-plane binary entry point.

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use sentinel_core::{config::ConfigLoader, ConfigHandle};
use sentinel_proxy::ProxyServer;
use tokio::sync::watch;
use tracing::{error, info};

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

/// Sentinel WAF — high-performance application firewall and reverse proxy.
#[derive(Parser, Debug)]
#[command(name = "sentinel", version, about, long_about = None)]
struct Args {
    /// Path to the configuration file.
    #[arg(
        short,
        long,
        env = "SENTINEL_CONFIG",
        default_value = "configs/examples/sentinel.yaml"
    )]
    config: std::path::PathBuf,

    /// Log level override (trace | debug | info | warn | error).
    /// Defaults to the value set in the config file.
    #[arg(long, env = "RUST_LOG")]
    log_level: Option<String>,

    /// Validate config and exit without starting the proxy.
    #[arg(long, default_value_t = false)]
    check: bool,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Install default rustls crypto provider (required by rustls 0.23+).
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Bootstrap a minimal logger before config is loaded (so startup errors
    // are visible).  The log level from config is applied after loading.
    init_tracing(args.log_level.as_deref().unwrap_or("info"));

    info!(version = env!("CARGO_PKG_VERSION"), "Sentinel WAF starting");

    // Load config.
    let loader = Arc::new(
        ConfigLoader::from_file(&args.config)
            .with_context(|| format!("loading config from {}", args.config.display()))?,
    );

    if args.check {
        info!("config OK — exiting (--check)");
        return Ok(());
    }

    // Build tokio runtime.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("sentinel-worker")
        .build()
        .context("building tokio runtime")?;

    rt.block_on(async_main(loader))
}

async fn async_main(loader: Arc<ConfigLoader>) -> anyhow::Result<()> {
    let config: ConfigHandle = loader.handle();

    // Register SIGHUP handler for config hot-reload.
    ConfigLoader::spawn_signal_watcher(Arc::clone(&loader));

    // Graceful shutdown channel.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn the proxy server.
    let proxy = ProxyServer::new(Arc::clone(&config));
    let proxy_handle = tokio::spawn(async move {
        if let Err(e) = proxy.run(shutdown_rx).await {
            error!("proxy server error: {e:#}");
        }
    });

    // Wait for Ctrl-C / SIGTERM.
    wait_for_shutdown().await;
    info!("shutdown signal received — stopping");

    let _ = shutdown_tx.send(true);
    proxy_handle.await.ok();

    info!("goodbye");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing(level: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(true),
        )
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)))
        .init();
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = sigint.recv() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("Ctrl-C handler");
    }
}
