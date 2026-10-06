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

#[derive(Parser, Debug)]
#[command(
    name = "sentinel",
    version,
    about = concat!(sentinel_core::product_name!(), " — high-performance application firewall and reverse proxy."),
    long_about = None
)]
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
    // After tracing, so a panic is one structured line with its location (and
    // is counted at /metrics) rather than the default hook's stderr text.
    sentinel_proxy::install_panic_hook();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        concat!(sentinel_core::product_name!(), " starting")
    );

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
    let mut proxy_handle = tokio::spawn(async move { proxy.run(shutdown_rx).await });

    // Wait for Ctrl-C / SIGTERM — or for the proxy to stop on its own, which it
    // only does when it failed. That used to leave this process waiting for a
    // signal with no listeners: alive to the service manager, serving nothing.
    // Under the old panic="abort" profile a panic at least took the process
    // down; with unwinding the task absorbs it, so exiting is now this code's
    // job, and it applies to an error return just the same.
    tokio::select! {
        _ = wait_for_shutdown() => {}
        res = &mut proxy_handle => {
            match res {
                Ok(Ok(())) => error!("proxy stopped without a shutdown signal"),
                Ok(Err(e)) => error!("proxy server error: {e:#}"),
                Err(e) => error!("proxy server task failed: {e}"),
            }
            anyhow::bail!("proxy stopped unexpectedly; exiting so the service manager restarts it");
        }
    }
    info!("shutdown signal received — stopping");

    let _ = shutdown_tx.send(true);
    match proxy_handle.await {
        Ok(Err(e)) => error!("proxy server error during shutdown: {e:#}"),
        Err(e) => error!("proxy server task failed during shutdown: {e}"),
        Ok(Ok(())) => {}
    }

    info!("goodbye");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn init_tracing(level: &str) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    tracing_subscriber::registry()
        .with(fmt::layer().json().with_target(true).with_thread_ids(true))
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
