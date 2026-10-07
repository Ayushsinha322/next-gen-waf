//! Sentinel WAF — data-plane binary entry point.

use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use sentinel_core::{config::ConfigLoader, ConfigHandle};
use sentinel_proxy::ProxyServer;
use tokio::sync::watch;
use tracing::{error, info, warn};
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, NonBlockingBuilder, WorkerGuard};

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
    // The guard flushes queued lines when main returns, on every exit path.
    let _log_guard = init_tracing(args.log_level.as_deref().unwrap_or("info"));
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

fn init_tracing(level: &str) -> WorkerGuard {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let (stdout, guard) = stdout_writer(std::io::stdout());
    let dropped = stdout.error_counter();
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .json()
                .with_target(true)
                .with_thread_ids(true)
                .with_writer(stdout),
        )
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)))
        .init();
    report_dropped_lines(dropped);
    guard
}

/// Log lines held for a stdout that is not keeping up; past this they are
/// dropped. Bounds the queue at a few MB of formatted JSON.
const STDOUT_QUEUE_LINES: usize = 16 * 1024;

/// `out` behind a bounded queue drained by a thread of its own, which drops
/// lines when the queue is full rather than wait.
///
/// The fmt layer wrote on the thread that logged, and every request logs a
/// line. Under Docker stdout is a pipe to the logging driver: while that pipe
/// was slow or full, each write blocked a runtime worker mid-request, so
/// request handling ran at the speed of the log pipe. Losing stdout lines is
/// the lesser harm — access.log and waf.log have their own writer and queue.
fn stdout_writer<W: std::io::Write + Send + 'static>(out: W) -> (NonBlocking, WorkerGuard) {
    NonBlockingBuilder::default()
        .lossy(true)
        .buffered_lines_limit(STDOUT_QUEUE_LINES)
        .thread_name("log-stdout")
        .finish(out)
}

/// Say in the log itself when stdout lines were dropped, since a reader cannot
/// see a gap. Checked every 30 s: a pipe that stays slow costs a line per
/// interval, not one per drop.
fn report_dropped_lines(dropped: ErrorCounter) {
    let spawned = std::thread::Builder::new()
        .name("log-drops".into())
        .spawn(move || {
            let mut reported = 0;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));
                let total = dropped.dropped_lines();
                if total > reported {
                    warn!(
                        dropped_total = total,
                        dropped_since_last_report = total - reported,
                        "stdout log lines were dropped because the log pipe did not keep up; \
                         access.log and waf.log are written separately and are unaffected"
                    );
                    reported = total;
                }
            }
        });
    if let Err(e) = spawned {
        warn!("dropped stdout log lines will not be reported: {e}");
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc, Condvar, Mutex};
    use std::time::Duration;

    /// stdout as a full log pipe leaves it: every write waits until the test
    /// opens the pipe.
    #[derive(Clone)]
    struct StalledPipe(Arc<(Mutex<bool>, Condvar)>);

    impl StalledPipe {
        fn open(&self) {
            let (open, cv) = &*self.0;
            *open.lock().unwrap() = true;
            cv.notify_all();
        }
    }

    impl std::io::Write for StalledPipe {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let (open, cv) = &*self.0;
            let mut is_open = open.lock().unwrap();
            while !*is_open {
                is_open = cv.wait(is_open).unwrap();
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Every request logs a line, on the worker serving it. With stdout written
    /// in place, a log pipe that stopped draining stopped request handling.
    #[test]
    fn a_stalled_stdout_does_not_stall_the_thread_that_logs() {
        let pipe = StalledPipe(Arc::new((Mutex::new(false), Condvar::new())));
        let (writer, guard) = stdout_writer(pipe.clone());
        let dropped = writer.error_counter();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(writer)
            .finish();

        let (done, finished) = mpsc::channel();
        std::thread::spawn(move || {
            tracing::subscriber::with_default(subscriber, || {
                // More than the queue holds: the rest must be dropped, not waited for.
                for i in 0..STDOUT_QUEUE_LINES + 1_000 {
                    info!(i, "request");
                }
            });
            let _ = done.send(());
        });
        let returned = finished.recv_timeout(Duration::from_secs(10)).is_ok();
        // Open the pipe whatever happened, so no thread is left blocked on it.
        pipe.open();
        assert!(returned, "logging blocked on a stalled stdout");
        assert!(
            dropped.dropped_lines() > 0,
            "the overflow is counted, for the drop report"
        );
        drop(guard);
    }
}
