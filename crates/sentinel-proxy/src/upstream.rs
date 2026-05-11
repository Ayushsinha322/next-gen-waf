//! Upstream connection pool and load balancer.
//!
//! Currently implements round-robin selection. The `send_request` method
//! establishes a new HTTP/1.1 connection per request; a proper keep-alive
//! pool will replace this in Phase 1 (sentinel-storage).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context};
use bytes::Bytes;
use dashmap::DashMap;
use http::Request;
use http_body_util::combinators::BoxBody;
use hyper_util::rt::TokioIo;
use sentinel_core::config::{SentinelConfig, UpstreamServer};
use tracing::debug;

// ---------------------------------------------------------------------------
// Per-site server list with an atomic round-robin cursor
// ---------------------------------------------------------------------------

struct SiteUpstream {
    servers: Vec<UpstreamServer>,
    cursor: AtomicUsize,
}

impl SiteUpstream {
    fn new(servers: Vec<UpstreamServer>) -> Self {
        Self {
            servers,
            cursor: AtomicUsize::new(0),
        }
    }

    fn next(&self) -> Option<&UpstreamServer> {
        if self.servers.is_empty() {
            return None;
        }
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % self.servers.len();
        Some(&self.servers[idx])
    }
}

// ---------------------------------------------------------------------------
// UpstreamPool
// ---------------------------------------------------------------------------

/// Manages upstream server lists for all configured sites.
pub struct UpstreamPool {
    sites: DashMap<String, Arc<SiteUpstream>>,
}

impl UpstreamPool {
    /// Build the pool from the initial config.
    pub fn from_config(cfg: &SentinelConfig) -> Self {
        let pool = Self {
            sites: DashMap::new(),
        };
        for site in &cfg.sites {
            pool.sites.insert(
                site.id.clone(),
                Arc::new(SiteUpstream::new(site.upstream.servers.clone())),
            );
        }
        pool
    }

    /// Returns the next upstream server for `site_id`, or `None` if the site
    /// has no servers.
    pub fn next_server(&self, site_id: &str) -> Option<UpstreamServer> {
        self.sites
            .get(site_id)?
            .next()
            .cloned()
    }

    /// Send an HTTP/1.1 request to the upstream.
    ///
    /// Opens a fresh TCP connection for each request.  A keep-alive pool
    /// is planned for a later phase.
    pub async fn send_request(
        &self,
        site_id: &str,
        req: Request<BoxBody<Bytes, hyper::Error>>,
    ) -> anyhow::Result<http::Response<hyper::body::Incoming>> {
        let server = self
            .next_server(site_id)
            .ok_or_else(|| anyhow!("no upstream servers for site '{}'", site_id))?;

        let addr = server.addr();
        debug!(upstream = %addr, "connecting to upstream");

        let tcp = tokio::net::TcpStream::connect(&addr)
            .await
            .with_context(|| format!("connecting to upstream {}", addr))?;
        tcp.set_nodelay(true)?;

        let io = TokioIo::new(tcp);

        let (mut sender, conn) =
            hyper::client::conn::http1::Builder::new()
                .handshake(io)
                .await
                .context("HTTP/1.1 handshake with upstream")?;

        // Drive the connection in the background.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!("upstream connection closed: {e}");
            }
        });

        let response = sender
            .send_request(req)
            .await
            .context("sending request to upstream")?;

        Ok(response)
    }
}
