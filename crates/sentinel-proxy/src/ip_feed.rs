//! External IP-reputation feeds (`waf.ip_reputation.feeds` in a site policy).
//!
//! A feed URL is typed into the console by a site operator, synced to every
//! data-plane node and fetched from each of them on a timer. Console input
//! therefore drives an outbound fetcher on every node, and each fetch is
//! bounded on every axis this module controls:
//!
//! - **scheme** — http and https only. A `file://` branch used to read any path
//!   on the node, and every line of that file that was not a CIDR was then
//!   logged verbatim. Nothing in the repository (tests, docs, deploy files, the
//!   console, which labels the field "HTTP(S) URL") used it, so it is gone
//!   rather than gated; a local list can be served over HTTP.
//! - **time** — ONE deadline covers connect, TLS, headers and body. The old 30 s
//!   timeout ended when the headers arrived, so a feed that answered and then
//!   trickled its body held the loader forever, and the loader is sequential:
//!   every feed after it, and the table rebuild, never happened again.
//! - **size** — the body is read through [`Limited`]; a larger body fails the
//!   feed instead of being buffered without bound.
//! - **entries** — capped per feed and per node. `IpReputation::check` scans the
//!   suspect list linearly on every request, so this cap is also the bound on
//!   what a feed adds to every request's latency.
//!
//! Redirects are not followed (the legacy hyper client never does), so a 3xx
//! cannot move the fetch to another scheme or host; it fails as a non-2xx.

use std::convert::Infallible;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::{Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use sentinel_core::config::IpFeedConfig;
use sentinel_modules::ip_reputation::parse_ip_or_cidr;
use tracing::{info, warn};

/// Largest feed body read into memory. A feed at the per-feed entry cap is
/// about 1-2 MiB of text; past this it is the wrong URL or a hostile server.
const FEED_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// One deadline for the whole fetch: connect, TLS, headers and body together.
const FEED_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Entries kept from one feed; the rest are dropped with a warning.
const FEED_MAX_ENTRIES: usize = 50_000;
/// Entries kept across every feed on the node. Every request pays for the whole
/// table: `IpReputation::check` on an address in no feed measured ~13 µs per
/// 1,000 entries (opt-level 1), so this cap is ~1.3 ms per request in that build.
const FEED_MAX_TOTAL_ENTRIES: usize = 100_000;
/// Rejected lines quoted in the log, and how much of each.
const FEED_LOG_SAMPLES: usize = 3;
const FEED_SAMPLE_CHARS: usize = 64;

/// The bounds one load applies. Production uses [`FeedLimits::default`]; tests
/// shrink them so a cap can be hit without megabytes of fixture.
#[derive(Debug, Clone)]
pub(crate) struct FeedLimits {
    max_body_bytes: usize,
    timeout: Duration,
    max_entries: usize,
    max_total_entries: usize,
}

impl Default for FeedLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: FEED_MAX_BODY_BYTES,
            timeout: FEED_FETCH_TIMEOUT,
            max_entries: FEED_MAX_ENTRIES,
            max_total_entries: FEED_MAX_TOTAL_ENTRIES,
        }
    }
}

/// What one feed body yielded.
#[derive(Debug, Default)]
struct ParsedFeed {
    /// Addresses / CIDR ranges `IpReputation` accepts, in feed order.
    entries: Vec<String>,
    /// Valid entries dropped because `max_entries` was reached.
    over_cap: usize,
    /// Lines that are neither blank, a `#` comment, nor an address / range.
    rejected: usize,
    /// The first few rejected lines, truncated — never the whole line, and
    /// never all of them: a feed URL pointed at the wrong document would
    /// otherwise copy that document into the log line by line.
    rejected_samples: Vec<String>,
}

/// Fetch every configured feed and build the node-wide suspect table.
///
/// A feed that fails is logged and contributes nothing; the others still load.
pub(crate) async fn load_feed_table(
    feeds: &[IpFeedConfig],
    limits: &FeedLimits,
) -> Vec<(String, Vec<String>)> {
    let mut table: Vec<(String, Vec<String>)> = Vec::new();
    for (i, feed) in feeds.iter().enumerate() {
        if table.len() >= limits.max_total_entries {
            // Not fetched at all: everything they returned would be dropped.
            warn!(
                skipped_feeds = feeds.len() - i,
                "IP feeds on this node reached the limit of {} entries; the remaining feeds \
                 are not fetched",
                limits.max_total_entries
            );
            break;
        }
        let parsed = match fetch_feed(&feed.url, limits).await {
            Ok(p) => p,
            Err(e) => {
                warn!(url = %feed.url, "IP feed fetch failed: {e:#}");
                continue;
            }
        };
        if parsed.rejected > 0 {
            warn!(
                url = %feed.url,
                rejected = parsed.rejected,
                samples = ?parsed.rejected_samples,
                "IP feed: skipped lines that are not an IP address or CIDR range"
            );
        }
        if parsed.over_cap > 0 {
            warn!(
                url = %feed.url,
                kept = parsed.entries.len(),
                dropped = parsed.over_cap,
                "IP feed has more than {} entries; only the first {} are used",
                limits.max_entries,
                limits.max_entries
            );
        }
        let room = limits.max_total_entries - table.len();
        if parsed.entries.len() > room {
            warn!(
                url = %feed.url,
                kept = room,
                dropped = parsed.entries.len() - room,
                "IP feeds on this node reached the limit of {} entries; the rest of this feed \
                 is not used",
                limits.max_total_entries
            );
        }
        let kept = parsed.entries.len().min(room);
        info!(url = %feed.url, count = kept, "IP feed loaded");
        table.extend(
            parsed
                .entries
                .into_iter()
                .take(kept)
                .map(|cidr| (cidr, vec!["feed".to_string()])),
        );
    }
    table
}

/// Fetch one feed within `limits` and parse it.
async fn fetch_feed(url: &str, limits: &FeedLimits) -> anyhow::Result<ParsedFeed> {
    let uri = feed_uri(url)?;
    let body = tokio::time::timeout(limits.timeout, fetch_body(uri, limits.max_body_bytes))
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "feed did not finish within {:?} (connect, headers and body together)",
                limits.timeout
            )
        })??;
    let text = std::str::from_utf8(&body).context("feed body is not valid UTF-8")?;
    Ok(parse_feed_text(text, limits.max_entries))
}

/// Accept only an absolute http or https URL with a host.
fn feed_uri(url: &str) -> anyhow::Result<Uri> {
    const REFUSED: &str = "feed URL must start with http:// or https:// — no other scheme \
                           (file://, ftp://, …) is fetched";
    let url = url.trim();
    // Judged on the text first: `Uri` refuses `file:///x` as "invalid format",
    // which tells the operator nothing about why.
    let lower = url.get(..8).unwrap_or(url).to_ascii_lowercase();
    if !(lower.starts_with("http://") || lower.starts_with("https://")) {
        anyhow::bail!(REFUSED);
    }
    let uri: Uri = url
        .parse()
        .with_context(|| format!("invalid feed URL: {url}"))?;
    if !matches!(uri.scheme_str(), Some("http") | Some("https")) {
        anyhow::bail!(REFUSED);
    }
    if uri.host().is_none_or(str::is_empty) {
        anyhow::bail!("feed URL has no host");
    }
    Ok(uri)
}

async fn fetch_body(uri: Uri, max_body_bytes: usize) -> anyhow::Result<Bytes> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    let client: Client<_, http_body_util::combinators::BoxBody<Bytes, hyper::Error>> =
        Client::builder(TokioExecutor::new()).build(https);

    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("User-Agent", "sentinel-waf/1.0 ip-reputation-feed-fetcher")
        .body(
            http_body_util::Empty::<Bytes>::new()
                .map_err(|never: Infallible| match never {})
                .boxed(),
        )
        .context("building feed request")?;

    let resp = client
        .request(req)
        .await
        .context("feed HTTP request failed")?;
    if !resp.status().is_success() {
        anyhow::bail!("feed returned HTTP {}", resp.status());
    }

    let body = Limited::new(resp.into_body(), max_body_bytes)
        .collect()
        .await
        .map_err(|e| {
            if e.is::<LengthLimitError>() {
                anyhow::anyhow!("feed body is larger than the {max_body_bytes}-byte limit")
            } else {
                anyhow::anyhow!("reading feed body: {e}")
            }
        })?
        .to_bytes();
    Ok(body)
}

/// One entry per line; blank lines and `#` comments are skipped. An entry is
/// kept only if `IpReputation` will accept it, so what is counted here is what
/// is enforced.
fn parse_feed_text(text: &str, max_entries: usize) -> ParsedFeed {
    let mut out = ParsedFeed::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if parse_ip_or_cidr(line).is_err() {
            out.rejected += 1;
            if out.rejected_samples.len() < FEED_LOG_SAMPLES {
                out.rejected_samples.push(log_sample(line));
            }
            continue;
        }
        if out.entries.len() < max_entries {
            out.entries.push(line.to_string());
        } else {
            out.over_cap += 1;
        }
    }
    out
}

fn log_sample(line: &str) -> String {
    let mut s: String = line.chars().take(FEED_SAMPLE_CHARS).collect();
    if s.len() < line.len() {
        s.push('…');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// A local origin. Each connection's request head is read, then the socket
    /// is handed to `respond`, which writes whatever the test needs — including
    /// a response that never ends.
    async fn stub<F, Fut>(respond: F) -> String
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        // The binary installs this in main; the client's TLS config needs it.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = listener.local_addr().unwrap();
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let respond = Arc::clone(&respond);
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    respond(sock).await;
                });
            }
        });
        format!("http://{addr}/feed.netset")
    }

    /// A stub that answers 200 with `body`.
    async fn serving(body: String) -> String {
        stub(move |mut sock| {
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            async move {
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        })
        .await
    }

    /// `n` addresses under a /24 `prefix`, one per line.
    fn addresses(prefix: &str, n: u8) -> String {
        (1..=n)
            .map(|i| format!("{prefix}.{i}\n"))
            .collect::<Vec<_>>()
            .concat()
    }

    /// Fails the test, rather than hanging it, when a fetch does not return.
    async fn bounded<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("feed fetch never returned — nothing bounds it")
    }

    // What the loader keeps from a well-formed feed must not change: the same
    // trimmed lines, in order, with comments and blanks skipped.
    #[tokio::test]
    async fn a_well_formed_feed_loads_as_before() {
        let url = serving(
            "# FireHOL-style header\n\n10.0.0.1\n  198.51.100.0/24  \n2001:db8::/32\n# trailing\n"
                .to_string(),
        )
        .await;
        let parsed = bounded(fetch_feed(&url, &FeedLimits::default()))
            .await
            .expect("well-formed feed");
        assert_eq!(
            parsed.entries,
            ["10.0.0.1", "198.51.100.0/24", "2001:db8::/32"]
        );
        assert_eq!((parsed.rejected, parsed.over_cap), (0, 0));
    }

    // A file:// feed read any path on the node.
    #[tokio::test]
    async fn a_file_url_is_refused() {
        let path = std::env::temp_dir().join(format!("ip-feed-test-{}.txt", std::process::id()));
        std::fs::write(&path, "198.51.100.7\n").unwrap();
        let res = bounded(fetch_feed(
            &format!("file://{}", path.display()),
            &FeedLimits::default(),
        ))
        .await;
        let _ = std::fs::remove_file(&path);
        let err = res.expect_err("a file:// feed must not be read");
        assert!(
            format!("{err:#}").contains("http:// or https://"),
            "{err:#}"
        );
    }

    #[test]
    fn only_absolute_http_and_https_urls_are_accepted() {
        for bad in [
            "file:///etc/passwd",
            "FILE:///etc/passwd",
            "ftp://feeds.example/list",
            "gopher://feeds.example/",
            "//feeds.example/list",
            "feeds.example/list",
            "/etc/passwd",
            "http:///list",
            "",
        ] {
            assert!(feed_uri(bad).is_err(), "{bad} should be refused");
        }
        for ok in [
            "http://feeds.example/level1.netset",
            "https://feeds.example:8443/list?key=x",
            "HTTPS://FEEDS.EXAMPLE/list",
            "http://[2001:db8::1]/list",
            " https://feeds.example/list ",
        ] {
            assert!(feed_uri(ok).is_ok(), "{ok} should be accepted");
        }
    }

    // The production limit, against a body that never stops: the old reader
    // buffered it all.
    #[tokio::test]
    async fn a_body_over_the_size_cap_fails_the_feed() {
        let url = stub(|mut sock| async move {
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .await;
            let chunk = "10.0.0.1\n".repeat(64 * 1024 / 9);
            let mut sent = 0;
            while sent <= FEED_MAX_BODY_BYTES + chunk.len() {
                if sock.write_all(chunk.as_bytes()).await.is_err() {
                    return;
                }
                sent += chunk.len();
            }
        })
        .await;
        let err = bounded(fetch_feed(&url, &FeedLimits::default()))
            .await
            .expect_err("an over-cap body must fail the feed");
        assert!(format!("{err:#}").contains("limit"), "{err:#}");
    }

    // Headers on time, then one byte every 50 ms: each read makes progress, so
    // only a deadline over the WHOLE fetch ends it.
    #[tokio::test]
    async fn a_slow_body_is_cut_off_by_the_single_deadline() {
        let url = stub(|mut sock| async move {
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
                .await;
            loop {
                if sock.write_all(b"1").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        let limits = FeedLimits {
            timeout: Duration::from_millis(400),
            ..FeedLimits::default()
        };
        let started = Instant::now();
        let err = bounded(fetch_feed(&url, &limits))
            .await
            .expect_err("a trickled body must time out");
        assert!(format!("{err:#}").contains("did not finish"), "{err:#}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn entries_past_the_per_feed_cap_are_dropped() {
        let url = serving(addresses("10.0.0", 12)).await;
        let limits = FeedLimits {
            max_entries: 10,
            ..FeedLimits::default()
        };
        let parsed = bounded(fetch_feed(&url, &limits)).await.unwrap();
        assert_eq!(parsed.entries.len(), 10);
        assert_eq!(parsed.entries[0], "10.0.0.1");
        assert_eq!(parsed.over_cap, 2);
    }

    // Feeds on different sites add up on one node; the total is capped too, and
    // a failing feed in between costs only itself.
    #[tokio::test]
    async fn the_node_wide_cap_spans_feeds() {
        let a = serving(addresses("10.0.1", 10)).await;
        let b = serving(addresses("10.0.2", 10)).await;
        // Past the cap: must not even be contacted.
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c = {
            let hits = Arc::clone(&hits);
            stub(move |_sock| {
                hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async {}
            })
            .await
        };
        let feed = |url: &str| IpFeedConfig {
            url: url.to_string(),
            interval: "1h".to_string(),
            format: "cidr".to_string(),
        };
        let limits = FeedLimits {
            max_total_entries: 15,
            ..FeedLimits::default()
        };
        let table = bounded(load_feed_table(
            &[feed(&a), feed("file:///etc/hosts"), feed(&b), feed(&c)],
            &limits,
        ))
        .await;
        assert_eq!(table.len(), 15);
        assert_eq!(table[9].0, "10.0.1.10");
        assert_eq!(table[10].0, "10.0.2.1");
        assert!(table.iter().all(|(_, tags)| tags == &["feed"]));
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    // A URL pointed at the wrong document: its lines are counted, a few are
    // quoted short, and none of them become entries.
    #[test]
    fn rejected_lines_are_counted_and_sampled_not_kept() {
        let junk = "x".repeat(10_000);
        let text = format!("{}10.0.0.1\n", format!("{junk}\n").repeat(50));
        let parsed = parse_feed_text(&text, FEED_MAX_ENTRIES);
        assert_eq!(parsed.entries, ["10.0.0.1"]);
        assert_eq!(parsed.rejected, 50);
        assert_eq!(parsed.rejected_samples.len(), FEED_LOG_SAMPLES);
        assert!(parsed
            .rejected_samples
            .iter()
            .all(|s| s.chars().count() <= FEED_SAMPLE_CHARS + 1));
    }
}
