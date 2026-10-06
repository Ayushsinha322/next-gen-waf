//! Deadlines for the data plane's calls to the control plane.
//!
//! Config sync, plugin sync, threat-intel sync and the heartbeat each run a loop
//! that awaits one control-plane call per tick. None of those calls had a
//! deadline and the connector had no connect timeout, so a control plane that
//! accepted the connection and never answered (a wedged process, a pooled
//! connection left half-open by a restart or a VIP move) parked the loop on that
//! await for good. Nothing recorded it either: the failure paths only ran when
//! the call RETURNED, so the heartbeat kept describing the last sync that worked
//! while this node's config, plugins and IOC set stopped moving.
//!
//! Every such call now goes through [`call`], whose deadline covers the request
//! and the whole body, and a timeout comes back as an ordinary error that the
//! loop records and moves past like any other failed poll.

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use hyper::body::Body;
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::TokioExecutor;

/// TCP connect to the control plane. It sits on the private network, so a
/// handshake that has not completed by now is not going to, and failing here
/// keeps a long deadline (a wasm download) from being spent on the connect.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Probe a pooled connection idle this long, so one left half-open by a
/// control-plane restart is reaped instead of handed to the next poll.
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE_RETRIES: u32 = 3;

/// One config-sync poll, request plus body.
/// Env override: `SENTINEL_CP_CONFIG_TIMEOUT_SECS`.
pub(crate) const CONFIG_SYNC_DEADLINE: Duration = Duration::from_secs(10);
/// The threat-intel response is the whole IOC corpus (100k+ indicators), so it
/// gets longer. Env override: `SENTINEL_CP_THREAT_INTEL_TIMEOUT_SECS`.
pub(crate) const THREAT_INTEL_SYNC_DEADLINE: Duration = Duration::from_secs(30);
/// The plugin listing is a small digest of names and hashes.
/// Env override: `SENTINEL_CP_PLUGIN_LIST_TIMEOUT_SECS`.
pub(crate) const PLUGIN_LIST_DEADLINE: Duration = Duration::from_secs(10);
/// One plugin module, which can run to several megabytes.
/// Env override: `SENTINEL_CP_PLUGIN_WASM_TIMEOUT_SECS`.
pub(crate) const PLUGIN_WASM_DEADLINE: Duration = Duration::from_secs(60);
/// Heartbeats go every 10 s; one still unanswered after 5 s is lost anyway.
/// Env override: `SENTINEL_CP_HEARTBEAT_TIMEOUT_SECS`.
pub(crate) const HEARTBEAT_DEADLINE: Duration = Duration::from_secs(5);

/// `default`, or a positive whole number of seconds from the env var `var`.
pub(crate) fn deadline(var: &str, default: Duration) -> Duration {
    parse_deadline(std::env::var(var).ok().as_deref(), default)
}

fn parse_deadline(value: Option<&str>, default: Duration) -> Duration {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .map(Duration::from_secs)
        .unwrap_or(default)
}

pub(crate) type CpClient<B> = Client<HttpConnector, B>;

/// The client every control-plane loop uses: plain HTTP on the private network,
/// a bounded connect, and TCP keepalive on pooled connections.
pub(crate) fn client<B>() -> CpClient<B>
where
    B: Body + Send,
    B::Data: Send,
{
    client_with_connect_timeout(CONNECT_TIMEOUT)
}

fn client_with_connect_timeout<B>(connect_timeout: Duration) -> CpClient<B>
where
    B: Body + Send,
    B::Data: Send,
{
    let mut http = HttpConnector::new();
    http.set_connect_timeout(Some(connect_timeout));
    http.set_keepalive(Some(TCP_KEEPALIVE_IDLE));
    http.set_keepalive_interval(Some(TCP_KEEPALIVE_INTERVAL));
    http.set_keepalive_retries(Some(TCP_KEEPALIVE_RETRIES));
    Client::builder(TokioExecutor::new()).build(http)
}

/// Why a control-plane call produced no complete response. `Display` keeps the
/// `fetch:` / `body:` prefixes config sync always recorded, so a timeout reads
/// in the heartbeat's `config_sync.last_error` like any other failed poll.
#[derive(Debug)]
pub(crate) enum CallError {
    Fetch(hyper_util::client::legacy::Error),
    Body(hyper::Error),
    Timeout(Duration),
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallError::Fetch(e) => {
                f.write_str("fetch: ")?;
                write_chain(f, e)
            }
            CallError::Body(e) => {
                f.write_str("body: ")?;
                write_chain(f, e)
            }
            CallError::Timeout(d) => write!(f, "timeout: no complete response within {d:?}"),
        }
    }
}

/// `e` and every cause beneath it, joined with ": ".
///
/// hyper-util's own message is only the error kind, so a refused connection, a
/// failed DNS lookup and the connect timeout all read `client error (Connect)`;
/// what actually happened is one or two causes down. No layer of this chain
/// carries the peer's address (hyper-util keeps that to `Debug`), so the text is
/// fit for `/healthz`.
fn write_chain(f: &mut fmt::Formatter<'_>, e: &(dyn std::error::Error + 'static)) -> fmt::Result {
    let mut last = e.to_string();
    f.write_str(&last)?;
    let mut cause = e.source();
    while let Some(c) = cause {
        let msg = c.to_string();
        // A layer that already prints its cause would otherwise say it twice.
        if !last.contains(&msg) {
            write!(f, ": {msg}")?;
        }
        last = msg;
        cause = c.source();
    }
    Ok(())
}

/// Send `req` and read the whole response body, all within `deadline`.
///
/// The deadline covers the body as well as the head: a control plane that sends
/// headers and then stalls holds a loop exactly as long as one that never
/// answers. Any status is returned as-is; judging it is the caller's job.
pub(crate) async fn call<B>(
    client: &CpClient<B>,
    req: Request<B>,
    deadline: Duration,
) -> Result<(StatusCode, Bytes), CallError>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let exchange = async {
        let resp = client.request(req).await.map_err(CallError::Fetch)?;
        let status = resp.status();
        let body = resp.into_body().collect().await.map_err(CallError::Body)?;
        Ok((status, body.to_bytes()))
    };
    // Dropping the timed-out exchange drops its connection with it, so a wedged
    // socket is not handed back to the pool for the next tick.
    tokio::time::timeout(deadline, exchange)
        .await
        .unwrap_or(Err(CallError::Timeout(deadline)))
}

/// Stand-in control planes for the deadline tests, here and in `lib.rs`.
#[cfg(test)]
pub(crate) mod stub {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    /// Accepts every connection and never sends a byte: the wedged control
    /// plane. Sockets are held until the test's runtime shuts down.
    pub(crate) async fn silent() -> SocketAddr {
        answering_after(usize::MAX, 200, "").await
    }

    /// Holds its first `silent_first` connections without answering, then
    /// answers every later one with `status` and `body` and closes it.
    pub(crate) async fn answering_after(
        silent_first: usize,
        status: u16,
        body: &'static str,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            for n in 0usize.. {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                if n < silent_first {
                    held.push(sock);
                    continue;
                }
                tokio::spawn(async move {
                    read_head(&mut sock).await;
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        addr
    }

    /// Answers with a head promising 1000 bytes, sends ten, and stalls.
    pub(crate) async fn stalls_mid_body() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((mut sock, _)) = listener.accept().await {
                read_head(&mut sock).await;
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n{\"version\"")
                    .await;
                held.push(sock);
            }
        });
        addr
    }

    /// A listener whose accept queue is full, so the kernel drops the SYN of the
    /// next connect and that connect hangs: a black-holed control plane on
    /// loopback. Keep the returned values alive for as long as it is needed.
    pub(crate) fn unconnectable() -> (
        SocketAddr,
        tokio::net::TcpListener,
        Vec<std::net::TcpStream>,
    ) {
        let sock = tokio::net::TcpSocket::new_v4().unwrap();
        sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = sock.listen(0).unwrap();
        let addr = listener.local_addr().unwrap();
        // Fill the queue until a connect stops completing; the backlog actually
        // granted for `listen(0)` is the kernel's business.
        let mut fill = Vec::new();
        for _ in 0..16 {
            match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(250))
            {
                Ok(s) => fill.push(s),
                Err(_) => break,
            }
        }
        (addr, listener, fill)
    }

    async fn read_head(sock: &mut tokio::net::TcpStream) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    type Empty = http_body_util::Empty<Bytes>;

    /// Short enough to keep the suite fast, long enough that loopback never
    /// trips it on a healthy exchange.
    const DEADLINE: Duration = Duration::from_millis(300);
    /// How long a test waits before declaring the call hung. Without a
    /// deadline the call never returns, and this is what turns that into a
    /// failure instead of a test that never finishes.
    const HUNG: Duration = Duration::from_secs(5);

    fn get(addr: std::net::SocketAddr) -> Request<Empty> {
        Request::get(format!("http://{addr}/api/v1/internal/config"))
            .body(Empty::new())
            .unwrap()
    }

    async fn call_or_hang(
        client: &CpClient<Empty>,
        addr: std::net::SocketAddr,
        deadline: Duration,
    ) -> Result<(StatusCode, Bytes), CallError> {
        tokio::time::timeout(HUNG, call(client, get(addr), deadline))
            .await
            .expect("the control-plane call never returned: no deadline is bounding it")
    }

    /// The control plane accepts the connection and never answers. The call
    /// must come back as a timeout at the deadline, not park the caller.
    #[tokio::test]
    async fn a_control_plane_that_never_answers_times_out_at_the_deadline() {
        let addr = stub::silent().await;
        let client = client::<Empty>();
        let started = Instant::now();
        let err = call_or_hang(&client, addr, DEADLINE).await.unwrap_err();
        let took = started.elapsed();
        assert!(
            matches!(err, CallError::Timeout(d) if d == DEADLINE),
            "{err}"
        );
        assert!(took >= DEADLINE, "returned before the deadline: {took:?}");
        assert!(
            took < DEADLINE * 4,
            "took {took:?} for a {DEADLINE:?} deadline"
        );
        assert!(err.to_string().starts_with("timeout:"), "{err}");
    }

    /// A head and then nothing. The deadline has to cover the body as well, or
    /// this stalls the loop exactly like a control plane that never answers.
    #[tokio::test]
    async fn a_body_that_stalls_after_the_head_times_out_too() {
        let addr = stub::stalls_mid_body().await;
        let client = client::<Empty>();
        let err = call_or_hang(&client, addr, DEADLINE).await.unwrap_err();
        assert!(matches!(err, CallError::Timeout(_)), "{err}");
    }

    /// The loop's next tick, on the same client, after a timeout. The wedged
    /// connection must not be pooled and reused, or every later poll would
    /// time out against a control plane that has since recovered.
    #[tokio::test]
    async fn the_next_call_after_a_timeout_gets_a_fresh_connection() {
        let addr = stub::answering_after(1, 200, r#"{"version":7}"#).await;
        let client = client::<Empty>();
        let first = call_or_hang(&client, addr, DEADLINE).await;
        assert!(matches!(first, Err(CallError::Timeout(_))), "{first:?}");
        let (status, body) = call_or_hang(&client, addr, DEADLINE)
            .await
            .expect("the control plane answered the second connection");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], br#"{"version":7}"#);
    }

    /// A SYN that is never answered fails at the connect timeout, well inside
    /// a long call deadline, instead of spending the whole of it.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_connect_that_never_completes_fails_at_the_connect_timeout() {
        let (addr, _listener, _fill) = stub::unconnectable();
        let client = client_with_connect_timeout::<Empty>(Duration::from_millis(200));
        let started = Instant::now();
        let err = call_or_hang(&client, addr, Duration::from_secs(4))
            .await
            .unwrap_err();
        let took = started.elapsed();
        match &err {
            CallError::Fetch(e) => assert!(e.is_connect(), "{e:?}"),
            other => panic!("expected a connect failure, got {other}"),
        }
        assert!(took < Duration::from_secs(2), "connect took {took:?}");
    }

    /// The recorded error has to say WHICH connect failure it was. hyper-util's
    /// message is `client error (Connect)` for all of them, so a black-holed
    /// control plane (the connect timeout) read exactly like one that is down.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_connect_timeout_reads_differently_from_a_refused_connect() {
        let (black_holed, _listener, _fill) = stub::unconnectable();
        let client = client_with_connect_timeout::<Empty>(Duration::from_millis(200));
        let timed_out = call_or_hang(&client, black_holed, Duration::from_secs(4))
            .await
            .unwrap_err()
            .to_string();

        // A port nothing listens on: bound, then released.
        let down = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let refused = call_or_hang(&client, down, Duration::from_secs(4))
            .await
            .unwrap_err()
            .to_string();

        assert!(
            timed_out.starts_with("fetch: client error (Connect): tcp connect error: "),
            "{timed_out}"
        );
        assert!(timed_out.contains("deadline has elapsed"), "{timed_out}");
        assert!(
            refused.to_lowercase().contains("connection refused"),
            "{refused}"
        );
        assert_ne!(timed_out, refused);
        // Both reach the public /healthz, so neither may name the peer.
        for msg in [&timed_out, &refused] {
            assert!(!msg.contains("127.0.0.1"), "{msg}");
        }
    }

    /// An answering control plane is unaffected: status and whole body.
    #[tokio::test]
    async fn an_answering_control_plane_returns_status_and_body() {
        let addr = stub::answering_after(0, 403, r#"{"error":"forbidden"}"#).await;
        let client = client::<Empty>();
        let (status, body) = call_or_hang(&client, addr, DEADLINE).await.unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(&body[..], br#"{"error":"forbidden"}"#);
    }

    #[test]
    fn deadline_overrides_take_whole_positive_seconds_only() {
        let d = Duration::from_secs(10);
        assert_eq!(parse_deadline(None, d), d);
        assert_eq!(parse_deadline(Some("45"), d), Duration::from_secs(45));
        assert_eq!(parse_deadline(Some(" 45 "), d), Duration::from_secs(45));
        // Zero would mean "time out immediately", which no operator means.
        assert_eq!(parse_deadline(Some("0"), d), d);
        assert_eq!(parse_deadline(Some("1.5"), d), d);
        assert_eq!(parse_deadline(Some("ten"), d), d);
    }
}
