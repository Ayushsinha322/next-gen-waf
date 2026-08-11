//! Does the configured `sni_name` actually reach the wire?
//!
//! The unit tests in `upstream.rs` prove the resolver returns the right name and
//! that the registry is built and torn down correctly. They do NOT prove that
//! hyper-rustls asks the resolver at all — that depends on
//! `with_server_name_resolver` being called at the right point in a typestate
//! builder chain, which compiles just as happily in the wrong place.
//!
//! So this test runs a real TLS listener that records the SNI from the incoming
//! ClientHello and asserts on it. The handshake afterwards is EXPECTED to fail:
//! the connector trusts webpki roots and the listener holds a self-signed cert,
//! so verification cannot succeed. That is fine and is the point — the assertion
//! is on what the client sent, which happens before verification.

use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// Records the server name from each ClientHello it sees.
#[derive(Debug)]
struct SniRecorder {
    seen: Arc<Mutex<Vec<Option<String>>>>,
    certified: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for SniRecorder {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.seen
            .lock()
            .unwrap()
            .push(hello.server_name().map(str::to_string));
        Some(Arc::clone(&self.certified))
    }
}

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["irrelevant.test".to_string()])
        .expect("generate self-signed cert");
    let der = CertificateDer::from(cert.serialize_der().expect("serialize cert"));
    let key = PrivateKeyDer::try_from(cert.serialize_private_key_der()).expect("key");
    (der, key)
}

/// Start a TLS listener that records SNI. Returns its port and the shared log.
async fn start_sni_recording_tls_server() -> (u16, Arc<Mutex<Vec<Option<String>>>>) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (cert, key) = self_signed();
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).expect("signing key");
    let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![cert], signing_key));

    let seen: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let resolver = Arc::new(SniRecorder {
        seen: Arc::clone(&seen),
        certified,
    });

    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // The handshake is driven far enough for the ClientHello (and so
                // the resolver) to be processed. It then fails verification on the
                // client side, which we neither need nor assert on.
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let _ = tls.shutdown().await;
                }
            });
        }
    });

    (port, seen)
}

/// The `sni_name` override must appear in the ClientHello.
#[tokio::test]
async fn configured_sni_name_is_sent_in_the_client_hello() {
    let (port, seen) = start_sni_recording_tls_server().await;

    let cfg = sentinel_core::config::SentinelConfig {
        sites: vec![site_with_sni(port, Some("app.internal"))],
        ..Default::default()
    };
    let pool = sentinel_proxy::upstream::UpstreamPool::from_config(&cfg);

    // Failure is expected (self-signed cert vs webpki roots); we assert on SNI.
    let _ = send_probe(&pool, port).await;

    let recorded = seen.lock().unwrap().clone();
    assert!(
        !recorded.is_empty(),
        "the TLS listener saw no ClientHello — the request never reached it, so this \
         test proves nothing about SNI"
    );
    assert_eq!(
        recorded[0].as_deref(),
        Some("app.internal"),
        "the configured sni_name must be the server name presented on the wire"
    );
}

/// Without an override the upstream host is presented — and for a bare IP that
/// means NO SNI at all, which is exactly why the override exists.
#[tokio::test]
async fn without_an_override_an_ip_origin_sends_no_sni() {
    let (port, seen) = start_sni_recording_tls_server().await;

    let cfg = sentinel_core::config::SentinelConfig {
        sites: vec![site_with_sni(port, None)],
        ..Default::default()
    };
    let pool = sentinel_proxy::upstream::UpstreamPool::from_config(&cfg);
    let _ = send_probe(&pool, port).await;

    let recorded = seen.lock().unwrap().clone();
    assert!(!recorded.is_empty(), "no ClientHello reached the listener");
    assert_eq!(
        recorded[0], None,
        "TLS forbids an IP literal as a server name, so an IP-addressed origin must \
         receive no SNI — this is the behaviour sni_name is there to fix"
    );
}

fn site_with_sni(port: u16, sni: Option<&str>) -> sentinel_core::config::SiteConfig {
    use sentinel_core::config::*;
    SiteConfig {
        id: "sni-site".into(),
        tenant_id: String::new(),
        domains: vec!["sni-site.local".into()],
        upstream: UpstreamConfig {
            load_balancer: LoadBalancerStrategy::RoundRobin,
            // Bare IP on purpose: the no-override case must show "no SNI".
            servers: vec![UpstreamServer {
                host: "127.0.0.1".into(),
                port,
                weight: 1,
                tls: true,
            }],
            health_check: None,
            timeout_secs: Some(5),
            websocket: false,
            host_header: None,
            keepalive: true,
            connect_timeout_secs: None,
            sni_name: sni.map(str::to_string),
        },
        waf: WafConfig::default(),
        plugins: vec![],
        tls: Default::default(),
        origin: Default::default(),
    }
}

async fn send_probe(
    pool: &sentinel_proxy::upstream::UpstreamPool,
    port: u16,
) -> anyhow::Result<()> {
    use http_body_util::BodyExt as _;
    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(format!("https://127.0.0.1:{port}/"))
        .header(http::header::HOST, "sni-site.local")
        .body(
            http_body_util::Empty::<bytes::Bytes>::new()
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )?;
    pool.send_request("sni-site", "127.0.0.1", port, req)
        .await?;
    Ok(())
}
