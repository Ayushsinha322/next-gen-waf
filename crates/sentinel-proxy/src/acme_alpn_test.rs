//! TLS-ALPN-01 validation against the public SNI listener's real TLS config.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection,
    SignatureScheme,
};

use crate::tls::cert_store::{load_pem_bytes, CertStore};
use crate::tls::SentinelCertResolver;

#[derive(Debug)]
struct AcceptAny;
impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Runs a handshake offering only `acme-tls/1`, as a CA's validator does.
/// Returns the negotiated protocol and the presented leaf, or the error.
fn validate(server_cfg: ServerConfig) -> Result<(Option<Vec<u8>>, Vec<u8>), rustls::Error> {
    let mut client_cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    client_cfg.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    let name = ServerName::try_from("example.org").unwrap();
    let mut client = ClientConnection::new(Arc::new(client_cfg), name).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_cfg)).unwrap();
    for _ in 0..10 {
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        let mut wire = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut wire).unwrap();
        }
        let mut rd = wire.as_slice();
        while !rd.is_empty() {
            server.read_tls(&mut rd).unwrap();
            server.process_new_packets()?;
        }
        let mut wire = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut wire).unwrap();
        }
        let mut rd = wire.as_slice();
        while !rd.is_empty() {
            client.read_tls(&mut rd).unwrap();
            client.process_new_packets()?;
        }
    }
    let leaf = client
        .peer_certificates()
        .map(|c| c[0].as_ref().to_vec())
        .unwrap_or_default();
    Ok((client.alpn_protocol().map(|p| p.to_vec()), leaf))
}

#[test]
fn a_tls_alpn_01_validation_gets_the_challenge_cert() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let dir = std::env::temp_dir().join(format!("sk-alpn-{}", std::process::id()));
    let store = CertStore::new(dir);
    let challenge = rcgen::generate_simple_self_signed(vec!["example.org".to_string()]).unwrap();
    let ck = load_pem_bytes(
        challenge.serialize_pem().unwrap().as_bytes(),
        challenge.serialize_private_key_pem().as_bytes(),
    )
    .unwrap();
    let challenge_leaf = ck.cert[0].as_ref().to_vec();
    store.set_alpn_challenge("example.org", ck);

    // 1.1.16's list: the validator's only protocol is not offered, so the
    // handshake fails before the challenge cert can be presented.
    let mut old = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(SentinelCertResolver::new(Arc::clone(&store)));
    old.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    assert!(
        validate(old).is_err(),
        "the old ALPN list must refuse acme-tls/1"
    );

    let (alpn, leaf) = validate(crate::sni_listener_tls_config(SentinelCertResolver::new(
        Arc::clone(&store),
    )))
    .expect("the validation handshake must complete");
    assert_eq!(alpn.as_deref(), Some(&b"acme-tls/1"[..]));
    assert_eq!(
        leaf, challenge_leaf,
        "the validator must see the challenge cert"
    );
}
