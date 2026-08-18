//! Backend connection layer (extracted from fast_proxy.rs 2026-08-16):
//! TLS connectors and the plain/TLS backend stream.

use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};
use monoio::io::{AsyncReadRent, AsyncWriteRent};
use monoio::net::TcpStream;
use monoio_rustls::ClientTlsStream;
use monoio_rustls::TlsConnector;
use std::sync::Arc;

pub(crate) enum BackendStream {
    Plain(TcpStream),
    Tls(Box<ClientTlsStream<TcpStream>>),
}

// Both variants delegate read/write straight through to an inner type (`TcpStream` /
// `monoio_rustls::stream::Stream`) that monoio/monoio-rustls already mark `Split`-safe
// (independent, concurrently-runnable read and write halves) — this thin dispatch adds no new
// shared mutable state, so the guarantee carries through unchanged.
unsafe impl monoio::io::Split for BackendStream {}

impl AsyncReadRent for BackendStream {
    fn read<T: IoBufMut>(
        &mut self,
        buf: T,
    ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
        async move {
            match self {
                BackendStream::Plain(s) => s.read(buf).await,
                BackendStream::Tls(s) => s.read(buf).await,
            }
        }
    }
    fn readv<T: IoVecBufMut>(
        &mut self,
        buf: T,
    ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
        async move {
            match self {
                BackendStream::Plain(s) => s.readv(buf).await,
                BackendStream::Tls(s) => s.readv(buf).await,
            }
        }
    }
}

impl AsyncWriteRent for BackendStream {
    fn write<T: IoBuf>(
        &mut self,
        buf: T,
    ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
        async move {
            match self {
                BackendStream::Plain(s) => s.write(buf).await,
                BackendStream::Tls(s) => s.write(buf).await,
            }
        }
    }
    fn writev<T: IoVecBuf>(
        &mut self,
        buf_vec: T,
    ) -> impl std::future::Future<Output = monoio::BufResult<usize, T>> {
        async move {
            match self {
                BackendStream::Plain(s) => s.writev(buf_vec).await,
                BackendStream::Tls(s) => s.writev(buf_vec).await,
            }
        }
    }
    fn flush(&mut self) -> impl std::future::Future<Output = std::io::Result<()>> {
        async move {
            match self {
                BackendStream::Plain(s) => s.flush().await,
                BackendStream::Tls(s) => s.flush().await,
            }
        }
    }
    fn shutdown(&mut self) -> impl std::future::Future<Output = std::io::Result<()>> {
        async move {
            match self {
                BackendStream::Plain(s) => s.shutdown().await,
                BackendStream::Tls(s) => s.shutdown().await,
            }
        }
    }
}

/// A `ServerCertVerifier` that accepts any certificate chain outright — backs the per-backend
/// `tls_skip_verify` escape hatch for internal backends with a self-signed/private-CA cert that
/// isn't in the OS root store. The handshake signature itself is still checked (proves the peer
/// holds the private key for the cert it presented); only the trust-chain/hostname checks are
/// skipped. This is the standard shape recommended by rustls itself for a "danger" verifier — see
/// `rustls::client::danger::ServerCertVerifier`'s own docs — not an ad hoc bypass.
#[derive(Debug)]
struct NoCertVerification(rustls::crypto::CryptoProvider);

impl rustls::client::danger::ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub(crate) fn build_backend_tls_connector(skip_verify: bool) -> TlsConnector {
    if skip_verify {
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let verifier = Arc::new(NoCertVerification(provider));
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        return TlsConnector::from(Arc::new(config));
    }
    let mut roots = rustls::RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for err in &loaded.errors {
        tracing::warn!("native cert store: {}", err);
    }
    let (added, _ignored) = roots.add_parsable_certificates(loaded.certs);
    if added == 0 {
        tracing::warn!("no native root certificates loaded — upstream TLS backend verification will fail closed");
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

thread_local! {
    // Built once per worker thread (prefork model, one thread per worker) and cloned per
    // connection — `TlsConnector` is a cheap `Arc<ClientConfig>` handle. Kept as two separate
    // slots (rather than one keyed by bool) so the borrow pattern below can't accidentally
    // overlap a `Ref` with a `RefMut` on the same cell — see the explicit inner block in
    // `backend_tls_connector`. Sharing one connector across every skip_verify=false backend is
    // correct, not stale: there is no per-backend CA config to diverge on (SNI/hostname
    // verification happens per-connection via `ServerName`, not baked into the connector), and
    // there is no config-reload path (grepped: none) for a cached OS trust store to go stale
    // against — a config change means a process restart, which gets a fresh thread_local anyway.
    static BACKEND_TLS_CONNECTOR_VERIFY: std::cell::RefCell<Option<TlsConnector>> = const { std::cell::RefCell::new(None) };
    static BACKEND_TLS_CONNECTOR_SKIP_VERIFY: std::cell::RefCell<Option<TlsConnector>> = const { std::cell::RefCell::new(None) };
}

pub(crate) fn backend_tls_connector(skip_verify: bool) -> TlsConnector {
    if skip_verify {
        BACKEND_TLS_CONNECTOR_SKIP_VERIFY.with(|slot| {
            // Explicit block: the `Ref` this creates is dropped at its closing brace, before
            // `borrow_mut()` below ever runs on the cache-miss path — no overlap is possible.
            {
                if let Some(c) = slot.borrow().as_ref() {
                    return c.clone();
                }
            }
            let connector = build_backend_tls_connector(true);
            *slot.borrow_mut() = Some(connector.clone());
            connector
        })
    } else {
        BACKEND_TLS_CONNECTOR_VERIFY.with(|slot| {
            {
                if let Some(c) = slot.borrow().as_ref() {
                    return c.clone();
                }
            }
            let connector = build_backend_tls_connector(false);
            *slot.borrow_mut() = Some(connector.clone());
            connector
        })
    }
}

/// Connect to a backend, upgrading to TLS when `be.tls` (i.e. the config used an `https://`
/// host). `be.tls_skip_verify` (opt-in, default off) swaps in a verifier that accepts any
/// certificate — for internal backends with a self-signed/private-CA cert. On any failure
/// (connect, handshake, bad SNI name) returns `None`, which callers treat exactly like a plain
/// connect failure (skip/retry backend, eventual 502) — never falls back to cleartext.
pub(crate) async fn connect_backend(
    be: &crate::config::Backend,
    timeout_sec: u64,
) -> Option<BackendStream> {
    let tcp = match monoio::time::timeout(
        std::time::Duration::from_secs(timeout_sec),
        TcpStream::connect(&be.addr),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    let _ = tcp.set_nodelay(true);
    if !be.tls {
        return Some(BackendStream::Plain(tcp));
    }
    let domain = rustls::pki_types::ServerName::try_from(be.host.clone()).ok()?;
    let connector = backend_tls_connector(be.tls_skip_verify);
    match monoio::time::timeout(
        std::time::Duration::from_secs(timeout_sec),
        connector.connect(domain, tcp),
    )
    .await
    {
        Ok(Ok(tls)) => Some(BackendStream::Tls(Box::new(tls))),
        _ => None,
    }
}
