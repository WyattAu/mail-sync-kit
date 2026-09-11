//! TLS connector helpers: a rustls connector pinned to the
//! `webpki-roots` trust store, for hosts that do not bring their own
//! [`TlsConnector`].

use std::sync::Arc;

use tokio_rustls::TlsConnector;

/// Builds a [`TlsConnector`] trusting the bundled Mozilla root store
/// (`webpki-roots`). Hosts with custom PKI (private roots, client certs)
/// should build their own connector instead.
#[must_use]
pub fn webpki_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_builds_with_webpki_roots() {
        let _connector = webpki_connector();
    }
}
