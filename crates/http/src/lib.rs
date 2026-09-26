//! HTTPS client for external APIs (RPC, Tenderly, OpenAI).
//!
//! Certificates are verified against the bundled Mozilla roots (webpki-roots), not the OS store,
//! because there is no OS certificate store inside a Nitro Enclave.

use std::sync::Arc;
use std::time::Duration;

/// Build an HTTPS-only rustls client that verifies with webpki-roots.
pub fn client(timeout: Duration) -> Result<reqwest::Client, String> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(true)
        .timeout(timeout)
        .build()
        .map_err(describe)
}

/// Turn a reqwest error, with its chain of causes, into a string without the URL.
///
/// The URL may contain an API key, so it must never appear in an error message.
pub fn describe(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut out = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_plain_http_without_leaking_url() {
        let client = client(Duration::from_secs(1)).unwrap();
        let err = client
            .get("http://127.0.0.1:9/v2/SECRET-KEY-123")
            .send()
            .await
            .unwrap_err();
        let message = describe(err);
        assert!(!message.contains("SECRET-KEY-123"), "{message}");
    }
}
