//! 外部 API(RPC、Tenderly、OpenAI)用の HTTPS クライアント。
//!
//! 証明書は OS の証明書ストアではなく、同梱した Mozilla のルート(webpki-roots)で検証する。
//! Nitro Enclave の中には OS の証明書ストアがないため。

use std::sync::Arc;
use std::time::Duration;

/// HTTPS 専用で、webpki-roots で検証する rustls クライアントを作る。
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

/// reqwest のエラーを、URL を含めずに原因の連鎖まで文字列にする。
///
/// URL には API キーが含まれうるので、エラー文に出してはいけない。
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
