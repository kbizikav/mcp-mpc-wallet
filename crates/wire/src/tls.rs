//! A↔B 間の mTLS。
//!
//! デプロイごとに専用の CA を作り、B のサーバ証明書と A のクライアント証明書を発行する。
//! CA の秘密鍵は発行後に捨てるので、あとから証明書を増やすことはできない。
//! Nitro 移行後は、B の証明書を attestation に結びつける(M4 では未実装)。

use std::path::Path;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

/// B のサーバ証明書の名前
pub const SERVER_NAME: &str = "mw-node-b";

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("certificate generation: {0}")]
    Generate(#[from] rcgen::Error),
    #[error("reading {path}: {message}")]
    Read { path: String, message: String },
    #[error("writing {path}: {source}")]
    Write {
        path: String,
        source: std::io::Error,
    },
    #[error("TLS configuration: {0}")]
    Config(String),
}

/// 生成した PKI。鍵は PEM 文字列。
pub struct Pki {
    pub ca_pem: String,
    pub node_b_cert_pem: String,
    pub node_b_key_pem: String,
    pub node_a_cert_pem: String,
    pub node_a_key_pem: String,
}

pub fn generate_pki() -> Result<Pki, TlsError> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mcp-mpc-wallet deployment CA");
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf = |name: &str| -> Result<(String, String), TlsError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![name.to_owned()])?;
        params.distinguished_name.push(DnType::CommonName, name);
        let cert = params.signed_by(&key, &issuer)?;
        Ok((cert.pem(), key.serialize_pem()))
    };
    let (node_b_cert_pem, node_b_key_pem) = leaf(SERVER_NAME)?;
    let (node_a_cert_pem, node_a_key_pem) = leaf("mw-node-a")?;
    Ok(Pki {
        ca_pem: ca_cert.pem(),
        node_b_cert_pem,
        node_b_key_pem,
        node_a_cert_pem,
        node_a_key_pem,
    })
}

fn write_file(dir: &Path, name: &str, contents: &str, secret: bool) -> Result<(), TlsError> {
    let path = dir.join(name);
    let err = |source| TlsError::Write {
        path: path.display().to_string(),
        source,
    };
    std::fs::write(&path, contents).map_err(err)?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(err)?;
    }
    #[cfg(not(unix))]
    let _ = secret;
    Ok(())
}

impl Pki {
    /// B 用と A 用のディレクトリに分けて書き出す。
    pub fn write(&self, node_b_dir: &Path, node_a_dir: &Path) -> Result<(), TlsError> {
        for dir in [node_b_dir, node_a_dir] {
            std::fs::create_dir_all(dir).map_err(|source| TlsError::Write {
                path: dir.display().to_string(),
                source,
            })?;
            write_file(dir, "ca.pem", &self.ca_pem, false)?;
        }
        write_file(node_b_dir, "node-b.pem", &self.node_b_cert_pem, false)?;
        write_file(node_b_dir, "node-b.key", &self.node_b_key_pem, true)?;
        write_file(node_a_dir, "node-a.pem", &self.node_a_cert_pem, false)?;
        write_file(node_a_dir, "node-a.key", &self.node_a_key_pem, true)?;
        Ok(())
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn roots(ca_pem: &str) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        let cert = cert.map_err(|e| TlsError::Config(e.to_string()))?;
        roots
            .add(cert)
            .map_err(|e| TlsError::Config(e.to_string()))?;
    }
    Ok(roots)
}

fn identity(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsError> {
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::Config(e.to_string()))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| TlsError::Config(e.to_string()))?;
    Ok((certs, key))
}

/// B 側: デプロイ CA が発行したクライアント証明書だけを受け付ける。
pub fn server_config(
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<ServerConfig>, TlsError> {
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots(ca_pem)?), provider())
            .build()
            .map_err(|e| TlsError::Config(e.to_string()))?;
    let (certs, key) = identity(cert_pem, key_pem)?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    Ok(Arc::new(config))
}

/// A 側: デプロイ CA が発行した B の証明書だけを信頼する。
pub fn client_config(
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<ClientConfig>, TlsError> {
    let (certs, key) = identity(cert_pem, key_pem)?;
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError::Config(e.to_string()))?
        .with_root_certificates(roots(ca_pem)?)
        .with_client_auth_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    Ok(Arc::new(config))
}

pub fn server_name() -> ServerName<'static> {
    ServerName::try_from(SERVER_NAME).expect("valid DNS name")
}

pub fn read_pem(path: &Path) -> Result<String, TlsError> {
    std::fs::read_to_string(path).map_err(|e| TlsError::Read {
        path: path.display().to_string(),
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;

    async fn handshake(server: Arc<ServerConfig>, client: Arc<ClientConfig>) -> bool {
        let (c, s) = tokio::io::duplex(64 * 1024);
        let accept = async move {
            let mut tls = match TlsAcceptor::from(server).accept(s).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("server: {e}");
                    return None;
                }
            };
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.ok()?;
            Some(buf)
        };
        let connect = async move {
            let mut tls = match TlsConnector::from(client).connect(server_name(), c).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("client: {e}");
                    return None;
                }
            };
            tls.write_all(b"ping").await.ok()?;
            tls.flush().await.ok()?;
            // サーバが読み終えるまで接続を閉じない
            Some(tls)
        };
        let (got, _client) = tokio::join!(accept, connect);
        got == Some(*b"ping")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mutual_tls_with_deployment_ca() {
        let pki = generate_pki().unwrap();
        let server = server_config(&pki.ca_pem, &pki.node_b_cert_pem, &pki.node_b_key_pem).unwrap();
        let client = client_config(&pki.ca_pem, &pki.node_a_cert_pem, &pki.node_a_key_pem).unwrap();
        assert!(handshake(server, client).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_client_from_another_deployment() {
        let ours = generate_pki().unwrap();
        let theirs = generate_pki().unwrap();
        let server =
            server_config(&ours.ca_pem, &ours.node_b_cert_pem, &ours.node_b_key_pem).unwrap();
        // 相手の CA が発行したクライアント証明書(サーバは正しく信頼している)
        let client = client_config(
            &ours.ca_pem,
            &theirs.node_a_cert_pem,
            &theirs.node_a_key_pem,
        )
        .unwrap();
        assert!(!handshake(server, client).await);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_impostor_server() {
        let ours = generate_pki().unwrap();
        let theirs = generate_pki().unwrap();
        let impostor = server_config(
            &ours.ca_pem,
            &theirs.node_b_cert_pem,
            &theirs.node_b_key_pem,
        )
        .unwrap();
        let client =
            client_config(&ours.ca_pem, &ours.node_a_cert_pem, &ours.node_a_key_pem).unwrap();
        assert!(!handshake(impostor, client).await);
    }

    #[test]
    fn writes_keys_with_restricted_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let (b, a) = (dir.path().join("b"), dir.path().join("a"));
        generate_pki().unwrap().write(&b, &a).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(b.join("node-b.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert!(!a.join("node-b.key").exists(), "A never gets B's key");
    }
}
