//! TEE なしで動かすためのモック。秘密を守らないので開発・テスト専用。

use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};
use tokio::io::DuplexStream;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use crate::{
    AttestationDocument, AttestationVerifier, Attestor, Connector, ExpectedMeasurement, Listener,
    SealedStorage, TeeError, VerifiedAttestation,
};

const MOCK_FORMAT: &str = "insecure-mock";

/// メモリに平文で置くだけの SealedStorage。
#[derive(Default)]
pub struct InsecureMemoryStorage {
    secrets: Mutex<HashMap<String, Vec<u8>>>,
}

impl SealedStorage for InsecureMemoryStorage {
    fn seal(&self, label: &str, secret: &SecretSlice<u8>) -> Result<(), TeeError> {
        self.secrets
            .lock()
            .map_err(|_| TeeError::Storage("poisoned".into()))?
            .insert(label.to_owned(), secret.expose_secret().to_vec());
        Ok(())
    }

    fn unseal(&self, label: &str) -> Result<SecretSlice<u8>, TeeError> {
        self.secrets
            .lock()
            .map_err(|_| TeeError::Storage("poisoned".into()))?
            .get(label)
            .map(|bytes| SecretSlice::from(bytes.clone()))
            .ok_or_else(|| TeeError::NotFound(label.to_owned()))
    }
}

/// ファイルに平文で置く SealedStorage(TEE なしで B を動かす開発用)。
///
/// ファイルは所有者だけが読める権限で作る。秘密は守られないので本番で使ってはいけない。
pub struct InsecureFileStorage {
    dir: std::path::PathBuf,
}

impl InsecureFileStorage {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Result<Self, TeeError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| TeeError::Storage(e.to_string()))?;
        Ok(Self { dir })
    }

    fn path(&self, label: &str) -> Result<std::path::PathBuf, TeeError> {
        if label.is_empty() || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(TeeError::Storage(format!("invalid label {label:?}")));
        }
        Ok(self.dir.join(format!("{label}.sealed")))
    }

    pub fn exists(&self, label: &str) -> bool {
        self.path(label).is_ok_and(|p| p.exists())
    }
}

impl SealedStorage for InsecureFileStorage {
    fn seal(&self, label: &str, secret: &SecretSlice<u8>) -> Result<(), TeeError> {
        use std::io::Write;
        let path = self.path(label)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options
            .open(&path)
            .map_err(|e| TeeError::Storage(format!("{}: {e}", path.display())))?;
        file.write_all(secret.expose_secret())
            .and_then(|()| file.sync_all())
            .map_err(|e| TeeError::Storage(e.to_string()))
    }

    fn unseal(&self, label: &str) -> Result<SecretSlice<u8>, TeeError> {
        let path = self.path(label)?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(SecretSlice::from(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(TeeError::NotFound(label.to_owned()))
            }
            Err(e) => Err(TeeError::Storage(e.to_string())),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct MockDocument {
    pcrs: Vec<Vec<u8>>,
    user_data: Vec<u8>,
}

/// 署名なしの attestation document を発行する。
pub struct InsecureMockAttestor {
    pub pcrs: Vec<Vec<u8>>,
}

impl Attestor for InsecureMockAttestor {
    fn attest(&self, user_data: &[u8]) -> Result<AttestationDocument, TeeError> {
        let document = MockDocument {
            pcrs: self.pcrs.clone(),
            user_data: user_data.to_vec(),
        };
        Ok(AttestationDocument {
            format: MOCK_FORMAT.into(),
            bytes: serde_json::to_vec(&document)
                .map_err(|e| TeeError::Attestation(e.to_string()))?,
        })
    }
}

/// モックの document を、測定値の一致だけで受け入れる検証器。
pub struct InsecureMockVerifier;

impl AttestationVerifier for InsecureMockVerifier {
    fn verify(
        &self,
        document: &AttestationDocument,
        expected: &ExpectedMeasurement,
    ) -> Result<VerifiedAttestation, TeeError> {
        if document.format != MOCK_FORMAT {
            return Err(TeeError::Attestation(format!(
                "unsupported format {:?}",
                document.format
            )));
        }
        let parsed: MockDocument = serde_json::from_slice(&document.bytes)
            .map_err(|e| TeeError::Attestation(e.to_string()))?;
        if parsed.pcrs != expected.pcrs {
            return Err(TeeError::Attestation("measurement mismatch".into()));
        }
        Ok(VerifiedAttestation {
            pcrs: parsed.pcrs,
            user_data: parsed.user_data,
        })
    }
}

const DUPLEX_BUFFER: usize = 64 * 1024;

/// プロセス内でつながる Connector / Listener の組を作る。
pub fn in_memory_transport() -> (InMemoryConnector, InMemoryListener) {
    let (tx, rx) = mpsc::channel(16);
    (
        InMemoryConnector { tx },
        InMemoryListener {
            rx: AsyncMutex::new(rx),
        },
    )
}

pub struct InMemoryConnector {
    tx: mpsc::Sender<DuplexStream>,
}

pub struct InMemoryListener {
    rx: AsyncMutex<mpsc::Receiver<DuplexStream>>,
}

impl Connector for InMemoryConnector {
    type Stream = DuplexStream;

    async fn connect(&self) -> io::Result<DuplexStream> {
        let (client, server) = tokio::io::duplex(DUPLEX_BUFFER);
        self.tx
            .send(server)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionRefused, "listener closed"))?;
        Ok(client)
    }
}

impl Listener for InMemoryListener {
    type Stream = DuplexStream;

    async fn accept(&self) -> io::Result<DuplexStream> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "all connectors dropped"))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn sealed_storage_round_trip() {
        let storage = InsecureMemoryStorage::default();
        storage
            .seal("share-b", &SecretSlice::from(vec![1, 2, 3]))
            .unwrap();
        assert_eq!(
            storage.unseal("share-b").unwrap().expose_secret(),
            &[1, 2, 3]
        );
        assert!(matches!(
            storage.unseal("missing"),
            Err(TeeError::NotFound(_))
        ));
    }

    #[test]
    fn file_storage_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("mw-tee-test-{}", std::process::id()));
        let storage = InsecureFileStorage::new(&dir).unwrap();
        storage
            .seal("share-b", &SecretSlice::from(vec![9]))
            .unwrap();
        assert!(
            storage
                .seal("share-b", &SecretSlice::from(vec![8]))
                .is_err()
        );
        assert_eq!(storage.unseal("share-b").unwrap().expose_secret(), &[9]);
        assert!(
            storage
                .seal("../escape", &SecretSlice::from(vec![1]))
                .is_err()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn verifier_checks_measurement() {
        let attestor = InsecureMockAttestor {
            pcrs: vec![vec![0xaa; 48]],
        };
        let document = attestor.attest(b"tls-key-hash").unwrap();

        let ok = InsecureMockVerifier
            .verify(
                &document,
                &ExpectedMeasurement {
                    pcrs: vec![vec![0xaa; 48]],
                },
            )
            .unwrap();
        assert_eq!(ok.user_data, b"tls-key-hash");

        assert!(
            InsecureMockVerifier
                .verify(
                    &document,
                    &ExpectedMeasurement {
                        pcrs: vec![vec![0xbb; 48]],
                    },
                )
                .is_err()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn in_memory_transport_connects() {
        let (connector, listener) = in_memory_transport();
        let (client, server) = tokio::join!(connector.connect(), listener.accept());
        let (mut client, mut server) = (client.unwrap(), server.unwrap());

        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
    }
}
