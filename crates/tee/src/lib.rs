//! Abstractions over the parts that depend on the TEE (AWS Nitro Enclaves).
//!
//! The early phase runs without a TEE, so the `insecure-mock` feature provides mock implementations.
//! The mocks do not protect secrets, so never enable them in production builds.

use std::future::Future;
use std::io;

use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "insecure-mock")]
pub mod mock;

#[cfg(feature = "nitro")]
pub mod kms;

#[cfg(all(feature = "nitro", target_os = "linux"))]
pub mod nsm;

#[cfg(feature = "attest-verify")]
pub mod verify;

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error("sealed secret not found: {0}")]
    NotFound(String),
    #[error("sealed storage failure: {0}")]
    Storage(String),
    #[error("attestation failure: {0}")]
    Attestation(String),
}

/// Stores secrets (such as share B) in a form that cannot be read outside the enclave.
pub trait SealedStorage: Send + Sync {
    fn seal(&self, label: &str, secret: &SecretSlice<u8>) -> Result<(), TeeError>;
    fn unseal(&self, label: &str) -> Result<SecretSlice<u8>, TeeError>;
    fn exists(&self, label: &str) -> bool;
    /// The names that are stored.
    fn labels(&self) -> Result<Vec<String>, TeeError>;
}

/// Return the names of the files in `dir` ending in `suffix` (without the `suffix`).
#[cfg(any(feature = "insecure-mock", feature = "nitro"))]
pub(crate) fn labels_in(dir: &std::path::Path, suffix: &str) -> Result<Vec<String>, TeeError> {
    let entries = std::fs::read_dir(dir).map_err(|e| TeeError::Storage(e.to_string()))?;
    let mut labels = Vec::new();
    for entry in entries {
        let name = entry
            .map_err(|e| TeeError::Storage(e.to_string()))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if let Some(label) = name.strip_suffix(suffix) {
            labels.push(label.to_owned());
        }
    }
    labels.sort();
    Ok(labels)
}

/// An attestation document before verification.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationDocument {
    /// "aws-nitro", "insecure-mock", ...
    pub format: String,
    pub bytes: Vec<u8>,
}

/// The expected measurements of the enclave image (PCR0..2 on Nitro).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedMeasurement {
    pub pcrs: Vec<Vec<u8>>,
}

/// Values taken from an attestation that passed verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub pcrs: Vec<Vec<u8>>,
    /// Data embedded at request time (the hash of the TLS public key, the nonce)
    pub user_data: Vec<u8>,
}

/// Issues the enclave's own attestation document from inside the enclave.
///
/// `user_data` holds values to bind to the document, such as the hash of the TLS certificate.
/// `nonce` is chosen by the verifier and prevents reuse.
pub trait Attestor: Send + Sync {
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<AttestationDocument, TeeError>;
}

/// The user app or A verifies B's attestation.
pub trait AttestationVerifier: Send + Sync {
    fn verify(
        &self,
        document: &AttestationDocument,
        expected: &ExpectedMeasurement,
    ) -> Result<VerifiedAttestation, TeeError>;
}

/// Opens a bidirectional stream between A and B (the connecting side).
///
/// In production it carries rustls mTLS, and after moving to Nitro it goes through the parent instance's vsock-TCP relay.
pub trait Connector: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// Accepts a bidirectional stream between A and B (the listening side).
pub trait Listener: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn accept(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}
