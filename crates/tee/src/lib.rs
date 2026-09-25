//! TEE(AWS Nitro Enclaves)に依存する部分の抽象化。
//!
//! 初期フェーズでは TEE なしで動かすため、`insecure-mock` feature でモック実装を提供する。
//! モックは秘密を守らないので、本番ビルドで有効にしてはいけない。

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

/// エンクレーブの外では読めない形で秘密(シェア B など)を保存する。
pub trait SealedStorage: Send + Sync {
    fn seal(&self, label: &str, secret: &SecretSlice<u8>) -> Result<(), TeeError>;
    fn unseal(&self, label: &str) -> Result<SecretSlice<u8>, TeeError>;
    fn exists(&self, label: &str) -> bool;
    /// 保存されている名前の一覧。
    fn labels(&self) -> Result<Vec<String>, TeeError>;
}

/// `dir` の中で `suffix` で終わるファイルの名前(`suffix` を除く)を返す。
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

/// 検証前の attestation document。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationDocument {
    /// "aws-nitro" や "insecure-mock" など
    pub format: String,
    pub bytes: Vec<u8>,
}

/// 期待するエンクレーブイメージの測定値(Nitro では PCR0..2)。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedMeasurement {
    pub pcrs: Vec<Vec<u8>>,
}

/// 検証を通った attestation から取り出した値。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub pcrs: Vec<Vec<u8>>,
    /// 要求時に埋め込んだデータ(TLS 公開鍵のハッシュや nonce)
    pub user_data: Vec<u8>,
}

/// エンクレーブ内で自分の attestation document を発行する。
///
/// `user_data` には TLS 証明書の hash など、document に結びつけたい値を入れる。
/// `nonce` は検証する側が決めた値で、使い回しを防ぐ。
pub trait Attestor: Send + Sync {
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<AttestationDocument, TeeError>;
}

/// ユーザーアプリや A が B の attestation を検証する。
pub trait AttestationVerifier: Send + Sync {
    fn verify(
        &self,
        document: &AttestationDocument,
        expected: &ExpectedMeasurement,
    ) -> Result<VerifiedAttestation, TeeError>;
}

/// A と B の間の双方向ストリームを張る(接続側)。
///
/// 本番では rustls の mTLS を載せ、Nitro 移行後は親インスタンスの vsock-TCP 中継を通す。
pub trait Connector: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn connect(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// A と B の間の双方向ストリームを受け付ける(待ち受け側)。
pub trait Listener: Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn accept(&self) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}
