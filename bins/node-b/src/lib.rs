//! 判定ノード B のサーバ: A との mTLS 接続、鍵生成、cggmp21 による閾値署名。

pub mod keygen;
pub mod net;
pub mod notifier;
pub mod server;
pub mod signer;

pub use signer::CggmpSigner;

/// B のシェアを SealedStorage に保存するときのラベル
pub const SHARE_LABEL: &str = "share-b";

/// enclave の中で attestation document を発行する。user_data は TLS 証明書の SHA-256。
pub struct AttestationService {
    pub attestor: Box<dyn mw_tee::Attestor>,
    pub cert_hash: [u8; 32],
}

impl AttestationService {
    pub fn respond(&self, nonce: &alloy_primitives::B256) -> mw_wire::BtoA {
        match self.attestor.attest(&self.cert_hash, nonce.as_slice()) {
            Ok(doc) => mw_wire::BtoA::Attestation {
                document: doc.bytes.into(),
            },
            Err(e) => mw_wire::BtoA::Error {
                message: format!("attestation failed: {e}"),
            },
        }
    }
}
