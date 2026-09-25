//! 閾値署名の抽象化。
//!
//! 署名は `ApprovedDigest`(承認済み・期限内・未使用であることを確認済みの値)を
//! 消費してしか始められない(不変条件 1)。

use std::future::Future;

use alloy_primitives::{Address, Signature};
use mw_core::ApprovedDigest;

#[cfg(feature = "insecure-test-signer")]
pub mod insecure_test;

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("approved digest belongs to another wallet")]
    WrongWallet,
    #[error("co-signer unavailable: {0}")]
    Unavailable(String),
    #[error("threshold signing protocol failed: {0}")]
    Protocol(String),
    #[error("combined signature does not recover to the wallet address")]
    InvalidSignature,
}

/// B 側から見た閾値署名。最終署名を得るのは呼び出し側(B)だけ。
pub trait ThresholdSigner: Send + Sync {
    fn address(&self) -> Address;

    fn sign(
        &self,
        approved: ApprovedDigest,
    ) -> impl Future<Output = Result<Signature, SignError>> + Send;
}

/// 署名がウォレットのアドレスに復元されることを確かめる。送信前に必ず呼ぶ。
pub fn ensure_recovers_to(
    signature: &Signature,
    approved: &ApprovedDigest,
    address: Address,
) -> Result<(), SignError> {
    match signature.recover_address_from_prehash(&approved.key().signing_hash) {
        Ok(recovered) if recovered == address => Ok(()),
        _ => Err(SignError::InvalidSignature),
    }
}
