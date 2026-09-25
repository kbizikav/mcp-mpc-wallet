//! 閾値署名(cggmp21, secp256k1, 2-of-3)。
//!
//! 署名は `ApprovedDigest`(承認済み・期限内・未使用であることを確認済みの値)を
//! 消費してしか始められない(不変条件 1)。
//! 最終署名を合成するのは B だけで、A は自分の部分署名を B に送るだけ(不変条件 5)。

use std::future::Future;

use alloy_primitives::{Address, Signature};
use mw_core::ApprovedDigest;

pub use cggmp21::round_based;

pub mod net;
pub mod protocol;

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
///
/// `Peer` は署名に参加する相手(A)とのセッション。
/// 1 つの B が複数のウォレットのシェアを持てる。
pub trait ThresholdSigner: Send + Sync {
    type Peer: Send;

    /// このウォレットのシェアを持っているか。
    fn holds(&self, wallet: Address) -> bool;

    fn sign(
        &self,
        approved: ApprovedDigest,
        peer: &mut Self::Peer,
    ) -> impl Future<Output = Result<Signature, SignError>> + Send;
}
