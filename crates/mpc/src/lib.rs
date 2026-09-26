//! Threshold signing (cggmp21, secp256k1, 2-of-3).
//!
//! Signing can only start by consuming an `ApprovedDigest` (a value checked to be approved, within its expiry
//! and unused) (invariant 1).
//! Only B combines the final signature; A only sends its partial signature to B (invariant 5).

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

/// Threshold signing from B's side. Only the caller (B) gets the final signature.
///
/// `Peer` is the session with the other signer (A).
/// A single B can hold shares for several wallets.
pub trait ThresholdSigner: Send + Sync {
    type Peer: Send;

    /// Whether this signer holds a share for this wallet.
    fn holds(&self, wallet: Address) -> bool;

    fn sign(
        &self,
        approved: ApprovedDigest,
        peer: &mut Self::Peer,
    ) -> impl Future<Output = Result<Signature, SignError>> + Send;
}
