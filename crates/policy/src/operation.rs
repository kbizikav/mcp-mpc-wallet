use alloy_primitives::{Address, B256};
use mw_core::{Policy, canonical_hash};
use serde::{Deserialize, Serialize};

use crate::{PasskeyAssertion, RegisteredPasskey};

const OPERATION_DOMAIN: &str = "mcp-mpc-wallet/user-operation/v1";

/// User operations that need a passkey signature. Each one is shaped so it cannot be replayed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum UserOperation {
    /// Set or change the policy. `policy.version` increases monotonically
    SetPolicy { policy: Policy },
    /// Approve a tx that needs confirmation. A pending request can be approved only once
    ApproveRequest { wallet: Address, request_id: B256 },
    /// Unfreeze. `freeze_epoch` increases on every freeze, so an old unfreeze cannot be reused
    Unfreeze { wallet: Address, freeze_epoch: u64 },
    /// View the details of pending requests. Ones whose `issued_at` is too old are not accepted
    ListPending { wallet: Address, issued_at: u64 },
    /// When A is lost, approve a recovery tx that B+C sign (bound to the tx's signing hash)
    ApproveRecovery { wallet: Address, signing_hash: B256 },
    /// Rotate the passkey. Signed with the current passkey
    RotatePasskey {
        wallet: Address,
        new_passkey: RegisteredPasskey,
    },
}

impl UserOperation {
    pub fn wallet(&self) -> Address {
        match self {
            UserOperation::SetPolicy { policy } => policy.wallet,
            UserOperation::ApproveRequest { wallet, .. }
            | UserOperation::Unfreeze { wallet, .. }
            | UserOperation::ListPending { wallet, .. }
            | UserOperation::ApproveRecovery { wallet, .. }
            | UserOperation::RotatePasskey { wallet, .. } => *wallet,
        }
    }

    /// The challenge the passkey signs.
    pub fn challenge(&self) -> B256 {
        canonical_hash(OPERATION_DOMAIN, self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedUserOperation {
    pub operation: UserOperation,
    pub assertion: PasskeyAssertion,
}
