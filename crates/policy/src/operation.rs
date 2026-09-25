use alloy_primitives::{Address, B256};
use mw_core::{Policy, canonical_hash};
use serde::{Deserialize, Serialize};

use crate::PasskeyAssertion;

const OPERATION_DOMAIN: &str = "mcp-mpc-wallet/user-operation/v1";

/// パスキーでの署名が必要なユーザー操作。どれも再送(リプレイ)できない形にしてある。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum UserOperation {
    /// 方針の登録・変更。`policy.version` は単調増加
    SetPolicy { policy: Policy },
    /// 要確認の tx を承認する。保留中の要求は一度しか承認できない
    ApproveRequest { wallet: Address, request_id: B256 },
    /// 凍結を解除する。`freeze_epoch` は凍結のたびに増えるので、古い解除は使い回せない
    Unfreeze { wallet: Address, freeze_epoch: u64 },
    /// 保留中の要求の詳細を見る。`issued_at` が古すぎるものは受け付けない
    ListPending { wallet: Address, issued_at: u64 },
}

impl UserOperation {
    pub fn wallet(&self) -> Address {
        match self {
            UserOperation::SetPolicy { policy } => policy.wallet,
            UserOperation::ApproveRequest { wallet, .. }
            | UserOperation::Unfreeze { wallet, .. }
            | UserOperation::ListPending { wallet, .. } => *wallet,
        }
    }

    /// パスキーに署名させる challenge。
    pub fn challenge(&self) -> B256 {
        canonical_hash(OPERATION_DOMAIN, self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedUserOperation {
    pub operation: UserOperation,
    pub assertion: PasskeyAssertion,
}
