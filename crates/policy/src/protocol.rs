//! ユーザーアプリと B のあいだのメッセージ。
//!
//! 方針の変更・要確認 tx の承認・凍結の解除・保留一覧の閲覧は、パスキー署名が必要。
//! 凍結・保留中の要求の却下・状態の確認は、署名なしでできる(どれも資金を動かさない)。

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::SignedUserOperation;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum UserRequest {
    Signed { signed: SignedUserOperation },
    Freeze { wallet: Address },
    RejectPending { wallet: Address, request_id: B256 },
    Status { wallet: Address },
}

/// 保留中の要求の詳細(ユーザーにだけ見せる)。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingView {
    pub request_id: B256,
    pub created_at: u64,
    pub approved: bool,
    pub reasons: Vec<String>,
    pub summary: Option<String>,
    /// B が抽出した効果(JSON)。攻撃者由来の文字列はエスケープ済み
    pub effects: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum UserResponse {
    PolicySet {
        version: u64,
    },
    Approved {
        request_id: B256,
    },
    Unfrozen,
    Frozen {
        freeze_epoch: u64,
    },
    PendingRequests {
        requests: Vec<PendingView>,
    },
    RequestRejected {
        request_id: B256,
    },
    Status {
        wallet: Address,
        frozen: bool,
        freeze_epoch: u64,
        policy_version: Option<u64>,
        passkey_registered: bool,
    },
    Error {
        message: String,
    },
}
