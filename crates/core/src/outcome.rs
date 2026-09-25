use alloy_primitives::{B256, Bytes};
use serde::{Deserialize, Serialize};

/// エージェントに返す粗い理由。判定の詳細はユーザーにだけ見せる。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoarseReason {
    PolicyViolation,
    SimulationFailed,
    InvalidRequest,
    RateLimited,
    Unavailable,
}

/// A がエージェントに返す結果。tx の署名は含まない(B が送信する)。typed data の署名だけは返す。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentOutcome {
    Submitted {
        tx_hash: B256,
    },
    /// EIP-712 の署名(r || s || v、v は 27 か 28)。typed data のときだけ返す
    Signed {
        signature: Bytes,
    },
    PendingUserConfirmation {
        request_id: B256,
    },
    Rejected {
        reason: CoarseReason,
    },
    Frozen,
}
