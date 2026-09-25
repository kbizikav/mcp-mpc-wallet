use alloy_primitives::B256;
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

/// A がエージェントに返す結果。署名そのものは含まない(B が送信する)。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentOutcome {
    Submitted { tx_hash: B256 },
    PendingUserConfirmation { request_id: B256 },
    Rejected { reason: CoarseReason },
    Frozen,
}
