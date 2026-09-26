use alloy_primitives::{B256, Bytes};
use serde::{Deserialize, Serialize};

/// The coarse reason returned to the agent. Judgment details are shown to the user only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoarseReason {
    PolicyViolation,
    SimulationFailed,
    InvalidRequest,
    RateLimited,
    Unavailable,
}

/// What A returns to the agent. It never contains a tx signature (B sends the tx). Only typed data signatures are returned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AgentOutcome {
    Submitted {
        tx_hash: B256,
    },
    /// An EIP-712 signature (r || s || v, v is 27 or 28). Returned for typed data only
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
