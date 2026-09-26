//! Messages between the user app and B.
//!
//! Changing the policy, approving txs that need confirmation, unfreezing and viewing pending requests need a passkey signature.
//! Freezing, rejecting a pending request and checking the status need no signature (none of them moves funds).

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

/// Details of a pending request (shown to the user only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingView {
    pub request_id: B256,
    pub created_at: u64,
    pub approved: bool,
    pub reasons: Vec<String>,
    pub summary: Option<String>,
    /// The effects B extracted (JSON). Attacker-controlled strings are escaped
    pub effects: String,
}

/// An event B notified to the user (a send, a rejection and its reasons, a freeze, ...).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityView {
    pub at: u64,
    pub notice: serde_json::Value,
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
    PasskeyRotated,
    Frozen {
        freeze_epoch: u64,
    },
    /// The owner view: pending requests, recent events and the policy text
    PendingRequests {
        requests: Vec<PendingView>,
        #[serde(default)]
        recent: Vec<ActivityView>,
        #[serde(default)]
        policy_text: Option<String>,
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
