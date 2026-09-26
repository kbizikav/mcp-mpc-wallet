use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::canonical_hash;

const POLICY_DOMAIN: &str = "mcp-mpc-wallet/policy/v1";

/// A policy the user registers. B only accepts ones with a verified passkey signature (M5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub wallet: Address,
    /// Monotonically increasing. Used to reject replays of older policies
    pub version: u64,
    /// The policy the user wrote in natural language
    pub text: String,
}

pub type PolicyHash = B256;

impl Policy {
    pub fn hash(&self) -> PolicyHash {
        canonical_hash(POLICY_DOMAIN, self)
    }
}
