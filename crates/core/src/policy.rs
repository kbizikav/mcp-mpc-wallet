use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::canonical_hash;

const POLICY_DOMAIN: &str = "mcp-mpc-wallet/policy/v1";

/// ユーザーが登録する方針。B はパスキー署名を検証できたものだけを受け付ける(M5)。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub wallet: Address,
    /// 単調増加。古い方針の再送を拒否するのに使う
    pub version: u64,
    /// ユーザーが自然言語で書いた方針
    pub text: String,
}

pub type PolicyHash = B256;

impl Policy {
    pub fn hash(&self) -> PolicyHash {
        canonical_hash(POLICY_DOMAIN, self)
    }
}
