use alloy_primitives::{Address, Bytes};
use serde::{Deserialize, Serialize};

/// A string an attacker may control, such as one from the agent or an external contract.
///
/// It does not implement `Display`, so `format!` can never slip it into a prompt or a log.
/// To use its contents, call `as_untrusted_str` explicitly.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UntrustedText(String);

impl UntrustedText {
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    pub fn as_untrusted_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for UntrustedText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UntrustedText({} bytes)", self.0.len())
    }
}

/// A proposal for an EIP-712 signature, sent by the agent to B through A.
///
/// B decodes `typed_data` and computes the digest itself. The signature goes back to the agent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedDataProposal {
    pub wallet: Address,
    pub chain_id: u64,
    /// EIP-712 typed data (types / primaryType / domain / message)
    pub typed_data: serde_json::Value,
    pub agent_note: UntrustedText,
}

/// A signing proposal, sent by the agent to B through A.
///
/// B trusts only the raw bytes of `unsigned_tx`; `agent_note` is context only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    /// The address of the wallet that signs (= the tx's from)
    pub wallet: Address,
    pub chain_id: u64,
    /// The unsigned tx, EIP-2718 encoded
    pub unsigned_tx: Bytes,
    pub agent_note: UntrustedText,
}
