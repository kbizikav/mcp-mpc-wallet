use alloy_primitives::{Address, B256, Bytes};
use mw_core::{AgentOutcome, Proposal, TypedDataProposal};
use mw_mpc::net::WireMsg;
use mw_policy::{RegisteredPasskey, SignedUserOperation, UserRequest, UserResponse};
use serde::{Deserialize, Serialize};

/// From A (the user's machine) to B (the judge node).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AtoB {
    /// A signing proposal. B judges it and, if approved, follows up with a `SignRequest`
    Propose {
        proposal: Proposal,
    },
    /// An EIP-712 signature proposal. If approved, the signature comes back in `Outcome`
    ProposeTypedData {
        proposal: TypedDataProposal,
    },
    /// Resume signing and sending a request the user approved
    Resume {
        wallet: Address,
        request_id: B256,
    },
    /// An operation from the user app (policy, approval, freeze, ...)
    User {
        request: UserRequest,
    },
    /// Recovery when A's device is lost. The sender joins the signing with share C
    Recover {
        signed: SignedUserOperation,
        unsigned_tx: Bytes,
    },
    /// Ask B (in the enclave) for an attestation document. Sent right after the TLS connection is set up
    Attest {
        nonce: B256,
    },
    /// Key generation, accepted only while B has no share yet
    Keygen {
        session: B256,
        /// The new wallet's first passkey. Registered over the attested connection
        #[serde(default)]
        passkey: Option<RegisteredPasskey>,
    },
    /// Key generation finished; the address of the public key A obtained (checked to match B's)
    KeygenResult {
        address: Address,
    },
    Mpc {
        msg: WireMsg,
    },
    /// A's partial signature. Sent to B only
    PartialSignature {
        partial: serde_json::Value,
    },
    /// A refused the signing request
    Decline {
        reason: String,
    },
}

/// From B to A.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BtoA {
    /// Please join the signing of an approved tx. `signing_hash` must match what A proposed
    SignRequest {
        session: B256,
        signing_hash: B256,
    },
    KeygenAccepted,
    /// An attestation document with the SHA-256 of B's TLS certificate in user_data
    Attestation {
        document: Bytes,
    },
    KeygenDone {
        address: Address,
    },
    /// B sealed its share and the wallet is ready to use
    KeygenStored {
        address: Address,
    },
    Mpc {
        msg: WireMsg,
    },
    /// The final outcome. Never contains a signed tx
    Outcome {
        outcome: AgentOutcome,
    },
    User {
        response: UserResponse,
    },
    Error {
        message: String,
    },
}

// Non-MPC messages are returned as is, to be read later (carrying them in Err is intended)
#[allow(clippy::result_large_err)]
impl AtoB {
    pub fn into_mpc(self) -> Result<WireMsg, Self> {
        match self {
            AtoB::Mpc { msg } => Ok(msg),
            other => Err(other),
        }
    }
}

#[allow(clippy::result_large_err)]
impl BtoA {
    pub fn into_mpc(self) -> Result<WireMsg, Self> {
        match self {
            BtoA::Mpc { msg } => Ok(msg),
            other => Err(other),
        }
    }
}
