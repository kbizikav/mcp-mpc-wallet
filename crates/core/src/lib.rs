//! Types shared by the judge node, the signing node and the user app.

pub mod approval;
pub mod hash;
pub mod outcome;
pub mod policy;
pub mod proposal;
pub mod verdict;

pub use approval::{
    APPROVAL_TTL_SECS, Approval, ApprovalError, ApprovalOrigin, ApprovalRegistry, ApprovedDigest,
    SigningKind, SigningRequestKey, TimeWitness,
};
pub use hash::canonical_hash;
pub use outcome::{AgentOutcome, CoarseReason};
pub use policy::{Policy, PolicyHash};
pub use proposal::{Proposal, TypedDataProposal, UntrustedText};
pub use verdict::Verdict;
