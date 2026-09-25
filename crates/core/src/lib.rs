//! 判定ノード・署名ノード・ユーザーアプリで共有する型。

pub mod approval;
pub mod hash;
pub mod outcome;
pub mod policy;
pub mod proposal;
pub mod verdict;

pub use approval::{
    APPROVAL_TTL_SECS, Approval, ApprovalError, ApprovalOrigin, ApprovalRegistry, ApprovedDigest,
    SigningRequestKey, TimeWitness,
};
pub use hash::canonical_hash;
pub use outcome::{AgentOutcome, CoarseReason};
pub use policy::{Policy, PolicyHash};
pub use proposal::{Proposal, UntrustedText};
pub use verdict::Verdict;
