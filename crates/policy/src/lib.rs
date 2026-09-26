//! Operations signed with the user's passkey (WebAuthn, ES256), and their verification.
//!
//! B accepts policy changes, approvals of txs needing confirmation, and unfreezing only when signed by the registered passkey
//! (invariant 6). What is signed (the challenge) is the operation's canonical hash, so it is bound to the operation's contents.
//! Verification uses p256 ECDSA; no cryptographic primitive is implemented here.

mod operation;
mod protocol;
mod webauthn;

#[cfg(feature = "software-passkey")]
pub mod software;

pub use operation::{SignedUserOperation, UserOperation};
pub use protocol::{ActivityView, PendingView, UserRequest, UserResponse};
pub use webauthn::{
    PasskeyAssertion, PasskeyError, PasskeyVerifier, RegisteredPasskey, RelyingParty,
};
