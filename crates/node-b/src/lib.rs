//! The core of judge node B: from accepting a proposal through decoding, validation, simulation,
//! AI judgment and threshold signing to sending.
//!
//! Everything external (chain RPC, simulator, LLM, threshold signing, notifications, clock)
//! comes in through traits, so tests can swap in mocks.

pub mod clock;
pub mod crosscheck;
pub mod guard;
pub mod notify;
pub mod pipeline;
pub mod policy_store;
pub mod signals;
pub mod user;

pub use clock::{Clock, ManualClock, SystemClock};
pub use guard::{Admission, GuardConfig, WalletGuard};
pub use notify::{RecordingNotifier, UserNotice, UserNotifier};
pub use pipeline::{Components, DEFAULT_ORIGIN, DEFAULT_RP_ID, JudgeNode, NodeConfig};
pub use policy_store::PolicyStore;
pub use user::{UserError, UserStateSnapshot};
