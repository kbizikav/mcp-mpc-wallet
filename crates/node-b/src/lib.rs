//! 判定ノード B の中核: 提案の受付からデコード・検証・シミュレーション・AI 判定・
//! 閾値署名・送信まで。
//!
//! 外部とのやりとり(チェーン RPC、シミュレータ、LLM、閾値署名、通知、時計)は
//! trait で受け取るので、テストではモックに差し替えられる。

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
