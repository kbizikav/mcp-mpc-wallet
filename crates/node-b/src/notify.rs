use std::sync::Mutex;

use alloy_primitives::{Address, B256};
use serde::Serialize;

/// ユーザーにだけ見せる通知。判定の詳細な理由はここにだけ載せる。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UserNotice {
    NeedsConfirmation {
        wallet: Address,
        request_id: B256,
        reasons: Vec<String>,
        summary: Option<String>,
    },
    Rejected {
        wallet: Address,
        request_id: B256,
        reasons: Vec<String>,
    },
    Frozen {
        wallet: Address,
        reason: String,
    },
    Submitted {
        wallet: Address,
        tx_hash: B256,
    },
    /// EIP-712 の署名をエージェントに渡した
    Signed {
        wallet: Address,
        request_id: B256,
    },
    ApprovedByUser {
        wallet: Address,
        request_id: B256,
    },
    PolicyUpdated {
        wallet: Address,
        version: u64,
    },
    Unfrozen {
        wallet: Address,
    },
    SubmissionFailed {
        wallet: Address,
        request_id: B256,
        error: String,
    },
}

impl UserNotice {
    pub fn wallet(&self) -> Address {
        match self {
            UserNotice::NeedsConfirmation { wallet, .. }
            | UserNotice::Rejected { wallet, .. }
            | UserNotice::Frozen { wallet, .. }
            | UserNotice::Submitted { wallet, .. }
            | UserNotice::Signed { wallet, .. }
            | UserNotice::ApprovedByUser { wallet, .. }
            | UserNotice::PolicyUpdated { wallet, .. }
            | UserNotice::Unfrozen { wallet }
            | UserNotice::SubmissionFailed { wallet, .. } => *wallet,
        }
    }
}

pub trait UserNotifier: Send + Sync {
    fn notify(&self, notice: UserNotice);
}

/// 通知を記録するだけの実装(テスト用)。
#[derive(Default)]
pub struct RecordingNotifier(Mutex<Vec<UserNotice>>);

impl RecordingNotifier {
    pub fn notices(&self) -> Vec<UserNotice> {
        self.0.lock().expect("notifier poisoned").clone()
    }
}

impl UserNotifier for RecordingNotifier {
    fn notify(&self, notice: UserNotice) {
        self.0.lock().expect("notifier poisoned").push(notice);
    }
}
