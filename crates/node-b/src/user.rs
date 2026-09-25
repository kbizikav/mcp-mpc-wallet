//! ユーザー操作(パスキー署名つき)と、ユーザーが承認した要求の再開。
//!
//! - 方針の変更、要確認 tx の承認、凍結の解除、保留一覧の閲覧は、登録済みのパスキーの署名が必要
//!   (不変条件 6)。署名カウンタを保存して、同じ assertion の再送を拒否する。
//! - ユーザーが承認した tx も、承認時点で nonce を確かめ、承認から 5 分以内に
//!   A が再開したときにだけ署名する(不変条件 3, 4)。

use alloy_primitives::{Address, B256};
use mw_audit::{AuditRecord, AuditSink};
use mw_chain::ChainClient;
use mw_core::{
    APPROVAL_TTL_SECS, AgentOutcome, Approval, ApprovalOrigin, CoarseReason, Policy, Verdict,
};
use mw_judge::LlmClient;
use mw_mpc::ThresholdSigner;
use mw_policy::{
    PasskeyVerifier, PendingView, RegisteredPasskey, SignedUserOperation, UserOperation,
    UserRequest, UserResponse,
};
use mw_simulator::Simulator;
use serde::{Deserialize, Serialize};

use crate::guard::{Admission, FreezeState};
use crate::notify::{UserNotice, UserNotifier};
use crate::pipeline::PENDING_TTL_SECS;
use crate::{Clock, JudgeNode};

/// 永続化するユーザー関連の状態。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserStateSnapshot {
    pub passkeys: Vec<(Address, RegisteredPasskey)>,
    pub policies: Vec<Policy>,
    pub freezes: Vec<FreezeState>,
}

#[derive(Debug, thiserror::Error)]
pub enum UserError {
    #[error("no passkey is registered for this wallet")]
    NoPasskey,
    #[error("a passkey is already registered for this wallet")]
    PasskeyAlreadyRegistered,
    #[error("unknown wallet")]
    UnknownWallet,
    #[error("passkey: {0}")]
    Passkey(#[from] mw_policy::PasskeyError),
    #[error("policy: {0}")]
    Policy(#[from] crate::policy_store::PolicyStoreError),
    #[error("no pending request with this id")]
    NoSuchRequest,
    #[error("the request is already approved")]
    AlreadyApproved,
    #[error("the account nonce moved on; the request is stale")]
    StaleRequest,
    #[error("the signed request is too old")]
    StaleOperation,
    #[error("unfreeze: {0}")]
    Unfreeze(#[from] crate::guard::UnfreezeError),
    #[error("chain: {0}")]
    Chain(#[from] mw_chain::ChainError),
    #[error("approval: {0}")]
    Approval(#[from] mw_core::ApprovalError),
    #[error("audit log: {0}")]
    Audit(#[from] mw_audit::AuditError),
}

impl<C, S, L, T, N, K, A> JudgeNode<C, S, L, T, N, K, A>
where
    C: ChainClient,
    S: Simulator,
    L: LlmClient,
    T: ThresholdSigner,
    N: UserNotifier,
    K: Clock,
    A: AuditSink,
{
    /// ユーザーのパスキーを登録する。まだ登録がないときだけ(初回の信頼)。
    ///
    /// パスキーの差し替えは、今のパスキーの署名つき操作として後で追加する。
    pub fn register_passkey(
        &self,
        wallet: Address,
        passkey: RegisteredPasskey,
    ) -> Result<(), UserError> {
        if wallet != self.wallet() {
            return Err(UserError::UnknownWallet);
        }
        let mut passkeys = self.passkeys.lock().expect("passkeys poisoned");
        if passkeys.contains_key(&wallet) {
            return Err(UserError::PasskeyAlreadyRegistered);
        }
        passkeys.insert(wallet, passkey);
        Ok(())
    }

    pub fn snapshot(&self) -> UserStateSnapshot {
        UserStateSnapshot {
            passkeys: self
                .passkeys
                .lock()
                .expect("passkeys poisoned")
                .iter()
                .map(|(w, k)| (*w, k.clone()))
                .collect(),
            policies: self.policies.all(),
            freezes: self.guard.lock().expect("guard poisoned").snapshot(),
        }
    }

    /// B 自身が保存した状態から復元する(起動時)。
    pub fn restore(&self, snapshot: &UserStateSnapshot) -> Result<(), UserError> {
        let mut passkeys = self.passkeys.lock().expect("passkeys poisoned");
        for (wallet, key) in &snapshot.passkeys {
            passkeys.insert(*wallet, key.clone());
        }
        for policy in &snapshot.policies {
            self.policies.install_verified(policy.clone())?;
        }
        self.guard
            .lock()
            .expect("guard poisoned")
            .restore(&snapshot.freezes);
        Ok(())
    }

    /// ユーザーアプリからの要求を処理する。
    pub async fn handle_user_request(&self, request: UserRequest) -> UserResponse {
        let result = match request {
            UserRequest::Signed { signed } => self.signed_operation(signed).await,
            UserRequest::Freeze { wallet } => {
                self.checked_wallet(wallet).map(|w| UserResponse::Frozen {
                    freeze_epoch: self.freeze(w),
                })
            }
            UserRequest::RejectPending { wallet, request_id } => {
                self.reject_pending(wallet, request_id)
            }
            UserRequest::Status { wallet } => self.checked_wallet(wallet).map(|w| self.status(w)),
        };
        result.unwrap_or_else(|e| UserResponse::Error {
            message: e.to_string(),
        })
    }

    fn checked_wallet(&self, wallet: Address) -> Result<Address, UserError> {
        if wallet == self.wallet() {
            Ok(wallet)
        } else {
            Err(UserError::UnknownWallet)
        }
    }

    fn status(&self, wallet: Address) -> UserResponse {
        let guard = self.guard.lock().expect("guard poisoned");
        UserResponse::Status {
            wallet,
            frozen: guard.is_frozen(wallet),
            freeze_epoch: guard.freeze_epoch(wallet),
            policy_version: self.policies.get(wallet).map(|p| p.version),
            passkey_registered: self
                .passkeys
                .lock()
                .expect("passkeys poisoned")
                .contains_key(&wallet),
        }
    }

    fn reject_pending(&self, wallet: Address, request_id: B256) -> Result<UserResponse, UserError> {
        self.checked_wallet(wallet)?;
        self.pending
            .lock()
            .expect("pending poisoned")
            .remove(&request_id)
            .ok_or(UserError::NoSuchRequest)?;
        Ok(UserResponse::RequestRejected { request_id })
    }

    /// パスキーの署名を検証し、署名カウンタを進める。
    fn verify_passkey(&self, signed: &SignedUserOperation) -> Result<(), UserError> {
        let wallet = self.checked_wallet(signed.operation.wallet())?;
        let verifier = PasskeyVerifier {
            rp_id: self.config.passkey_rp_id.clone(),
            origin: self.config.passkey_origin.clone(),
        };
        let mut passkeys = self.passkeys.lock().expect("passkeys poisoned");
        let key = passkeys.get_mut(&wallet).ok_or(UserError::NoPasskey)?;
        key.sign_count = verifier.verify(key, signed)?;
        Ok(())
    }

    async fn signed_operation(
        &self,
        signed: SignedUserOperation,
    ) -> Result<UserResponse, UserError> {
        let _serial = self.serial.lock().await;
        self.verify_passkey(&signed)?;
        let now = self.parts.clock.now_unix();
        match signed.operation {
            UserOperation::SetPolicy { policy } => {
                let (wallet, version) = (policy.wallet, policy.version);
                self.policies.install_verified(policy)?;
                self.parts
                    .notifier
                    .notify(UserNotice::PolicyUpdated { wallet, version });
                Ok(UserResponse::PolicySet { version })
            }
            UserOperation::ApproveRequest { wallet, request_id } => {
                self.approve_pending(wallet, request_id).await?;
                Ok(UserResponse::Approved { request_id })
            }
            UserOperation::Unfreeze {
                wallet,
                freeze_epoch,
            } => {
                self.guard
                    .lock()
                    .expect("guard poisoned")
                    .unfreeze(wallet, freeze_epoch)?;
                self.parts.notifier.notify(UserNotice::Unfrozen { wallet });
                Ok(UserResponse::Unfrozen)
            }
            UserOperation::ListPending { issued_at, .. } => {
                if now.abs_diff(issued_at) > APPROVAL_TTL_SECS {
                    return Err(UserError::StaleOperation);
                }
                Ok(UserResponse::PendingRequests {
                    requests: self.pending_views(now),
                })
            }
        }
    }

    fn pending_views(&self, now: u64) -> Vec<PendingView> {
        let mut pending = self.pending.lock().expect("pending poisoned");
        pending.retain(|_, p| now.saturating_sub(p.created_at) < PENDING_TTL_SECS);
        let mut views: Vec<PendingView> = pending
            .iter()
            .map(|(id, p)| PendingView {
                request_id: *id,
                created_at: p.created_at,
                approved: p.approved,
                reasons: p.reasons.clone(),
                summary: p.summary.clone(),
                effects: p.input_summary.clone(),
            })
            .collect();
        views.sort_by_key(|v| v.created_at);
        views
    }

    /// ユーザーの承認を登録する。nonce が進んでいたら要求を捨てる。
    async fn approve_pending(&self, wallet: Address, request_id: B256) -> Result<(), UserError> {
        let now = self.parts.clock.now_unix();
        let (key, input_summary) = {
            let mut pending = self.pending.lock().expect("pending poisoned");
            let entry = pending.get(&request_id).ok_or(UserError::NoSuchRequest)?;
            if now.saturating_sub(entry.created_at) >= PENDING_TTL_SECS {
                pending.remove(&request_id);
                return Err(UserError::NoSuchRequest);
            }
            if entry.approved {
                return Err(UserError::AlreadyApproved);
            }
            (entry.prepared.key, entry.input_summary.clone())
        };
        if key.from != wallet {
            return Err(UserError::UnknownWallet);
        }

        let (witness, pending_nonce) = self.time_and_nonce(wallet).await?;
        if pending_nonce != key.nonce {
            self.pending
                .lock()
                .expect("pending poisoned")
                .remove(&request_id);
            return Err(UserError::StaleRequest);
        }
        self.append_audit(AuditRecord {
            wallet,
            proposal_hash: request_id,
            input_summary,
            policy_hash: None,
            simulation_hash: None,
            verdict: Verdict::Approve,
            reasons: vec!["approved by the owner's passkey".into()],
        })?;
        self.approvals.insert(Approval {
            key,
            issued: witness,
            origin: ApprovalOrigin::User,
        })?;
        if let Some(entry) = self
            .pending
            .lock()
            .expect("pending poisoned")
            .get_mut(&request_id)
        {
            entry.approved = true;
        }
        self.parts
            .notifier
            .notify(UserNotice::ApprovedByUser { wallet, request_id });
        Ok(())
    }

    /// ユーザーが承認した要求を、A と署名して送信する。
    ///
    /// まだ承認されていなければ `PendingUserConfirmation` を返す。
    pub async fn resume(
        &self,
        wallet: Address,
        request_id: B256,
        peer: &mut T::Peer,
    ) -> AgentOutcome {
        let _serial = self.serial.lock().await;
        if wallet != self.wallet() {
            return AgentOutcome::Rejected {
                reason: CoarseReason::InvalidRequest,
            };
        }
        let admission = self
            .guard
            .lock()
            .expect("guard poisoned")
            .admit(wallet, self.parts.clock.now_unix());
        match admission {
            Admission::Frozen => return AgentOutcome::Frozen,
            Admission::RateLimited => {
                return AgentOutcome::Rejected {
                    reason: CoarseReason::RateLimited,
                };
            }
            Admission::Allowed => {}
        }

        let prepared = {
            let mut pending = self.pending.lock().expect("pending poisoned");
            match pending.get(&request_id) {
                None => {
                    return AgentOutcome::Rejected {
                        reason: CoarseReason::InvalidRequest,
                    };
                }
                Some(p) if !p.approved => {
                    return AgentOutcome::PendingUserConfirmation { request_id };
                }
                Some(_) => pending.remove(&request_id).expect("present").prepared,
            }
        };

        match self.redeem_and_submit(wallet, prepared, peer).await {
            Ok(tx_hash) => {
                self.parts
                    .notifier
                    .notify(UserNotice::Submitted { wallet, tx_hash });
                AgentOutcome::Submitted { tx_hash }
            }
            Err(e) => {
                self.parts.notifier.notify(UserNotice::SubmissionFailed {
                    wallet,
                    request_id,
                    error: e.to_string(),
                });
                AgentOutcome::Rejected {
                    reason: CoarseReason::Unavailable,
                }
            }
        }
    }
}
