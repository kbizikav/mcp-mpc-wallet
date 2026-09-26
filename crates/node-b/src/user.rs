//! User operations (signed with the passkey) and resuming requests the user approved.
//!
//! - Changing the policy, approving txs that need confirmation, unfreezing and viewing pending requests need a
//!   signature from the registered passkey (invariant 6). The signature counter is stored so the same assertion cannot be replayed.
//! - A tx the user approved is signed only if its nonce checks out at approval time and A resumes it
//!   within 5 minutes of the approval (invariants 3, 4).
//! - When A's device is lost, a recovery tx approved with the passkey is signed by B+C.

use alloy_primitives::{Address, B256, Bytes, keccak256};
use mw_audit::{AuditRecord, AuditSink};
use mw_chain::{ChainClient, decode_unsigned};
use mw_core::{
    APPROVAL_TTL_SECS, AgentOutcome, Approval, ApprovalOrigin, CoarseReason, Policy, SigningKind,
    SigningRequestKey, Verdict,
};
use mw_judge::LlmClient;
use mw_mpc::ThresholdSigner;
use mw_policy::{
    ActivityView, PasskeyVerifier, PendingView, RegisteredPasskey, SignedUserOperation,
    UserOperation, UserRequest, UserResponse,
};
use mw_simulator::Simulator;
use serde::{Deserialize, Serialize};

use crate::guard::{Admission, FreezeState};
use crate::notify::{UserNotice, UserNotifier};
use crate::pipeline::{PENDING_TTL_SECS, Payload, Prepared};
use crate::{Clock, JudgeNode};

/// Persisted user-related state.
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
    #[error("this operation must be sent through the recovery flow")]
    WrongFlow,
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
    /// Register the user's passkey. Only when none is registered yet (trust on first use).
    ///
    /// Rotation is possible only with a `RotatePasskey` signed by the current passkey.
    pub fn register_passkey(
        &self,
        wallet: Address,
        passkey: RegisteredPasskey,
    ) -> Result<(), UserError> {
        if !self.holds(wallet) {
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

    /// Restore from the state B itself saved (at startup).
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

    /// Handle a request from the user app.
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
        if self.holds(wallet) {
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

    /// Verify the passkey signature and advance the signature counter.
    fn verify_passkey(&self, signed: &SignedUserOperation) -> Result<(), UserError> {
        let wallet = self.checked_wallet(signed.operation.wallet())?;
        let verifier = PasskeyVerifier {
            allowed: self.config.passkey_rps.clone(),
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
        // Before advancing the signature counter, check that this path handles the operation
        if let UserOperation::ApproveRecovery { .. } = signed.operation {
            return Err(UserError::WrongFlow);
        }
        self.verify_passkey(&signed)?;
        let now = self.parts.clock.now_unix();
        match signed.operation {
            UserOperation::SetPolicy { policy } => {
                let (wallet, version) = (policy.wallet, policy.version);
                self.policies.install_verified(policy)?;
                self.notify(UserNotice::PolicyUpdated { wallet, version });
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
                self.notify(UserNotice::Unfrozen { wallet });
                Ok(UserResponse::Unfrozen)
            }
            UserOperation::ListPending { wallet, issued_at } => {
                if now.abs_diff(issued_at) > APPROVAL_TTL_SECS {
                    return Err(UserError::StaleOperation);
                }
                Ok(UserResponse::PendingRequests {
                    requests: self.pending_views(now),
                    recent: self.activity_views(wallet),
                    policy_text: self.policies.get(wallet).map(|p| p.text),
                })
            }
            UserOperation::ApproveRecovery { .. } => Err(UserError::WrongFlow),
            UserOperation::RotatePasskey {
                wallet,
                new_passkey,
            } => {
                self.passkeys
                    .lock()
                    .expect("passkeys poisoned")
                    .insert(wallet, new_passkey);
                Ok(UserResponse::PasskeyRotated)
            }
        }
    }

    /// Recovery when A's device is lost. Signs a passkey-approved tx with `peer` (C) and sends it.
    ///
    /// Works even while frozen (in an emergency, the wallet should already be frozen).
    pub async fn recover(
        &self,
        signed: SignedUserOperation,
        unsigned_tx: Bytes,
        peer: &mut T::Peer,
    ) -> AgentOutcome {
        let _serial = self.serial.lock().await;
        let reject = |reason| AgentOutcome::Rejected { reason };
        let UserOperation::ApproveRecovery {
            wallet,
            signing_hash,
        } = signed.operation
        else {
            return reject(CoarseReason::InvalidRequest);
        };
        if !self.holds(wallet) {
            return reject(CoarseReason::InvalidRequest);
        }
        if let Err(e) = self.verify_passkey(&signed) {
            self.notify(UserNotice::Rejected {
                wallet,
                request_id: signing_hash,
                reasons: vec![format!("recovery refused: {e}")],
            });
            return reject(CoarseReason::PolicyViolation);
        }

        let Ok(decoded) = decode_unsigned(&unsigned_tx) else {
            return reject(CoarseReason::InvalidRequest);
        };
        if decoded.signing_hash != signing_hash || decoded.tx.chain_id != self.config.chain_id {
            return reject(CoarseReason::InvalidRequest);
        }
        let Ok((witness, pending_nonce)) = self.time_and_nonce(wallet).await else {
            return reject(CoarseReason::Unavailable);
        };
        if decoded.tx.nonce != pending_nonce {
            return reject(CoarseReason::InvalidRequest);
        }
        let key = SigningRequestKey {
            kind: SigningKind::Transaction,
            chain_id: decoded.tx.chain_id,
            from: wallet,
            nonce: decoded.tx.nonce,
            signing_hash,
            payload_hash: keccak256(&decoded.payload),
        };
        let recorded = self.append_audit(AuditRecord {
            wallet,
            proposal_hash: signing_hash,
            input_summary: String::new(),
            policy_hash: None,
            simulation_hash: None,
            verdict: Verdict::Approve,
            reasons: vec!["recovery (B+C) approved by the owner's passkey".into()],
        });
        let inserted = self.approvals.insert(Approval {
            key,
            issued: witness,
            origin: ApprovalOrigin::User,
        });
        if recorded.is_err() || inserted.is_err() {
            return reject(CoarseReason::Unavailable);
        }

        let prepared = Prepared {
            payload: Payload::Tx(Box::new(decoded)),
            key,
            witness,
        };
        let result = self.redeem_and_submit(wallet, prepared, peer).await;
        self.report_submission(wallet, signing_hash, result)
    }

    /// Recent events for this wallet (newest first).
    fn activity_views(&self, wallet: Address) -> Vec<ActivityView> {
        self.activity
            .lock()
            .expect("activity poisoned")
            .iter()
            .rev()
            .filter(|(_, w, _)| *w == wallet)
            .take(crate::pipeline::ACTIVITY_PER_WALLET)
            .map(|(at, _, notice)| ActivityView {
                at: *at,
                notice: serde_json::to_value(notice).unwrap_or_default(),
            })
            .collect()
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

    /// Register the user's approval. If the nonce has moved on, drop the request.
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
        // Typed data has no account nonce, so this is checked for txs only
        if key.kind == SigningKind::Transaction && pending_nonce != key.nonce {
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
        self.notify(UserNotice::ApprovedByUser { wallet, request_id });
        Ok(())
    }

    /// Sign a request the user approved together with A, and send it.
    ///
    /// If it is not approved yet, returns `PendingUserConfirmation`.
    pub async fn resume(
        &self,
        wallet: Address,
        request_id: B256,
        peer: &mut T::Peer,
    ) -> AgentOutcome {
        let _serial = self.serial.lock().await;
        if !self.holds(wallet) {
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

        let result = self.redeem_and_submit(wallet, prepared, peer).await;
        self.report_submission(wallet, request_id, result)
    }
}
