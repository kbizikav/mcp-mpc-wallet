//! 提案の受付から送信まで。
//!
//! 判定が「承認」になるのは、次がすべて揃ったときだけ:
//! デコード成功、chainId・from・nonce の一致、方針あり、シミュレーション成功、
//! 検算の食い違いなし、LLM の全サンプルが承認。
//! それ以外はすべて「要確認」か「拒否」に倒れる(不変条件 7)。

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_primitives::{Address, B256, keccak256};
use mw_audit::{AuditLog, AuditRecord, AuditSink};
use mw_chain::{ChainClient, DecodedTx, decode_known_call, decode_unsigned, encode_signed};
use mw_core::{
    AgentOutcome, Approval, ApprovalOrigin, ApprovalRegistry, CoarseReason, Policy, PolicyHash,
    Proposal, SigningRequestKey, TimeWitness, Verdict,
};
use mw_judge::{LlmClient, build_request, escape_data, judge};
use mw_mpc::ThresholdSigner;
use mw_policy::RegisteredPasskey;
use mw_simulator::{SimulationRequest, Simulator};

use crate::Clock;
use crate::crosscheck::crosscheck;
use crate::guard::{Admission, GuardConfig, WalletGuard};
use crate::notify::{UserNotice, UserNotifier};
use crate::policy_store::PolicyStore;
use crate::signals::{Effects, JudgeData};

#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// 対象チェーン(初期は Base Sepolia = 84532)
    pub chain_id: u64,
    /// LLM に同じ問い合わせを投げる回数
    pub llm_samples: usize,
    pub guard: GuardConfig,
    /// ユーザーのパスキーの RP ID と origin
    pub passkey_rp_id: String,
    pub passkey_origin: String,
}

impl NodeConfig {
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            llm_samples: 3,
            guard: GuardConfig::default(),
            passkey_rp_id: DEFAULT_RP_ID.into(),
            passkey_origin: DEFAULT_ORIGIN.into(),
        }
    }
}

pub const DEFAULT_RP_ID: &str = "mcp-mpc-wallet.local";
pub const DEFAULT_ORIGIN: &str = "https://mcp-mpc-wallet.local";

/// 要確認の要求は、この時間を過ぎたら捨てる
pub(crate) const PENDING_TTL_SECS: u64 = 3_600;

/// B が外部とやりとりする部品。
pub struct Components<C, S, L, T, N, K> {
    pub chain: C,
    pub simulator: S,
    pub llm: L,
    pub signer: T,
    pub notifier: N,
    pub clock: K,
}

/// 署名に進むために必要な、検証済みの情報。
pub(crate) struct Prepared {
    pub(crate) decoded: DecodedTx,
    pub(crate) key: SigningRequestKey,
    pub(crate) witness: TimeWitness,
}

/// ユーザーの確認を待っている要求。
pub(crate) struct Pending {
    pub(crate) prepared: Prepared,
    pub(crate) created_at: u64,
    pub(crate) reasons: Vec<String>,
    pub(crate) summary: Option<String>,
    pub(crate) input_summary: String,
    pub(crate) approved: bool,
}

/// 1 件の提案の判定結果。
struct Assessment {
    verdict: Verdict,
    /// 拒否時にエージェントへ返す粗い理由
    coarse: CoarseReason,
    reasons: Vec<String>,
    summary: Option<String>,
    request_id: B256,
    input_summary: String,
    policy_hash: Option<PolicyHash>,
    simulation_hash: Option<B256>,
    prepared: Option<Prepared>,
}

impl Assessment {
    fn reject(request_id: B256, coarse: CoarseReason, reason: impl Into<String>) -> Self {
        Self {
            verdict: Verdict::Reject,
            coarse,
            reasons: vec![reason.into()],
            summary: None,
            request_id,
            input_summary: String::new(),
            policy_hash: None,
            simulation_hash: None,
            prepared: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SubmitError {
    #[error("approval: {0}")]
    Approval(#[from] mw_core::ApprovalError),
    #[error("chain: {0}")]
    Chain(#[from] mw_chain::ChainError),
    #[error("signing: {0}")]
    Signing(#[from] mw_mpc::SignError),
    #[error("signature does not recover to the wallet")]
    BadSignature,
    #[error("RPC returned tx hash {returned}, expected {expected}")]
    HashMismatch { expected: B256, returned: B256 },
}

pub struct JudgeNode<C, S, L, T, N, K, A> {
    pub(crate) config: NodeConfig,
    pub(crate) parts: Components<C, S, L, T, N, K>,
    pub(crate) policies: PolicyStore,
    pub(crate) approvals: ApprovalRegistry,
    pub(crate) guard: Mutex<WalletGuard>,
    pub(crate) audit: Mutex<AuditLog<A>>,
    pub(crate) pending: Mutex<HashMap<B256, Pending>>,
    pub(crate) passkeys: Mutex<HashMap<Address, RegisteredPasskey>>,
    /// 提案とユーザー操作を 1 件ずつ処理する(nonce の競合を避ける)
    pub(crate) serial: tokio::sync::Mutex<()>,
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
    pub fn new(
        config: NodeConfig,
        parts: Components<C, S, L, T, N, K>,
        audit: AuditLog<A>,
    ) -> Self {
        Self {
            guard: Mutex::new(WalletGuard::new(config.guard.clone())),
            config,
            parts,
            policies: PolicyStore::default(),
            approvals: ApprovalRegistry::new(),
            audit: Mutex::new(audit),
            pending: Mutex::new(HashMap::new()),
            passkeys: Mutex::new(HashMap::new()),
            serial: tokio::sync::Mutex::new(()),
        }
    }

    pub fn parts(&self) -> &Components<C, S, L, T, N, K> {
        &self.parts
    }

    pub fn wallet(&self) -> Address {
        self.parts.signer.address()
    }

    /// パスキー検証を通さずに方針を登録する(不変条件 6 を満たさない)。テスト専用。
    #[cfg(feature = "unverified-policy")]
    pub fn install_unverified_policy(
        &self,
        policy: Policy,
    ) -> Result<(), crate::policy_store::PolicyStoreError> {
        self.policies.install_verified(policy)
    }

    /// ユーザー操作による凍結。署名なしでできる。現在の凍結の世代を返す。
    pub fn freeze(&self, wallet: Address) -> u64 {
        let mut guard = self.guard.lock().expect("guard poisoned");
        if guard.freeze(wallet) {
            self.parts.notifier.notify(UserNotice::Frozen {
                wallet,
                reason: "frozen by user".into(),
            });
        }
        guard.freeze_epoch(wallet)
    }

    pub fn is_frozen(&self, wallet: Address) -> bool {
        self.guard.lock().expect("guard poisoned").is_frozen(wallet)
    }

    pub fn audit_log(&self) -> std::sync::MutexGuard<'_, AuditLog<A>> {
        self.audit.lock().expect("audit poisoned")
    }

    /// エージェントからの提案を処理する。エージェントには粗い結果だけを返す。
    ///
    /// `peer` は提案してきた A とのセッション。承認したときだけ、閾値署名に使う。
    pub async fn handle_proposal(&self, proposal: Proposal, peer: &mut T::Peer) -> AgentOutcome {
        let _serial = self.serial.lock().await;
        let wallet = proposal.wallet;

        // 別のウォレット宛ての提案は、レート制限の状態を作る前に弾く
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

        let assessment = self.assess(&proposal).await;

        // 監査ログに残せなければ、署名に進まない
        if let Err(e) = self.record_audit(wallet, &assessment) {
            self.parts.notifier.notify(UserNotice::SubmissionFailed {
                wallet,
                request_id: assessment.request_id,
                error: format!("audit log: {e}"),
            });
            return AgentOutcome::Rejected {
                reason: CoarseReason::Unavailable,
            };
        }

        let newly_frozen = self.guard.lock().expect("guard poisoned").record(
            wallet,
            assessment.verdict,
            self.parts.clock.now_unix(),
        );
        if newly_frozen {
            self.parts.notifier.notify(UserNotice::Frozen {
                wallet,
                reason: "too many rejected proposals in a short time".into(),
            });
        }

        match (assessment.verdict, assessment.prepared) {
            (Verdict::Approve, Some(_)) if self.is_frozen(wallet) => {
                // 判定中にユーザーが凍結した
                AgentOutcome::Frozen
            }
            (Verdict::Approve, Some(prepared)) => {
                match self
                    .submit(wallet, prepared, ApprovalOrigin::Judge, peer)
                    .await
                {
                    Ok(tx_hash) => {
                        self.parts
                            .notifier
                            .notify(UserNotice::Submitted { wallet, tx_hash });
                        AgentOutcome::Submitted { tx_hash }
                    }
                    Err(e) => {
                        self.parts.notifier.notify(UserNotice::SubmissionFailed {
                            wallet,
                            request_id: assessment.request_id,
                            error: e.to_string(),
                        });
                        AgentOutcome::Rejected {
                            reason: CoarseReason::Unavailable,
                        }
                    }
                }
            }
            (Verdict::NeedsUserConfirmation, Some(prepared)) => {
                self.parts.notifier.notify(UserNotice::NeedsConfirmation {
                    wallet,
                    request_id: assessment.request_id,
                    reasons: assessment.reasons.clone(),
                    summary: assessment.summary.clone(),
                });
                self.pending.lock().expect("pending poisoned").insert(
                    assessment.request_id,
                    Pending {
                        prepared,
                        created_at: self.parts.clock.now_unix(),
                        reasons: assessment.reasons,
                        summary: assessment.summary,
                        input_summary: assessment.input_summary,
                        approved: false,
                    },
                );
                AgentOutcome::PendingUserConfirmation {
                    request_id: assessment.request_id,
                }
            }
            _ => {
                self.parts.notifier.notify(UserNotice::Rejected {
                    wallet,
                    request_id: assessment.request_id,
                    reasons: assessment.reasons,
                });
                AgentOutcome::Rejected {
                    reason: assessment.coarse,
                }
            }
        }
    }

    async fn assess(&self, proposal: &Proposal) -> Assessment {
        let wallet = proposal.wallet;

        // 1. 生の未署名 tx を自分でデコードする(エージェントの説明は使わない)
        let decoded = match decode_unsigned(&proposal.unsigned_tx) {
            Ok(decoded) => decoded,
            Err(e) => {
                return Assessment::reject(
                    keccak256(&proposal.unsigned_tx),
                    CoarseReason::InvalidRequest,
                    format!("cannot decode transaction: {e}"),
                );
            }
        };
        let request_id = decoded.signing_hash;
        let tx = &decoded.tx;

        // 2. chainId と from を束縛する
        if proposal.chain_id != self.config.chain_id || tx.chain_id != self.config.chain_id {
            return Assessment::reject(
                request_id,
                CoarseReason::InvalidRequest,
                format!(
                    "chain id mismatch: proposal {}, tx {}, node {}",
                    proposal.chain_id, tx.chain_id, self.config.chain_id
                ),
            );
        }

        // 3. 時刻の証拠と nonce をチェーンから取る。将来 nonce は受け付けない
        let (witness, pending_nonce) = match self.time_and_nonce(wallet).await {
            Ok(v) => v,
            Err(e) => {
                return Assessment::reject(request_id, CoarseReason::Unavailable, e.to_string());
            }
        };
        if tx.nonce != pending_nonce {
            return Assessment::reject(
                request_id,
                CoarseReason::InvalidRequest,
                format!(
                    "nonce {} is not the next nonce of the account ({pending_nonce})",
                    tx.nonce
                ),
            );
        }

        let key = SigningRequestKey {
            chain_id: tx.chain_id,
            from: wallet,
            nonce: tx.nonce,
            signing_hash: decoded.signing_hash,
            payload_hash: keccak256(&decoded.payload),
        };
        let call = decode_known_call(&tx.input);
        let simulation_request = SimulationRequest {
            chain_id: tx.chain_id,
            from: wallet,
            to: tx.to.to().copied(),
            input: tx.input.clone(),
            value: tx.value,
            gas_limit: tx.gas_limit,
            max_fee_per_gas: tx.max_fee_per_gas,
            block_number: Some(witness.block_number),
        };
        let prepared = Prepared {
            decoded: decoded.clone(),
            key,
            witness,
        };

        // 4. 方針がなければユーザーに確認する
        let Some(policy) = self.policies.get(wallet) else {
            return Assessment {
                verdict: Verdict::NeedsUserConfirmation,
                coarse: CoarseReason::PolicyViolation,
                reasons: vec!["no policy is registered for this wallet".into()],
                summary: None,
                request_id,
                input_summary: String::new(),
                policy_hash: None,
                simulation_hash: None,
                prepared: Some(prepared),
            };
        };
        let policy_hash = Some(policy.hash());

        // 5. 自分でシミュレーションする
        let report = match self.parts.simulator.simulate(&simulation_request).await {
            Ok(report) => report,
            Err(e) => {
                let mut a = Assessment::reject(
                    request_id,
                    CoarseReason::Unavailable,
                    format!("simulation unavailable: {e}"),
                );
                a.policy_hash = policy_hash;
                return a;
            }
        };
        let simulation_hash = Some(report.raw_response_hash);
        let effects = Effects::new(wallet, &decoded, call.as_ref(), &report);
        let input_summary = escape_data(&effects);

        let base = Assessment {
            verdict: Verdict::Reject,
            coarse: CoarseReason::PolicyViolation,
            reasons: Vec::new(),
            summary: None,
            request_id,
            input_summary,
            policy_hash,
            simulation_hash,
            prepared: Some(prepared),
        };

        if !report.success {
            return Assessment {
                coarse: CoarseReason::SimulationFailed,
                reasons: vec!["the transaction reverts in simulation".into()],
                prepared: None,
                ..base
            };
        }

        // 6. デコード結果とシミュレーション結果を検算する
        let discrepancies = crosscheck(
            wallet,
            &decoded,
            call.as_ref(),
            &report,
            witness.block_number,
        );
        if !discrepancies.is_empty() {
            return Assessment {
                verdict: Verdict::NeedsUserConfirmation,
                reasons: discrepancies.iter().map(ToString::to_string).collect(),
                ..base
            };
        }

        // 7. 効果を方針と照合する
        self.llm_judgement(&policy, &effects, proposal, base).await
    }

    async fn llm_judgement(
        &self,
        policy: &Policy,
        effects: &Effects,
        proposal: &Proposal,
        base: Assessment,
    ) -> Assessment {
        let data = JudgeData::new(&policy.text, effects, &proposal.agent_note);
        let request = build_request(&data);
        let outcome = judge(&self.parts.llm, &request, self.config.llm_samples).await;
        let summary = outcome.samples.iter().find_map(|s| match s {
            mw_judge::SampleResult::Judged(j) => Some(j.user_summary.clone()),
            _ => None,
        });
        let mut reasons = outcome.reasons();
        reasons.push(format!("model: {}", outcome.model_id));
        Assessment {
            verdict: outcome.verdict,
            reasons,
            summary,
            ..base
        }
    }

    pub(crate) async fn time_and_nonce(
        &self,
        wallet: Address,
    ) -> Result<(TimeWitness, u64), mw_chain::ChainError> {
        let block = self.parts.chain.latest_block().await?;
        let nonce = self.parts.chain.pending_nonce(wallet).await?;
        let witness = TimeWitness {
            local_unix: self.parts.clock.now_unix(),
            block_number: block.number,
            block_timestamp: block.timestamp,
        };
        Ok((witness, nonce))
    }

    fn record_audit(&self, wallet: Address, a: &Assessment) -> Result<(), mw_audit::AuditError> {
        self.append_audit(AuditRecord {
            wallet,
            proposal_hash: a.request_id,
            input_summary: a.input_summary.clone(),
            policy_hash: a.policy_hash,
            simulation_hash: a.simulation_hash,
            verdict: a.verdict,
            reasons: a.reasons.clone(),
        })
    }

    pub(crate) fn append_audit(&self, record: AuditRecord) -> Result<(), mw_audit::AuditError> {
        self.audit
            .lock()
            .expect("audit poisoned")
            .append(record, self.parts.clock.now_unix())
            .map(|_| ())
    }

    /// 承認を登録してから、引き換えて署名・送信する。
    async fn submit(
        &self,
        wallet: Address,
        prepared: Prepared,
        origin: ApprovalOrigin,
        peer: &mut T::Peer,
    ) -> Result<B256, SubmitError> {
        self.approvals.insert(Approval {
            key: prepared.key,
            issued: prepared.witness,
            origin,
        })?;
        self.redeem_and_submit(wallet, prepared, peer).await
    }

    /// 登録済みの承認を、直前に取り直した時刻と nonce で引き換えてから署名・送信する。
    pub(crate) async fn redeem_and_submit(
        &self,
        wallet: Address,
        prepared: Prepared,
        peer: &mut T::Peer,
    ) -> Result<B256, SubmitError> {
        let (now, pending_nonce) = self.time_and_nonce(wallet).await?;
        let approved = self.approvals.redeem(&prepared.key, &now, pending_nonce)?;

        let signature = self.parts.signer.sign(approved, peer).await?;
        let recovered = signature
            .recover_address_from_prehash(&prepared.key.signing_hash)
            .map_err(|_| SubmitError::BadSignature)?;
        if recovered != wallet {
            return Err(SubmitError::BadSignature);
        }

        // 署名済み tx は B の外に出さない。自分で送信し、hash だけを返す(不変条件 5)
        let (raw, tx_hash) = encode_signed(prepared.decoded.tx, signature);
        let returned = self.parts.chain.send_raw_transaction(raw).await?;
        if returned != tx_hash {
            return Err(SubmitError::HashMismatch {
                expected: tx_hash,
                returned,
            });
        }
        Ok(tx_hash)
    }
}
