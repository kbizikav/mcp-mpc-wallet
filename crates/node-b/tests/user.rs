//! パスキー署名つきのユーザー操作と、ユーザーが承認した要求の再開。

#![allow(clippy::unwrap_used)]

use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{Address, B256, TxKind, U256};
use mw_audit::{AuditLog, MemorySink, verify_chain};
use mw_chain::{BlockInfo, MockChain};
use mw_core::{AgentOutcome, CoarseReason, Policy, Proposal, UntrustedText};
use mw_judge::ScriptedLlm;
use mw_mpc::ThresholdSigner;
use mw_mpc::insecure_test::InsecureSingleKeySigner;
use mw_node_b::{
    Components, DEFAULT_ORIGIN, DEFAULT_RP_ID, JudgeNode, ManualClock, NodeConfig,
    RecordingNotifier,
};
use mw_policy::software::SoftwarePasskey;
use mw_policy::{UserOperation, UserRequest, UserResponse};
use mw_simulator::ScriptedSimulator;

const CHAIN_ID: u64 = 84532;
const NOW: u64 = 1_700_000_000;
const BOB: Address = Address::repeat_byte(0xb0);

type Node = JudgeNode<
    MockChain,
    ScriptedSimulator,
    ScriptedLlm,
    InsecureSingleKeySigner,
    RecordingNotifier,
    ManualClock,
    MemorySink,
>;

fn setup() -> (Node, SoftwarePasskey) {
    let signer = InsecureSingleKeySigner::from_secret_bytes(&[7u8; 32]);
    let wallet = signer.address();
    let chain = MockChain::new(
        CHAIN_ID,
        BlockInfo {
            number: 100,
            timestamp: NOW,
        },
    );
    chain.set_nonce(wallet, 0);
    let node = JudgeNode::new(
        NodeConfig::new(CHAIN_ID),
        Components {
            chain,
            simulator: ScriptedSimulator::new([]),
            llm: ScriptedLlm::new([]),
            signer,
            notifier: RecordingNotifier::default(),
            clock: ManualClock::new(NOW),
        },
        AuditLog::new(MemorySink::default()),
    );
    let passkey = SoftwarePasskey::generate(DEFAULT_RP_ID, DEFAULT_ORIGIN);
    node.register_passkey(wallet, passkey.registration())
        .unwrap();
    (node, passkey)
}

async fn signed(node: &Node, passkey: &mut SoftwarePasskey, op: UserOperation) -> UserResponse {
    node.handle_user_request(UserRequest::Signed {
        signed: passkey.sign(op),
    })
    .await
}

fn policy(wallet: Address, version: u64) -> UserOperation {
    UserOperation::SetPolicy {
        policy: Policy {
            wallet,
            version,
            text: "small transfers only".into(),
        },
    }
}

/// 方針がないので必ず「要確認」になる提案。
fn proposal(wallet: Address) -> Proposal {
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000,
        to: TxKind::Call(BOB),
        value: U256::from(1_000u64),
        access_list: Default::default(),
        input: Default::default(),
    };
    let mut unsigned = Vec::new();
    tx.encode_for_signing(&mut unsigned);
    Proposal {
        wallet,
        chain_id: CHAIN_ID,
        unsigned_tx: unsigned.into(),
        agent_note: UntrustedText::new(""),
    }
}

async fn pending_request(node: &Node) -> B256 {
    match node.handle_proposal(proposal(node.wallet()), &mut ()).await {
        AgentOutcome::PendingUserConfirmation { request_id } => request_id,
        other => panic!("expected pending, got {other:?}"),
    }
}

fn is_error(r: &UserResponse) -> bool {
    matches!(r, UserResponse::Error { .. })
}

#[tokio::test(flavor = "current_thread")]
async fn policy_requires_the_registered_passkey() {
    let (node, mut passkey) = setup();
    let wallet = node.wallet();

    assert_eq!(
        signed(&node, &mut passkey, policy(wallet, 1)).await,
        UserResponse::PolicySet { version: 1 }
    );

    // 別のパスキー(同じ credential id を名乗っても)では変えられない
    let mut impostor = SoftwarePasskey::generate(DEFAULT_RP_ID, DEFAULT_ORIGIN);
    let mut forged = impostor.sign(policy(wallet, 2));
    forged.assertion.credential_id = passkey.credential_id.clone();
    let r = node
        .handle_user_request(UserRequest::Signed { signed: forged })
        .await;
    assert!(is_error(&r), "{r:?}");

    // 署名済みの操作の再送(カウンタが進まない)は受け付けない
    let replay = passkey.sign(policy(wallet, 3));
    let first = node
        .handle_user_request(UserRequest::Signed {
            signed: replay.clone(),
        })
        .await;
    assert_eq!(first, UserResponse::PolicySet { version: 3 });
    let second = node
        .handle_user_request(UserRequest::Signed { signed: replay })
        .await;
    assert!(is_error(&second));

    // 古いバージョンには戻せない
    assert!(is_error(
        &signed(&node, &mut passkey, policy(wallet, 2)).await
    ));

    // パスキーの差し替えは初回登録の口ではできない
    assert!(
        node.register_passkey(wallet, impostor.registration())
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn user_approval_then_resume_submits_once() {
    let (node, mut passkey) = setup();
    let wallet = node.wallet();
    let request_id = pending_request(&node).await;

    // 承認前の再開は保留のまま
    assert_eq!(
        node.resume(wallet, request_id, &mut ()).await,
        AgentOutcome::PendingUserConfirmation { request_id }
    );

    let approve = UserOperation::ApproveRequest { wallet, request_id };
    assert_eq!(
        signed(&node, &mut passkey, approve.clone()).await,
        UserResponse::Approved { request_id }
    );
    // 二重承認はできない
    assert!(is_error(&signed(&node, &mut passkey, approve).await));

    let outcome = node.resume(wallet, request_id, &mut ()).await;
    assert!(
        matches!(outcome, AgentOutcome::Submitted { .. }),
        "{outcome:?}"
    );
    assert_eq!(node.parts().chain.sent().len(), 1);

    // 同じ要求はもう使えない
    assert_eq!(
        node.resume(wallet, request_id, &mut ()).await,
        AgentOutcome::Rejected {
            reason: CoarseReason::InvalidRequest
        }
    );
    assert_eq!(node.parts().chain.sent().len(), 1);

    verify_chain(&node.audit_log().sink().entries).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn user_approval_expires_after_five_minutes() {
    let (node, mut passkey) = setup();
    let wallet = node.wallet();
    let request_id = pending_request(&node).await;
    signed(
        &node,
        &mut passkey,
        UserOperation::ApproveRequest { wallet, request_id },
    )
    .await;
    node.parts().clock.advance(301);
    assert_eq!(
        node.resume(wallet, request_id, &mut ()).await,
        AgentOutcome::Rejected {
            reason: CoarseReason::Unavailable
        }
    );
    assert!(node.parts().chain.sent().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn approval_of_a_stale_request_is_refused() {
    let (node, mut passkey) = setup();
    let wallet = node.wallet();
    let request_id = pending_request(&node).await;
    // 別の tx が先に通って nonce が進んだ
    node.parts().chain.set_nonce(wallet, 1);
    assert!(is_error(
        &signed(
            &node,
            &mut passkey,
            UserOperation::ApproveRequest { wallet, request_id },
        )
        .await
    ));
    assert_eq!(
        node.resume(wallet, request_id, &mut ()).await,
        AgentOutcome::Rejected {
            reason: CoarseReason::InvalidRequest
        }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_pending_request_cannot_be_approved() {
    let (node, mut passkey) = setup();
    let wallet = node.wallet();
    let request_id = pending_request(&node).await;
    assert_eq!(
        node.handle_user_request(UserRequest::RejectPending { wallet, request_id })
            .await,
        UserResponse::RequestRejected { request_id }
    );
    assert!(is_error(
        &signed(
            &node,
            &mut passkey,
            UserOperation::ApproveRequest { wallet, request_id },
        )
        .await
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn freeze_without_passkey_unfreeze_with_current_epoch() {
    let (node, mut passkey) = setup();
    let wallet = node.wallet();

    assert_eq!(
        node.handle_user_request(UserRequest::Freeze { wallet })
            .await,
        UserResponse::Frozen { freeze_epoch: 1 }
    );
    assert_eq!(
        node.handle_proposal(proposal(wallet), &mut ()).await,
        AgentOutcome::Frozen
    );

    // 別の世代に対する解除は通らない
    assert!(is_error(
        &signed(
            &node,
            &mut passkey,
            UserOperation::Unfreeze {
                wallet,
                freeze_epoch: 0
            },
        )
        .await
    ));
    assert_eq!(
        signed(
            &node,
            &mut passkey,
            UserOperation::Unfreeze {
                wallet,
                freeze_epoch: 1
            },
        )
        .await,
        UserResponse::Unfrozen
    );
    assert!(matches!(
        node.handle_proposal(proposal(wallet), &mut ()).await,
        AgentOutcome::PendingUserConfirmation { .. }
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn listing_pending_requires_a_fresh_signature() {
    let (node, mut passkey) = setup();
    let wallet = node.wallet();
    let request_id = pending_request(&node).await;

    let stale = signed(
        &node,
        &mut passkey,
        UserOperation::ListPending {
            wallet,
            issued_at: NOW - 3_600,
        },
    )
    .await;
    assert!(is_error(&stale));

    match signed(
        &node,
        &mut passkey,
        UserOperation::ListPending {
            wallet,
            issued_at: NOW,
        },
    )
    .await
    {
        UserResponse::PendingRequests { requests } => {
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].request_id, request_id);
            assert!(!requests[0].approved);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn state_survives_snapshot_and_restore() {
    let (node, mut passkey) = setup();
    let wallet = node.wallet();
    signed(&node, &mut passkey, policy(wallet, 4)).await;
    node.freeze(wallet);
    let snapshot = node.snapshot();

    let restored = setup_without_passkey();
    restored.restore(&snapshot).unwrap();
    assert_eq!(
        restored
            .handle_user_request(UserRequest::Status { wallet })
            .await,
        UserResponse::Status {
            wallet,
            frozen: true,
            freeze_epoch: 1,
            policy_version: Some(4),
            passkey_registered: true,
        }
    );
    // 署名カウンタも引き継がれるので、以前の assertion は再送できない
    assert_eq!(snapshot.passkeys[0].1.sign_count, passkey.sign_count);
}

fn setup_without_passkey() -> Node {
    let signer = InsecureSingleKeySigner::from_secret_bytes(&[7u8; 32]);
    let chain = MockChain::new(
        CHAIN_ID,
        BlockInfo {
            number: 100,
            timestamp: NOW,
        },
    );
    JudgeNode::new(
        NodeConfig::new(CHAIN_ID),
        Components {
            chain,
            simulator: ScriptedSimulator::new([]),
            llm: ScriptedLlm::new([]),
            signer,
            notifier: RecordingNotifier::default(),
            clock: ManualClock::new(NOW),
        },
        AuditLog::new(MemorySink::default()),
    )
}
