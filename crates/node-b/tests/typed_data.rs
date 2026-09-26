//! EIP-712 signatures: B computes the digest itself, judges it, and on approval returns the signature to the agent.

#![allow(clippy::unwrap_used)]

use alloy_primitives::{Signature, U256};
use mw_audit::{AuditLog, MemorySink};
use mw_chain::{BlockInfo, MockChain, decode_typed_data};
use mw_core::{AgentOutcome, CoarseReason, Policy, TypedDataProposal, UntrustedText};
use mw_judge::ScriptedLlm;
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
const SPENDER: &str = "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

type Node = JudgeNode<
    MockChain,
    ScriptedSimulator,
    ScriptedLlm,
    InsecureSingleKeySigner,
    RecordingNotifier,
    ManualClock,
    MemorySink,
>;

fn signer() -> InsecureSingleKeySigner {
    InsecureSingleKeySigner::from_secret_bytes(&[7u8; 32])
}

fn build(verdict: Option<&str>, with_policy: bool) -> Node {
    let judgement = verdict.map(|v| {
        serde_json::json!({"verdict": v, "reasons": ["r"], "user_summary": "s"}).to_string()
    });
    let node = JudgeNode::new(
        NodeConfig::new(CHAIN_ID),
        Components {
            chain: MockChain::new(
                CHAIN_ID,
                BlockInfo {
                    number: 100,
                    timestamp: NOW,
                },
            ),
            simulator: ScriptedSimulator::new([]),
            llm: ScriptedLlm::new(judgement.into_iter().cycle().take(3).map(Ok)),
            signer: signer(),
            notifier: RecordingNotifier::default(),
            clock: ManualClock::new(NOW),
        },
        AuditLog::new(MemorySink::default()),
    );
    if with_policy {
        node.install_unverified_policy(Policy {
            wallet: node.parts().signer.address(),
            version: 1,
            text: "Permits of up to 5 USDC to 0xb0b0... are fine.".into(),
        })
        .unwrap();
    }
    node
}

fn permit(chain_id: Option<u64>, value: &str) -> serde_json::Value {
    let mut domain = serde_json::json!({
        "name": "USDC",
        "version": "2",
        "verifyingContract": "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    });
    let mut domain_types = vec![
        serde_json::json!({"name": "name", "type": "string"}),
        serde_json::json!({"name": "version", "type": "string"}),
    ];
    if let Some(id) = chain_id {
        domain["chainId"] = serde_json::json!(id);
        domain_types.push(serde_json::json!({"name": "chainId", "type": "uint256"}));
    }
    domain_types.push(serde_json::json!({"name": "verifyingContract", "type": "address"}));
    serde_json::json!({
        "types": {
            "EIP712Domain": domain_types,
            "Permit": [
                {"name": "owner", "type": "address"},
                {"name": "spender", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"}
            ]
        },
        "primaryType": "Permit",
        "domain": domain,
        "message": {
            "owner": signer().address(),
            "spender": SPENDER,
            "value": value,
            "nonce": 0,
            "deadline": "1700003600"
        }
    })
}

fn proposal(typed_data: serde_json::Value) -> TypedDataProposal {
    TypedDataProposal {
        wallet: signer().address(),
        chain_id: CHAIN_ID,
        typed_data,
        agent_note: UntrustedText::new("permit for the swap router"),
    }
}

fn assert_valid_signature(outcome: &AgentOutcome, typed_data: &serde_json::Value) {
    let AgentOutcome::Signed { signature } = outcome else {
        panic!("expected a signature, got {outcome:?}");
    };
    assert_eq!(signature.len(), 65);
    let sig = Signature::try_from(signature.as_ref()).unwrap();
    let digest = decode_typed_data(typed_data).unwrap().digest;
    assert_eq!(
        sig.recover_address_from_prehash(&digest).unwrap(),
        signer().address()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn approved_permit_returns_a_signature_without_sending_anything() {
    let node = build(Some("approve"), true);
    let typed = permit(Some(CHAIN_ID), "5000000");
    let outcome = node
        .handle_typed_data(proposal(typed.clone()), &mut ())
        .await;
    assert_valid_signature(&outcome, &typed);
    assert!(node.parts().chain.sent().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn permit_for_another_chain_is_rejected() {
    let node = build(Some("approve"), true);
    let outcome = node
        .handle_typed_data(proposal(permit(Some(1), "1")), &mut ())
        .await;
    assert_eq!(
        outcome,
        AgentOutcome::Rejected {
            reason: CoarseReason::InvalidRequest
        }
    );
    assert!(node.parts().llm.requests().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_typed_data_is_rejected() {
    let node = build(Some("approve"), true);
    let outcome = node
        .handle_typed_data(
            proposal(serde_json::json!({"primaryType": "Permit"})),
            &mut (),
        )
        .await;
    assert_eq!(
        outcome,
        AgentOutcome::Rejected {
            reason: CoarseReason::InvalidRequest
        }
    );
}

#[tokio::test(flavor = "current_thread")]
async fn unlimited_permit_is_flagged_to_the_judge() {
    let node = build(Some("reject"), true);
    let outcome = node
        .handle_typed_data(
            proposal(permit(Some(CHAIN_ID), &U256::MAX.to_string())),
            &mut (),
        )
        .await;
    assert_eq!(
        outcome,
        AgentOutcome::Rejected {
            reason: CoarseReason::PolicyViolation
        }
    );
    let data: serde_json::Value =
        serde_json::from_str(&node.parts().llm.requests()[0].data).unwrap();
    assert_eq!(data["effects"]["kind"], "eip712_signature");
    assert_eq!(data["effects"]["grants"]["kind"], "erc2612_permit");
    assert_eq!(data["effects"]["grants"]["unlimited"], true);
    assert_eq!(data["effects"]["grants"]["owner_is_wallet"], true);
}

#[tokio::test(flavor = "current_thread")]
async fn permit_without_chain_id_needs_the_owner_then_resumes_to_a_signature() {
    let node = build(None, true);
    let wallet = node.parts().signer.address();
    let mut passkey = SoftwarePasskey::generate(DEFAULT_RP_ID, DEFAULT_ORIGIN);
    node.register_passkey(wallet, passkey.registration())
        .unwrap();

    let typed = permit(None, "1");
    let request_id = match node
        .handle_typed_data(proposal(typed.clone()), &mut ())
        .await
    {
        AgentOutcome::PendingUserConfirmation { request_id } => request_id,
        other => panic!("expected pending, got {other:?}"),
    };
    assert_eq!(request_id, decode_typed_data(&typed).unwrap().digest);
    assert!(node.parts().llm.requests().is_empty());

    // Typed data has no account nonce, so it can be approved and resumed even after the nonce moved on
    node.parts().chain.set_nonce(wallet, 5);
    let approved = node
        .handle_user_request(UserRequest::Signed {
            signed: passkey.sign(UserOperation::ApproveRequest { wallet, request_id }),
        })
        .await;
    assert_eq!(approved, UserResponse::Approved { request_id });

    let outcome = node.resume(wallet, request_id, &mut ()).await;
    assert_valid_signature(&outcome, &typed);
}
