//! A と B をつないだエンドツーエンドのテスト(チェーン・シミュレータ・LLM はモック)。
//!
//! 1. mTLS 越しに 2-of-3 の鍵生成(A 側は A と C、B 側は B)
//! 2. A の提案 → B の判定 → A+B の閾値署名 → B が送信
//! 3. B から A に流れたバイト列に、最終署名が一度も現れないこと

#![allow(clippy::unwrap_used)]

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, TxKind, U256};
use mw_audit::{AuditLog, MemorySink};
use mw_chain::{BlockInfo, MockChain};
use mw_core::{AgentOutcome, CoarseReason, Policy, Proposal, UntrustedText};
use mw_judge::ScriptedLlm;
use mw_mpc::protocol::{KeyShare, PARTY_A, PARTY_B, PARTY_C};
use mw_node_a::session::{BConnection, keygen, propose, resume, user_request};
use mw_node_a::shares::{load_share_c, save_share_c};
use mw_node_b::{
    Components, DEFAULT_ORIGIN, DEFAULT_RP_ID, JudgeNode, ManualClock, NodeConfig,
    RecordingNotifier,
};
use mw_node_b_server::CggmpSigner;
use mw_node_b_server::keygen::run_keygen;
use mw_node_b_server::server::serve_connection;
use mw_policy::software::SoftwarePasskey;
use mw_policy::{UserOperation, UserRequest, UserResponse};
use mw_simulator::{AssetTransfer, ScriptedSimulator, SimulationReport};
use mw_wire::tls::{client_config, generate_pki, server_config, server_name};
use mw_wire::{AtoB, BtoA, Connection};
use secrecy::SecretString;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CHAIN_ID: u64 = 84532;
const BLOCK: BlockInfo = BlockInfo {
    number: 100,
    timestamp: 1_700_000_000,
};
const BOB: Address = Address::repeat_byte(0xb0);
const AMOUNT: u64 = 10_000_000_000_000_000;

/// 読んだバイト列をすべて記録するストリーム。
struct Tap {
    inner: DuplexStream,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        let new = buf.filled()[before..].to_vec();
        self.seen.lock().unwrap().extend_from_slice(&new);
        result
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// mTLS で鍵生成を行い、(A, C, B) のシェアを返す。
async fn keygen_over_tls() -> (KeyShare, KeyShare, KeyShare) {
    let pki = generate_pki().unwrap();
    let server = server_config(&pki.ca_pem, &pki.node_b_cert_pem, &pki.node_b_key_pem).unwrap();
    let client = client_config(&pki.ca_pem, &pki.node_a_cert_pem, &pki.node_a_key_pem).unwrap();
    let (a_io, b_io) = tokio::io::duplex(1 << 20);

    let b_side = async move {
        let tls = TlsAcceptor::from(server).accept(b_io).await.unwrap();
        let mut conn = Connection::new(tls);
        let output = run_keygen(&mut conn, None).await.unwrap();
        let address = mw_mpc::protocol::address_of(&output.share.shared_public_key);
        conn.send(&BtoA::KeygenStored { address }).await.unwrap();
        output.share
    };
    let a_side = async move {
        let tls = TlsConnector::from(client)
            .connect(server_name(), a_io)
            .await
            .unwrap();
        let mut conn: BConnection<_> = Connection::new(tls);
        keygen(&mut conn, None, &|_| {}).await.unwrap()
    };
    let (share_b, out) = tokio::join!(tokio::spawn(b_side), tokio::spawn(a_side));
    let (share_b, out) = (share_b.unwrap(), out.unwrap());
    assert_eq!(out.share_a.i, PARTY_A);
    assert_eq!(out.share_c.i, PARTY_C);
    assert_eq!(share_b.i, PARTY_B);
    (out.share_a, out.share_c, share_b)
}

type Node = JudgeNode<
    MockChain,
    ScriptedSimulator,
    ScriptedLlm,
    CggmpSigner<DuplexStream>,
    RecordingNotifier,
    ManualClock,
    MemorySink,
>;

fn node(share_b: KeyShare, verdicts: &str) -> Node {
    node_with(share_b, verdicts, true)
}

fn node_with(share_b: KeyShare, verdicts: &str, with_policy: bool) -> Node {
    let signer = CggmpSigner::<DuplexStream>::new(share_b).unwrap();
    let wallet = signer.wallets()[0];
    let chain = MockChain::new(CHAIN_ID, BLOCK);
    chain.set_nonce(wallet, 0);
    let judgement = serde_json::json!({
        "verdict": verdicts, "reasons": ["ok"], "user_summary": "s"
    })
    .to_string();
    let node = JudgeNode::new(
        NodeConfig::new(CHAIN_ID),
        Components {
            chain,
            simulator: ScriptedSimulator::new([Ok(SimulationReport {
                success: true,
                gas_used: 21_000,
                block_number: BLOCK.number,
                transfers: vec![AssetTransfer {
                    token: None,
                    from: wallet,
                    to: BOB,
                    amount: U256::from(AMOUNT),
                    symbol: None,
                    decimals: None,
                }],
                allowance_changes: vec![],
                unrecognized_changes: vec![],
                raw_response_hash: B256::ZERO,
            })]),
            llm: ScriptedLlm::new(vec![Ok(judgement); 3]),
            signer,
            notifier: RecordingNotifier::default(),
            clock: ManualClock::new(BLOCK.timestamp),
        },
        AuditLog::new(MemorySink::default()),
    );
    if !with_policy {
        return node;
    }
    node.install_unverified_policy(Policy {
        wallet,
        version: 1,
        text: "small transfers are fine".into(),
    })
    .unwrap();
    node
}

fn proposal(wallet: Address) -> Proposal {
    let tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: 21_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000,
        to: TxKind::Call(BOB),
        value: U256::from(AMOUNT),
        access_list: Default::default(),
        input: Default::default(),
    };
    let mut unsigned = Vec::new();
    tx.encode_for_signing(&mut unsigned);
    Proposal {
        wallet,
        chain_id: CHAIN_ID,
        unsigned_tx: unsigned.into(),
        agent_note: UntrustedText::new("coffee"),
    }
}

/// 提案を 1 件流し、(結果, B→A のバイト列) を返す。
async fn run_proposal(node: &Node, share_a: &KeyShare, p: Proposal) -> (AgentOutcome, Vec<u8>) {
    let (a_io, b_io) = tokio::io::duplex(1 << 20);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let tap = Tap {
        inner: a_io,
        seen: seen.clone(),
    };
    let b_side = serve_connection(node, Connection::new(b_io), None, None, || {});
    let a_side = async {
        let mut conn: BConnection<Tap> = Connection::new(tap);
        let outcome = propose(&mut conn, share_a, p).await.unwrap();
        drop(conn);
        outcome
    };
    let (served, outcome) = tokio::join!(b_side, a_side);
    served.unwrap();
    let bytes = seen.lock().unwrap().clone();
    (outcome, bytes)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn keygen_propose_sign_and_submit() {
    let (share_a, share_c, share_b) = keygen_over_tls().await;

    // シェア C はパスフレーズで暗号化して保存し、同じパスフレーズでだけ戻せる
    let dir = tempfile::tempdir().unwrap();
    let pass = SecretString::from("correct horse battery staple");
    save_share_c(dir.path(), &share_c, &pass).unwrap();
    let raw = std::fs::read(dir.path().join("share-c.age")).unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("\"i\""));
    assert!(load_share_c(dir.path(), &SecretString::from("wrong")).is_err());
    assert_eq!(
        load_share_c(dir.path(), &pass).unwrap().shared_public_key,
        share_c.shared_public_key
    );

    // 承認される提案: A+B で署名し、B が送信する
    let node = node(share_b.clone(), "approve");
    let wallet = node.parts().signer.wallets()[0];
    let (outcome, b_to_a) = run_proposal(&node, &share_a, proposal(wallet)).await;
    let sent = node.parts().chain.sent();
    assert_eq!(sent.len(), 1);
    let envelope = TxEnvelope::decode_2718(&mut sent[0].as_ref()).unwrap();
    assert_eq!(envelope.recover_signer().unwrap(), wallet);
    assert_eq!(
        outcome,
        AgentOutcome::Submitted {
            tx_hash: *envelope.tx_hash()
        }
    );

    // A には最終署名(s)も署名済み tx も届いていない
    let s = envelope.signature().s().to_be_bytes::<32>();
    let s_hex = alloy_primitives::hex::encode(s);
    let text = String::from_utf8_lossy(&b_to_a).to_lowercase();
    assert!(!text.contains(&s_hex), "B leaked the final signature to A");
    assert!(
        !b_to_a.windows(32).any(|w| w == s),
        "B leaked s as raw bytes"
    );
    assert!(!text.contains(&alloy_primitives::hex::encode(&sent[0])));

    // 提案と違う tx への署名要求を、A は断る
    let reply = decline_mismatched_request(&share_a, proposal(wallet)).await;
    assert!(matches!(reply, AtoB::Decline { .. }), "{reply:?}");

    // 方針なし → 要確認 → パスキーで承認 → A が再開して送信
    user_approval_over_the_wire(share_b.clone(), &share_a).await;

    // A をなくしたとき: B+C で復旧
    recovery_with_b_and_c(share_b.clone(), &share_c).await;

    // EIP-712: A+B で署名し、署名が A(エージェント)に返る
    typed_data_signature(share_b.clone(), &share_a).await;

    // serve のまま 2 つ目のウォレットを作る(パスキーはこの接続の上で登録される)
    second_wallet_while_serving(share_b.clone()).await;

    // 拒否される提案: 署名要求は来ず、何も送信されない
    let node = self::node(share_b, "reject");
    let (outcome, _) = run_proposal(&node, &share_a, proposal(wallet)).await;
    assert_eq!(
        outcome,
        AgentOutcome::Rejected {
            reason: CoarseReason::PolicyViolation
        }
    );
    assert!(node.parts().chain.sent().is_empty());
}

/// 偽の B が、提案と違う hash への署名を求める。A の返事を返す。
async fn decline_mismatched_request(share_a: &KeyShare, p: Proposal) -> AtoB {
    let (a_io, b_io) = tokio::io::duplex(1 << 16);
    let fake_b = async move {
        let mut conn: Connection<DuplexStream, BtoA, AtoB> = Connection::new(b_io);
        let AtoB::Propose { .. } = conn.recv().await.unwrap() else {
            panic!("expected a proposal");
        };
        conn.send(&BtoA::SignRequest {
            session: B256::repeat_byte(1),
            signing_hash: B256::repeat_byte(0xee),
        })
        .await
        .unwrap();
        let reply = conn.recv().await.unwrap();
        conn.send(&BtoA::Outcome {
            outcome: AgentOutcome::Rejected {
                reason: CoarseReason::Unavailable,
            },
        })
        .await
        .unwrap();
        reply
    };
    let a = async move {
        let mut conn: BConnection<DuplexStream> = Connection::new(a_io);
        propose(&mut conn, share_a, p).await.unwrap()
    };
    let (reply, outcome) = tokio::join!(fake_b, a);
    assert_eq!(
        outcome,
        AgentOutcome::Rejected {
            reason: CoarseReason::Unavailable
        }
    );
    reply
}

/// 1 本の接続で B と話す。
async fn with_b<T>(
    node: &Node,
    session: impl AsyncFnOnce(&mut BConnection<DuplexStream>) -> T,
) -> T {
    let (a_io, b_io) = tokio::io::duplex(1 << 20);
    let b_side = serve_connection(node, Connection::new(b_io), None, None, || {});
    let a_side = async {
        let mut conn: BConnection<DuplexStream> = Connection::new(a_io);
        let out = session(&mut conn).await;
        drop(conn);
        out
    };
    let (served, out) = tokio::join!(b_side, a_side);
    served.unwrap();
    out
}

async fn user_approval_over_the_wire(share_b: KeyShare, share_a: &KeyShare) {
    // 方針がないので、提案は必ず要確認になる
    let node = node_with(share_b, "approve", false);
    let wallet = node.parts().signer.wallets()[0];
    let mut passkey = SoftwarePasskey::generate(DEFAULT_RP_ID, DEFAULT_ORIGIN);
    node.register_passkey(wallet, passkey.registration())
        .unwrap();

    let request_id = match with_b(&node, async |c| propose(c, share_a, proposal(wallet)).await)
        .await
        .unwrap()
    {
        AgentOutcome::PendingUserConfirmation { request_id } => request_id,
        other => panic!("expected pending, got {other:?}"),
    };

    // 承認前の再開は保留のまま
    let early = with_b(&node, async |c| {
        resume(c, share_a, wallet, request_id).await
    })
    .await
    .unwrap();
    assert_eq!(early, AgentOutcome::PendingUserConfirmation { request_id });

    let signed = passkey.sign(UserOperation::ApproveRequest { wallet, request_id });
    let approved = with_b(&node, async |c| {
        user_request(c, UserRequest::Signed { signed }).await
    })
    .await
    .unwrap();
    assert_eq!(approved, UserResponse::Approved { request_id });

    let outcome = with_b(&node, async |c| {
        resume(c, share_a, wallet, request_id).await
    })
    .await
    .unwrap();
    let AgentOutcome::Submitted { tx_hash } = outcome else {
        panic!("expected submission, got {outcome:?}");
    };
    let sent = node.parts().chain.sent();
    assert_eq!(sent.len(), 1);
    let envelope = TxEnvelope::decode_2718(&mut sent[0].as_ref()).unwrap();
    assert_eq!(*envelope.tx_hash(), tx_hash);
    assert_eq!(envelope.recover_signer().unwrap(), wallet);
}

/// A の端末をなくしたとき: 凍結中でも、パスキー承認 + C のシェアで B と署名して全額を移せる。
async fn recovery_with_b_and_c(share_b: KeyShare, share_c: &KeyShare) {
    let node = node_with(share_b, "reject", false);
    let wallet = node.parts().signer.wallets()[0];
    let mut passkey = SoftwarePasskey::generate(DEFAULT_RP_ID, DEFAULT_ORIGIN);
    node.register_passkey(wallet, passkey.registration())
        .unwrap();
    node.freeze(wallet);

    let unsigned = proposal(wallet).unsigned_tx;
    let signing_hash = alloy_primitives::keccak256(&unsigned);

    // 別の tx への承認では通らない
    let wrong = passkey.sign(UserOperation::ApproveRecovery {
        wallet,
        signing_hash: B256::repeat_byte(0xee),
    });
    let outcome = with_b(&node, async |c| {
        mw_node_a::session::recover(c, share_c, wrong, unsigned.clone()).await
    })
    .await
    .unwrap();
    assert!(
        matches!(outcome, AgentOutcome::Rejected { .. }),
        "{outcome:?}"
    );

    let signed = passkey.sign(UserOperation::ApproveRecovery {
        wallet,
        signing_hash,
    });
    let outcome = with_b(&node, async |c| {
        mw_node_a::session::recover(c, share_c, signed, unsigned.clone()).await
    })
    .await
    .unwrap();
    let AgentOutcome::Submitted { tx_hash } = outcome else {
        panic!("expected submission, got {outcome:?}");
    };
    let sent = node.parts().chain.sent();
    assert_eq!(sent.len(), 1);
    let envelope = TxEnvelope::decode_2718(&mut sent[0].as_ref()).unwrap();
    assert_eq!(*envelope.tx_hash(), tx_hash);
    assert_eq!(envelope.recover_signer().unwrap(), wallet);
}

async fn typed_data_signature(share_b: KeyShare, share_a: &KeyShare) {
    let node = node_with(share_b, "approve", true);
    let wallet = node.parts().signer.wallets()[0];
    let typed = serde_json::json!({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Mail": [{"name": "contents", "type": "string"}]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Test",
            "chainId": CHAIN_ID,
            "verifyingContract": "0x0000000000000000000000000000000000000001"
        },
        "message": {"contents": "hello"}
    });
    let proposal = mw_core::TypedDataProposal {
        wallet,
        chain_id: CHAIN_ID,
        typed_data: typed.clone(),
        agent_note: UntrustedText::new("login"),
    };
    let outcome = with_b(&node, async |c| {
        mw_node_a::session::propose_typed_data(c, share_a, proposal).await
    })
    .await
    .unwrap();
    let AgentOutcome::Signed { signature } = outcome else {
        panic!("expected a signature, got {outcome:?}");
    };
    let sig = alloy_primitives::Signature::try_from(signature.as_ref()).unwrap();
    let digest = mw_chain::decode_typed_data(&typed).unwrap().digest;
    assert_eq!(sig.recover_address_from_prehash(&digest).unwrap(), wallet);
    assert!(node.parts().chain.sent().is_empty());
}

/// `serve` の接続で新しいウォレットを作る。パスキーがなければ断る。
async fn second_wallet_while_serving(share_b: KeyShare) {
    let node = node_with(share_b, "approve", false);
    let first = node.parts().signer.wallets()[0];
    let keygen_service = mw_node_b_server::server::KeygenService {
        storage: Box::new(mw_tee::mock::InsecureMemoryStorage::default()),
        busy: tokio::sync::Mutex::new(()),
    };

    let run = |passkey: Option<mw_policy::RegisteredPasskey>| {
        let node = &node;
        let keygen_service = &keygen_service;
        async move {
            let (a_io, b_io) = tokio::io::duplex(1 << 20);
            let b_side = serve_connection(
                node,
                Connection::new(b_io),
                None,
                Some(keygen_service),
                || {},
            );
            let a_side = async {
                let mut conn: BConnection<DuplexStream> = Connection::new(a_io);
                let out = keygen(&mut conn, passkey, &|_| {}).await;
                drop(conn);
                out
            };
            let (served, out) = tokio::join!(b_side, a_side);
            let _ = served;
            out
        }
    };

    // パスキーのない鍵生成は断る
    assert!(run(None).await.is_err());
    assert_eq!(node.parts().signer.wallets(), vec![first]);

    let mut passkey = SoftwarePasskey::generate(DEFAULT_RP_ID, DEFAULT_ORIGIN);
    let out = run(Some(passkey.registration())).await.unwrap();
    let second = out.address;
    assert_ne!(second, first);
    let mut wallets = vec![first, second];
    wallets.sort();
    assert_eq!(node.parts().signer.wallets(), wallets);
    assert!(
        keygen_service
            .storage
            .exists(&mw_node_b_server::share_label(second))
    );

    // 登録されたパスキーで、新しいウォレットのオーナー用の一覧を開ける
    let view = node
        .handle_user_request(UserRequest::Signed {
            signed: passkey.sign(UserOperation::ListPending {
                wallet: second,
                issued_at: 1_700_000_000,
            }),
        })
        .await;
    assert!(
        matches!(view, UserResponse::PendingRequests { .. }),
        "{view:?}"
    );
}
