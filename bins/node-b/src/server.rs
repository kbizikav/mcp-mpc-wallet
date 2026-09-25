//! A とユーザーアプリからの接続を処理する。

use mw_audit::AuditSink;
use mw_chain::ChainClient;
use mw_judge::LlmClient;
use mw_node_b::{Clock, JudgeNode, UserNotifier};
use mw_simulator::Simulator;
use mw_wire::{AtoB, BtoA, WireError};
use tokio::io::{AsyncRead, AsyncWrite};

use mw_mpc::protocol::{PARTY_A, PARTY_C};

use crate::AttestationService;
use crate::signer::{AConnection, CggmpSigner, PeerSession};

/// 1 本の接続で届く要求を順に処理する。署名済み tx は返さず、結果だけを返す。
///
/// `after_request` は要求を 1 件処理するたびに呼ばれる(状態の保存に使う)。
pub async fn serve_connection<C, Sim, L, N, K, A, S>(
    node: &JudgeNode<C, Sim, L, CggmpSigner<S>, N, K, A>,
    conn: AConnection<S>,
    attestation: Option<&AttestationService>,
    after_request: impl Fn(),
) -> Result<(), WireError>
where
    C: ChainClient,
    Sim: Simulator,
    L: LlmClient,
    N: UserNotifier,
    K: Clock,
    A: AuditSink,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut session = PeerSession::with_a(conn);
    loop {
        let msg = match session.conn.recv().await {
            Ok(msg) => msg,
            Err(WireError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
        match msg {
            AtoB::Propose { proposal } => {
                let outcome = node.handle_proposal(proposal, &mut session).await;
                after_request();
                session.conn.send(&BtoA::Outcome { outcome }).await?;
            }
            AtoB::Attest { nonce } => {
                let reply = match attestation {
                    Some(service) => service.respond(&nonce),
                    None => BtoA::Error {
                        message: "this node does not run in an enclave".into(),
                    },
                };
                session.conn.send(&reply).await?;
            }
            AtoB::ProposeTypedData { proposal } => {
                let outcome = node.handle_typed_data(proposal, &mut session).await;
                after_request();
                session.conn.send(&BtoA::Outcome { outcome }).await?;
            }
            AtoB::Resume { wallet, request_id } => {
                let outcome = node.resume(wallet, request_id, &mut session).await;
                after_request();
                session.conn.send(&BtoA::Outcome { outcome }).await?;
            }
            AtoB::Recover {
                signed,
                unsigned_tx,
            } => {
                // 復旧では、相手は C のシェアで署名に参加する
                session.cosigner = PARTY_C;
                let outcome = node.recover(signed, unsigned_tx, &mut session).await;
                session.cosigner = PARTY_A;
                after_request();
                session.conn.send(&BtoA::Outcome { outcome }).await?;
            }
            AtoB::User { request } => {
                let response = node.handle_user_request(request).await;
                after_request();
                session.conn.send(&BtoA::User { response }).await?;
            }
            // 中断した署名セッションの残り。読み捨てる
            AtoB::Decline { .. } | AtoB::PartialSignature { .. } | AtoB::Mpc { .. } => {}
            other => {
                let message = format!("unexpected message: {}", kind(&other));
                session
                    .conn
                    .send(&BtoA::Error {
                        message: message.clone(),
                    })
                    .await?;
                return Err(WireError::Unexpected(message));
            }
        }
    }
}

fn kind(msg: &AtoB) -> &'static str {
    match msg {
        AtoB::Propose { .. } => "propose",
        AtoB::Resume { .. } => "resume",
        AtoB::Attest { .. } => "attest",
        AtoB::ProposeTypedData { .. } => "propose_typed_data",
        AtoB::User { .. } => "user",
        AtoB::Recover { .. } => "recover",
        AtoB::Keygen { .. } => "keygen",
        AtoB::KeygenResult { .. } => "keygen_result",
        AtoB::Mpc { .. } => "mpc",
        AtoB::PartialSignature { .. } => "partial_signature",
        AtoB::Decline { .. } => "decline",
    }
}
