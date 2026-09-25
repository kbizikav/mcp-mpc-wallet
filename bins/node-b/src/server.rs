//! A からの接続を処理する。

use mw_audit::AuditSink;
use mw_chain::ChainClient;
use mw_judge::LlmClient;
use mw_node_b::{Clock, JudgeNode, UserNotifier};
use mw_simulator::Simulator;
use mw_wire::{AtoB, BtoA, WireError};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::signer::{AConnection, CggmpSigner};

/// 1 本の接続で届く提案を順に処理する。署名済み tx は返さず、結果だけを返す。
pub async fn serve_connection<C, Sim, L, N, K, A, S>(
    node: &JudgeNode<C, Sim, L, CggmpSigner<S>, N, K, A>,
    mut conn: AConnection<S>,
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
    loop {
        let msg = match conn.recv().await {
            Ok(msg) => msg,
            Err(WireError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
        match msg {
            AtoB::Propose { proposal } => {
                let outcome = node.handle_proposal(proposal, &mut conn).await;
                conn.send(&BtoA::Outcome { outcome }).await?;
            }
            // 中断した署名セッションの残り。読み捨てる
            AtoB::Decline { .. } | AtoB::PartialSignature { .. } | AtoB::Mpc { .. } => {}
            other => {
                let message = format!("unexpected message: {}", kind(&other));
                conn.send(&BtoA::Error {
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
        AtoB::Keygen { .. } => "keygen",
        AtoB::KeygenResult { .. } => "keygen_result",
        AtoB::Mpc { .. } => "mpc",
        AtoB::PartialSignature { .. } => "partial_signature",
        AtoB::Decline { .. } => "decline",
    }
}
