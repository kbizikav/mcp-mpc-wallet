//! A から B へのセッション: 鍵生成と提案。

use std::sync::Arc;

use alloy_primitives::{Address, B256, keccak256};
use mw_core::{AgentOutcome, Proposal};
use mw_mpc::protocol::{
    KeyShare, PARTIES, PARTY_A, PARTY_C, PregeneratedPrimes, ProtocolError, SIGNERS_AB, address_of,
    aux_party, complete_share, execution_id, issue_partial, keygen_party, presign_party,
};
use mw_policy::{UserRequest, UserResponse};
use mw_wire::{AtoB, BtoA, Connection, WireError};
use rand_core::{OsRng, RngCore};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub type BConnection<S> = Connection<S, AtoB, BtoA>;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("connection: {0}")]
    Wire(#[from] WireError),
    #[error("connecting to B: {0}")]
    Connect(std::io::Error),
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("B reported an error: {0}")]
    Remote(String),
    #[error("unexpected message from B: {0}")]
    Unexpected(String),
    #[error("parties disagree on the wallet address")]
    AddressMismatch,
}

pub async fn connect(
    node_b: &str,
    tls: Arc<ClientConfig>,
) -> Result<BConnection<TlsStream<TcpStream>>, SessionError> {
    let tcp = TcpStream::connect(node_b)
        .await
        .map_err(SessionError::Connect)?;
    let stream = TlsConnector::from(tls)
        .connect(mw_wire::tls::server_name(), tcp)
        .await
        .map_err(SessionError::Connect)?;
    Ok(Connection::new(stream))
}

pub struct KeygenOutput {
    pub share_a: KeyShare,
    pub share_c: KeyShare,
    pub address: Address,
}

/// B と 2-of-3 の鍵生成を行う。このプロセスは A と C のパーティを動かす。
pub async fn keygen<S>(conn: &mut BConnection<S>) -> Result<KeygenOutput, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 素数の生成は重いので、プロトコルを始める前に済ませておく
    let (primes_a, primes_c) = tokio::join!(
        tokio::task::spawn_blocking(|| PregeneratedPrimes::generate(&mut OsRng)),
        tokio::task::spawn_blocking(|| PregeneratedPrimes::generate(&mut OsRng)),
    );
    let mut primes = vec![
        primes_c.map_err(|e| SessionError::Unexpected(e.to_string()))?,
        primes_a.map_err(|e| SessionError::Unexpected(e.to_string()))?,
    ];

    let mut session = [0u8; 32];
    OsRng.fill_bytes(&mut session);
    conn.send(&AtoB::Keygen {
        session: B256::from(session),
    })
    .await?;
    match conn.recv().await? {
        BtoA::KeygenAccepted => {}
        BtoA::Error { message } => return Err(SessionError::Remote(message)),
        other => return Err(SessionError::Unexpected(format!("{other:?}"))),
    }

    let local = [PARTY_A, PARTY_C];
    let kg = execution_id(&session, "keygen");
    let incomplete = conn
        .run_mpc(
            PARTIES,
            &local,
            |msg| AtoB::Mpc { msg },
            BtoA::into_mpc,
            |i, party| {
                let kg = kg.clone();
                async move { keygen_party(&kg, i, party).await }
            },
        )
        .await?;

    let aux_eid = execution_id(&session, "aux");
    let aux = conn
        .run_mpc(
            PARTIES,
            &local,
            |msg| AtoB::Mpc { msg },
            BtoA::into_mpc,
            |i, party| {
                let aux_eid = aux_eid.clone();
                let primes = primes.pop().expect("one set of primes per local party");
                async move { aux_party(&aux_eid, i, primes, party).await }
            },
        )
        .await?;

    let mut shares = Vec::new();
    for (incomplete, aux) in incomplete.into_iter().zip(aux) {
        shares.push(complete_share(incomplete?, aux?)?);
    }
    let [share_a, share_c]: [KeyShare; 2] = shares
        .try_into()
        .map_err(|_| SessionError::Unexpected("expected two local shares".into()))?;
    if share_a.shared_public_key != share_c.shared_public_key {
        return Err(SessionError::AddressMismatch);
    }
    let address = address_of(&share_a.shared_public_key);

    match conn.recv().await? {
        BtoA::KeygenDone { address: b } if b == address => {}
        BtoA::KeygenDone { .. } => return Err(SessionError::AddressMismatch),
        other => return Err(SessionError::Unexpected(format!("{other:?}"))),
    }
    conn.send(&AtoB::KeygenResult { address }).await?;
    Ok(KeygenOutput {
        share_a,
        share_c,
        address,
    })
}

/// 提案を送り、B が承認したら署名に参加して、結果を返す。
///
/// B の署名要求は、この提案の tx の hash に対するもの 1 回だけに応じる。
pub async fn propose<S>(
    conn: &mut BConnection<S>,
    share_a: &KeyShare,
    proposal: Proposal,
) -> Result<AgentOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // EIP-1559 の未署名 tx では、ペイロードの keccak256 が署名する hash
    let expected_hash = keccak256(&proposal.unsigned_tx);
    conn.send(&AtoB::Propose { proposal }).await?;
    cosign_until_outcome(conn, share_a, expected_hash).await
}

/// ユーザーが承認した要求の署名・送信を B に再開させる。
///
/// `request_id` は提案した tx の signing hash なので、それ以外への署名要求には応じない。
pub async fn resume<S>(
    conn: &mut BConnection<S>,
    share_a: &KeyShare,
    wallet: Address,
    request_id: B256,
) -> Result<AgentOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    conn.send(&AtoB::Resume { wallet, request_id }).await?;
    cosign_until_outcome(conn, share_a, request_id).await
}

/// ユーザーアプリの要求を B に送る。
pub async fn user_request<S>(
    conn: &mut BConnection<S>,
    request: UserRequest,
) -> Result<UserResponse, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    conn.send(&AtoB::User { request }).await?;
    match conn.recv().await? {
        BtoA::User { response } => Ok(response),
        BtoA::Error { message } => Err(SessionError::Remote(message)),
        other => Err(SessionError::Unexpected(format!("{other:?}"))),
    }
}

/// B の署名要求のうち、`expected_hash` へのもの 1 回だけに応じ、最終結果を待つ。
async fn cosign_until_outcome<S>(
    conn: &mut BConnection<S>,
    share_a: &KeyShare,
    expected_hash: B256,
) -> Result<AgentOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut signed = false;
    loop {
        match conn.recv().await? {
            BtoA::SignRequest {
                session,
                signing_hash,
            } => {
                if signed || signing_hash != expected_hash {
                    conn.send(&AtoB::Decline {
                        reason: "signing request does not match the proposal".into(),
                    })
                    .await?;
                    continue;
                }
                signed = true;
                let eid = execution_id(&session.0, "presign");
                let presig = conn
                    .run_mpc(
                        SIGNERS_AB.len() as u16,
                        &[0],
                        |msg| AtoB::Mpc { msg },
                        BtoA::into_mpc,
                        |i, party| {
                            let eid = eid.clone();
                            async move { presign_party(&eid, i, &SIGNERS_AB, share_a, party).await }
                        },
                    )
                    .await?
                    .pop()
                    .ok_or_else(|| SessionError::Unexpected("no presignature".into()))??;
                // presignature はここで消費され、二度と使えない
                let partial = issue_partial(presig, &signing_hash);
                conn.send(&AtoB::PartialSignature {
                    partial: serde_json::to_value(&partial)
                        .map_err(|e| SessionError::Unexpected(e.to_string()))?,
                })
                .await?;
            }
            BtoA::Outcome { outcome } => return Ok(outcome),
            BtoA::Error { message } => return Err(SessionError::Remote(message)),
            // 断った署名要求の MPC メッセージは読み捨てる
            BtoA::Mpc { .. } => {}
            other => return Err(SessionError::Unexpected(format!("{other:?}"))),
        }
    }
}
