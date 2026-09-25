//! A から B へのセッション: 鍵生成と提案。

use std::sync::Arc;

use alloy_primitives::{Address, B256, Bytes, keccak256};
use mw_core::{AgentOutcome, Proposal, TypedDataProposal};
use mw_mpc::protocol::{
    KeyShare, PARTIES, PARTY_A, PARTY_C, PregeneratedPrimes, ProtocolError, address_of, aux_party,
    complete_share, execution_id, issue_partial, keygen_party, presign_party, signer_index,
    signers_with_b,
};
use mw_policy::{RegisteredPasskey, SignedUserOperation, UserRequest, UserResponse};
use mw_tee::verify::{ExpectedPcrs, verify_nitro_attestation};
use mw_wire::{AtoB, BtoA, Connection, WireError};
use rand_core::{OsRng, RngCore};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

pub type BConnection<S> = Connection<S, AtoB, BtoA>;

/// B への接続先。`expected` があれば、B が期待する enclave であることを attestation で確かめる。
#[derive(Clone)]
pub struct BEndpoint {
    pub addr: String,
    pub tls: Arc<ClientConfig>,
    pub expected: Option<ExpectedPcrs>,
}

impl BEndpoint {
    /// `tls_dir` の `node-a.pem` / `node-a.key`(と CA)から作る。
    ///
    /// PCR0 を指定すると、B の証明書はデプロイ CA ではなく attestation で信頼する。
    pub fn from_files(
        addr: &str,
        tls_dir: &std::path::Path,
        expected_pcr0: Option<&str>,
    ) -> Result<Self, SessionError> {
        use mw_wire::tls::{client_config, client_config_for_attested_server, read_pem};
        let config = |e: mw_wire::tls::TlsError| SessionError::Config(e.to_string());
        let cert = read_pem(&tls_dir.join("node-a.pem")).map_err(config)?;
        let key = read_pem(&tls_dir.join("node-a.key")).map_err(config)?;
        let (tls, expected) = match expected_pcr0 {
            Some(pcr0) => (
                client_config_for_attested_server(&cert, &key).map_err(config)?,
                Some(ExpectedPcrs::pcr0(pcr0).map_err(|e| SessionError::Config(e.to_string()))?),
            ),
            None => {
                let ca = read_pem(&tls_dir.join("ca.pem")).map_err(config)?;
                (client_config(&ca, &cert, &key).map_err(config)?, None)
            }
        };
        Ok(Self {
            addr: addr.to_owned(),
            tls,
            expected,
        })
    }
}

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
    #[error("B failed attestation: {0}")]
    Attestation(String),
    #[error("configuration: {0}")]
    Config(String),
}

/// B に接続する。enclave の B なら、他の要求を送る前に attestation を検証する。
pub async fn connect(
    endpoint: &BEndpoint,
) -> Result<BConnection<TlsStream<TcpStream>>, SessionError> {
    let tcp = TcpStream::connect(&endpoint.addr)
        .await
        .map_err(SessionError::Connect)?;
    let stream = TlsConnector::from(endpoint.tls.clone())
        .connect(mw_wire::tls::server_name(), tcp)
        .await
        .map_err(SessionError::Connect)?;
    let cert_hash: Option<[u8; 32]> = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| <sha2::Sha256 as sha2::Digest>::digest(cert.as_ref()).into());
    let mut conn = Connection::new(stream);
    if let Some(expected) = &endpoint.expected {
        let cert_hash =
            cert_hash.ok_or_else(|| SessionError::Attestation("no server certificate".into()))?;
        attest(&mut conn, expected, &cert_hash).await?;
    }
    Ok(conn)
}

/// B に新しい nonce で attestation を求め、この TLS 接続の証明書に結びついているかを確かめる。
async fn attest<S>(
    conn: &mut BConnection<S>,
    expected: &ExpectedPcrs,
    cert_hash: &[u8; 32],
) -> Result<(), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    conn.send(&AtoB::Attest {
        nonce: B256::from(nonce),
    })
    .await?;
    match conn.recv().await? {
        BtoA::Attestation { document } => {
            verify_nitro_attestation(&document, expected, &nonce, cert_hash)
                .map_err(|e| SessionError::Attestation(e.to_string()))
        }
        BtoA::Error { message } => Err(SessionError::Attestation(message)),
        other => Err(SessionError::Unexpected(format!("{other:?}"))),
    }
}

/// 鍵生成の進み具合(画面に出すため)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeygenStep {
    GeneratingPrimes,
    DistributedKeygen,
    AuxInfo,
    Sealing,
    Done,
}

pub struct KeygenOutput {
    pub share_a: KeyShare,
    pub share_c: KeyShare,
    pub address: Address,
}

/// B と 2-of-3 の鍵生成を行う。このプロセスは A と C のパーティを動かす。
///
/// `passkey` は新しいウォレットの最初のパスキー。B は鍵生成と同じ(attestation を検証した)
/// 接続の上でこれを登録する。`progress` には進み具合が通知される。
pub async fn keygen<S>(
    conn: &mut BConnection<S>,
    passkey: Option<RegisteredPasskey>,
    progress: &(dyn Fn(KeygenStep) + Send + Sync),
) -> Result<KeygenOutput, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    progress(KeygenStep::GeneratingPrimes);
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
        passkey,
    })
    .await?;
    match conn.recv().await? {
        BtoA::KeygenAccepted => {}
        BtoA::Error { message } => return Err(SessionError::Remote(message)),
        other => return Err(SessionError::Unexpected(format!("{other:?}"))),
    }

    let local = [PARTY_A, PARTY_C];
    progress(KeygenStep::DistributedKeygen);
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

    progress(KeygenStep::AuxInfo);
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

    // B がシェアを封印し終えるのを待つ(失敗したら、このウォレットは使えない)
    progress(KeygenStep::Sealing);
    match conn.recv().await? {
        BtoA::KeygenStored { address: b } if b == address => {}
        BtoA::KeygenStored { .. } => return Err(SessionError::AddressMismatch),
        BtoA::Error { message } => return Err(SessionError::Remote(message)),
        other => return Err(SessionError::Unexpected(format!("{other:?}"))),
    }
    progress(KeygenStep::Done);
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

/// EIP-712 署名を提案する。承認されたら署名(`AgentOutcome::Signed`)が返る。
///
/// digest は A も自分で計算し、それ以外への署名要求には応じない。
pub async fn propose_typed_data<S>(
    conn: &mut BConnection<S>,
    share_a: &KeyShare,
    proposal: TypedDataProposal,
) -> Result<AgentOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let expected_hash = mw_chain::decode_typed_data(&proposal.typed_data)
        .map_err(|e| SessionError::Unexpected(e.to_string()))?
        .digest;
    conn.send(&AtoB::ProposeTypedData { proposal }).await?;
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

/// C のシェアで B と署名し、全額を移す復旧 tx を送る(A の端末をなくしたとき)。
///
/// `signed` は復旧 tx の signing hash へのパスキー署名(`ApproveRecovery`)。
pub async fn recover<S>(
    conn: &mut BConnection<S>,
    share_c: &KeyShare,
    signed: SignedUserOperation,
    unsigned_tx: Bytes,
) -> Result<AgentOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let expected_hash = keccak256(&unsigned_tx);
    conn.send(&AtoB::Recover {
        signed,
        unsigned_tx,
    })
    .await?;
    cosign_until_outcome(conn, share_c, expected_hash).await
}

/// B の署名要求のうち、`expected_hash` へのもの 1 回だけに応じ、最終結果を待つ。
///
/// `share` は A か C のシェア。B と組む署名者の組の中での自分の位置で presign に参加する。
async fn cosign_until_outcome<S>(
    conn: &mut BConnection<S>,
    share: &KeyShare,
    expected_hash: B256,
) -> Result<AgentOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let signers = signers_with_b(share.i);
    let local = signer_index(&signers, share.i)
        .ok_or_else(|| SessionError::Unexpected("share cannot co-sign with B".into()))?;
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
                        signers.len() as u16,
                        &[local],
                        |msg| AtoB::Mpc { msg },
                        BtoA::into_mpc,
                        |i, party| {
                            let eid = eid.clone();
                            async move { presign_party(&eid, i, &signers, share, party).await }
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
