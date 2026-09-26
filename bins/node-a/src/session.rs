//! Sessions from A to B: key generation and proposals.

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

/// Where B is. With `expected`, attestation proves that B is the expected enclave.
#[derive(Clone)]
pub struct BEndpoint {
    pub addr: String,
    pub tls: Arc<ClientConfig>,
    pub expected: Option<ExpectedPcrs>,
}

impl BEndpoint {
    /// Built from `node-a.pem` / `node-a.key` (and the CA) in `tls_dir`.
    ///
    /// With a PCR0, B's certificate is trusted through attestation instead of the deployment CA.
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

/// Connect to B. For an enclave B, verify the attestation before sending any other request.
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

/// Ask B for an attestation with a fresh nonce and check that it is bound to this TLS connection's certificate.
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

/// Key generation progress (shown in the UI).
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

/// Run 2-of-3 key generation with B. This process runs parties A and C.
///
/// `passkey` is the new wallet's first passkey. B registers it over the same (attested)
/// connection as the key generation. `progress` receives progress updates.
pub async fn keygen<S>(
    conn: &mut BConnection<S>,
    passkey: Option<RegisteredPasskey>,
    progress: &(dyn Fn(KeygenStep) + Send + Sync),
) -> Result<KeygenOutput, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    progress(KeygenStep::GeneratingPrimes);
    // Prime generation is slow, so do it before the protocol starts
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
            "keygen",
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
            "aux",
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

    // Wait until B has sealed its share (if that fails, this wallet is unusable)
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

/// Send a proposal, join the signing if B approves it, and return the outcome.
///
/// Only one signing request from B is honoured: the one for this proposal's tx hash.
pub async fn propose<S>(
    conn: &mut BConnection<S>,
    share_a: &KeyShare,
    proposal: Proposal,
) -> Result<AgentOutcome, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // For an unsigned EIP-1559 tx, the keccak256 of the payload is the hash to sign
    let expected_hash = keccak256(&proposal.unsigned_tx);
    conn.send(&AtoB::Propose { proposal }).await?;
    cosign_until_outcome(conn, share_a, expected_hash).await
}

/// Propose an EIP-712 signature. If approved, the signature (`AgentOutcome::Signed`) is returned.
///
/// A computes the digest itself and refuses signing requests for anything else.
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

/// Have B resume signing and sending a request the user approved.
///
/// `request_id` is the proposed tx's signing hash, so signing requests for anything else are refused.
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

/// Send a user app request to B.
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

/// Sign with B using share C and send a recovery tx that moves all funds (when A's device is lost).
///
/// `signed` is the passkey signature over the recovery tx's signing hash (`ApproveRecovery`).
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

/// Honour only one of B's signing requests, the one for `expected_hash`, and wait for the final outcome.
///
/// `share` is share A or C. It joins presigning at its position in the signer set it forms with B.
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
                        "presign",
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
                // The presignature is consumed here and can never be used again
                let partial = issue_partial(presig, &signing_hash);
                conn.send(&AtoB::PartialSignature {
                    partial: serde_json::to_value(&partial)
                        .map_err(|e| SessionError::Unexpected(e.to_string()))?,
                })
                .await?;
            }
            BtoA::Outcome { outcome } => return Ok(outcome),
            BtoA::Error { message } => return Err(SessionError::Remote(message)),
            // Drain the MPC messages of a signing request we refused
            BtoA::Mpc { .. } => {}
            other => return Err(SessionError::Unexpected(format!("{other:?}"))),
        }
    }
}
