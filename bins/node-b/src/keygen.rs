//! Key generation on B's side (2-of-3 DKG and aux info generation).
//!
//! One connection creates one new wallet. The process on A's side runs parties A and C.
//! A single B can hold shares for several wallets.

use alloy_primitives::B256;
use mw_mpc::protocol::{
    KeyShare, PARTIES, PARTY_B, PregeneratedPrimes, ProtocolError, address_of, aux_party,
    complete_share, execution_id, keygen_party,
};
use mw_policy::RegisteredPasskey;
use mw_wire::{AtoB, BtoA, WireError};
use rand_core::OsRng;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::AttestationService;
use crate::signer::AConnection;

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("connection: {0}")]
    Wire(#[from] WireError),
    #[error("protocol: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("unexpected message: {0}")]
    Unexpected(String),
    #[error("A derived a different address ({a}) than B ({b})")]
    AddressMismatch {
        a: alloy_primitives::Address,
        b: alloy_primitives::Address,
    },
}

/// The result of key generation. `passkey` is what A sent as the new wallet's first passkey.
pub struct KeygenOutput {
    pub share: KeyShare,
    pub passkey: Option<RegisteredPasskey>,
}

/// Wait for the first request, then run key generation (for the `keygen` subcommand).
pub async fn run_keygen<S>(
    conn: &mut AConnection<S>,
    attestation: Option<&AttestationService>,
) -> Result<KeygenOutput, KeygenError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // A checks the attestation before key generation (so it never creates shares with a fake B)
    let session = loop {
        match conn.recv().await? {
            AtoB::Keygen { session, passkey } => break (session, passkey),
            AtoB::Attest { nonce } => {
                let reply = match attestation {
                    Some(service) => service.respond(&nonce),
                    None => BtoA::Error {
                        message: "this node does not run in an enclave".into(),
                    },
                };
                conn.send(&reply).await?;
            }
            other => return Err(KeygenError::Unexpected(format!("{other:?}"))),
        }
    };
    let (session, passkey) = session;
    let share = keygen_after_request(conn, session).await?;
    Ok(KeygenOutput { share, passkey })
}

/// Key generation after receiving `Keygen`. At the end, the address is checked against A's.
///
/// The caller seals the share and sends `KeygenStored`.
pub async fn keygen_after_request<S>(
    conn: &mut AConnection<S>,
    session: B256,
) -> Result<KeyShare, KeygenError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Prime generation is slow, so do it before the protocol starts
    let primes = tokio::task::spawn_blocking(|| PregeneratedPrimes::generate(&mut OsRng))
        .await
        .map_err(|e| KeygenError::Unexpected(e.to_string()))?;
    conn.send(&BtoA::KeygenAccepted).await?;

    let kg = execution_id(&session.0, "keygen");
    let incomplete = conn
        .run_mpc(
            "keygen",
            PARTIES,
            &[PARTY_B],
            |msg| BtoA::Mpc { msg },
            AtoB::into_mpc,
            |i, party| {
                let kg = kg.clone();
                async move { keygen_party(&kg, i, party).await }
            },
        )
        .await?
        .pop()
        .ok_or_else(|| KeygenError::Unexpected("no keygen output".into()))??;

    let aux_eid = execution_id(&session.0, "aux");
    let mut primes = Some(primes);
    let aux = conn
        .run_mpc(
            "aux",
            PARTIES,
            &[PARTY_B],
            |msg| BtoA::Mpc { msg },
            AtoB::into_mpc,
            |i, party| {
                let aux_eid = aux_eid.clone();
                let primes = primes.take().expect("B runs exactly one party");
                async move { aux_party(&aux_eid, i, primes, party).await }
            },
        )
        .await?
        .pop()
        .ok_or_else(|| KeygenError::Unexpected("no aux output".into()))??;

    let share = complete_share(incomplete, aux)?;
    let address = address_of(&share.shared_public_key);
    conn.send(&BtoA::KeygenDone { address }).await?;
    match conn.recv().await? {
        AtoB::KeygenResult { address: a } if a == address => Ok(share),
        AtoB::KeygenResult { address: a } => Err(KeygenError::AddressMismatch { a, b: address }),
        other => Err(KeygenError::Unexpected(format!("{other:?}"))),
    }
}
