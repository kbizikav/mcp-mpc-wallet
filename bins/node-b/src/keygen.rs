//! B 側の鍵生成(2-of-3 DKG と aux info 生成)。
//!
//! B のシェアがまだないときにだけ、A からの接続 1 本で行う。
//! A 側のプロセスは A と C のパーティを動かす。

use mw_mpc::protocol::{
    KeyShare, PARTIES, PARTY_B, PregeneratedPrimes, ProtocolError, address_of, aux_party,
    complete_share, execution_id, keygen_party,
};
use mw_wire::{AtoB, BtoA, WireError};
use rand_core::OsRng;
use tokio::io::{AsyncRead, AsyncWrite};

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

pub async fn run_keygen<S>(conn: &mut AConnection<S>) -> Result<KeyShare, KeygenError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let session = match conn.recv().await? {
        AtoB::Keygen { session } => session,
        other => return Err(KeygenError::Unexpected(format!("{other:?}"))),
    };

    // 素数の生成は重いので、プロトコルを始める前に済ませておく
    let primes = tokio::task::spawn_blocking(|| PregeneratedPrimes::generate(&mut OsRng))
        .await
        .map_err(|e| KeygenError::Unexpected(e.to_string()))?;
    conn.send(&BtoA::KeygenAccepted).await?;

    let kg = execution_id(&session.0, "keygen");
    let incomplete = conn
        .run_mpc(
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
