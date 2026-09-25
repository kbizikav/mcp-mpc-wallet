//! B 側の鍵生成(2-of-3 DKG と aux info 生成)。
//!
//! 1 本の接続で新しいウォレットを 1 つ作る。A 側のプロセスは A と C のパーティを動かす。
//! B は 1 つで複数のウォレットのシェアを持てる。

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

/// 鍵生成の結果。`passkey` は A が新しいウォレットの最初のパスキーとして送ってきたもの。
pub struct KeygenOutput {
    pub share: KeyShare,
    pub passkey: Option<RegisteredPasskey>,
}

/// 最初の要求を待ってから鍵生成を行う(`keygen` サブコマンド用)。
pub async fn run_keygen<S>(
    conn: &mut AConnection<S>,
    attestation: Option<&AttestationService>,
) -> Result<KeygenOutput, KeygenError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // A は鍵生成の前に attestation を確かめる(偽の B とシェアを作らないため)
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

/// `Keygen` を受け取った後の鍵生成。最後に A とアドレスを突き合わせる。
///
/// シェアの封印と `KeygenStored` の送信は呼び出し側で行う。
pub async fn keygen_after_request<S>(
    conn: &mut AConnection<S>,
    session: B256,
) -> Result<KeyShare, KeygenError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 素数の生成は重いので、プロトコルを始める前に済ませておく
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
