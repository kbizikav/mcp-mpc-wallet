//! cggmp21 による B 側の閾値署名。
//!
//! 承認済みの digest についてだけ、A と新しい presignature を作り、A の部分署名を受け取って
//! B が合成する。B の部分署名と最終署名は B の外に出さない(不変条件 1, 5)。

use std::marker::PhantomData;
use std::time::Duration;

use alloy_primitives::{Address, B256, Signature};
use mw_core::ApprovedDigest;
use mw_mpc::protocol::{
    KeyShare, PARTY_A, PARTY_B, PARTY_C, PartialSignature, address_of, combine, execution_id,
    issue_partial, presign_party, signer_index, signers_with_b,
};
use mw_mpc::{SignError, ThresholdSigner};
use mw_wire::{AtoB, BtoA, Connection};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite};

/// A が署名セッションに応答しないまま処理を占有できないようにする
const SIGNING_TIMEOUT: Duration = Duration::from_secs(120);

pub type AConnection<S> = Connection<S, BtoA, AtoB>;

/// 署名の相手とのセッション。通常は A、復旧(B+C)のときは C。
pub struct PeerSession<S> {
    pub conn: AConnection<S>,
    pub cosigner: u16,
}

impl<S> PeerSession<S> {
    pub fn with_a(conn: AConnection<S>) -> Self {
        Self {
            conn,
            cosigner: PARTY_A,
        }
    }
}

pub struct CggmpSigner<S> {
    share: KeyShare,
    address: Address,
    _stream: PhantomData<fn() -> S>,
}

impl<S> CggmpSigner<S> {
    pub fn new(share: KeyShare) -> Result<Self, SignError> {
        if share.i != PARTY_B {
            return Err(SignError::Protocol(format!(
                "key share belongs to party {}, not B",
                share.i
            )));
        }
        let address = address_of(&share.shared_public_key);
        Ok(Self {
            share,
            address,
            _stream: PhantomData,
        })
    }
}

impl<S> ThresholdSigner for CggmpSigner<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Peer = PeerSession<S>;

    fn address(&self) -> Address {
        self.address
    }

    async fn sign(
        &self,
        approved: ApprovedDigest,
        peer: &mut PeerSession<S>,
    ) -> Result<Signature, SignError> {
        if approved.key().from != self.address {
            return Err(SignError::WrongWallet);
        }
        if peer.cosigner != PARTY_A && peer.cosigner != PARTY_C {
            return Err(SignError::Protocol(format!(
                "party {} cannot co-sign with B",
                peer.cosigner
            )));
        }
        let signing_hash = approved.key().signing_hash;
        tokio::time::timeout(SIGNING_TIMEOUT, self.sign_with_a(signing_hash, peer))
            .await
            .map_err(|_| SignError::Unavailable("signing session timed out".into()))?
    }
}

impl<S> CggmpSigner<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    async fn sign_with_a(
        &self,
        signing_hash: B256,
        peer: &mut PeerSession<S>,
    ) -> Result<Signature, SignError> {
        let signers = signers_with_b(peer.cosigner);
        let local = signer_index(&signers, PARTY_B).expect("B is always a signer");
        let peer = &mut peer.conn;
        let unavailable = |e: mw_wire::WireError| SignError::Unavailable(e.to_string());

        let mut session = [0u8; 32];
        OsRng.fill_bytes(&mut session);
        peer.send(&BtoA::SignRequest {
            session: B256::from(session),
            signing_hash,
        })
        .await
        .map_err(unavailable)?;

        // 承認後に毎回新しい presignature を作る。保存はせず、この 1 件で使い切る
        let eid = execution_id(&session, "presign");
        let share = &self.share;
        let mut presigs = peer
            .run_mpc(
                signers.len() as u16,
                &[local],
                |msg| BtoA::Mpc { msg },
                AtoB::into_mpc,
                |i, party| {
                    let eid = eid.clone();
                    async move { presign_party(&eid, i, &signers, share, party).await }
                },
            )
            .await
            .map_err(unavailable)?;
        let presig_b = presigs
            .pop()
            .ok_or_else(|| SignError::Protocol("no presignature".into()))?
            .map_err(|e| SignError::Protocol(e.to_string()))?;

        let partial_a = match peer.recv().await.map_err(unavailable)? {
            AtoB::PartialSignature { partial } => {
                serde_json::from_value::<PartialSignature>(partial)
                    .map_err(|e| SignError::Protocol(format!("malformed partial signature: {e}")))?
            }
            AtoB::Decline { reason } => {
                return Err(SignError::Unavailable(format!("A declined: {reason}")));
            }
            other => {
                return Err(SignError::Protocol(format!(
                    "unexpected message during signing: {other:?}"
                )));
            }
        };
        let partial_b = issue_partial(presig_b, &signing_hash);
        combine(
            &[partial_a, partial_b],
            &signing_hash,
            &self.share.shared_public_key,
        )
        .ok_or(SignError::InvalidSignature)
    }
}
