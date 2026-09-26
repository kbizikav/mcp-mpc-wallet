//! Threshold signing on B's side with cggmp21.
//!
//! Only for an approved digest, B creates a fresh presignature with A, receives A's partial signature,
//! and combines them. B's partial signature and the final signature never leave B (invariants 1, 5).

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, RwLock};
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

/// Keeps A from holding the signer hostage by not answering a signing session
const SIGNING_TIMEOUT: Duration = Duration::from_secs(120);

pub type AConnection<S> = Connection<S, BtoA, AtoB>;

/// Session with the signing peer: normally A, or C for recovery (B+C).
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

/// Threshold signer holding B's share for each wallet.
pub struct CggmpSigner<S> {
    shares: RwLock<HashMap<Address, Arc<KeyShare>>>,
    _stream: PhantomData<fn() -> S>,
}

impl<S> Default for CggmpSigner<S> {
    fn default() -> Self {
        Self {
            shares: RwLock::new(HashMap::new()),
            _stream: PhantomData,
        }
    }
}

impl<S> CggmpSigner<S> {
    /// Create one from a single share.
    pub fn new(share: KeyShare) -> Result<Self, SignError> {
        let signer = Self::default();
        signer.add(share)?;
        Ok(signer)
    }

    /// Add a wallet's share and return its address.
    pub fn add(&self, share: KeyShare) -> Result<Address, SignError> {
        if share.i != PARTY_B {
            return Err(SignError::Protocol(format!(
                "key share belongs to party {}, not B",
                share.i
            )));
        }
        let address = address_of(&share.shared_public_key);
        self.shares
            .write()
            .expect("shares poisoned")
            .insert(address, Arc::new(share));
        Ok(address)
    }

    pub fn wallets(&self) -> Vec<Address> {
        let mut wallets: Vec<Address> = self
            .shares
            .read()
            .expect("shares poisoned")
            .keys()
            .copied()
            .collect();
        wallets.sort();
        wallets
    }

    fn share(&self, wallet: Address) -> Option<Arc<KeyShare>> {
        self.shares
            .read()
            .expect("shares poisoned")
            .get(&wallet)
            .cloned()
    }
}

impl<S> ThresholdSigner for CggmpSigner<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Peer = PeerSession<S>;

    fn holds(&self, wallet: Address) -> bool {
        self.shares
            .read()
            .expect("shares poisoned")
            .contains_key(&wallet)
    }

    async fn sign(
        &self,
        approved: ApprovedDigest,
        peer: &mut PeerSession<S>,
    ) -> Result<Signature, SignError> {
        let share = self
            .share(approved.key().from)
            .ok_or(SignError::WrongWallet)?;
        if peer.cosigner != PARTY_A && peer.cosigner != PARTY_C {
            return Err(SignError::Protocol(format!(
                "party {} cannot co-sign with B",
                peer.cosigner
            )));
        }
        let signing_hash = approved.key().signing_hash;
        tokio::time::timeout(SIGNING_TIMEOUT, sign_with_peer(&share, signing_hash, peer))
            .await
            .map_err(|_| SignError::Unavailable("signing session timed out".into()))?
    }
}

async fn sign_with_peer<S>(
    share: &KeyShare,
    signing_hash: B256,
    peer: &mut PeerSession<S>,
) -> Result<Signature, SignError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    {
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

        // A fresh presignature after every approval. Never stored, used up by this one request
        let eid = execution_id(&session, "presign");
        let mut presigs = peer
            .run_mpc(
                "presign",
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
            &share.shared_public_key,
        )
        .ok_or(SignError::InvalidSignature)
    }
}
