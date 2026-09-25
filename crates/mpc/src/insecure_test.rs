//! テスト専用: 1 つの鍵で署名するモック。閾値署名ではない。

use alloy_primitives::{Address, Signature, U256};
use k256::ecdsa::SigningKey;
use mw_core::ApprovedDigest;

use crate::{SignError, ThresholdSigner, ensure_recovers_to};

pub struct InsecureSingleKeySigner {
    key: SigningKey,
    address: Address,
}

impl InsecureSingleKeySigner {
    pub fn random() -> Self {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let address = Address::from_public_key(key.verifying_key());
        Self { key, address }
    }
}

impl ThresholdSigner for InsecureSingleKeySigner {
    fn address(&self) -> Address {
        self.address
    }

    async fn sign(&self, approved: ApprovedDigest) -> Result<Signature, SignError> {
        if approved.key().from != self.address {
            return Err(SignError::WrongWallet);
        }
        let (sig, recid) = self
            .key
            .sign_prehash_recoverable(approved.key().signing_hash.as_slice())
            .map_err(|e| SignError::Protocol(e.to_string()))?;
        let signature = Signature::new(
            U256::from_be_slice(&sig.r().to_bytes()),
            U256::from_be_slice(&sig.s().to_bytes()),
            recid.is_y_odd(),
        );
        ensure_recovers_to(&signature, &approved, self.address)?;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use mw_core::{Approval, ApprovalOrigin, ApprovalRegistry, SigningRequestKey, TimeWitness};

    use super::*;

    const NOW: TimeWitness = TimeWitness {
        local_unix: 1_000,
        block_number: 10,
        block_timestamp: 1_000,
    };

    fn approved_for(from: Address) -> ApprovedDigest {
        let key = SigningRequestKey {
            chain_id: 84532,
            from,
            nonce: 0,
            signing_hash: B256::repeat_byte(0x42),
            payload_hash: B256::repeat_byte(0x43),
        };
        let registry = ApprovalRegistry::new();
        registry
            .insert(Approval {
                key,
                issued: NOW,
                origin: ApprovalOrigin::Judge,
            })
            .unwrap();
        registry.redeem(&key, &NOW, 0).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn signs_approved_digest() {
        let signer = InsecureSingleKeySigner::random();
        let approved = approved_for(signer.address());
        let hash = approved.key().signing_hash;
        let sig = signer.sign(approved).await.unwrap();
        assert_eq!(
            sig.recover_address_from_prehash(&hash).unwrap(),
            signer.address()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refuses_other_wallet() {
        let signer = InsecureSingleKeySigner::random();
        let approved = approved_for(Address::repeat_byte(9));
        assert!(matches!(
            signer.sign(approved).await,
            Err(SignError::WrongWallet)
        ));
    }
}
