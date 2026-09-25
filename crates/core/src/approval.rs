//! 承認の束縛・期限判定・一回限りの引き換え(不変条件 1, 3, 4)。

use std::collections::HashMap;
use std::sync::Mutex;

use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

/// 承認の有効期限(秒)
pub const APPROVAL_TTL_SECS: u64 = 300;

/// ある時点の時刻の証拠。
///
/// エンクレーブの時計だけに頼らないよう、TLS 経由で取得した最新ブロックも併せて持つ。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWitness {
    pub local_unix: u64,
    pub block_number: u64,
    pub block_timestamp: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOrigin {
    Judge,
    User,
}

/// 署名するものの種類。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningKind {
    /// EIP-1559 tx。アカウントの nonce に束縛する
    Transaction,
    /// EIP-712 typed data。アカウントの nonce はないので digest 全体に束縛する
    TypedData,
}

/// 署名要求を一意に指す値。承認時と署名時で完全に一致しなければならない。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRequestKey {
    pub kind: SigningKind,
    pub chain_id: u64,
    pub from: Address,
    /// tx の nonce。typed data では 0
    pub nonce: u64,
    /// 署名対象のハッシュ(tx の signing hash、または EIP-712 digest)
    pub signing_hash: B256,
    /// エンコード済み未署名 tx 全体(または typed data 全体)のハッシュ
    pub payload_hash: B256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub key: SigningRequestKey,
    pub issued: TimeWitness,
    pub origin: ApprovalOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalError {
    #[error("no approval for this signing hash")]
    NotApproved,
    #[error("request does not match the approval")]
    Mismatch,
    #[error("approval expired")]
    Expired,
    #[error("clock or chain view went backwards")]
    TimeWentBackwards,
    #[error("nonce is no longer the next nonce of the account")]
    StaleNonce,
    #[error("an approval for this signing hash already exists")]
    Duplicate,
}

impl Approval {
    /// 期限内かを、ローカル時計とチェーンの両方で確かめる。
    pub fn check_fresh(&self, now: &TimeWitness) -> Result<(), ApprovalError> {
        let issued = &self.issued;
        if now.local_unix < issued.local_unix
            || now.block_number < issued.block_number
            || now.block_timestamp < issued.block_timestamp
        {
            return Err(ApprovalError::TimeWentBackwards);
        }
        if now.local_unix - issued.local_unix > APPROVAL_TTL_SECS
            || now.block_timestamp - issued.block_timestamp > APPROVAL_TTL_SECS
        {
            return Err(ApprovalError::Expired);
        }
        Ok(())
    }
}

/// 承認済みで、期限内であることを確認済みの署名対象。
///
/// `ApprovalRegistry::redeem` でしか作れず、`Clone` もできない。
/// 閾値署名はこの値を消費してしか始められない。
#[derive(Debug)]
pub struct ApprovedDigest {
    key: SigningRequestKey,
    origin: ApprovalOrigin,
}

impl ApprovedDigest {
    pub fn key(&self) -> &SigningRequestKey {
        &self.key
    }

    pub fn origin(&self) -> ApprovalOrigin {
        self.origin
    }
}

/// B が承認した署名要求の表。各承認は一度しか引き換えられない。
#[derive(Default)]
pub struct ApprovalRegistry {
    entries: Mutex<HashMap<B256, Approval>>,
}

impl ApprovalRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, approval: Approval) -> Result<(), ApprovalError> {
        let mut entries = self.entries.lock().expect("approval registry poisoned");
        let hash = approval.key.signing_hash;
        if entries.contains_key(&hash) {
            return Err(ApprovalError::Duplicate);
        }
        entries.insert(hash, approval);
        Ok(())
    }

    /// 承認を引き換える。成否にかかわらず、該当する承認はこの時点で削除される。
    ///
    /// `pending_nonce` は署名直前に取得したアカウントの次の nonce。
    pub fn redeem(
        &self,
        request: &SigningRequestKey,
        now: &TimeWitness,
        pending_nonce: u64,
    ) -> Result<ApprovedDigest, ApprovalError> {
        let approval = self
            .entries
            .lock()
            .expect("approval registry poisoned")
            .remove(&request.signing_hash)
            .ok_or(ApprovalError::NotApproved)?;
        if approval.key != *request {
            return Err(ApprovalError::Mismatch);
        }
        approval.check_fresh(now)?;
        if approval.key.kind == SigningKind::Transaction && approval.key.nonce != pending_nonce {
            return Err(ApprovalError::StaleNonce);
        }
        Ok(ApprovedDigest {
            key: approval.key,
            origin: approval.origin,
        })
    }

    /// 期限切れの承認を捨てる。
    pub fn purge_expired(&self, now: &TimeWitness) {
        self.entries
            .lock()
            .expect("approval registry poisoned")
            .retain(|_, approval| approval.check_fresh(now).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(nonce: u64) -> SigningRequestKey {
        SigningRequestKey {
            kind: SigningKind::Transaction,
            chain_id: 84532,
            from: Address::repeat_byte(0xaa),
            nonce,
            signing_hash: B256::repeat_byte(nonce as u8),
            payload_hash: B256::repeat_byte(0xbb),
        }
    }

    const T0: TimeWitness = TimeWitness {
        local_unix: 1_000,
        block_number: 100,
        block_timestamp: 1_000,
    };

    fn later(secs: u64) -> TimeWitness {
        TimeWitness {
            local_unix: T0.local_unix + secs,
            block_number: T0.block_number + secs / 2,
            block_timestamp: T0.block_timestamp + secs,
        }
    }

    fn registry_with(nonce: u64) -> ApprovalRegistry {
        let registry = ApprovalRegistry::new();
        registry
            .insert(Approval {
                key: key(nonce),
                issued: T0,
                origin: ApprovalOrigin::Judge,
            })
            .expect("insert");
        registry
    }

    #[test]
    fn redeems_once() {
        let registry = registry_with(7);
        let approved = registry.redeem(&key(7), &later(10), 7).expect("redeem");
        assert_eq!(approved.key(), &key(7));
        assert_eq!(
            registry.redeem(&key(7), &later(11), 7).unwrap_err(),
            ApprovalError::NotApproved
        );
    }

    #[test]
    fn rejects_unapproved_digest() {
        let registry = registry_with(7);
        assert_eq!(
            registry.redeem(&key(8), &later(10), 8).unwrap_err(),
            ApprovalError::NotApproved
        );
    }

    #[test]
    fn rejects_mismatched_binding() {
        for tamper in [
            |k: &mut SigningRequestKey| k.chain_id = 1,
            |k: &mut SigningRequestKey| k.from = Address::repeat_byte(0xcc),
            |k: &mut SigningRequestKey| k.nonce += 1,
            |k: &mut SigningRequestKey| k.payload_hash = B256::ZERO,
        ] {
            let registry = registry_with(7);
            let mut request = key(7);
            tamper(&mut request);
            assert_eq!(
                registry.redeem(&request, &later(10), 7).unwrap_err(),
                ApprovalError::Mismatch
            );
            // 失敗した引き換えでも承認は消える
            assert_eq!(
                registry.redeem(&key(7), &later(10), 7).unwrap_err(),
                ApprovalError::NotApproved
            );
        }
    }

    #[test]
    fn expires_by_local_clock_or_chain_time() {
        let registry = registry_with(7);
        assert_eq!(
            registry
                .redeem(&key(7), &later(APPROVAL_TTL_SECS + 1), 7)
                .unwrap_err(),
            ApprovalError::Expired
        );

        // ローカル時計が止められていても、チェーンの時刻で期限切れになる
        let registry = registry_with(7);
        let frozen_clock = TimeWitness {
            local_unix: T0.local_unix,
            ..later(APPROVAL_TTL_SECS + 1)
        };
        assert_eq!(
            registry.redeem(&key(7), &frozen_clock, 7).unwrap_err(),
            ApprovalError::Expired
        );

        // チェーンの見え方が止められていても、ローカル時計で期限切れになる
        let registry = registry_with(7);
        let stale_chain = TimeWitness {
            local_unix: T0.local_unix + APPROVAL_TTL_SECS + 1,
            ..T0
        };
        assert_eq!(
            registry.redeem(&key(7), &stale_chain, 7).unwrap_err(),
            ApprovalError::Expired
        );
    }

    #[test]
    fn rejects_time_going_backwards() {
        let registry = registry_with(7);
        let rolled_back = TimeWitness {
            block_number: T0.block_number - 1,
            ..later(10)
        };
        assert_eq!(
            registry.redeem(&key(7), &rolled_back, 7).unwrap_err(),
            ApprovalError::TimeWentBackwards
        );
    }

    #[test]
    fn rejects_stale_nonce() {
        let registry = registry_with(7);
        assert_eq!(
            registry.redeem(&key(7), &later(10), 8).unwrap_err(),
            ApprovalError::StaleNonce
        );
    }

    #[test]
    fn rejects_duplicate_insert() {
        let registry = registry_with(7);
        let dup = Approval {
            key: key(7),
            issued: T0,
            origin: ApprovalOrigin::User,
        };
        assert_eq!(registry.insert(dup).unwrap_err(), ApprovalError::Duplicate);
    }

    #[test]
    fn purges_expired() {
        let registry = registry_with(7);
        registry.purge_expired(&later(APPROVAL_TTL_SECS + 1));
        assert_eq!(
            registry.redeem(&key(7), &later(10), 7).unwrap_err(),
            ApprovalError::NotApproved
        );
    }
}
