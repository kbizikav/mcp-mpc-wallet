use std::collections::HashMap;
use std::sync::Mutex;

use alloy_primitives::Address;
use mw_core::Policy;

/// The active policy for each wallet.
///
/// Only policies with a verified passkey signature from the user are registered (invariant 6).
#[derive(Default)]
pub struct PolicyStore {
    policies: Mutex<HashMap<Address, Policy>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyStoreError {
    #[error("policy version {new} is not newer than the current version {current}")]
    NotNewer { current: u64, new: u64 },
}

impl PolicyStore {
    pub fn get(&self, wallet: Address) -> Option<Policy> {
        self.policies
            .lock()
            .expect("policy store poisoned")
            .get(&wallet)
            .cloned()
    }

    pub fn all(&self) -> Vec<Policy> {
        self.policies
            .lock()
            .expect("policy store poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Register a verified policy. Replays of older versions are rejected.
    pub(crate) fn install_verified(&self, policy: Policy) -> Result<(), PolicyStoreError> {
        let mut policies = self.policies.lock().expect("policy store poisoned");
        if let Some(current) = policies.get(&policy.wallet)
            && policy.version <= current.version
        {
            return Err(PolicyStoreError::NotNewer {
                current: current.version,
                new: policy.version,
            });
        }
        policies.insert(policy.wallet, policy);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(version: u64) -> Policy {
        Policy {
            wallet: Address::repeat_byte(1),
            version,
            text: "only small transfers".into(),
        }
    }

    #[test]
    fn rejects_rollback() {
        let store = PolicyStore::default();
        store.install_verified(policy(2)).unwrap();
        assert_eq!(
            store.install_verified(policy(2)).unwrap_err(),
            PolicyStoreError::NotNewer { current: 2, new: 2 }
        );
        assert!(store.install_verified(policy(1)).is_err());
        store.install_verified(policy(3)).unwrap();
        assert_eq!(store.get(Address::repeat_byte(1)).unwrap().version, 3);
    }
}
