use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use alloy_primitives::{Address, B256, Bytes, keccak256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    pub number: u64,
    pub timestamp: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("RPC unavailable: {0}")]
    Unavailable(String),
    #[error("RPC rejected the request: {0}")]
    Rejected(String),
}

/// B が TLS 経由で使うチェーン RPC(本実装は M3)。
pub trait ChainClient: Send + Sync {
    fn chain_id(&self) -> impl Future<Output = Result<u64, ChainError>> + Send;
    fn latest_block(&self) -> impl Future<Output = Result<BlockInfo, ChainError>> + Send;
    /// pending を含めたアカウントの次の nonce
    fn pending_nonce(
        &self,
        address: Address,
    ) -> impl Future<Output = Result<u64, ChainError>> + Send;
    fn send_raw_transaction(
        &self,
        raw: Bytes,
    ) -> impl Future<Output = Result<B256, ChainError>> + Send;
}

/// テスト用のチェーン。状態を直接書き換えられる。
pub struct MockChain {
    pub chain_id: u64,
    state: Mutex<MockState>,
}

#[derive(Default)]
struct MockState {
    block: Option<BlockInfo>,
    nonces: HashMap<Address, u64>,
    sent: Vec<Bytes>,
    available: bool,
}

impl MockChain {
    pub fn new(chain_id: u64, block: BlockInfo) -> Self {
        Self {
            chain_id,
            state: Mutex::new(MockState {
                block: Some(block),
                available: true,
                ..Default::default()
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, MockState> {
        self.state.lock().expect("mock chain poisoned")
    }

    pub fn set_block(&self, block: BlockInfo) {
        self.state().block = Some(block);
    }

    pub fn set_nonce(&self, address: Address, nonce: u64) {
        self.state().nonces.insert(address, nonce);
    }

    pub fn set_available(&self, available: bool) {
        self.state().available = available;
    }

    pub fn sent(&self) -> Vec<Bytes> {
        self.state().sent.clone()
    }

    fn ensure_available(&self) -> Result<(), ChainError> {
        if self.state().available {
            Ok(())
        } else {
            Err(ChainError::Unavailable("mock chain is down".into()))
        }
    }
}

impl ChainClient for MockChain {
    async fn chain_id(&self) -> Result<u64, ChainError> {
        self.ensure_available()?;
        Ok(self.chain_id)
    }

    async fn latest_block(&self) -> Result<BlockInfo, ChainError> {
        self.ensure_available()?;
        self.state()
            .block
            .ok_or_else(|| ChainError::Unavailable("no block".into()))
    }

    async fn pending_nonce(&self, address: Address) -> Result<u64, ChainError> {
        self.ensure_available()?;
        Ok(self.state().nonces.get(&address).copied().unwrap_or(0))
    }

    async fn send_raw_transaction(&self, raw: Bytes) -> Result<B256, ChainError> {
        self.ensure_available()?;
        let hash = keccak256(&raw);
        self.state().sent.push(raw);
        Ok(hash)
    }
}
