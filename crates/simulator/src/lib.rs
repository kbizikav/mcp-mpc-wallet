//! tx シミュレーションの抽象化。本実装は Tenderly Simulation API(M3)。
//!
//! シミュレーション結果に含まれるトークン名・シンボルは攻撃者が制御しうるので、
//! `UntrustedText` として保持する。

use std::future::Future;
use std::sync::Mutex;

use alloy_primitives::{Address, B256, Bytes, U256};
use mw_core::UntrustedText;
use serde::{Deserialize, Serialize};

/// B が自分でデコードした tx から組み立てる入力。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationRequest {
    pub chain_id: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub input: Bytes,
    pub value: U256,
    pub gas_limit: u64,
    /// シミュレーションの基準ブロック。`None` なら最新
    pub block_number: Option<u64>,
}

/// 資産の移動 1 件。`token` が `None` ならネイティブ ETH。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetTransfer {
    pub token: Option<Address>,
    pub from: Address,
    pub to: Address,
    pub amount: U256,
    pub symbol: Option<UntrustedText>,
    pub decimals: Option<u8>,
}

/// ERC-20 の allowance 変更(approve / permit)1 件。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowanceChange {
    pub token: Address,
    pub owner: Address,
    pub spender: Address,
    pub amount: U256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimulationReport {
    pub success: bool,
    pub gas_used: u64,
    pub block_number: u64,
    pub transfers: Vec<AssetTransfer>,
    pub allowance_changes: Vec<AllowanceChange>,
    /// レスポンス本文のハッシュ。監査ログに残す
    pub raw_response_hash: B256,
}

#[derive(Debug, thiserror::Error)]
pub enum SimulationError {
    #[error("simulator unavailable: {0}")]
    Unavailable(String),
    #[error("unexpected simulator response: {0}")]
    InvalidResponse(String),
}

pub trait Simulator: Send + Sync {
    fn simulate(
        &self,
        request: &SimulationRequest,
    ) -> impl Future<Output = Result<SimulationReport, SimulationError>> + Send;
}

/// あらかじめ決めた結果を順に返すモック。
#[derive(Default)]
pub struct ScriptedSimulator {
    responses: Mutex<Vec<Result<SimulationReport, String>>>,
    requests: Mutex<Vec<SimulationRequest>>,
}

impl ScriptedSimulator {
    pub fn new(responses: impl IntoIterator<Item = Result<SimulationReport, String>>) -> Self {
        let mut responses: Vec<_> = responses.into_iter().collect();
        responses.reverse();
        Self {
            responses: Mutex::new(responses),
            requests: Mutex::default(),
        }
    }

    pub fn requests(&self) -> Vec<SimulationRequest> {
        self.requests.lock().expect("poisoned").clone()
    }
}

impl Simulator for ScriptedSimulator {
    async fn simulate(
        &self,
        request: &SimulationRequest,
    ) -> Result<SimulationReport, SimulationError> {
        self.requests
            .lock()
            .expect("poisoned")
            .push(request.clone());
        match self.responses.lock().expect("poisoned").pop() {
            Some(Ok(report)) => Ok(report),
            Some(Err(message)) => Err(SimulationError::Unavailable(message)),
            None => Err(SimulationError::Unavailable("no scripted response".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SimulationRequest {
        SimulationRequest {
            chain_id: 84532,
            from: Address::repeat_byte(1),
            to: Some(Address::repeat_byte(2)),
            input: Bytes::new(),
            value: U256::from(1),
            gas_limit: 21_000,
            block_number: None,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn scripted_responses_in_order_then_unavailable() {
        let report = SimulationReport {
            success: true,
            gas_used: 21_000,
            block_number: 1,
            transfers: vec![],
            allowance_changes: vec![],
            raw_response_hash: B256::ZERO,
        };
        let sim = ScriptedSimulator::new([Ok(report.clone()), Err("down".into())]);
        assert_eq!(sim.simulate(&request()).await.unwrap(), report);
        assert!(sim.simulate(&request()).await.is_err());
        assert!(sim.simulate(&request()).await.is_err());
        assert_eq!(sim.requests().len(), 3);
    }
}
