//! Build an unsigned EIP-1559 tx from what the agent asked for (recipient, amount, calldata).

use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{Address, Bytes, TxKind, U256};
use mw_chain::{ChainClient, ChainError, JsonRpcClient};

pub struct TxParams {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub gas_limit: Option<u64>,
}

pub async fn build(
    rpc: &JsonRpcClient,
    chain_id: u64,
    from: Address,
    params: TxParams,
) -> Result<TxEip1559, ChainError> {
    let nonce = rpc.pending_nonce(from).await?;
    let fees = rpc.suggest_fees().await?;
    let gas_limit = match params.gas_limit {
        Some(gas) => gas,
        // Leave 20% headroom on the estimate
        None => {
            let estimate = rpc
                .estimate_gas(from, params.to, params.value, &params.data)
                .await?;
            estimate + estimate / 5
        }
    };
    Ok(TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: TxKind::Call(params.to),
        value: params.value,
        access_list: Default::default(),
        input: params.data,
    })
}

/// For recovery: a tx that sends the whole balance minus gas to `to`. `to` must be an EOA.
pub async fn build_sweep(
    rpc: &JsonRpcClient,
    chain_id: u64,
    from: Address,
    to: Address,
) -> Result<TxEip1559, ChainError> {
    const TRANSFER_GAS: u64 = 21_000;
    let balance = rpc.balance(from).await?;
    let nonce = rpc.pending_nonce(from).await?;
    let fees = rpc.suggest_fees().await?;
    let max_cost = U256::from(TRANSFER_GAS) * U256::from(fees.max_fee_per_gas);
    if balance <= max_cost {
        return Err(ChainError::Rejected(format!(
            "balance {balance} wei does not cover the gas ({max_cost} wei)"
        )));
    }
    Ok(TxEip1559 {
        chain_id,
        nonce,
        gas_limit: TRANSFER_GAS,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: TxKind::Call(to),
        value: balance - max_cost,
        access_list: Default::default(),
        input: Bytes::new(),
    })
}

pub fn encode_unsigned(tx: &TxEip1559) -> Bytes {
    let mut out = Vec::new();
    tx.encode_for_signing(&mut out);
    out.into()
}
