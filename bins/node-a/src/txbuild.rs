//! エージェントの指定(宛先・金額・calldata)から未署名 EIP-1559 tx を組み立てる。

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
        // 見積もりに 20% の余裕を持たせる
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

/// 復旧用: 残高からガス代を引いた全額を `to` に送る tx を作る。`to` は EOA であること。
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
