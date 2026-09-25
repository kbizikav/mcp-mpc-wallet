//! LLM に渡す「効果」の抽出。
//!
//! 値はすべて B が自分でデコード・シミュレーションしたものから作る。
//! 攻撃者が制御しうる値はフィールド名の末尾を `_untrusted` にし、長さも切り詰める。

use alloy_primitives::{Address, U256, utils::format_ether};
use mw_chain::{DecodedTx, KnownCall};
use mw_core::UntrustedText;
use mw_simulator::{AssetTransfer, SimulationReport};
use serde::Serialize;

const MAX_SYMBOL_LEN: usize = 32;
const MAX_NOTE_LEN: usize = 1_000;

/// この値以上の allowance は実質無制限とみなす。
fn is_unlimited(amount: U256) -> bool {
    amount >= U256::from(1) << 128
}

fn truncate(text: &UntrustedText, max: usize) -> String {
    let s = text.as_untrusted_str();
    match s.char_indices().nth(max) {
        Some((cut, _)) => format!("{}…[truncated]", &s[..cut]),
        None => s.to_owned(),
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallEffect {
    Erc20Transfer {
        token: Address,
        to: Address,
        amount_raw: String,
    },
    Erc20Approve {
        token: Address,
        spender: Address,
        amount_raw: String,
        unlimited: bool,
    },
    Erc20TransferFrom {
        token: Address,
        from: Address,
        to: Address,
        amount_raw: String,
    },
    Erc20IncreaseAllowance {
        token: Address,
        spender: Address,
        added_raw: String,
        unlimited: bool,
    },
    SetApprovalForAll {
        collection: Address,
        operator: Address,
        approved: bool,
    },
}

impl CallEffect {
    fn new(token: Address, call: &KnownCall) -> Self {
        match *call {
            KnownCall::Erc20Transfer { to, amount } => Self::Erc20Transfer {
                token,
                to,
                amount_raw: amount.to_string(),
            },
            KnownCall::Erc20Approve { spender, amount } => Self::Erc20Approve {
                token,
                spender,
                amount_raw: amount.to_string(),
                unlimited: is_unlimited(amount),
            },
            KnownCall::Erc20TransferFrom { from, to, amount } => Self::Erc20TransferFrom {
                token,
                from,
                to,
                amount_raw: amount.to_string(),
            },
            KnownCall::Erc20IncreaseAllowance { spender, added } => Self::Erc20IncreaseAllowance {
                token,
                spender,
                added_raw: added.to_string(),
                unlimited: is_unlimited(added),
            },
            KnownCall::SetApprovalForAll { operator, approved } => Self::SetApprovalForAll {
                collection: token,
                operator,
                approved,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TransferEffect {
    /// ネイティブ ETH なら `None`
    pub token: Option<Address>,
    pub counterparty: Address,
    pub amount_raw: String,
    /// ネイティブ ETH のときだけ、ETH 単位の値
    pub amount_eth: Option<String>,
    pub token_symbol_untrusted: Option<String>,
    pub token_decimals_untrusted: Option<u8>,
}

impl TransferEffect {
    fn new(transfer: &AssetTransfer, counterparty: Address) -> Self {
        Self {
            token: transfer.token,
            counterparty,
            amount_raw: transfer.amount.to_string(),
            amount_eth: transfer
                .token
                .is_none()
                .then(|| format_ether(transfer.amount)),
            token_symbol_untrusted: transfer
                .symbol
                .as_ref()
                .map(|s| truncate(s, MAX_SYMBOL_LEN)),
            token_decimals_untrusted: transfer.decimals,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AllowanceEffect {
    pub token: Address,
    pub spender: Address,
    pub amount_raw: String,
    pub unlimited: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SimulationEffects {
    pub success: bool,
    pub gas_used: u64,
    /// ウォレットから出ていく資産
    pub outgoing: Vec<TransferEffect>,
    /// ウォレットに入ってくる資産
    pub incoming: Vec<TransferEffect>,
    /// ウォレットが owner の allowance 変更
    pub allowance_changes: Vec<AllowanceEffect>,
    /// ウォレットが関与しない資産移動の件数
    pub unrelated_transfers: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Effects {
    pub chain_id: u64,
    pub wallet: Address,
    pub nonce: u64,
    pub to: Option<Address>,
    pub contract_creation: bool,
    pub native_value_wei: String,
    pub native_value_eth: String,
    pub max_gas_cost_eth: String,
    pub selector: Option<String>,
    pub calldata_len: usize,
    pub decoded_call: Option<CallEffect>,
    pub simulation: SimulationEffects,
}

impl Effects {
    pub fn new(
        wallet: Address,
        decoded: &DecodedTx,
        call: Option<&KnownCall>,
        report: &SimulationReport,
    ) -> Self {
        let tx = &decoded.tx;
        let to = tx.to.to().copied();
        let max_gas_cost = U256::from(tx.gas_limit) * U256::from(tx.max_fee_per_gas);

        let mut outgoing = Vec::new();
        let mut incoming = Vec::new();
        let mut unrelated_transfers = 0;
        for transfer in &report.transfers {
            if transfer.from == wallet {
                outgoing.push(TransferEffect::new(transfer, transfer.to));
            } else if transfer.to == wallet {
                incoming.push(TransferEffect::new(transfer, transfer.from));
            } else {
                unrelated_transfers += 1;
            }
        }

        Self {
            chain_id: tx.chain_id,
            wallet,
            nonce: tx.nonce,
            to,
            contract_creation: to.is_none(),
            native_value_wei: tx.value.to_string(),
            native_value_eth: format_ether(tx.value),
            max_gas_cost_eth: format_ether(max_gas_cost),
            selector: tx
                .input
                .get(..4)
                .map(|s| format!("0x{}", alloy_primitives::hex::encode(s))),
            calldata_len: tx.input.len(),
            decoded_call: to
                .zip(call)
                .map(|(token, call)| CallEffect::new(token, call)),
            simulation: SimulationEffects {
                success: report.success,
                gas_used: report.gas_used,
                outgoing,
                incoming,
                allowance_changes: report
                    .allowance_changes
                    .iter()
                    .filter(|c| c.owner == wallet)
                    .map(|c| AllowanceEffect {
                        token: c.token,
                        spender: c.spender,
                        amount_raw: c.amount.to_string(),
                        unlimited: is_unlimited(c.amount),
                    })
                    .collect(),
                unrelated_transfers,
            },
        }
    }
}

/// LLM のデータ領域に入れる文書。
#[derive(Clone, Debug, Serialize)]
pub struct JudgeData<'a> {
    pub user_policy: &'a str,
    pub effects: &'a Effects,
    pub agent_note_untrusted: String,
}

impl<'a> JudgeData<'a> {
    pub fn new(user_policy: &'a str, effects: &'a Effects, agent_note: &UntrustedText) -> Self {
        Self {
            user_policy,
            effects,
            agent_note_untrusted: truncate(agent_note, MAX_NOTE_LEN),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_on_char_boundary() {
        let text = UntrustedText::new("あいうえお");
        assert_eq!(truncate(&text, 3), "あいう…[truncated]");
        assert_eq!(truncate(&text, 5), "あいうえお");
    }

    #[test]
    fn unlimited_threshold() {
        assert!(is_unlimited(U256::MAX));
        assert!(!is_unlimited(U256::from(10u64).pow(U256::from(30))));
    }
}
