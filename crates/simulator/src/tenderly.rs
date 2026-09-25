//! Tenderly Simulation API(single simulate)による実装。
//!
//! `POST {base}/api/v1/account/{account}/project/{project}/simulate` を `X-Access-Key` で呼ぶ。
//! 資産の移動は `transaction.transaction_info.asset_changes`、allowance の変化は
//! `exposure_changes` から読む。形は 2026-09 時点のレスポンスで確認した。
//!
//! このモジュールが理解できない変化は `unrecognized_changes` に入れ、呼び出し側で
//! 「要確認」に倒せるようにする。

use std::time::Duration;

use alloy_primitives::{Address, U256, keccak256};
use mw_core::UntrustedText;
use mw_http::describe;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::{
    AllowanceChange, AssetTransfer, SimulationError, SimulationReport, SimulationRequest, Simulator,
};

const DEFAULT_BASE_URL: &str = "https://api.tenderly.co";
/// quick モードのレスポンスは数 KB。これを大きく超えるものは受け取らない
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

pub struct TenderlyConfig {
    pub account_slug: String,
    pub project_slug: String,
    pub access_key: SecretString,
    pub base_url: String,
    pub timeout: Duration,
}

impl TenderlyConfig {
    pub fn new(account_slug: String, project_slug: String, access_key: SecretString) -> Self {
        Self {
            account_slug,
            project_slug,
            access_key,
            base_url: DEFAULT_BASE_URL.into(),
            timeout: Duration::from_secs(20),
        }
    }
}

pub struct TenderlySimulator {
    http: reqwest::Client,
    endpoint: String,
    access_key: SecretString,
}

impl TenderlySimulator {
    pub fn new(config: TenderlyConfig) -> Result<Self, SimulationError> {
        let http = mw_http::client(config.timeout).map_err(SimulationError::Unavailable)?;
        Ok(Self {
            http,
            endpoint: format!(
                "{}/api/v1/account/{}/project/{}/simulate",
                config.base_url.trim_end_matches('/'),
                config.account_slug,
                config.project_slug
            ),
            access_key: config.access_key,
        })
    }
}

fn request_body(request: &SimulationRequest) -> serde_json::Value {
    serde_json::json!({
        "network_id": request.chain_id.to_string(),
        "from": request.from,
        "to": request.to,
        "input": request.input,
        "gas": request.gas_limit,
        "gas_price": request.max_fee_per_gas.to_string(),
        "value": request.value.to_string(),
        "block_number": request.block_number,
        "simulation_type": "quick",
        "save": false,
        "save_if_fails": false,
    })
}

impl Simulator for TenderlySimulator {
    async fn simulate(
        &self,
        request: &SimulationRequest,
    ) -> Result<SimulationReport, SimulationError> {
        let response = self
            .http
            .post(&self.endpoint)
            .header("X-Access-Key", self.access_key.expose_secret())
            .json(&request_body(request))
            .send()
            .await
            .map_err(|e| SimulationError::Unavailable(describe(e)))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|e| SimulationError::Unavailable(describe(e)))?;
        if !status.is_success() {
            return Err(SimulationError::Unavailable(format!("HTTP {status}")));
        }
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(SimulationError::InvalidResponse(format!(
                "response too large ({} bytes)",
                body.len()
            )));
        }
        parse_response(&body)
    }
}

#[derive(Deserialize)]
struct Response {
    transaction: Transaction,
}

#[derive(Deserialize)]
struct Transaction {
    status: bool,
    gas_used: u64,
    block_number: u64,
    transaction_info: Option<TransactionInfo>,
}

#[derive(Deserialize)]
struct TransactionInfo {
    asset_changes: Option<Vec<AssetChange>>,
    exposure_changes: Option<Vec<ExposureChange>>,
}

#[derive(Deserialize)]
struct TokenInfo {
    standard: String,
    contract_address: Option<Address>,
    symbol: Option<String>,
    decimals: Option<u8>,
}

#[derive(Deserialize)]
struct AssetChange {
    token_info: TokenInfo,
    #[serde(rename = "type")]
    kind: String,
    from: Option<Address>,
    to: Option<Address>,
    raw_amount: Option<String>,
}

#[derive(Deserialize)]
struct ExposureChange {
    token_info: TokenInfo,
    #[serde(rename = "type")]
    kind: String,
    owner: Option<Address>,
    spender: Option<Address>,
    raw_amount: Option<String>,
}

fn parse_amount(raw: Option<&str>) -> Option<U256> {
    U256::from_str_radix(raw?, 10).ok()
}

impl AssetChange {
    fn to_transfer(&self) -> Option<AssetTransfer> {
        let token = match self.token_info.standard.as_str() {
            "NativeCurrency" => None,
            "ERC20" => Some(self.token_info.contract_address?),
            _ => return None,
        };
        let (from, to) = match self.kind.as_str() {
            "Transfer" => (self.from?, self.to?),
            "Mint" => (Address::ZERO, self.to?),
            "Burn" => (self.from?, Address::ZERO),
            _ => return None,
        };
        Some(AssetTransfer {
            token,
            from,
            to,
            amount: parse_amount(self.raw_amount.as_deref())?,
            symbol: self.token_info.symbol.clone().map(UntrustedText::new),
            decimals: self.token_info.decimals,
        })
    }

    fn describe(&self) -> String {
        format!("{} {}", self.token_info.standard, self.kind)
    }
}

impl ExposureChange {
    fn to_allowance(&self) -> Option<AllowanceChange> {
        if self.token_info.standard != "ERC20" || self.kind != "Approve" {
            return None;
        }
        Some(AllowanceChange {
            token: self.token_info.contract_address?,
            owner: self.owner?,
            spender: self.spender?,
            amount: parse_amount(self.raw_amount.as_deref())?,
        })
    }

    fn describe(&self) -> String {
        format!("{} {}", self.token_info.standard, self.kind)
    }
}

pub(crate) fn parse_response(body: &[u8]) -> Result<SimulationReport, SimulationError> {
    let parsed: Response = serde_json::from_slice(body)
        .map_err(|e| SimulationError::InvalidResponse(e.to_string()))?;
    let tx = parsed.transaction;

    let mut transfers = Vec::new();
    let mut allowance_changes = Vec::new();
    let mut unrecognized_changes = Vec::new();
    if let Some(info) = tx.transaction_info {
        for change in info.asset_changes.unwrap_or_default() {
            match change.to_transfer() {
                Some(t) => transfers.push(t),
                None => unrecognized_changes.push(change.describe()),
            }
        }
        for change in info.exposure_changes.unwrap_or_default() {
            match change.to_allowance() {
                Some(a) => allowance_changes.push(a),
                None => unrecognized_changes.push(change.describe()),
            }
        }
    }

    Ok(SimulationReport {
        success: tx.status,
        gas_used: tx.gas_used,
        block_number: tx.block_number,
        transfers,
        allowance_changes,
        unrecognized_changes,
        raw_response_hash: keccak256(body),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WALLET: &str = "0x1111111111111111111111111111111111111111";
    const BOB: &str = "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";
    const USDC: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";

    fn body(asset_changes: serde_json::Value, exposure_changes: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "transaction": {
                "status": true,
                "gas_used": 55785,
                "block_number": 47287788,
                "transaction_info": {
                    "asset_changes": asset_changes,
                    "exposure_changes": exposure_changes,
                    "balance_changes": []
                }
            },
            "simulation": { "id": "x", "block_number": 47287788 }
        }))
        .unwrap()
    }

    #[test]
    fn parses_native_and_erc20_transfers() {
        let b = body(
            serde_json::json!([
                {
                    "token_info": { "standard": "NativeCurrency", "type": "Native", "symbol": "ETH", "decimals": 18 },
                    "type": "Transfer", "from": WALLET, "to": BOB,
                    "amount": "0.01", "raw_amount": "10000000000000000"
                },
                {
                    "token_info": { "standard": "ERC20", "type": "Fungible", "contract_address": USDC, "symbol": "USDC", "decimals": 6 },
                    "type": "Transfer", "from": WALLET, "to": BOB, "raw_amount": "5000000"
                }
            ]),
            serde_json::Value::Null,
        );
        let report = parse_response(&b).unwrap();
        assert!(report.success);
        assert_eq!(report.block_number, 47287788);
        assert_eq!(report.transfers.len(), 2);
        assert_eq!(report.transfers[0].token, None);
        assert_eq!(
            report.transfers[0].amount,
            U256::from(10_000_000_000_000_000u64)
        );
        assert_eq!(report.transfers[1].token, Some(USDC.parse().unwrap()));
        assert_eq!(
            report.transfers[1]
                .symbol
                .as_ref()
                .unwrap()
                .as_untrusted_str(),
            "USDC"
        );
        assert!(report.unrecognized_changes.is_empty());
        assert_eq!(report.raw_response_hash, keccak256(&b));
    }

    #[test]
    fn parses_erc20_approval() {
        let b = body(
            serde_json::Value::Null,
            serde_json::json!([{
                "token_info": { "standard": "ERC20", "type": "Fungible", "contract_address": USDC, "symbol": "USDC", "decimals": 6 },
                "type": "Approve", "owner": WALLET, "spender": BOB,
                "raw_amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935"
            }]),
        );
        let report = parse_response(&b).unwrap();
        assert_eq!(report.allowance_changes.len(), 1);
        assert_eq!(report.allowance_changes[0].amount, U256::MAX);
        assert!(report.transfers.is_empty());
    }

    #[test]
    fn unknown_changes_are_reported_not_dropped() {
        let b = body(
            serde_json::json!([{
                "token_info": { "standard": "ERC721", "type": "NonFungible", "contract_address": USDC },
                "type": "Transfer", "from": WALLET, "to": BOB, "token_id": "1"
            }]),
            serde_json::json!([{
                "token_info": { "standard": "ERC721", "type": "NonFungible", "contract_address": USDC },
                "type": "ApproveForAll", "owner": WALLET, "spender": BOB
            }]),
        );
        let report = parse_response(&b).unwrap();
        assert_eq!(
            report.unrecognized_changes,
            vec![
                "ERC721 Transfer".to_string(),
                "ERC721 ApproveForAll".to_string()
            ]
        );
    }

    #[test]
    fn malformed_amount_is_unrecognized() {
        let b = body(
            serde_json::json!([{
                "token_info": { "standard": "NativeCurrency", "type": "Native" },
                "type": "Transfer", "from": WALLET, "to": BOB, "raw_amount": "0x10"
            }]),
            serde_json::Value::Null,
        );
        assert_eq!(parse_response(&b).unwrap().unrecognized_changes.len(), 1);
    }

    #[test]
    fn rejects_non_json() {
        assert!(matches!(
            parse_response(b"<html>"),
            Err(SimulationError::InvalidResponse(_))
        ));
    }

    #[test]
    fn request_uses_quick_mode_and_decimal_values() {
        let body = request_body(&SimulationRequest {
            chain_id: 84532,
            from: WALLET.parse().unwrap(),
            to: None,
            input: Default::default(),
            value: U256::from(10u64).pow(U256::from(18)),
            gas_limit: 21_000,
            max_fee_per_gas: 7,
            block_number: Some(5),
        });
        assert_eq!(body["network_id"], "84532");
        assert_eq!(body["value"], "1000000000000000000");
        assert_eq!(body["gas_price"], "7");
        assert_eq!(body["simulation_type"], "quick");
        assert_eq!(body["save"], false);
        assert!(body["to"].is_null());
    }
}
