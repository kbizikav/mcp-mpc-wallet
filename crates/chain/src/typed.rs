//! EIP-712 typed data のデコード。
//!
//! digest は B が自分で計算する(A やエージェントの計算は使わない)。
//! 資産を動かす権限を与える既知の型(ERC-2612 Permit、Permit2)は、中身を読み取ってシグナルにする。

use alloy_dyn_abi::TypedData;
use alloy_primitives::{Address, B256, U256, keccak256};
use serde::Serialize;

#[derive(Clone, Debug)]
pub struct DecodedTypedData {
    pub typed: TypedData,
    /// 署名する digest(`\x19\x01 || domainSeparator || hashStruct(message)` の keccak256)
    pub digest: B256,
    pub chain_id: Option<u64>,
    pub verifying_contract: Option<Address>,
    /// 入力の JSON を正規化したもの。hash を監査ログに残す
    pub canonical_json: Vec<u8>,
    pub known: Option<KnownTypedData>,
}

/// 資産を動かす権限を与える既知の typed data。
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KnownTypedData {
    /// ERC-2612: `token` の allowance を `spender` に与える
    Erc2612Permit {
        token: Option<Address>,
        owner: Address,
        spender: Address,
        value: U256,
        deadline: U256,
    },
    /// Permit2 PermitSingle: Permit2 経由の allowance を `spender` に与える
    Permit2Allowance {
        token: Address,
        amount: U256,
        expiration: U256,
        spender: Address,
        sig_deadline: U256,
    },
    /// Permit2 PermitTransferFrom: `spender` が一度だけ `token` を持ち出せる
    Permit2Transfer {
        token: Address,
        amount: U256,
        spender: Address,
        deadline: U256,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypedDataError {
    #[error("not valid EIP-712 typed data: {0}")]
    Invalid(String),
    #[error("chainId in the domain is not a valid u64")]
    BadChainId,
}

pub fn decode_typed_data(json: &serde_json::Value) -> Result<DecodedTypedData, TypedDataError> {
    let typed: TypedData =
        serde_json::from_value(json.clone()).map_err(|e| TypedDataError::Invalid(e.to_string()))?;
    let digest = typed
        .eip712_signing_hash()
        .map_err(|e| TypedDataError::Invalid(e.to_string()))?;
    let chain_id = match typed.domain.chain_id {
        Some(id) => Some(u64::try_from(id).map_err(|_| TypedDataError::BadChainId)?),
        None => None,
    };
    let verifying_contract = typed.domain.verifying_contract;
    let known = detect_known(&typed, verifying_contract);
    Ok(DecodedTypedData {
        canonical_json: serde_json::to_vec(json).expect("serializable"),
        typed,
        digest,
        chain_id,
        verifying_contract,
        known,
    })
}

impl DecodedTypedData {
    pub fn payload_hash(&self) -> B256 {
        keccak256(&self.canonical_json)
    }
}

fn address(v: &serde_json::Value) -> Option<Address> {
    v.as_str()?.parse().ok()
}

/// 10 進の文字列、0x 始まりの 16 進の文字列、JSON の数値を受け付ける。
fn uint(v: &serde_json::Value) -> Option<U256> {
    match v {
        serde_json::Value::String(s) => match s.strip_prefix("0x") {
            Some(hex) => U256::from_str_radix(hex, 16).ok(),
            None => U256::from_str_radix(s, 10).ok(),
        },
        serde_json::Value::Number(n) => n.as_u64().map(U256::from),
        _ => None,
    }
}

fn detect_known(typed: &TypedData, verifying_contract: Option<Address>) -> Option<KnownTypedData> {
    let m = &typed.message;
    match typed.primary_type.as_str() {
        "Permit" => Some(KnownTypedData::Erc2612Permit {
            token: verifying_contract,
            owner: address(&m["owner"])?,
            spender: address(&m["spender"])?,
            value: uint(&m["value"])?,
            deadline: uint(&m["deadline"])?,
        }),
        "PermitSingle" => Some(KnownTypedData::Permit2Allowance {
            token: address(&m["details"]["token"])?,
            amount: uint(&m["details"]["amount"])?,
            expiration: uint(&m["details"]["expiration"])?,
            spender: address(&m["spender"])?,
            sig_deadline: uint(&m["sigDeadline"])?,
        }),
        "PermitTransferFrom" => Some(KnownTypedData::Permit2Transfer {
            token: address(&m["permitted"]["token"])?,
            amount: uint(&m["permitted"]["amount"])?,
            spender: address(&m["spender"])?,
            deadline: uint(&m["deadline"])?,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permit(chain_id: u64) -> serde_json::Value {
        serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Permit": [
                    {"name": "owner", "type": "address"},
                    {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"}
                ]
            },
            "primaryType": "Permit",
            "domain": {
                "name": "USDC",
                "version": "2",
                "chainId": chain_id,
                "verifyingContract": "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
            },
            "message": {
                "owner": "0x9e0d4f484317b3c9f73601fa806be37cba4e3cbb",
                "spender": "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
                "value": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                "nonce": 0,
                "deadline": "0x7fffffff"
            }
        })
    }

    #[test]
    fn decodes_erc2612_permit() {
        let d = decode_typed_data(&permit(84532)).unwrap();
        assert_eq!(d.chain_id, Some(84532));
        match d.known.unwrap() {
            KnownTypedData::Erc2612Permit {
                value, deadline, ..
            } => {
                assert_eq!(value, U256::MAX);
                assert_eq!(deadline, U256::from(0x7fff_ffffu64));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn digest_depends_on_every_field() {
        let a = decode_typed_data(&permit(84532)).unwrap().digest;
        assert_ne!(a, decode_typed_data(&permit(1)).unwrap().digest);
        let mut other = permit(84532);
        other["message"]["value"] = serde_json::json!("1");
        assert_ne!(a, decode_typed_data(&other).unwrap().digest);
    }

    #[test]
    fn rejects_malformed_typed_data() {
        assert!(decode_typed_data(&serde_json::json!({"primaryType": "X"})).is_err());
        let mut missing_type = permit(84532);
        missing_type["primaryType"] = serde_json::json!("Nope");
        assert!(decode_typed_data(&missing_type).is_err());
    }
}
