//! JSON-RPC over HTTPS(rustls)による `ChainClient`。
//!
//! RPC の URL には API キーが含まれうるので、秘密として保持し、エラー文にも URL を出さない。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use alloy_primitives::{Address, B256, Bytes, U64};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use mw_http::describe;

use crate::{BlockInfo, ChainClient, ChainError};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub struct JsonRpcClient {
    http: reqwest::Client,
    url: SecretString,
    chain_id: u64,
    next_id: AtomicU64,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct Block {
    number: U64,
    timestamp: U64,
}

impl JsonRpcClient {
    /// 接続して chainId が期待どおりかを確かめる。
    pub async fn connect(url: SecretString, expected_chain_id: u64) -> Result<Self, ChainError> {
        let http = mw_http::client(Duration::from_secs(15)).map_err(ChainError::Unavailable)?;
        let client = Self {
            http,
            url,
            chain_id: expected_chain_id,
            next_id: AtomicU64::new(1),
        };
        let actual: U64 = client.call("eth_chainId", serde_json::json!([])).await?;
        if actual.to::<u64>() != expected_chain_id {
            return Err(ChainError::Rejected(format!(
                "RPC serves chain {actual}, expected {expected_chain_id}"
            )));
        }
        Ok(client)
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, ChainError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let response = self
            .http
            .post(self.url.expose_secret())
            .json(&serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": method, "params": params,
            }))
            .send()
            .await
            .map_err(|e| ChainError::Unavailable(describe(e)))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|e| ChainError::Unavailable(describe(e)))?;
        if !status.is_success() {
            return Err(ChainError::Unavailable(format!("{method}: HTTP {status}")));
        }
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(ChainError::Unavailable(format!(
                "{method}: response too large"
            )));
        }
        parse_response(method, &body)
    }
}

fn parse_response<T: DeserializeOwned>(method: &str, body: &[u8]) -> Result<T, ChainError> {
    let parsed: RpcResponse<T> = serde_json::from_slice(body)
        .map_err(|e| ChainError::Unavailable(format!("{method}: invalid response: {e}")))?;
    match (parsed.result, parsed.error) {
        (_, Some(e)) => Err(ChainError::Rejected(format!(
            "{method}: {} ({})",
            e.message, e.code
        ))),
        (Some(result), None) => Ok(result),
        (None, None) => Err(ChainError::Unavailable(format!("{method}: empty result"))),
    }
}

impl ChainClient for JsonRpcClient {
    async fn chain_id(&self) -> Result<u64, ChainError> {
        Ok(self.chain_id)
    }

    async fn latest_block(&self) -> Result<BlockInfo, ChainError> {
        let block: Block = self
            .call("eth_getBlockByNumber", serde_json::json!(["latest", false]))
            .await?;
        Ok(BlockInfo {
            number: block.number.to(),
            timestamp: block.timestamp.to(),
        })
    }

    async fn pending_nonce(&self, address: Address) -> Result<u64, ChainError> {
        let nonce: U64 = self
            .call(
                "eth_getTransactionCount",
                serde_json::json!([address, "pending"]),
            )
            .await?;
        Ok(nonce.to())
    }

    async fn send_raw_transaction(&self, raw: Bytes) -> Result<B256, ChainError> {
        self.call("eth_sendRawTransaction", serde_json::json!([raw]))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_block_result() {
        let block: Block = parse_response(
            "eth_getBlockByNumber",
            br#"{"jsonrpc":"2.0","id":1,"result":{"number":"0x2d18a6c","timestamp":"0x66f1a2b3","hash":"0x00"}}"#,
        )
        .unwrap();
        assert_eq!(block.number.to::<u64>(), 0x2d18a6c);
        assert_eq!(block.timestamp.to::<u64>(), 0x66f1a2b3);
    }

    #[test]
    fn rpc_error_is_rejected() {
        let err = parse_response::<U64>(
            "eth_sendRawTransaction",
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}"#,
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::Rejected(m) if m.contains("nonce too low")));
    }

    #[test]
    fn missing_result_is_unavailable() {
        assert!(matches!(
            parse_response::<U64>("eth_chainId", br#"{"jsonrpc":"2.0","id":1}"#),
            Err(ChainError::Unavailable(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn connection_errors_do_not_leak_the_url() {
        // 到達できないアドレス。URL にキーが含まれていても、エラー文には出ない
        let url = SecretString::from("http://127.0.0.1:9/v2/SECRET-KEY-123");
        let err = JsonRpcClient::connect(url, 84532).await.err().unwrap();
        assert!(!err.to_string().contains("SECRET-KEY-123"), "{err}");
    }
}
