//! エージェント向けの MCP ツール。
//!
//! エージェントにできるのは、ウォレットの情報を見ることと、tx を提案することだけ。
//! 方針を変えるツールは作らない(不変条件 6)。

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, U256, utils::format_ether};
use mw_chain::JsonRpcClient;
use mw_core::{Proposal, UntrustedText};
use mw_mpc::protocol::KeyShare;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{schemars, tool, tool_router};
use rustls::ClientConfig;
use serde::Deserialize;

use crate::session::{connect, propose, resume};
use crate::txbuild::{TxParams, build, encode_unsigned};

pub struct WalletConfig {
    pub chain_id: u64,
    pub node_b: String,
    pub tls: Arc<ClientConfig>,
    pub share_a: KeyShare,
    pub address: Address,
    pub rpc: JsonRpcClient,
}

#[derive(Clone)]
pub struct WalletServer {
    config: Arc<WalletConfig>,
}

impl WalletServer {
    pub fn new(config: WalletConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ProposeParams {
    /// 送り先のアドレス(0x から始まる 20 バイト)
    pub to: String,
    /// 送る ETH の量(wei、10 進の文字列)。省略時は 0
    pub value_wei: Option<String>,
    /// calldata(0x から始まる 16 進)。省略時は空
    pub data: Option<String>,
    /// この tx の目的の説明。判定では参考情報としてだけ扱われる
    pub note: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ResumeParams {
    /// `pending_user_confirmation` で返された request_id
    pub request_id: String,
}

fn parse_params(p: &ProposeParams) -> Result<TxParams, String> {
    let to: Address = p.to.parse().map_err(|e| format!("invalid `to`: {e}"))?;
    let value = match &p.value_wei {
        Some(v) => U256::from_str_radix(v, 10).map_err(|e| format!("invalid `value_wei`: {e}"))?,
        None => U256::ZERO,
    };
    let data = match &p.data {
        Some(d) => d
            .parse::<Bytes>()
            .map_err(|e| format!("invalid `data`: {e}"))?,
        None => Bytes::new(),
    };
    Ok(TxParams {
        to,
        value,
        data,
        gas_limit: None,
    })
}

#[tool_router(server_handler)]
impl WalletServer {
    #[tool(
        name = "wallet_info",
        description = "Show this wallet's address, chain and ETH balance."
    )]
    async fn wallet_info(&self) -> Result<String, String> {
        let c = &self.config;
        let balance = c.rpc.balance(c.address).await.map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "address": c.address,
            "chain_id": c.chain_id,
            "balance_wei": balance.to_string(),
            "balance_eth": format_ether(balance),
        })
        .to_string())
    }

    #[tool(
        name = "propose_transaction",
        description = "Propose a transaction from this wallet. An independent judge decodes and \
                       simulates it and checks the effects against the owner's policy. \
                       Returns `submitted` with the tx hash, `pending_user_confirmation` if the \
                       owner must approve it, `rejected` with a coarse reason, or `frozen`. \
                       The note is shown to the judge only as untrusted context."
    )]
    async fn propose_transaction(
        &self,
        Parameters(params): Parameters<ProposeParams>,
    ) -> Result<String, String> {
        let c = &self.config;
        let tx_params = parse_params(&params)?;
        let tx = build(&c.rpc, c.chain_id, c.address, tx_params)
            .await
            .map_err(|e| format!("could not prepare the transaction: {e}"))?;
        let proposal = Proposal {
            wallet: c.address,
            chain_id: c.chain_id,
            unsigned_tx: encode_unsigned(&tx),
            agent_note: UntrustedText::new(params.note),
        };
        let mut conn = connect(&c.node_b, c.tls.clone())
            .await
            .map_err(|e| format!("judge node unavailable: {e}"))?;
        let outcome = propose(&mut conn, &c.share_a, proposal)
            .await
            .map_err(|e| format!("judge node session failed: {e}"))?;
        serde_json::to_string(&outcome).map_err(|e| e.to_string())
    }

    #[tool(
        name = "resume_transaction",
        description = "Continue a transaction that returned `pending_user_confirmation`. \
                       If the owner has approved it with their passkey (within the last 5 \
                       minutes), it is signed and submitted. Otherwise it stays pending."
    )]
    async fn resume_transaction(
        &self,
        Parameters(params): Parameters<ResumeParams>,
    ) -> Result<String, String> {
        let c = &self.config;
        let request_id = params
            .request_id
            .parse()
            .map_err(|e| format!("invalid `request_id`: {e}"))?;
        let mut conn = connect(&c.node_b, c.tls.clone())
            .await
            .map_err(|e| format!("judge node unavailable: {e}"))?;
        let outcome = resume(&mut conn, &c.share_a, c.address, request_id)
            .await
            .map_err(|e| format!("judge node session failed: {e}"))?;
        serde_json::to_string(&outcome).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(to: &str, value: Option<&str>, data: Option<&str>) -> ProposeParams {
        ProposeParams {
            to: to.into(),
            value_wei: value.map(Into::into),
            data: data.map(Into::into),
            note: String::new(),
        }
    }

    #[test]
    fn parses_valid_params() {
        let p = parse_params(&params(
            "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
            Some("1000"),
            Some("0xdeadbeef"),
        ))
        .unwrap();
        assert_eq!(p.value, U256::from(1000));
        assert_eq!(p.data.len(), 4);
    }

    #[test]
    fn rejects_invalid_params() {
        assert!(parse_params(&params("0x12", None, None)).is_err());
        assert!(
            parse_params(&params(
                "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
                Some("0x10"),
                None
            ))
            .is_err()
        );
        assert!(
            parse_params(&params(
                "0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
                None,
                Some("zz")
            ))
            .is_err()
        );
    }
}
