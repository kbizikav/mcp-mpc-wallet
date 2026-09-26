//! MCP tools for the agent.
//!
//! The agent can only look at the wallet and propose transactions.
//! There is deliberately no tool that changes the policy (invariant 6).

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, U256, utils::format_ether};
use mw_chain::JsonRpcClient;
use mw_core::{Proposal, TypedDataProposal, UntrustedText};
use mw_mpc::protocol::KeyShare;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{schemars, tool, tool_router};
use serde::Deserialize;

use crate::session::{BEndpoint, connect, propose, propose_typed_data, resume};
use crate::txbuild::{TxParams, build, encode_unsigned};

pub struct WalletConfig {
    pub chain_id: u64,
    pub node_b: BEndpoint,
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
    /// Recipient address (20 bytes, starting with 0x)
    pub to: String,
    /// Amount of ETH to send (wei, as a decimal string). Defaults to 0
    pub value_wei: Option<String>,
    /// Calldata (hex starting with 0x). Defaults to empty
    pub data: Option<String>,
    /// What this tx is for. The judge treats it as context only
    pub note: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SignTypedDataParams {
    /// EIP-712 typed data (types, primaryType, domain, message), as a JSON object or a string of one
    pub typed_data: serde_json::Value,
    /// What this signature is for. The judge treats it as context only
    pub note: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ResumeParams {
    /// The request_id returned with `pending_user_confirmation`
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
        let mut conn = connect(&c.node_b)
            .await
            .map_err(|e| format!("judge node unavailable: {e}"))?;
        let outcome = propose(&mut conn, &c.share_a, proposal)
            .await
            .map_err(|e| format!("judge node session failed: {e}"))?;
        let _ = conn.close().await;
        serde_json::to_string(&outcome).map_err(|e| e.to_string())
    }

    #[tool(
        name = "sign_typed_data",
        description = "Ask for an EIP-712 signature (eth_signTypedData_v4) from this wallet. \
                       An independent judge checks what the signature authorizes (for example \
                       token permits) against the owner's policy. Returns `signed` with the \
                       65-byte signature, `pending_user_confirmation`, `rejected` or `frozen`."
    )]
    async fn sign_typed_data(
        &self,
        Parameters(params): Parameters<SignTypedDataParams>,
    ) -> Result<String, String> {
        let c = &self.config;
        let typed_data = match params.typed_data {
            serde_json::Value::String(s) => {
                serde_json::from_str(&s).map_err(|e| format!("invalid `typed_data`: {e}"))?
            }
            other => other,
        };
        let proposal = TypedDataProposal {
            wallet: c.address,
            chain_id: c.chain_id,
            typed_data,
            agent_note: UntrustedText::new(params.note),
        };
        let mut conn = connect(&c.node_b)
            .await
            .map_err(|e| format!("judge node unavailable: {e}"))?;
        let outcome = propose_typed_data(&mut conn, &c.share_a, proposal)
            .await
            .map_err(|e| format!("judge node session failed: {e}"))?;
        let _ = conn.close().await;
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
        let mut conn = connect(&c.node_b)
            .await
            .map_err(|e| format!("judge node unavailable: {e}"))?;
        let outcome = resume(&mut conn, &c.share_a, c.address, request_id)
            .await
            .map_err(|e| format!("judge node session failed: {e}"))?;
        let _ = conn.close().await;
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
