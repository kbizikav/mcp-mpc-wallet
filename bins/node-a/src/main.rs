//! 署名ノード A。
//!
//! ```text
//! mw-node-a keygen  --node-b <addr> --tls-dir <dir> --data-dir <dir> [--passphrase-file <path>]
//! mw-node-a info    --data-dir <dir>
//! mw-node-a propose --node-b <addr> --tls-dir <dir> --data-dir <dir> --to <addr> [--value-wei N] [--data 0x..] --note <text>
//! mw-node-a resume  --node-b <addr> --tls-dir <dir> --data-dir <dir> --request-id <id> [--wait]
//! mw-node-a mcp     --node-b <addr> --tls-dir <dir> --data-dir <dir>   # stdio の MCP サーバ
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use mw_chain::JsonRpcClient;
use mw_core::{AgentOutcome, Proposal, UntrustedText};
use mw_mpc::protocol::address_of;
use mw_node_a::mcp::{ProposeParams, WalletConfig, WalletServer};
use mw_node_a::session::{connect, keygen, propose, resume};
use mw_node_a::shares::{load_share_a, save_share_a, save_share_c};
use mw_node_a::txbuild::{TxParams, build, encode_unsigned};
use mw_wire::tls::{client_config, read_pem};
use rmcp::ServiceExt;
use secrecy::SecretString;

/// Base Sepolia
const CHAIN_ID: u64 = 84532;

#[derive(Parser)]
#[command(name = "mw-node-a", about = "MCP MPC wallet signing node (A)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct Conn {
    /// 判定ノード B のアドレス(host:port)
    #[arg(long)]
    node_b: String,
    #[arg(long)]
    tls_dir: PathBuf,
    #[arg(long)]
    data_dir: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// B と 2-of-3 の鍵生成を行い、シェア A と暗号化したシェア C を保存する
    ///
    /// シェア C を暗号化するパスフレーズは `--passphrase-file` の 1 行目か、
    /// 環境変数 MW_RECOVERY_PASSPHRASE から読む。
    Keygen {
        #[command(flatten)]
        conn: Conn,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// ウォレットのアドレスを表示する
    Info {
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// tx を 1 件提案する(動作確認用)
    Propose {
        #[command(flatten)]
        conn: Conn,
        #[arg(long)]
        to: String,
        #[arg(long)]
        value_wei: Option<String>,
        #[arg(long)]
        data: Option<String>,
        #[arg(long)]
        note: String,
        /// 採掘まで待つ
        #[arg(long)]
        wait: bool,
    },
    /// ユーザーが承認した要求の署名・送信を再開する(動作確認用)
    Resume {
        #[command(flatten)]
        conn: Conn,
        #[arg(long)]
        request_id: alloy_primitives::B256,
        #[arg(long)]
        wait: bool,
    },
    /// エージェント向けの MCP サーバを stdio で動かす
    Mcp {
        #[command(flatten)]
        conn: Conn,
    },
}

fn tls(tls_dir: &Path) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    Ok(client_config(
        &read_pem(&tls_dir.join("ca.pem"))?,
        &read_pem(&tls_dir.join("node-a.pem"))?,
        &read_pem(&tls_dir.join("node-a.key"))?,
    )?)
}

async fn rpc() -> anyhow::Result<JsonRpcClient> {
    let key = std::env::var("ALCHEMY_API_KEY").context("ALCHEMY_API_KEY is not set")?;
    let url = SecretString::from(format!("https://base-sepolia.g.alchemy.com/v2/{key}"));
    Ok(JsonRpcClient::connect(url, CHAIN_ID).await?)
}

async fn wallet_config(conn: &Conn) -> anyhow::Result<WalletConfig> {
    let share_a = load_share_a(&conn.data_dir)?;
    let address = address_of(&share_a.shared_public_key);
    Ok(WalletConfig {
        chain_id: CHAIN_ID,
        node_b: conn.node_b.clone(),
        tls: tls(&conn.tls_dir)?,
        share_a,
        address,
        rpc: rpc().await?,
    })
}

fn recovery_passphrase(file: Option<&Path>) -> anyhow::Result<SecretString> {
    let passphrase = match file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?
            .lines()
            .next()
            .unwrap_or_default()
            .to_owned(),
        None => std::env::var("MW_RECOVERY_PASSPHRASE").context(
            "set MW_RECOVERY_PASSPHRASE or pass --passphrase-file (encrypts the recovery share C)",
        )?,
    };
    if passphrase.chars().count() < 12 {
        bail!("the recovery passphrase must be at least 12 characters");
    }
    Ok(SecretString::from(passphrase))
}

async fn run_keygen(conn: &Conn, passphrase_file: Option<&Path>) -> anyhow::Result<()> {
    let passphrase = recovery_passphrase(passphrase_file)?;
    std::fs::create_dir_all(&conn.data_dir)?;
    if conn.data_dir.join(mw_node_a::shares::SHARE_A_FILE).exists() {
        bail!("share A already exists in {}", conn.data_dir.display());
    }
    eprintln!("generating primes and running keygen with B (this takes a while)...");
    let mut b = connect(&conn.node_b, tls(&conn.tls_dir)?).await?;
    let out = keygen(&mut b).await?;
    save_share_a(&conn.data_dir, &out.share_a)?;
    save_share_c(&conn.data_dir, &out.share_c, &passphrase)?;
    println!("{}", out.address);
    Ok(())
}

async fn run_propose(conn: &Conn, params: ProposeParams, wait: bool) -> anyhow::Result<()> {
    let config = wallet_config(conn).await?;
    let tx_params = TxParams {
        to: params.to.parse()?,
        value: match &params.value_wei {
            Some(v) => alloy_primitives::U256::from_str_radix(v, 10)?,
            None => alloy_primitives::U256::ZERO,
        },
        data: match &params.data {
            Some(d) => d.parse()?,
            None => Default::default(),
        },
        gas_limit: None,
    };
    let tx = build(&config.rpc, CHAIN_ID, config.address, tx_params).await?;
    let proposal = Proposal {
        wallet: config.address,
        chain_id: CHAIN_ID,
        unsigned_tx: encode_unsigned(&tx),
        agent_note: UntrustedText::new(params.note),
    };
    let mut b = connect(&config.node_b, config.tls.clone()).await?;
    let outcome = propose(&mut b, &config.share_a, proposal).await?;
    report(&config, outcome, wait).await
}

async fn run_resume(
    conn: &Conn,
    request_id: alloy_primitives::B256,
    wait: bool,
) -> anyhow::Result<()> {
    let config = wallet_config(conn).await?;
    let mut b = connect(&config.node_b, config.tls.clone()).await?;
    let outcome = resume(&mut b, &config.share_a, config.address, request_id).await?;
    report(&config, outcome, wait).await
}

/// 結果を表示し、`wait` なら採掘まで待つ。
async fn report(config: &WalletConfig, outcome: AgentOutcome, wait: bool) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string(&outcome)?);
    if let (true, AgentOutcome::Submitted { tx_hash }) = (wait, &outcome) {
        for _ in 0..60 {
            if let Some(receipt) = config.rpc.receipt(*tx_hash).await? {
                println!(
                    "mined in block {} ({})",
                    receipt.block_number,
                    if receipt.success {
                        "success"
                    } else {
                        "reverted"
                    }
                );
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        bail!("transaction not mined after 2 minutes");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Keygen {
            conn,
            passphrase_file,
        } => run_keygen(&conn, passphrase_file.as_deref()).await,
        Command::Info { data_dir } => {
            let share = load_share_a(&data_dir)?;
            println!("{}", address_of(&share.shared_public_key));
            Ok(())
        }
        Command::Propose {
            conn,
            to,
            value_wei,
            data,
            note,
            wait,
        } => {
            let params = ProposeParams {
                to,
                value_wei,
                data,
                note,
            };
            run_propose(&conn, params, wait).await
        }
        Command::Resume {
            conn,
            request_id,
            wait,
        } => run_resume(&conn, request_id, wait).await,
        Command::Mcp { conn } => {
            let server = WalletServer::new(wallet_config(&conn).await?);
            let service = server.serve(rmcp::transport::stdio()).await?;
            service.waiting().await?;
            Ok(())
        }
    }
}
