//! 判定ノード B。
//!
//! ```text
//! mw-node-b pki    --node-b-dir <dir> --node-a-dir <dir>   # デプロイ用の CA と証明書を作る
//! mw-node-b keygen --listen <addr> --tls-dir <dir> --data-dir <dir>
//! mw-node-b serve  --listen <addr> --tls-dir <dir> --data-dir <dir>
//! ```
//!
//! TEE なしで動く開発用の構成。B のシェアは `<data-dir>/sealed` に平文で置かれる。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use mw_audit::{AuditLog, JsonlSink};
use mw_chain::JsonRpcClient;
use mw_judge::{OpenAiClient, OpenAiConfig};
use mw_mpc::ThresholdSigner;
use mw_mpc::protocol::KeyShare;
use mw_node_b::{Components, GuardConfig, JudgeNode, NodeConfig, SystemClock};
use mw_node_b_server::keygen::run_keygen;
use mw_node_b_server::notifier::JsonlNotifier;
use mw_node_b_server::server::serve_connection;
use mw_node_b_server::{CggmpSigner, SHARE_LABEL};
use mw_simulator::{TenderlyConfig, TenderlySimulator};
use mw_tee::SealedStorage;
use mw_tee::mock::InsecureFileStorage;
use mw_wire::Connection;
use mw_wire::tls::{read_pem, server_config};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// Base Sepolia
const CHAIN_ID: u64 = 84532;
const DEFAULT_MODEL: &str = "gpt-5.5-2026-04-23";

#[derive(Parser)]
#[command(name = "mw-node-b", about = "MCP MPC wallet judge node (B)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// デプロイ用の CA を作り、B と A の証明書を発行する(CA の鍵は捨てる)
    Pki {
        #[arg(long)]
        node_b_dir: PathBuf,
        #[arg(long)]
        node_a_dir: PathBuf,
    },
    /// A からの接続を 1 本受け付けて 2-of-3 の鍵生成を行う
    Keygen {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        tls_dir: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
    },
    /// 提案を受け付けて判定・署名・送信する
    Serve {
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        tls_dir: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        /// パスキー検証なしで読み込む方針ファイル(開発用)
        #[cfg(feature = "unverified-policy")]
        #[arg(long)]
        unverified_policy_file: Option<PathBuf>,
    },
}

type Stream = TlsStream<TcpStream>;

fn acceptor(tls_dir: &Path) -> anyhow::Result<TlsAcceptor> {
    let config = server_config(
        &read_pem(&tls_dir.join("ca.pem"))?,
        &read_pem(&tls_dir.join("node-b.pem"))?,
        &read_pem(&tls_dir.join("node-b.key"))?,
    )?;
    Ok(TlsAcceptor::from(config))
}

fn storage(data_dir: &Path) -> anyhow::Result<InsecureFileStorage> {
    Ok(InsecureFileStorage::new(data_dir.join("sealed"))?)
}

fn env_secret(name: &str) -> anyhow::Result<SecretString> {
    std::env::var(name)
        .map(SecretString::from)
        .with_context(|| format!("{name} is not set"))
}

fn env_var(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

async fn keygen(listen: SocketAddr, tls_dir: &Path, data_dir: &Path) -> anyhow::Result<()> {
    let storage = storage(data_dir)?;
    if storage.exists(SHARE_LABEL) {
        bail!("B already has a key share; refusing to run keygen again");
    }
    let acceptor = acceptor(tls_dir)?;
    let listener = TcpListener::bind(listen).await?;
    eprintln!("waiting for A on {listen} to run keygen");
    let (tcp, peer) = listener.accept().await?;
    eprintln!("keygen with {peer}");
    let tls = acceptor.accept(tcp).await?;
    let mut conn = Connection::new(tls);
    let share = run_keygen(&mut conn).await?;
    let bytes = serde_json::to_vec(&share)?;
    storage.seal(SHARE_LABEL, &SecretSlice::from(bytes))?;
    let signer = CggmpSigner::<Stream>::new(share)?;
    println!("{}", signer.address());
    Ok(())
}

fn load_share(storage: &InsecureFileStorage) -> anyhow::Result<KeyShare> {
    let sealed = storage.unseal(SHARE_LABEL)?;
    Ok(serde_json::from_slice(sealed.expose_secret())?)
}

async fn serve(
    listen: SocketAddr,
    tls_dir: &Path,
    data_dir: &Path,
    #[cfg(feature = "unverified-policy")] policy_file: Option<PathBuf>,
) -> anyhow::Result<()> {
    let signer = CggmpSigner::<Stream>::new(load_share(&storage(data_dir)?)?)?;
    let wallet = signer.address();

    let rpc_url = SecretString::from(format!(
        "https://base-sepolia.g.alchemy.com/v2/{}",
        env_var("ALCHEMY_API_KEY")?
    ));
    let chain = JsonRpcClient::connect(rpc_url, CHAIN_ID).await?;
    let simulator = TenderlySimulator::new(TenderlyConfig::new(
        env_var("TENDERLY_ACCOUNT_SLUG")?,
        env_var("TENDERLY_PROJECT_SLUG")?,
        env_secret("TENDERLY_API_KEY")?,
    ))?;
    let model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| DEFAULT_MODEL.into());
    let llm = OpenAiClient::new(OpenAiConfig::new(env_secret("OPENAI_API_KEY")?, model))?;

    let audit_sink = JsonlSink::open(data_dir.join("audit.jsonl"))?;
    let existing = audit_sink.load()?;
    let audit = AuditLog::resume(audit_sink, &existing)?;

    let node = Arc::new(JudgeNode::new(
        NodeConfig {
            chain_id: CHAIN_ID,
            llm_samples: 3,
            guard: GuardConfig::default(),
        },
        Components {
            chain,
            simulator,
            llm,
            signer,
            notifier: JsonlNotifier::new(data_dir.join("notices.jsonl")),
            clock: SystemClock,
        },
        audit,
    ));

    #[cfg(feature = "unverified-policy")]
    if let Some(path) = policy_file {
        #[derive(serde::Deserialize)]
        struct PolicyFile {
            version: u64,
            text: String,
        }
        let file: PolicyFile = serde_json::from_slice(&std::fs::read(&path)?)?;
        eprintln!("WARNING: installing a policy without passkey verification (development only)");
        node.install_unverified_policy(mw_core::Policy {
            wallet,
            version: file.version,
            text: file.text,
        })?;
    }

    let acceptor = acceptor(tls_dir)?;
    let listener = TcpListener::bind(listen).await?;
    eprintln!("judge node for wallet {wallet} on chain {CHAIN_ID}, listening on {listen}");
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let node = node.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(tls) => tls,
                Err(e) => {
                    eprintln!("TLS handshake with {peer} failed: {e}");
                    return;
                }
            };
            if let Err(e) = serve_connection(&node, Connection::new(tls)).await {
                eprintln!("connection with {peer}: {e}");
            }
        });
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Pki {
            node_b_dir,
            node_a_dir,
        } => {
            mw_wire::tls::generate_pki()?.write(&node_b_dir, &node_a_dir)?;
            eprintln!(
                "wrote B credentials to {} and A credentials to {}",
                node_b_dir.display(),
                node_a_dir.display()
            );
            Ok(())
        }
        Command::Keygen {
            listen,
            tls_dir,
            data_dir,
        } => keygen(listen, &tls_dir, &data_dir).await,
        Command::Serve {
            listen,
            tls_dir,
            data_dir,
            #[cfg(feature = "unverified-policy")]
            unverified_policy_file,
        } => {
            serve(
                listen,
                &tls_dir,
                &data_dir,
                #[cfg(feature = "unverified-policy")]
                unverified_policy_file,
            )
            .await
        }
    }
}
