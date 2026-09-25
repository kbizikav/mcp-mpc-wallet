//! 判定ノード B。
//!
//! ```text
//! mw-node-b pki    --node-b-dir <dir> --node-a-dir <dir>   # デプロイ用の CA と証明書を作る
//! mw-node-b keygen --listen <tcp:addr|vsock:port> --tls-dir <dir> --data-dir <dir>
//! mw-node-b register-passkey --data-dir <dir> --passkey <registration.json>   # B を止めて実行
//! mw-node-b serve  --listen <tcp:addr|vsock:port> --tls-dir <dir> --data-dir <dir>
//! ```
//!
//! TEE なしで動く開発用の構成。B のシェアは `<data-dir>/sealed` に平文で置かれる。
//! パスキー・方針・凍結状態は `<data-dir>/user-state.json` に保存する。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use mw_audit::{AuditLog, JsonlSink};
use mw_chain::JsonRpcClient;
use mw_judge::{OpenAiClient, OpenAiConfig};
use mw_mpc::ThresholdSigner;
use mw_mpc::protocol::KeyShare;
use mw_node_b::{
    Components, DEFAULT_ORIGIN, DEFAULT_RP_ID, JudgeNode, NodeConfig, SystemClock,
    UserStateSnapshot,
};
use mw_policy::RelyingParty;

fn default_rps() -> Vec<RelyingParty> {
    vec![RelyingParty::new(DEFAULT_RP_ID, DEFAULT_ORIGIN)]
}
use mw_node_b_server::keygen::run_keygen;
use mw_node_b_server::net::{Listen, RawListener, RawStream};
use mw_node_b_server::notifier::JsonlNotifier;
use mw_node_b_server::server::serve_connection;
use mw_node_b_server::{AttestationService, CggmpSigner, SHARE_LABEL};
use mw_simulator::{TenderlyConfig, TenderlySimulator};
use mw_tee::SealedStorage;
use mw_tee::kms::{KmsCredentials, KmsToolSealedStorage};
use mw_tee::mock::InsecureFileStorage;
use mw_wire::Connection;
use mw_wire::tls::{read_pem, server_config, server_config_with_ephemeral_cert};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
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
        listen: Listen,
        #[arg(long)]
        tls_dir: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        #[command(flatten)]
        seal: SealArgs,
        /// TLS 証明書を enclave の中で作り、attestation で証明する(Nitro Enclave 用)
        #[arg(long)]
        enclave_tls: bool,
    },
    /// ユーザーのパスキーを登録する(初回だけ。B を止めた状態で実行する)
    RegisterPasskey {
        #[arg(long)]
        data_dir: PathBuf,
        #[command(flatten)]
        seal: SealArgs,
        /// パスキーの公開情報(credential_id, public_key)の JSON
        #[arg(long)]
        passkey: PathBuf,
    },
    /// 提案とユーザー操作を受け付けて判定・署名・送信する
    Serve {
        #[arg(long)]
        listen: Listen,
        #[arg(long)]
        tls_dir: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        /// 受け付けるパスキーの RP(`<rp_id>=<origin>`)。何回でも指定できる
        #[arg(long = "passkey-rp", default_values_t = default_rps())]
        passkey_rps: Vec<RelyingParty>,
        #[command(flatten)]
        seal: SealArgs,
        /// TLS 証明書を enclave の中で作り、attestation で証明する(Nitro Enclave 用)
        #[arg(long)]
        enclave_tls: bool,
    },
}

type Stream = TlsStream<RawStream>;

fn acceptor(tls_dir: &Path) -> anyhow::Result<TlsAcceptor> {
    let config = server_config(
        &read_pem(&tls_dir.join("ca.pem"))?,
        &read_pem(&tls_dir.join("node-b.pem"))?,
        &read_pem(&tls_dir.join("node-b.key"))?,
    )?;
    Ok(TlsAcceptor::from(config))
}

/// B のシェアの封印方法。`--kms-key-id` を指定すると Nitro Enclave の中で KMS を使う。
#[derive(clap::Args, Clone)]
struct SealArgs {
    /// KMS キー(指定しなければ開発用に平文ファイルで保存する)
    #[arg(long)]
    kms_key_id: Option<String>,
    #[arg(long, default_value = "ap-northeast-1")]
    kms_region: String,
    #[arg(long, default_value = "/app/kmstool_enclave_cli")]
    kmstool: PathBuf,
    /// 親インスタンスで KMS への vsock-proxy が待つポート
    #[arg(long, default_value_t = 8000)]
    kms_proxy_port: u16,
}

/// TLS の設定と、enclave なら attestation の発行元。
fn tls_setup(
    tls_dir: &Path,
    enclave_tls: bool,
) -> anyhow::Result<(TlsAcceptor, Option<Arc<AttestationService>>)> {
    if !enclave_tls {
        return Ok((acceptor(tls_dir)?, None));
    }
    let (config, cert_der) =
        server_config_with_ephemeral_cert(&read_pem(&tls_dir.join("ca.pem"))?)?;
    let cert_hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&cert_der).into();
    Ok((
        TlsAcceptor::from(config),
        Some(Arc::new(AttestationService {
            attestor: nsm_attestor()?,
            cert_hash,
        })),
    ))
}

#[cfg(target_os = "linux")]
fn nsm_attestor() -> anyhow::Result<Box<dyn mw_tee::Attestor>> {
    Ok(Box::new(mw_tee::nsm::NsmAttestor))
}

#[cfg(not(target_os = "linux"))]
fn nsm_attestor() -> anyhow::Result<Box<dyn mw_tee::Attestor>> {
    bail!("--enclave-tls needs a Nitro Enclave (Linux)")
}

fn storage(data_dir: &Path, seal: &SealArgs) -> anyhow::Result<Box<dyn SealedStorage>> {
    let dir = data_dir.join("sealed");
    std::fs::create_dir_all(&dir)?;
    Ok(match &seal.kms_key_id {
        Some(key_id) => Box::new(KmsToolSealedStorage {
            dir,
            tool: seal.kmstool.clone(),
            region: seal.kms_region.clone(),
            key_id: key_id.clone(),
            proxy_port: seal.kms_proxy_port,
            credentials: KmsCredentials::from_env()?,
        }),
        None => Box::new(InsecureFileStorage::new(dir)?),
    })
}

fn env_secret(name: &str) -> anyhow::Result<SecretString> {
    std::env::var(name)
        .map(SecretString::from)
        .with_context(|| format!("{name} is not set"))
}

fn env_var(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

async fn keygen(
    listen: Listen,
    tls_dir: &Path,
    data_dir: &Path,
    seal: &SealArgs,
    enclave_tls: bool,
) -> anyhow::Result<()> {
    let storage = storage(data_dir, seal)?;
    if storage.exists(SHARE_LABEL) {
        bail!("B already has a key share; refusing to run keygen again");
    }
    let (acceptor, attestation) = tls_setup(tls_dir, enclave_tls)?;
    let listener = RawListener::bind(&listen).await?;
    eprintln!("waiting for A on {listen} to run keygen");
    let (tcp, peer) = listener.accept().await?;
    eprintln!("keygen with {peer}");
    let tls = acceptor.accept(tcp).await?;
    let mut conn = Connection::new(tls);
    let share = run_keygen(&mut conn, attestation.as_deref()).await?;
    let bytes = serde_json::to_vec(&share)?;
    storage.seal(SHARE_LABEL, &SecretSlice::from(bytes))?;
    let signer = CggmpSigner::<Stream>::new(share)?;
    println!("{}", signer.address());
    Ok(())
}

fn load_share(storage: &dyn SealedStorage) -> anyhow::Result<KeyShare> {
    let sealed = storage.unseal(SHARE_LABEL)?;
    Ok(serde_json::from_slice(sealed.expose_secret())?)
}

const USER_STATE_FILE: &str = "user-state.json";

fn load_user_state(data_dir: &Path) -> anyhow::Result<UserStateSnapshot> {
    match std::fs::read(data_dir.join(USER_STATE_FILE)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UserStateSnapshot::default()),
        Err(e) => Err(e.into()),
    }
}

/// 一時ファイルに書いてから置き換えるので、書きかけの状態は残らない。
fn save_user_state(data_dir: &Path, state: &UserStateSnapshot) -> anyhow::Result<()> {
    static SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SAVE_LOCK.lock().expect("save lock poisoned");
    let tmp = data_dir.join(format!("{USER_STATE_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
    std::fs::rename(&tmp, data_dir.join(USER_STATE_FILE))?;
    Ok(())
}

fn register_passkey(data_dir: &Path, passkey: &Path, seal: &SealArgs) -> anyhow::Result<()> {
    let signer = CggmpSigner::<Stream>::new(load_share(&*storage(data_dir, seal)?)?)?;
    let wallet = signer.address();
    let registration: mw_policy::RegisteredPasskey =
        serde_json::from_slice(&std::fs::read(passkey)?)?;
    let mut state = load_user_state(data_dir)?;
    if state.passkeys.iter().any(|(w, _)| *w == wallet) {
        bail!("a passkey is already registered for {wallet}");
    }
    state.passkeys.push((wallet, registration));
    save_user_state(data_dir, &state)?;
    eprintln!("registered the passkey for {wallet}");
    Ok(())
}

async fn serve(
    listen: Listen,
    tls_dir: &Path,
    data_dir: &Path,
    passkey_rps: Vec<RelyingParty>,
    seal: &SealArgs,
    enclave_tls: bool,
) -> anyhow::Result<()> {
    let signer = CggmpSigner::<Stream>::new(load_share(&*storage(data_dir, seal)?)?)?;
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
            passkey_rps,
            ..NodeConfig::new(CHAIN_ID)
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

    node.restore(&load_user_state(data_dir)?)?;

    let (acceptor, attestation) = tls_setup(tls_dir, enclave_tls)?;
    let listener = RawListener::bind(&listen).await?;
    eprintln!("judge node for wallet {wallet} on chain {CHAIN_ID}, listening on {listen}");
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let node = node.clone();
        let data_dir = data_dir.to_path_buf();
        let attestation = attestation.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(tcp).await {
                Ok(tls) => tls,
                Err(e) => {
                    eprintln!("TLS handshake with {peer} failed: {e}");
                    return;
                }
            };
            let save = || {
                if let Err(e) = save_user_state(&data_dir, &node.snapshot()) {
                    eprintln!("failed to save user state: {e}");
                }
            };
            if let Err(e) =
                serve_connection(&node, Connection::new(tls), attestation.as_deref(), save).await
            {
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
            seal,
            enclave_tls,
        } => keygen(listen, &tls_dir, &data_dir, &seal, enclave_tls).await,
        Command::RegisterPasskey {
            data_dir,
            passkey,
            seal,
        } => register_passkey(&data_dir, &passkey, &seal),
        Command::Serve {
            listen,
            tls_dir,
            data_dir,
            passkey_rps,
            seal,
            enclave_tls,
        } => serve(listen, &tls_dir, &data_dir, passkey_rps, &seal, enclave_tls).await,
    }
}
