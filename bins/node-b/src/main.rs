//! Judge node B.
//!
//! ```text
//! mw-node-b pki    --node-b-dir <dir> --node-a-dir <dir>   # create the deployment CA and certificates
//! mw-node-b keygen --listen <tcp:addr|vsock:port> --tls-dir <dir> --data-dir <dir>
//! mw-node-b register-passkey --data-dir <dir> --passkey <registration.json>   # run with B stopped
//! mw-node-b serve  --listen <tcp:addr|vsock:port> --tls-dir <dir> --data-dir <dir>
//! ```
//!
//! Development setup without a TEE. B's share is stored in plaintext under `<data-dir>/sealed`.
//! The passkey, policies and freeze state are stored in `<data-dir>/user-state.json`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use mw_audit::{AuditLog, JsonlSink};
use mw_chain::{JsonRpcClient, Network};
use mw_judge::{OpenAiClient, OpenAiConfig};
use mw_node_b::{
    Components, DEFAULT_ORIGIN, DEFAULT_RP_ID, JudgeNode, NodeConfig, SystemClock,
    UserStateSnapshot,
};
use mw_policy::RelyingParty;

fn default_rps() -> Vec<RelyingParty> {
    vec![RelyingParty::new(DEFAULT_RP_ID, DEFAULT_ORIGIN)]
}
use alloy_primitives::Address;
use mw_node_b_server::keygen::run_keygen;
use mw_node_b_server::net::{Listen, RawListener, RawStream};
use mw_node_b_server::notifier::JsonlNotifier;
use mw_node_b_server::server::KeygenService;
use mw_node_b_server::server::serve_connection;
use mw_node_b_server::{AttestationService, CggmpSigner, load_shares, store_share};
use mw_simulator::{TenderlyConfig, TenderlySimulator};
use mw_tee::SealedStorage;
use mw_tee::kms::{KmsCredentials, KmsToolSealedStorage};
use mw_tee::mock::InsecureFileStorage;
use mw_wire::BtoA;
use mw_wire::Connection;
use mw_wire::tls::{read_pem, server_config, server_config_with_ephemeral_cert};
use secrecy::SecretString;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

const DEFAULT_MODEL: &str = "gpt-5.5-2026-04-23";

#[derive(Parser)]
#[command(name = "mw-node-b", about = "MCP MPC wallet judge node (B)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the deployment CA and issue B's and A's certificates (the CA key is discarded)
    Pki {
        #[arg(long)]
        node_b_dir: PathBuf,
        #[arg(long)]
        node_a_dir: PathBuf,
    },
    /// Accept one connection from A and run 2-of-3 key generation
    Keygen {
        #[arg(long)]
        listen: Listen,
        #[arg(long)]
        tls_dir: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        #[command(flatten)]
        seal: SealArgs,
        /// Create the TLS certificate inside the enclave and prove it with attestation (for Nitro Enclaves)
        #[arg(long)]
        enclave_tls: bool,
    },
    /// Register the user's passkey (first time only, with B stopped)
    RegisterPasskey {
        #[arg(long)]
        data_dir: PathBuf,
        /// The wallet (may be omitted if B holds only one)
        #[arg(long)]
        wallet: Option<Address>,
        #[command(flatten)]
        seal: SealArgs,
        /// JSON with the passkey's public data (credential_id, public_key)
        #[arg(long)]
        passkey: PathBuf,
    },
    /// Accept proposals and user operations; judge, sign and send
    Serve {
        #[arg(long)]
        listen: Listen,
        #[arg(long)]
        tls_dir: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        /// A passkey RP to accept (`<rp_id>=<origin>`). May be repeated
        #[arg(long = "passkey-rp", default_values_t = default_rps())]
        passkey_rps: Vec<RelyingParty>,
        #[command(flatten)]
        seal: SealArgs,
        /// Create the TLS certificate inside the enclave and prove it with attestation (for Nitro Enclaves)
        #[arg(long)]
        enclave_tls: bool,
        /// The chain to judge and send on (`base-sepolia` or `base`). `base` moves real funds
        #[arg(long, env = "MW_CHAIN", default_value_t = Network::BaseSepolia)]
        chain: Network,
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

/// How B's share is sealed. With `--kms-key-id`, KMS is used inside a Nitro Enclave.
#[derive(clap::Args, Clone)]
struct SealArgs {
    /// KMS key (without it, the share is stored in a plaintext file for development)
    #[arg(long)]
    kms_key_id: Option<String>,
    #[arg(long, default_value = "ap-northeast-1")]
    kms_region: String,
    #[arg(long, default_value = "/app/kmstool_enclave_cli")]
    kmstool: PathBuf,
    /// Port of the vsock-proxy to KMS on the parent instance
    #[arg(long, default_value_t = 8000)]
    kms_proxy_port: u16,
}

/// TLS settings and, in an enclave, the attestation issuer.
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

/// Accept one connection from A and create one new wallet.
async fn keygen(
    listen: Listen,
    tls_dir: &Path,
    data_dir: &Path,
    seal: &SealArgs,
    enclave_tls: bool,
) -> anyhow::Result<()> {
    let storage = storage(data_dir, seal)?;
    let (acceptor, attestation) = tls_setup(tls_dir, enclave_tls)?;
    let listener = RawListener::bind(&listen).await?;
    eprintln!("waiting for A on {listen} to run keygen");
    let (tcp, peer) = listener.accept().await?;
    eprintln!("keygen with {peer}");
    let tls = acceptor.accept(tcp).await?;
    let mut conn = Connection::new(tls);
    let output = run_keygen(&mut conn, attestation.as_deref()).await?;
    let signer = CggmpSigner::<Stream>::default();
    let wallet = store_share(&*storage, &signer, output.share)?;
    if let Some(passkey) = output.passkey {
        let mut state = load_user_state(data_dir)?;
        state.passkeys.retain(|(w, _)| *w != wallet);
        state.passkeys.push((wallet, passkey));
        save_user_state(data_dir, &state)?;
    }
    conn.send(&BtoA::KeygenStored { address: wallet }).await?;
    println!("{wallet}");
    Ok(())
}

const USER_STATE_FILE: &str = "user-state.json";

fn load_user_state(data_dir: &Path) -> anyhow::Result<UserStateSnapshot> {
    match std::fs::read(data_dir.join(USER_STATE_FILE)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UserStateSnapshot::default()),
        Err(e) => Err(e.into()),
    }
}

/// Writes to a temporary file and then renames it, so a half-written state is never left behind.
fn save_user_state(data_dir: &Path, state: &UserStateSnapshot) -> anyhow::Result<()> {
    static SAVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = SAVE_LOCK.lock().expect("save lock poisoned");
    let tmp = data_dir.join(format!("{USER_STATE_FILE}.tmp"));
    std::fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
    std::fs::rename(&tmp, data_dir.join(USER_STATE_FILE))?;
    Ok(())
}

fn register_passkey(
    data_dir: &Path,
    passkey: &Path,
    wallet: Option<Address>,
    seal: &SealArgs,
) -> anyhow::Result<()> {
    let signer = CggmpSigner::<Stream>::default();
    let wallets = load_shares(&*storage(data_dir, seal)?, &signer)?;
    let wallet = match (wallet, wallets.as_slice()) {
        (Some(w), _) if wallets.contains(&w) => w,
        (Some(w), _) => bail!("B has no key share for {w}"),
        (None, [only]) => *only,
        (None, _) => bail!("B holds {} wallets; pass --wallet", wallets.len()),
    };
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
    network: Network,
) -> anyhow::Result<()> {
    let storage = storage(data_dir, seal)?;
    let signer = CggmpSigner::<Stream>::default();
    let wallets = load_shares(&*storage, &signer)?;
    let keygen = Arc::new(KeygenService {
        storage,
        busy: tokio::sync::Mutex::new(()),
    });

    let rpc_url = SecretString::from(network.alchemy_url(&env_var("ALCHEMY_API_KEY")?));
    let chain = JsonRpcClient::connect(rpc_url, network.chain_id()).await?;
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
            ..NodeConfig::new(network.chain_id())
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
    eprintln!(
        "judge node for {} wallet(s) {wallets:?} on {} (chain {}), listening on {listen}",
        wallets.len(),
        network.name(),
        network.chain_id()
    );
    loop {
        let (tcp, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let node = node.clone();
        let data_dir = data_dir.to_path_buf();
        let attestation = attestation.clone();
        let keygen = keygen.clone();
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
            if let Err(e) = serve_connection(
                &node,
                Connection::new(tls),
                attestation.as_deref(),
                Some(&keygen),
                save,
            )
            .await
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
            wallet,
            seal,
        } => register_passkey(&data_dir, &passkey, wallet, &seal),
        Command::Serve {
            listen,
            tls_dir,
            data_dir,
            passkey_rps,
            seal,
            enclave_tls,
            chain,
        } => serve(listen, &tls_dir, &data_dir, passkey_rps, &seal, enclave_tls, chain).await,
    }
}
