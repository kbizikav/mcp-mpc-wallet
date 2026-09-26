//! Development user app. Signs operations with a software passkey and sends them to B.
//!
//! A stand-in until the user app with a real passkey (WebAuthn) exists.
//! The passkey's private key sits in a file, so when used on the same machine as the agent,
//! keep it somewhere the agent cannot read.
//!
//! ```text
//! mw-user passkey-new --passkey <file>          # register <file>.pub.json with B
//! mw-user status      --node-b .. --tls-dir .. --wallet <addr>
//! mw-user set-policy  --node-b .. --tls-dir .. --wallet <addr> --passkey <file> --text-file <policy.txt>
//! mw-user pending     --node-b .. --tls-dir .. --wallet <addr> --passkey <file>
//! mw-user approve     --node-b .. --tls-dir .. --wallet <addr> --passkey <file> --request-id <id>
//! mw-user reject      --node-b .. --tls-dir .. --wallet <addr> --request-id <id>
//! mw-user freeze      --node-b .. --tls-dir .. --wallet <addr>
//! mw-user unfreeze    --node-b .. --tls-dir .. --wallet <addr> --passkey <file>
//!
//! # Recovery (moves all funds; needs --yes)
//! mw-user recover            --node-b .. --tls-dir .. --wallet <addr> --passkey <file> \
//!                            --share-dir <dir> --passphrase-file <file> --to <addr> --yes   # B+C
//! mw-user emergency-withdraw --share-dir <dir> --passphrase-file <file> --to <addr> --yes   # A+C (without B)
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256};
use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use mw_chain::{ChainClient, JsonRpcClient, Network, encode_signed};
use mw_core::AgentOutcome;
use mw_core::Policy;
use mw_mpc::protocol::{address_of, sign_with_local_shares};
use mw_node_a::session::{BEndpoint, connect, recover, user_request};
use mw_node_a::shares::{load_share_a, load_share_c};
use mw_node_a::txbuild::{build_sweep, encode_unsigned};
use mw_node_b::{DEFAULT_ORIGIN, DEFAULT_RP_ID};
use mw_policy::software::SoftwarePasskey;
use mw_policy::{UserOperation, UserRequest, UserResponse};
use secrecy::SecretString;

#[derive(Parser)]
#[command(name = "mw-user", about = "MCP MPC wallet user app (development)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// The chain for recovery transactions (`base-sepolia` or `base`)
    #[arg(long, global = true, env = "MW_CHAIN", default_value_t = Network::BaseSepolia)]
    chain: Network,
}

#[derive(clap::Args)]
struct Target {
    #[arg(long)]
    node_b: String,
    /// Directory with the client certificate for connecting to B
    #[arg(long)]
    tls_dir: PathBuf,
    #[arg(long)]
    wallet: Address,
    /// When B runs in a Nitro Enclave, the expected image PCR0 (hex)
    #[arg(long)]
    expected_pcr0: Option<String>,
}

impl Target {
    fn endpoint(&self) -> anyhow::Result<BEndpoint> {
        Ok(BEndpoint::from_files(
            &self.node_b,
            &self.tls_dir,
            self.expected_pcr0.as_deref(),
        )?)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Create a software passkey
    PasskeyNew {
        #[arg(long)]
        passkey: PathBuf,
        #[arg(long, default_value = DEFAULT_RP_ID)]
        rp_id: String,
        #[arg(long, default_value = DEFAULT_ORIGIN)]
        origin: String,
    },
    Status {
        #[command(flatten)]
        target: Target,
    },
    /// Set or change the policy (the version is the current one plus one)
    SetPolicy {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        passkey: PathBuf,
        #[arg(long)]
        text_file: PathBuf,
    },
    /// Show the details of pending requests
    Pending {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        passkey: PathBuf,
    },
    Approve {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        passkey: PathBuf,
        #[arg(long)]
        request_id: B256,
    },
    Reject {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        request_id: B256,
    },
    Freeze {
        #[command(flatten)]
        target: Target,
    },
    Unfreeze {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        passkey: PathBuf,
    },
    /// Rotate the passkey (signed with the current passkey)
    RotatePasskey {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        passkey: PathBuf,
        /// The new passkey file (created with `passkey-new`)
        #[arg(long)]
        new_passkey: PathBuf,
    },
    /// When A is lost: sign with B using share C and the passkey, and move all funds to `to`
    Recover {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        passkey: PathBuf,
        #[command(flatten)]
        recovery: Recovery,
    },
    /// When B is down: sign with shares A and C only, and move all funds to `to` (bypasses B's judgment)
    EmergencyWithdraw {
        #[command(flatten)]
        recovery: Recovery,
    },
}

#[derive(clap::Args)]
struct Recovery {
    /// Directory with share-a.json and share-c.age
    #[arg(long)]
    share_dir: PathBuf,
    #[arg(long)]
    passphrase_file: PathBuf,
    /// Destination (an EOA)
    #[arg(long)]
    to: Address,
    /// Agree to move all funds
    #[arg(long)]
    yes: bool,
}

async fn rpc(network: Network) -> anyhow::Result<JsonRpcClient> {
    let key = std::env::var("ALCHEMY_API_KEY").context("ALCHEMY_API_KEY is not set")?;
    let url = SecretString::from(network.alchemy_url(&key));
    Ok(JsonRpcClient::connect(url, network.chain_id()).await?)
}

fn passphrase(path: &Path) -> anyhow::Result<SecretString> {
    let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
    Ok(SecretString::from(
        text.lines().next().unwrap_or_default().to_owned(),
    ))
}

fn require_consent(recovery: &Recovery) -> anyhow::Result<()> {
    if !recovery.yes {
        bail!(
            "this moves the whole balance to {}; pass --yes to proceed",
            recovery.to
        );
    }
    Ok(())
}

fn load_passkey(path: &Path) -> anyhow::Result<SoftwarePasskey> {
    serde_json::from_slice(&std::fs::read(path).with_context(|| path.display().to_string())?)
        .context("malformed passkey file")
}

/// Save the passkey, whose signature counter moved, before sending.
fn save_passkey(path: &Path, passkey: &SoftwarePasskey) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(&tmp)?
        .write_all(&serde_json::to_vec_pretty(passkey)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

async fn send(target: &Target, request: UserRequest) -> anyhow::Result<UserResponse> {
    let mut conn = connect(&target.endpoint()?).await?;
    let response = user_request(&mut conn, request).await?;
    let _ = conn.close().await;
    Ok(response)
}

async fn send_signed(
    target: &Target,
    passkey_path: &Path,
    operation: UserOperation,
) -> anyhow::Result<UserResponse> {
    let mut passkey = load_passkey(passkey_path)?;
    let signed = passkey.sign(operation);
    save_passkey(passkey_path, &passkey)?;
    send(target, UserRequest::Signed { signed }).await
}

async fn status(target: &Target) -> anyhow::Result<(bool, u64, Option<u64>)> {
    match send(
        target,
        UserRequest::Status {
            wallet: target.wallet,
        },
    )
    .await?
    {
        UserResponse::Status {
            frozen,
            freeze_epoch,
            policy_version,
            ..
        } => Ok((frozen, freeze_epoch, policy_version)),
        other => bail!("unexpected response: {other:?}"),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn print(response: &UserResponse) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(response)?);
    if let UserResponse::Error { .. } = response {
        bail!("B refused the request");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let network = cli.chain;
    match cli.command {
        Command::PasskeyNew {
            passkey,
            rp_id,
            origin,
        } => {
            if passkey.exists() {
                bail!("{} already exists", passkey.display());
            }
            let key = SoftwarePasskey::generate(&rp_id, &origin);
            save_passkey(&passkey, &key)?;
            let public = passkey.with_extension("pub.json");
            std::fs::write(&public, serde_json::to_vec_pretty(&key.registration())?)?;
            eprintln!(
                "wrote the passkey to {} and its public part to {}",
                passkey.display(),
                public.display()
            );
            Ok(())
        }
        Command::Status { target } => print(
            &send(
                &target,
                UserRequest::Status {
                    wallet: target.wallet,
                },
            )
            .await?,
        ),
        Command::SetPolicy {
            target,
            passkey,
            text_file,
        } => {
            let text = std::fs::read_to_string(&text_file)?;
            let (_, _, current) = status(&target).await?;
            let policy = Policy {
                wallet: target.wallet,
                version: current.map_or(1, |v| v + 1),
                text: text.trim().to_owned(),
            };
            print(&send_signed(&target, &passkey, UserOperation::SetPolicy { policy }).await?)
        }
        Command::Pending { target, passkey } => {
            let op = UserOperation::ListPending {
                wallet: target.wallet,
                issued_at: now(),
            };
            print(&send_signed(&target, &passkey, op).await?)
        }
        Command::Approve {
            target,
            passkey,
            request_id,
        } => {
            let op = UserOperation::ApproveRequest {
                wallet: target.wallet,
                request_id,
            };
            print(&send_signed(&target, &passkey, op).await?)
        }
        Command::Reject { target, request_id } => print(
            &send(
                &target,
                UserRequest::RejectPending {
                    wallet: target.wallet,
                    request_id,
                },
            )
            .await?,
        ),
        Command::Freeze { target } => print(
            &send(
                &target,
                UserRequest::Freeze {
                    wallet: target.wallet,
                },
            )
            .await?,
        ),
        Command::RotatePasskey {
            target,
            passkey,
            new_passkey,
        } => {
            let op = UserOperation::RotatePasskey {
                wallet: target.wallet,
                new_passkey: load_passkey(&new_passkey)?.registration(),
            };
            print(&send_signed(&target, &passkey, op).await?)
        }
        Command::Recover {
            target,
            passkey,
            recovery,
        } => {
            require_consent(&recovery)?;
            let share_c =
                load_share_c(&recovery.share_dir, &passphrase(&recovery.passphrase_file)?)?;
            let wallet = address_of(&share_c.shared_public_key);
            if wallet != target.wallet {
                bail!("share C belongs to {wallet}, not {}", target.wallet);
            }
            let tx = build_sweep(&rpc(network).await?, network.chain_id(), wallet, recovery.to).await?;
            let unsigned = encode_unsigned(&tx);
            let mut key = load_passkey(&passkey)?;
            let signed = key.sign(UserOperation::ApproveRecovery {
                wallet,
                signing_hash: alloy_primitives::keccak256(&unsigned),
            });
            save_passkey(&passkey, &key)?;
            let mut conn = connect(&target.endpoint()?).await?;
            let outcome = recover(&mut conn, &share_c, signed, unsigned).await?;
            println!("{}", serde_json::to_string(&outcome)?);
            if !matches!(outcome, AgentOutcome::Submitted { .. }) {
                bail!("recovery was not submitted");
            }
            Ok(())
        }
        Command::EmergencyWithdraw { recovery } => {
            require_consent(&recovery)?;
            let share_a = load_share_a(&recovery.share_dir)?;
            let share_c =
                load_share_c(&recovery.share_dir, &passphrase(&recovery.passphrase_file)?)?;
            let wallet = address_of(&share_a.shared_public_key);
            let rpc = rpc(network).await?;
            let tx = build_sweep(&rpc, network.chain_id(), wallet, recovery.to).await?;
            let signing_hash = alloy_primitives::keccak256(encode_unsigned(&tx));
            let signature = sign_with_local_shares([&share_a, &share_c], &signing_hash).await?;
            let (raw, tx_hash) = encode_signed(tx, signature);
            let sent = rpc.send_raw_transaction(raw).await?;
            if sent != tx_hash {
                bail!("RPC returned {sent}, expected {tx_hash}");
            }
            println!("{tx_hash}");
            Ok(())
        }
        Command::Unfreeze { target, passkey } => {
            let (frozen, freeze_epoch, _) = status(&target).await?;
            if !frozen {
                bail!("the wallet is not frozen");
            }
            let op = UserOperation::Unfreeze {
                wallet: target.wallet,
                freeze_epoch,
            };
            print(&send_signed(&target, &passkey, op).await?)
        }
    }
}
