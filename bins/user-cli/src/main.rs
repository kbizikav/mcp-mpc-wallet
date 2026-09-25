//! 開発用のユーザーアプリ。ソフトウェアパスキーで操作に署名し、B に送る。
//!
//! 本物のパスキー(WebAuthn)を使うユーザーアプリができるまでの代わり。
//! パスキーの秘密鍵をファイルに置くので、エージェントと同じ PC で使う場合は
//! エージェントから読めない場所に置くこと。
//!
//! ```text
//! mw-user passkey-new --passkey <file>          # <file>.pub.json を B に登録する
//! mw-user status      --node-b .. --tls-dir .. --wallet <addr>
//! mw-user set-policy  --node-b .. --tls-dir .. --wallet <addr> --passkey <file> --text-file <policy.txt>
//! mw-user pending     --node-b .. --tls-dir .. --wallet <addr> --passkey <file>
//! mw-user approve     --node-b .. --tls-dir .. --wallet <addr> --passkey <file> --request-id <id>
//! mw-user reject      --node-b .. --tls-dir .. --wallet <addr> --request-id <id>
//! mw-user freeze      --node-b .. --tls-dir .. --wallet <addr>
//! mw-user unfreeze    --node-b .. --tls-dir .. --wallet <addr> --passkey <file>
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256};
use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use mw_core::Policy;
use mw_node_a::session::{connect, user_request};
use mw_node_b::{DEFAULT_ORIGIN, DEFAULT_RP_ID};
use mw_policy::software::SoftwarePasskey;
use mw_policy::{UserOperation, UserRequest, UserResponse};
use mw_wire::tls::{client_config, read_pem};

#[derive(Parser)]
#[command(name = "mw-user", about = "MCP MPC wallet user app (development)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct Target {
    #[arg(long)]
    node_b: String,
    /// B に接続するためのクライアント証明書のディレクトリ
    #[arg(long)]
    tls_dir: PathBuf,
    #[arg(long)]
    wallet: Address,
}

#[derive(Subcommand)]
enum Command {
    /// ソフトウェアパスキーを作る
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
    /// 方針を登録・変更する(バージョンは現在の次)
    SetPolicy {
        #[command(flatten)]
        target: Target,
        #[arg(long)]
        passkey: PathBuf,
        #[arg(long)]
        text_file: PathBuf,
    },
    /// 保留中の要求の詳細を見る
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
}

fn load_passkey(path: &Path) -> anyhow::Result<SoftwarePasskey> {
    serde_json::from_slice(&std::fs::read(path).with_context(|| path.display().to_string())?)
        .context("malformed passkey file")
}

/// 署名カウンタが進んだパスキーを、送る前に保存し直す。
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
    let tls = client_config(
        &read_pem(&target.tls_dir.join("ca.pem"))?,
        &read_pem(&target.tls_dir.join("node-a.pem"))?,
        &read_pem(&target.tls_dir.join("node-a.key"))?,
    )?;
    let mut conn = connect(&target.node_b, tls).await?;
    Ok(user_request(&mut conn, request).await?)
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
    match Cli::parse().command {
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
