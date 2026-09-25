//! オーナー用の Web アプリ(ローカルで動かす)。
//!
//! ブラウザのパスキー(Touch ID など)で操作に署名し、B に送る。
//! サーバは操作を組み立てて challenge を返し、ブラウザが作った assertion を B に中継するだけで、
//! 署名の鍵には触れない。B への接続は `--expected-pcr0` を指定すると attestation で検証する。
//!
//! ```text
//! mw-owner --node-b <host:port> --tls-dir <dir> --wallet <addr> [--expected-pcr0 <hex>]
//!          [--legacy-passkey <file>]   # ソフトウェアパスキーからブラウザのパスキーへ移すとき
//! ```
//! ブラウザでは http://localhost:8787 を開く(パスキーの RP ID が `localhost` なので)。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256, Bytes, utils::format_ether};
use anyhow::Context;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;
use mw_chain::JsonRpcClient;
use mw_core::Policy;
use mw_node_a::session::{BEndpoint, connect, user_request};
use mw_policy::software::SoftwarePasskey;
use mw_policy::{
    PasskeyAssertion, RegisteredPasskey, SignedUserOperation, UserOperation, UserRequest,
    UserResponse,
};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;

/// Base Sepolia
const CHAIN_ID: u64 = 84532;

#[derive(Parser)]
#[command(name = "mw-owner", about = "MCP MPC wallet owner app")]
struct Cli {
    #[arg(long)]
    node_b: String,
    #[arg(long)]
    tls_dir: PathBuf,
    #[arg(long)]
    wallet: Address,
    /// B が Nitro Enclave で動くとき、期待するイメージの PCR0(16 進)
    #[arg(long)]
    expected_pcr0: Option<String>,
    #[arg(long, default_value_t = 8787)]
    port: u16,
    /// いま登録されているソフトウェアパスキー。ブラウザのパスキーへ差し替えるときに一度だけ使う
    #[arg(long)]
    legacy_passkey: Option<PathBuf>,
}

struct AppState {
    endpoint: BEndpoint,
    wallet: Address,
    pcr0: Option<String>,
    rpc: Option<JsonRpcClient>,
    legacy_passkey: Option<PathBuf>,
}

type Shared = Arc<AppState>;

/// API のエラー。B が断った理由はそのまま画面に出す(オーナー本人の画面なので)。
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(StatusCode::BAD_GATEWAY, e.to_string())
    }
}

fn bad_request(message: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message.into())
}

async fn send(state: &AppState, request: UserRequest) -> Result<UserResponse, ApiError> {
    let mut conn = connect(&state.endpoint).await?;
    let response = user_request(&mut conn, request).await?;
    let _ = conn.close().await;
    Ok(response)
}

/// B の応答を返す。B が断ったら 400 にする。
fn reply(response: UserResponse) -> Result<Json<UserResponse>, ApiError> {
    match response {
        UserResponse::Error { message } => Err(bad_request(message)),
        other => Ok(Json(other)),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn decode(field: &str, value: &str) -> Result<Bytes, ApiError> {
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map(Bytes::from)
        .map_err(|e| bad_request(format!("{field}: {e}")))
}

struct Status {
    frozen: bool,
    freeze_epoch: u64,
    policy_version: Option<u64>,
    passkey_registered: bool,
}

async fn b_status(state: &AppState) -> Result<Status, ApiError> {
    match send(
        state,
        UserRequest::Status {
            wallet: state.wallet,
        },
    )
    .await?
    {
        UserResponse::Status {
            frozen,
            freeze_epoch,
            policy_version,
            passkey_registered,
            ..
        } => Ok(Status {
            frozen,
            freeze_epoch,
            policy_version,
            passkey_registered,
        }),
        UserResponse::Error { message } => Err(bad_request(message)),
        other => Err(ApiError(
            StatusCode::BAD_GATEWAY,
            format!("unexpected response: {other:?}"),
        )),
    }
}

async fn status(State(state): State<Shared>) -> Result<Json<serde_json::Value>, ApiError> {
    let b = b_status(&state).await?;
    let balance = match &state.rpc {
        Some(rpc) => rpc.balance(state.wallet).await.ok().map(format_ether),
        None => None,
    };
    Ok(Json(json!({
        "wallet": state.wallet,
        "chain": "Base Sepolia",
        "chain_id": CHAIN_ID,
        "balance_eth": balance,
        "attested": state.pcr0.is_some(),
        "pcr0": state.pcr0,
        "frozen": b.frozen,
        "freeze_epoch": b.freeze_epoch,
        "policy_version": b.policy_version,
        "passkey_registered": b.passkey_registered,
        "legacy_passkey": state.legacy_passkey.is_some(),
    })))
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ChallengeRequest {
    SetPolicy { text: String },
    Approve { request_id: B256 },
    Unfreeze,
    View,
}

/// 操作をサーバ側で組み立て、パスキーに署名させる challenge を返す。
async fn challenge(
    State(state): State<Shared>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let wallet = state.wallet;
    let operation = match request {
        ChallengeRequest::SetPolicy { text } => {
            let text = text.trim().to_owned();
            if text.is_empty() {
                return Err(bad_request("the policy is empty"));
            }
            let version = b_status(&state).await?.policy_version.map_or(1, |v| v + 1);
            UserOperation::SetPolicy {
                policy: Policy {
                    wallet,
                    version,
                    text,
                },
            }
        }
        ChallengeRequest::Approve { request_id } => {
            UserOperation::ApproveRequest { wallet, request_id }
        }
        ChallengeRequest::Unfreeze => UserOperation::Unfreeze {
            wallet,
            freeze_epoch: b_status(&state).await?.freeze_epoch,
        },
        ChallengeRequest::View => UserOperation::ListPending {
            wallet,
            issued_at: now(),
        },
    };
    Ok(Json(json!({
        "challenge": URL_SAFE_NO_PAD.encode(operation.challenge()),
        "operation": operation,
    })))
}

#[derive(Deserialize)]
struct BrowserAssertion {
    credential_id: String,
    authenticator_data: String,
    client_data_json: String,
    signature: String,
}

#[derive(Deserialize)]
struct SubmitRequest {
    operation: UserOperation,
    assertion: BrowserAssertion,
}

/// ブラウザが作った assertion を B に中継する。検証するのは B。
async fn submit(
    State(state): State<Shared>,
    Json(request): Json<SubmitRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let a = &request.assertion;
    let signed = SignedUserOperation {
        operation: request.operation,
        assertion: PasskeyAssertion {
            credential_id: decode("credential_id", &a.credential_id)?,
            authenticator_data: decode("authenticator_data", &a.authenticator_data)?,
            client_data_json: decode("client_data_json", &a.client_data_json)?,
            signature: decode("signature", &a.signature)?,
        },
    };
    reply(send(&state, UserRequest::Signed { signed }).await?)
}

async fn freeze(State(state): State<Shared>) -> Result<Json<UserResponse>, ApiError> {
    reply(
        send(
            &state,
            UserRequest::Freeze {
                wallet: state.wallet,
            },
        )
        .await?,
    )
}

#[derive(Deserialize)]
struct RejectRequest {
    request_id: B256,
}

async fn reject(
    State(state): State<Shared>,
    Json(request): Json<RejectRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    reply(
        send(
            &state,
            UserRequest::RejectPending {
                wallet: state.wallet,
                request_id: request.request_id,
            },
        )
        .await?,
    )
}

#[derive(Deserialize)]
struct AdoptRequest {
    credential_id: String,
    /// `AuthenticatorAttestationResponse.getPublicKey()`(SPKI DER)
    spki: String,
}

/// ブラウザのパスキーを登録する。いま登録されているソフトウェアパスキーで差し替えに署名する。
async fn adopt(
    State(state): State<Shared>,
    Json(request): Json<AdoptRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let path = state.legacy_passkey.as_ref().ok_or_else(|| {
        bad_request("start mw-owner with --legacy-passkey to adopt a new passkey")
    })?;
    let new_passkey = RegisteredPasskey::from_spki(
        decode("credential_id", &request.credential_id)?,
        &decode("spki", &request.spki)?,
    )?;
    let mut legacy: SoftwarePasskey = serde_json::from_slice(&std::fs::read(path)?)?;
    let signed = legacy.sign(UserOperation::RotatePasskey {
        wallet: state.wallet,
        new_passkey,
    });
    // 署名カウンタが進んだので、送る前に保存し直す
    std::fs::write(path, serde_json::to_vec_pretty(&legacy)?)?;
    reply(send(&state, UserRequest::Signed { signed }).await?)
}

fn asset(content_type: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type)], body).into_response()
}

fn router(state: Shared) -> Router {
    Router::new()
        .route(
            "/",
            get(|| async {
                asset(
                    "text/html; charset=utf-8",
                    include_str!("../static/index.html"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                asset(
                    "text/javascript; charset=utf-8",
                    include_str!("../static/app.js"),
                )
            }),
        )
        .route(
            "/style.css",
            get(|| async {
                asset(
                    "text/css; charset=utf-8",
                    include_str!("../static/style.css"),
                )
            }),
        )
        .route("/api/status", get(status))
        .route("/api/challenge", post(challenge))
        .route("/api/submit", post(submit))
        .route("/api/freeze", post(freeze))
        .route("/api/reject", post(reject))
        .route("/api/passkey/adopt", post(adopt))
        .with_state(state)
}

async fn rpc() -> Option<JsonRpcClient> {
    let key = std::env::var("ALCHEMY_API_KEY").ok()?;
    let url = SecretString::from(format!("https://base-sepolia.g.alchemy.com/v2/{key}"));
    JsonRpcClient::connect(url, CHAIN_ID).await.ok()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let endpoint = BEndpoint::from_files(&cli.node_b, &cli.tls_dir, cli.expected_pcr0.as_deref())
        .context("loading the TLS files")?;
    let state = Arc::new(AppState {
        endpoint,
        wallet: cli.wallet,
        pcr0: cli.expected_pcr0,
        rpc: rpc().await,
        legacy_passkey: cli.legacy_passkey,
    });
    // 自分の PC からだけ使う
    let addr = SocketAddr::from(([127, 0, 0, 1], cli.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!(
        "owner app for {} on http://localhost:{}",
        cli.wallet, cli.port
    );
    axum::serve(listener, router(state)).await?;
    Ok(())
}
