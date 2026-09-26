//! Owner web app (runs locally).
//!
//! Operations are signed with the browser's passkey (Touch ID and so on) and sent to B.
//! The server only builds operations, returns challenges and relays the browser's assertions to B;
//! it never touches a signing key. With `--expected-pcr0`, the connection to B is verified by attestation.
//!
//! If `--data-dir` has no wallet, it starts in setup mode and runs key generation from the UI.
//! The key generation request carries the passkey created in the browser, and B registers it as
//! the first passkey over the same attested connection.
//!
//! ```text
//! mw-owner --node-b <host:port> --tls-dir <dir> --data-dir <dir> [--expected-pcr0 <hex>]
//!          [--legacy-passkey <file>]   # when moving from a software passkey to a browser passkey
//! ```
//! Open http://localhost:8787 in the browser (the passkey RP ID is `localhost`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use alloy_primitives::{Address, B256, Bytes, utils::format_ether};
use anyhow::{Context, bail};
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
use mw_node_a::session::{BEndpoint, KeygenStep, connect, keygen, user_request};
use mw_node_a::shares::{
    SHARE_A_FILE, SHARE_C_FILE, load_wallet, save_share_a, save_share_c, save_wallet,
};
use mw_policy::software::SoftwarePasskey;
use mw_policy::{
    PasskeyAssertion, RegisteredPasskey, SignedUserOperation, UserOperation, UserRequest,
    UserResponse,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Base Sepolia
const CHAIN_ID: u64 = 84532;
/// Minimum length of the recovery passphrase (characters)
const MIN_PASSPHRASE_CHARS: usize = 12;

#[derive(Parser)]
#[command(name = "mw-owner", about = "MCP MPC wallet owner app")]
struct Cli {
    #[arg(long)]
    node_b: String,
    #[arg(long)]
    tls_dir: PathBuf,
    /// Directory with share A and the wallet address (the same one as `mw-node-a`)
    #[arg(long)]
    data_dir: PathBuf,
    /// When B runs in a Nitro Enclave, the expected image PCR0 (hex)
    #[arg(long)]
    expected_pcr0: Option<String>,
    #[arg(long, default_value_t = 8787)]
    port: u16,
    /// The currently registered software passkey. Used once, to switch to a browser passkey
    #[arg(long)]
    legacy_passkey: Option<PathBuf>,
}

/// Progress of a key generation started from the UI.
#[derive(Clone, Default, Serialize)]
struct SetupJob {
    running: bool,
    step: Option<KeygenStep>,
    error: Option<String>,
    address: Option<Address>,
}

struct AppState {
    endpoint: BEndpoint,
    node_b: String,
    tls_dir: PathBuf,
    data_dir: PathBuf,
    /// `None` until key generation has finished
    wallet: RwLock<Option<Address>>,
    setup: Mutex<SetupJob>,
    pcr0: Option<String>,
    rpc: Option<JsonRpcClient>,
    legacy_passkey: Option<PathBuf>,
}

impl AppState {
    fn wallet(&self) -> Result<Address, ApiError> {
        self.wallet
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .ok_or_else(|| {
                ApiError(
                    StatusCode::CONFLICT,
                    "no wallet yet: finish the setup".into(),
                )
            })
    }

    fn update_setup(&self, f: impl FnOnce(&mut SetupJob)) {
        f(&mut self.setup.lock().unwrap_or_else(PoisonError::into_inner));
    }
}

type Shared = Arc<AppState>;

/// An API error. B's reason for refusing is shown as is (this is the owner's own screen).
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

/// Return B's response. If B refused, respond with 400.
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

async fn b_status(state: &AppState, wallet: Address) -> Result<Status, ApiError> {
    match send(state, UserRequest::Status { wallet }).await? {
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
    let wallet = state.wallet()?;
    let b = b_status(&state, wallet).await?;
    let balance = match &state.rpc {
        Some(rpc) => rpc.balance(wallet).await.ok().map(format_ether),
        None => None,
    };
    Ok(Json(json!({
        "wallet": wallet,
        "chain": "Base Sepolia",
        "chain_id": CHAIN_ID,
        "balance_eth": balance,
        "attested": state.pcr0.is_some(),
        "pcr0": state.pcr0,
        "node_b": state.node_b,
        "frozen": b.frozen,
        "freeze_epoch": b.freeze_epoch,
        "policy_version": b.policy_version,
        "passkey_registered": b.passkey_registered,
        "legacy_passkey": state.legacy_passkey.is_some(),
        "recovery_share": state.data_dir.join(SHARE_C_FILE).exists(),
    })))
}

// ---- setup ------------------------------------------------------------------

/// The first call of the setup screen. Connects to B (verifying the attestation for an enclave) and returns the state.
async fn setup_state(State(state): State<Shared>) -> Json<serde_json::Value> {
    let wallet = *state.wallet.read().unwrap_or_else(PoisonError::into_inner);
    let judge = match connect(&state.endpoint).await {
        Ok(conn) => {
            let _ = conn.close().await;
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    };
    let job = state
        .setup
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    Json(json!({
        "wallet": wallet,
        "node_b": state.node_b,
        "attested": state.pcr0.is_some(),
        "pcr0": state.pcr0,
        "judge_reachable": judge.is_ok(),
        "judge_error": judge.err(),
        "job": job,
    }))
}

#[derive(Deserialize)]
struct KeygenRequest {
    passphrase: SecretString,
    credential_id: String,
    /// `AuthenticatorAttestationResponse.getPublicKey()`(SPKI DER)
    spki: String,
}

/// Start key generation. It takes tens of seconds, so progress is served at `/api/setup/progress`.
async fn setup_keygen(
    State(state): State<Shared>,
    Json(request): Json<KeygenRequest>,
) -> Result<Json<SetupJob>, ApiError> {
    if state.wallet().is_ok() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "a wallet already exists".into(),
        ));
    }
    if request.passphrase.expose_secret().chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(bad_request(format!(
            "the recovery passphrase needs at least {MIN_PASSPHRASE_CHARS} characters"
        )));
    }
    // Check this first, so a failure halfway does not leave a wallet on B only
    if state.data_dir.join(SHARE_A_FILE).exists() || state.data_dir.join(SHARE_C_FILE).exists() {
        return Err(ApiError(
            StatusCode::CONFLICT,
            format!("{} already holds key shares", state.data_dir.display()),
        ));
    }
    let passkey = RegisteredPasskey::from_spki(
        decode("credential_id", &request.credential_id)?,
        &decode("spki", &request.spki)?,
    )?;
    {
        let mut job = state.setup.lock().unwrap_or_else(PoisonError::into_inner);
        if job.running {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "keygen is already running".into(),
            ));
        }
        *job = SetupJob {
            running: true,
            ..SetupJob::default()
        };
    }
    let task_state = state.clone();
    tokio::spawn(async move {
        let state = task_state;
        let result = run_setup_keygen(&state, passkey, request.passphrase).await;
        state.update_setup(|job| {
            job.running = false;
            match result {
                Ok(address) => job.address = Some(address),
                Err(e) => job.error = Some(format!("{e:#}")),
            }
        });
    });
    Ok(Json(
        state
            .setup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone(),
    ))
}

async fn run_setup_keygen(
    state: &Shared,
    passkey: RegisteredPasskey,
    passphrase: SecretString,
) -> anyhow::Result<Address> {
    std::fs::create_dir_all(&state.data_dir)?;
    let mut conn = connect(&state.endpoint)
        .await
        .context("connecting to the judge node")?;
    let progress = |step| state.update_setup(|job| job.step = Some(step));
    let out = keygen(&mut conn, Some(passkey), &progress).await?;
    let _ = conn.close().await;
    save_share_a(&state.data_dir, &out.share_a)?;
    save_share_c(&state.data_dir, &out.share_c, &passphrase)?;
    save_wallet(&state.data_dir, out.address)?;
    *state.wallet.write().unwrap_or_else(PoisonError::into_inner) = Some(out.address);
    eprintln!("created wallet {}", out.address);
    Ok(out.address)
}

async fn setup_progress(State(state): State<Shared>) -> Json<SetupJob> {
    Json(
        state
            .setup
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone(),
    )
}

/// Quote an argument so it can be pasted into a shell as is.
fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@,+".contains(c))
    {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

fn absolute(path: &Path) -> PathBuf {
    std::fs::canonicalize(path)
        .or_else(|_| std::path::absolute(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// The command that registers the MCP server with Claude Code. API keys stay shell variables.
async fn mcp_command(State(state): State<Shared>) -> Json<serde_json::Value> {
    let binary = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("mw-node-a")))
        .unwrap_or_else(|| PathBuf::from("mw-node-a"));
    let mut args = vec![
        binary.display().to_string(),
        "mcp".into(),
        "--node-b".into(),
        state.node_b.clone(),
        "--tls-dir".into(),
        absolute(&state.tls_dir).display().to_string(),
        "--data-dir".into(),
        absolute(&state.data_dir).display().to_string(),
    ];
    if let Some(pcr0) = &state.pcr0 {
        args.extend(["--expected-pcr0".into(), pcr0.clone()]);
    }
    let args: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
    let command = format!(
        "claude mcp add mcp-mpc-wallet --scope user -e ALCHEMY_API_KEY=\"$ALCHEMY_API_KEY\" -- {}",
        args.join(" ")
    );
    Json(json!({
        "command": command,
        "binary_exists": binary.exists(),
    }))
}

// ---- operations signed with the passkey ----------------------------------------------

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ChallengeRequest {
    SetPolicy { text: String },
    Approve { request_id: B256 },
    Unfreeze,
    View,
}

/// Build the operation on the server and return the challenge for the passkey to sign.
async fn challenge(
    State(state): State<Shared>,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let wallet = state.wallet()?;
    let operation = match request {
        ChallengeRequest::SetPolicy { text } => {
            let text = text.trim().to_owned();
            if text.is_empty() {
                return Err(bad_request("the policy is empty"));
            }
            let version = b_status(&state, wallet)
                .await?
                .policy_version
                .map_or(1, |v| v + 1);
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
            freeze_epoch: b_status(&state, wallet).await?.freeze_epoch,
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

/// Relay the browser's assertion to B. B does the verification.
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
    let wallet = state.wallet()?;
    reply(send(&state, UserRequest::Freeze { wallet }).await?)
}

#[derive(Deserialize)]
struct RejectRequest {
    request_id: B256,
}

async fn reject(
    State(state): State<Shared>,
    Json(request): Json<RejectRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let wallet = state.wallet()?;
    reply(
        send(
            &state,
            UserRequest::RejectPending {
                wallet,
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

/// Register the browser's passkey. The currently registered software passkey signs the rotation.
async fn adopt(
    State(state): State<Shared>,
    Json(request): Json<AdoptRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let wallet = state.wallet()?;
    let path = state.legacy_passkey.as_ref().ok_or_else(|| {
        bad_request("start mw-owner with --legacy-passkey to adopt a new passkey")
    })?;
    let new_passkey = RegisteredPasskey::from_spki(
        decode("credential_id", &request.credential_id)?,
        &decode("spki", &request.spki)?,
    )?;
    let mut legacy: SoftwarePasskey = serde_json::from_slice(&std::fs::read(path)?)?;
    let signed = legacy.sign(UserOperation::RotatePasskey {
        wallet,
        new_passkey,
    });
    // The signature counter moved, so save it before sending
    std::fs::write(path, serde_json::to_vec_pretty(&legacy)?)?;
    reply(send(&state, UserRequest::Signed { signed }).await?)
}

// ---- assets --------------------------------------------------------------------

fn asset(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

fn router(state: Shared) -> Router {
    const JS: &str = "text/javascript; charset=utf-8";
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
            get(|| async { asset(JS, include_str!("../static/app.js")) }),
        )
        .route(
            "/setup.js",
            get(|| async { asset(JS, include_str!("../static/setup.js")) }),
        )
        .route(
            "/ui.js",
            get(|| async { asset(JS, include_str!("../static/ui.js")) }),
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
        .route("/api/setup/state", get(setup_state))
        .route("/api/setup/keygen", post(setup_keygen))
        .route("/api/setup/progress", get(setup_progress))
        .route("/api/mcp-command", get(mcp_command))
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
    let wallet = load_wallet(&cli.data_dir);
    if wallet.is_none() && cli.data_dir.join(SHARE_A_FILE).exists() {
        bail!(
            "{} holds share A but no {}; write the wallet address there first",
            cli.data_dir.display(),
            mw_node_a::shares::WALLET_FILE
        );
    }
    let state = Arc::new(AppState {
        endpoint,
        node_b: cli.node_b,
        tls_dir: cli.tls_dir,
        data_dir: cli.data_dir,
        wallet: RwLock::new(wallet),
        setup: Mutex::new(SetupJob::default()),
        pcr0: cli.expected_pcr0,
        rpc: rpc().await,
        legacy_passkey: cli.legacy_passkey,
    });
    // Only reachable from this machine
    let addr = SocketAddr::from(([127, 0, 0, 1], cli.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    match wallet {
        Some(wallet) => eprintln!("owner app for {wallet} on http://localhost:{}", cli.port),
        None => eprintln!(
            "no wallet yet: open http://localhost:{} to set one up",
            cli.port
        ),
    }
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::shell_quote;

    #[test]
    fn quotes_only_when_needed() {
        assert_eq!(shell_quote("/opt/mw/data"), "/opt/mw/data");
        assert_eq!(shell_quote("3.112.217.26:7443"), "3.112.217.26:7443");
        assert_eq!(shell_quote("/Users/me/My Wallet"), "'/Users/me/My Wallet'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(""), "''");
    }
}
