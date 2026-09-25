//! 判定ノード B のサーバ: A との mTLS 接続、鍵生成、cggmp21 による閾値署名。

pub mod keygen;
pub mod notifier;
pub mod server;
pub mod signer;

pub use signer::CggmpSigner;

/// B のシェアを SealedStorage に保存するときのラベル
pub const SHARE_LABEL: &str = "share-b";
