//! 判定ノード B のサーバ: A との mTLS 接続、鍵生成、cggmp21 による閾値署名。

pub mod keygen;
pub mod net;
pub mod notifier;
pub mod server;
pub mod signer;

pub use signer::CggmpSigner;

/// B のシェアを SealedStorage に保存するときのラベル(最初のウォレット。互換のため)
pub const SHARE_LABEL: &str = "share-b";

/// ウォレットごとのシェアのラベル。
pub fn share_label(wallet: alloy_primitives::Address) -> String {
    format!("{SHARE_LABEL}-{}", alloy_primitives::hex::encode(wallet))
}

/// 封印されたシェアをすべて復号し、署名器に読み込む。読み込んだウォレットを返す。
pub fn load_shares<S>(
    storage: &dyn mw_tee::SealedStorage,
    signer: &CggmpSigner<S>,
) -> Result<Vec<alloy_primitives::Address>, anyhow::Error> {
    use secrecy::ExposeSecret;
    let mut wallets = Vec::new();
    for label in storage.labels()? {
        if label != SHARE_LABEL && !label.starts_with(&format!("{SHARE_LABEL}-")) {
            continue;
        }
        let sealed = storage.unseal(&label)?;
        let share = serde_json::from_slice(sealed.expose_secret())?;
        wallets.push(signer.add(share)?);
    }
    Ok(wallets)
}

/// 新しいウォレットのシェアを封印してから、署名器に加える。
pub fn store_share<S>(
    storage: &dyn mw_tee::SealedStorage,
    signer: &CggmpSigner<S>,
    share: mw_mpc::protocol::KeyShare,
) -> Result<alloy_primitives::Address, anyhow::Error> {
    let wallet = mw_mpc::protocol::address_of(&share.shared_public_key);
    let bytes = serde_json::to_vec(&share)?;
    storage.seal(&share_label(wallet), &secrecy::SecretSlice::from(bytes))?;
    signer.add(share)?;
    Ok(wallet)
}

/// enclave の中で attestation document を発行する。user_data は TLS 証明書の SHA-256。
pub struct AttestationService {
    pub attestor: Box<dyn mw_tee::Attestor>,
    pub cert_hash: [u8; 32],
}

impl AttestationService {
    pub fn respond(&self, nonce: &alloy_primitives::B256) -> mw_wire::BtoA {
        match self.attestor.attest(&self.cert_hash, nonce.as_slice()) {
            Ok(doc) => mw_wire::BtoA::Attestation {
                document: doc.bytes.into(),
            },
            Err(e) => mw_wire::BtoA::Error {
                message: format!("attestation failed: {e}"),
            },
        }
    }
}
