//! Judge node B's server: the mTLS connection with A, key generation, and threshold signing with cggmp21.

pub mod keygen;
pub mod net;
pub mod notifier;
pub mod server;
pub mod signer;

pub use signer::CggmpSigner;

/// Label for B's share in SealedStorage (the first wallet, kept for compatibility)
pub const SHARE_LABEL: &str = "share-b";

/// Label for each wallet's share.
pub fn share_label(wallet: alloy_primitives::Address) -> String {
    format!("{SHARE_LABEL}-{}", alloy_primitives::hex::encode(wallet))
}

/// Unseal every sealed share and load it into the signer. Returns the loaded wallets.
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

/// Seal a new wallet's share, then add it to the signer.
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

/// Issue an attestation document inside the enclave. user_data is the SHA-256 of the TLS certificate.
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
