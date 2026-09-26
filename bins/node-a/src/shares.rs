//! Storage for share A and the recovery share C.
//!
//! - A: JSON in a file only the owner can read (assumed readable by the agent)
//! - C: encrypted with the user's passphrase using age (scrypt + ChaCha20-Poly1305).
//!   If A and C sat in plaintext on the same machine, they could sign without B.
//!   To be replaced with WebAuthn PRF encryption in M5.

use std::io::{Read, Write};
use std::path::Path;

use mw_mpc::protocol::KeyShare;
use secrecy::{ExposeSecret, SecretString};

pub const SHARE_A_FILE: &str = "share-a.json";
/// The wallet address (public). The owner app uses it to tell whether a wallet exists
pub const WALLET_FILE: &str = "wallet.json";
pub const SHARE_C_FILE: &str = "share-c.age";

#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    #[error("{path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("malformed key share: {0}")]
    Malformed(String),
    #[error("encryption: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), ShareError> {
    let err = |source| ShareError::Io {
        path: path.display().to_string(),
        source,
    };
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(err)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(err)
}

fn read(path: &Path) -> Result<Vec<u8>, ShareError> {
    std::fs::read(path).map_err(|source| ShareError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// Write the address of a wallet whose key generation has finished.
pub fn save_wallet(dir: &Path, address: alloy_primitives::Address) -> Result<(), ShareError> {
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({ "address": address }))
        .map_err(|e| ShareError::Malformed(e.to_string()))?;
    std::fs::write(dir.join(WALLET_FILE), bytes).map_err(|source| ShareError::Io {
        path: dir.join(WALLET_FILE).display().to_string(),
        source,
    })
}

/// Return the wallet address if key generation has finished.
pub fn load_wallet(dir: &Path) -> Option<alloy_primitives::Address> {
    let bytes = std::fs::read(dir.join(WALLET_FILE)).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value["address"].as_str()?.parse().ok()
}

pub fn save_share_a(dir: &Path, share: &KeyShare) -> Result<(), ShareError> {
    let bytes = serde_json::to_vec(share).map_err(|e| ShareError::Malformed(e.to_string()))?;
    write_new(&dir.join(SHARE_A_FILE), &bytes)
}

pub fn load_share_a(dir: &Path) -> Result<KeyShare, ShareError> {
    serde_json::from_slice(&read(&dir.join(SHARE_A_FILE))?)
        .map_err(|e| ShareError::Malformed(e.to_string()))
}

pub fn save_share_c(
    dir: &Path,
    share: &KeyShare,
    passphrase: &SecretString,
) -> Result<(), ShareError> {
    let plaintext = serde_json::to_vec(share).map_err(|e| ShareError::Malformed(e.to_string()))?;
    let encryptor = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(
        passphrase.expose_secret().to_owned(),
    ));
    let mut ciphertext = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut ciphertext)
        .map_err(|e| ShareError::Encrypt(e.to_string()))?;
    writer
        .write_all(&plaintext)
        .and_then(|()| writer.finish().map(|_| ()))
        .map_err(|e| ShareError::Encrypt(e.to_string()))?;
    write_new(&dir.join(SHARE_C_FILE), &ciphertext)
}

/// Used for recovery.
pub fn load_share_c(dir: &Path, passphrase: &SecretString) -> Result<KeyShare, ShareError> {
    let ciphertext = read(&dir.join(SHARE_C_FILE))?;
    let identity = age::scrypt::Identity::new(age::secrecy::SecretString::from(
        passphrase.expose_secret().to_owned(),
    ));
    let decryptor =
        age::Decryptor::new(&ciphertext[..]).map_err(|e| ShareError::Decrypt(e.to_string()))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|e| ShareError::Decrypt(e.to_string()))?;
    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| ShareError::Decrypt(e.to_string()))?;
    serde_json::from_slice(&plaintext).map_err(|e| ShareError::Malformed(e.to_string()))
}
