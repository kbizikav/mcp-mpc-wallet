use alloy_primitives::B256;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// ドメイン分離付きで値の SHA-256 を取る。
///
/// serde_json のシリアライズ結果をハッシュするので、ハッシュ対象の型には
/// `HashMap` のような順序が定まらないコンテナを入れないこと。
pub fn canonical_hash<T: Serialize + ?Sized>(domain: &str, value: &T) -> B256 {
    let body = serde_json::to_vec(value).expect("serializing to Vec<u8> does not fail");
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher.update(&body);
    B256::from_slice(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_separates() {
        assert_ne!(canonical_hash("a", &1u8), canonical_hash("b", &1u8));
        assert_eq!(canonical_hash("a", &1u8), canonical_hash("a", &1u8));
    }
}
