use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{B256, Bytes, Signature, keccak256};
use alloy_rlp::Decodable;

const EIP1559_TYPE: u8 = 0x02;

/// B が自分でデコードした未署名 tx。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTx {
    pub tx: TxEip1559,
    /// 署名対象のバイト列(`0x02 || rlp(fields)`)。入力と完全に一致する
    pub payload: Bytes,
    /// `keccak256(payload)`。typed tx ではこれがそのまま署名する hash になる
    pub signing_hash: B256,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("empty payload")]
    Empty,
    #[error("unsupported transaction type 0x{0:02x} (only EIP-1559 is accepted)")]
    UnsupportedType(u8),
    #[error("malformed RLP: {0}")]
    Rlp(String),
    #[error("trailing bytes after the transaction")]
    TrailingBytes,
    #[error("non-canonical encoding")]
    NonCanonical,
    #[error("max_priority_fee_per_gas exceeds max_fee_per_gas")]
    InvalidFees,
}

/// EIP-2718 形式の未署名 EIP-1559 tx をデコードする。
///
/// 再エンコードして入力と一致しない(非正規な)エンコーディングは拒否する。
/// 署名する hash とデコード結果が必ず対応するようにするため。
pub fn decode_unsigned(payload: &[u8]) -> Result<DecodedTx, DecodeError> {
    let (&ty, mut body) = payload.split_first().ok_or(DecodeError::Empty)?;
    if ty != EIP1559_TYPE {
        return Err(DecodeError::UnsupportedType(ty));
    }
    let tx = TxEip1559::decode(&mut body).map_err(|e| DecodeError::Rlp(e.to_string()))?;
    if !body.is_empty() {
        return Err(DecodeError::TrailingBytes);
    }
    let mut reencoded = Vec::with_capacity(payload.len());
    tx.encode_for_signing(&mut reencoded);
    if reencoded != payload {
        return Err(DecodeError::NonCanonical);
    }
    if tx.max_priority_fee_per_gas > tx.max_fee_per_gas {
        return Err(DecodeError::InvalidFees);
    }
    let signing_hash = tx.signature_hash();
    debug_assert_eq!(signing_hash, keccak256(payload));
    Ok(DecodedTx {
        tx,
        payload: Bytes::copy_from_slice(payload),
        signing_hash,
    })
}

/// 署名済み tx の raw バイト列と tx hash を作る。
pub fn encode_signed(tx: TxEip1559, signature: Signature) -> (Bytes, B256) {
    let signed = tx.into_signed(signature);
    let hash = *signed.hash();
    (Bytes::from(signed.encoded_2718()), hash)
}

#[cfg(test)]
pub(crate) mod tests {
    use alloy_primitives::{Address, TxKind, U256};

    use super::*;

    pub(crate) fn sample_tx() -> TxEip1559 {
        TxEip1559 {
            chain_id: 84532,
            nonce: 3,
            gas_limit: 21_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(Address::repeat_byte(0x22)),
            value: U256::from(10_000_000_000_000_000u64),
            access_list: Default::default(),
            input: Bytes::new(),
        }
    }

    pub(crate) fn encode_unsigned(tx: &TxEip1559) -> Vec<u8> {
        let mut out = Vec::new();
        tx.encode_for_signing(&mut out);
        out
    }

    #[test]
    fn round_trips() {
        let payload = encode_unsigned(&sample_tx());
        let decoded = decode_unsigned(&payload).unwrap();
        assert_eq!(decoded.tx, sample_tx());
        assert_eq!(decoded.signing_hash, keccak256(&payload));
    }

    #[test]
    fn rejects_other_types_and_garbage() {
        assert_eq!(decode_unsigned(&[]).unwrap_err(), DecodeError::Empty);
        let mut legacy = encode_unsigned(&sample_tx());
        legacy[0] = 0x00;
        assert_eq!(
            decode_unsigned(&legacy).unwrap_err(),
            DecodeError::UnsupportedType(0)
        );
        assert!(matches!(
            decode_unsigned(&[0x02, 0xff]).unwrap_err(),
            DecodeError::Rlp(_)
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut payload = encode_unsigned(&sample_tx());
        payload.push(0);
        assert_eq!(
            decode_unsigned(&payload).unwrap_err(),
            DecodeError::TrailingBytes
        );
    }

    #[test]
    fn rejects_inverted_fees() {
        let mut tx = sample_tx();
        tx.max_priority_fee_per_gas = tx.max_fee_per_gas + 1;
        assert_eq!(
            decode_unsigned(&encode_unsigned(&tx)).unwrap_err(),
            DecodeError::InvalidFees
        );
    }

    #[test]
    fn signed_encoding_has_expected_hash() {
        let sig = Signature::new(U256::from(1), U256::from(2), false);
        let (raw, hash) = encode_signed(sample_tx(), sig);
        assert_eq!(raw[0], 0x02);
        assert_eq!(hash, keccak256(&raw));
    }
}
