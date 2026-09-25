//! cggmp21 の鍵生成・aux info 生成・presign と、署名の変換。
//!
//! パーティの番号は鍵生成時に A = 0、B = 1、C = 2 に固定する。
//! presignature は承認後に毎回新しく作り、1 回だけ使って捨てる(再利用は鍵漏洩につながる)。

use alloy_primitives::{Address, B256, Signature, U256, keccak256};
use cggmp21::generic_ec::{NonZero, Point, Scalar};
use cggmp21::round_based::Mpc;
use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::{DataToSign, ExecutionId};
use rand_core::OsRng;

pub type Curve = Secp256k1;
pub type KeyShare = cggmp21::KeyShare<Curve, SecurityLevel128>;
pub type IncompleteKeyShare = cggmp21::IncompleteKeyShare<Curve>;
pub type AuxInfo = cggmp21::key_share::AuxInfo<SecurityLevel128>;
pub type PregeneratedPrimes = cggmp21::PregeneratedPrimes<SecurityLevel128>;
pub type Presignature = cggmp21::Presignature<Curve>;
/// 部分署名。A は自分のものを B にだけ送る
pub type PartialSignature = cggmp21::PartialSignature<Curve>;

pub const PARTY_A: u16 = 0;
pub const PARTY_B: u16 = 1;
pub const PARTY_C: u16 = 2;
pub const PARTIES: u16 = 3;
pub const THRESHOLD: u16 = 2;
/// 通常の署名は A と B で行う。signer index 0 = A、1 = B
pub const SIGNERS_AB: [u16; 2] = [PARTY_A, PARTY_B];

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("keygen failed: {0}")]
    Keygen(String),
    #[error("aux info generation failed: {0}")]
    Aux(String),
    #[error("presignature generation failed: {0}")]
    Presign(String),
    #[error("invalid key share: {0}")]
    InvalidShare(String),
}

/// 実行ごとに一意な ID。フェーズごとにドメインを分ける。
pub fn execution_id(session: &[u8; 32], phase: &str) -> Vec<u8> {
    let mut id = b"mcp-mpc-wallet/".to_vec();
    id.extend_from_slice(phase.as_bytes());
    id.push(b'/');
    id.extend_from_slice(session);
    id
}

pub async fn keygen_party<M>(
    eid: &[u8],
    i: u16,
    party: M,
) -> Result<IncompleteKeyShare, ProtocolError>
where
    M: Mpc<ProtocolMessage = cggmp21::keygen::ThresholdMsg<Curve, SecurityLevel128, sha2::Sha256>>,
{
    cggmp21::keygen::<Curve>(ExecutionId::new(eid), i, PARTIES)
        .set_threshold(THRESHOLD)
        .start(&mut OsRng, party)
        .await
        .map_err(|e| ProtocolError::Keygen(e.to_string()))
}

pub async fn aux_party<M>(
    eid: &[u8],
    i: u16,
    primes: PregeneratedPrimes,
    party: M,
) -> Result<AuxInfo, ProtocolError>
where
    M: Mpc<
        ProtocolMessage = cggmp21::key_refresh::msg::aux_only::Msg<sha2::Sha256, SecurityLevel128>,
    >,
{
    cggmp21::aux_info_gen(ExecutionId::new(eid), i, PARTIES, primes)
        .start(&mut OsRng, party)
        .await
        .map_err(|e| ProtocolError::Aux(e.to_string()))
}

pub fn complete_share(
    incomplete: IncompleteKeyShare,
    aux: AuxInfo,
) -> Result<KeyShare, ProtocolError> {
    KeyShare::from_parts((incomplete, aux)).map_err(|e| ProtocolError::InvalidShare(e.to_string()))
}

/// presignature を 1 つ作る。`signer_index` は `signers` の中での位置。
pub async fn presign_party<M>(
    eid: &[u8],
    signer_index: u16,
    signers: &[u16],
    share: &KeyShare,
    party: M,
) -> Result<Presignature, ProtocolError>
where
    M: Mpc<ProtocolMessage = cggmp21::signing::msg::Msg<Curve, sha2::Sha256>>,
{
    cggmp21::signing(ExecutionId::new(eid), signer_index, signers, share)
        .generate_presignature(&mut OsRng, party)
        .await
        .map_err(|e| ProtocolError::Presign(e.to_string()))
}

pub fn data_to_sign(signing_hash: &B256) -> DataToSign<Curve> {
    DataToSign::from_scalar(Scalar::from_be_bytes_mod_order(signing_hash.as_slice()))
}

/// presignature を消費して、この 1 件の hash にだけ部分署名する。
pub fn issue_partial(presig: Presignature, signing_hash: &B256) -> PartialSignature {
    presig.issue_partial_signature(data_to_sign(signing_hash))
}

pub fn public_key(share: &KeyShare) -> NonZero<Point<Curve>> {
    share.shared_public_key
}

pub fn address_of(public_key: &Point<Curve>) -> Address {
    let uncompressed = public_key.to_bytes(false);
    Address::from_slice(&keccak256(&uncompressed[1..])[12..])
}

/// 部分署名を合成し、公開鍵で検証してから Ethereum の (r, s, v) にする。
pub fn combine(
    partials: &[PartialSignature],
    signing_hash: &B256,
    public_key: &Point<Curve>,
) -> Option<Signature> {
    let sig = cggmp21::PartialSignature::combine(partials)?;
    sig.verify(public_key, &data_to_sign(signing_hash)).ok()?;
    let mut bytes = [0u8; 64];
    sig.write_to_slice(&mut bytes);
    let r = U256::from_be_slice(&bytes[..32]);
    let s = U256::from_be_slice(&bytes[32..]);
    let address = address_of(public_key);
    [false, true].into_iter().find_map(|parity| {
        let candidate = Signature::new(r, s, parity);
        (candidate.recover_address_from_prehash(signing_hash).ok() == Some(address))
            .then_some(candidate)
    })
}
