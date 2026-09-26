#![allow(clippy::unwrap_used)]

//! M0 spike: check that the following flow works with cggmp21.
//!
//! 1. A, B and C run 2-of-3 DKG and aux info generation
//! 2. Only for a digest B approved, A and B generate a fresh presignature
//! 3. A hands its partial signature to B only, and B combines and verifies
//!
//! A only ever holds the presignature and its own partial signature, never the final signature.

use cggmp21::{
    DataToSign, ExecutionId, KeyShare, PartialSignature, Presignature,
    generic_ec::{Point, coords::HasAffineX},
    security_level::SecurityLevel128,
    supported_curves::Secp256k1,
};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use round_based::sim::async_env;
use sha3::{Digest, Keccak256};

type E = Secp256k1;

const A: u16 = 0;
const B: u16 = 1;
const C: u16 = 2;

fn fresh_eid() -> Vec<u8> {
    let mut eid = vec![0u8; 32];
    OsRng.fill_bytes(&mut eid);
    eid
}

async fn setup_2_of_3() -> Vec<KeyShare<E, SecurityLevel128>> {
    let n = 3;

    let keygen_eid = fresh_eid();
    let incomplete = async_env::run(n, |i, party| {
        let eid = ExecutionId::new(&keygen_eid);
        async move {
            cggmp21::keygen::<E>(eid, i, n)
                .set_threshold(2)
                .start(&mut OsRng, party)
                .await
        }
    })
    .await
    .expect_ok()
    .into_vec();

    let aux_eid = fresh_eid();
    let aux = async_env::run(n, |i, party| {
        let eid = ExecutionId::new(&aux_eid);
        async move {
            let primes = cggmp21::PregeneratedPrimes::<SecurityLevel128>::generate(&mut OsRng);
            cggmp21::aux_info_gen(eid, i, n, primes)
                .start(&mut OsRng, party)
                .await
        }
    })
    .await
    .expect_ok()
    .into_vec();

    incomplete
        .into_iter()
        .zip(aux)
        .map(|parts| KeyShare::from_parts(parts).expect("valid key share"))
        .collect()
}

/// Generate one fresh presignature with the two parties in `signers`.
async fn presign(
    shares: &[KeyShare<E, SecurityLevel128>],
    signers: [u16; 2],
) -> Vec<Presignature<E>> {
    let eid_bytes = fresh_eid();
    let setups = signers.map(|keygen_index| shares[usize::from(keygen_index)].clone());
    async_env::run_with_setup(setups, |i, party, share| {
        let eid = ExecutionId::new(&eid_bytes);
        async move {
            cggmp21::signing(eid, i, &signers, &share)
                .generate_presignature(&mut OsRng, party)
                .await
        }
    })
    .await
    .expect_ok()
    .into_vec()
}

fn eth_address(public_key: &Point<E>) -> [u8; 20] {
    let uncompressed = public_key.to_bytes(false);
    let hash = Keccak256::digest(&uncompressed[1..]);
    hash[12..].try_into().unwrap()
}

/// Turn a cggmp21 (r, s) into Ethereum's (r, s, v). v is found by recovery.
fn to_recoverable(
    sig: &cggmp21::Signature<E>,
    prehash: &[u8; 32],
    expected: [u8; 20],
) -> (K256Signature, RecoveryId) {
    let mut bytes = [0u8; 64];
    sig.write_to_slice(&mut bytes);
    let k256_sig = K256Signature::from_slice(&bytes).expect("valid (r, s)");
    for v in 0..2u8 {
        let recid = RecoveryId::from_byte(v).unwrap();
        if let Ok(vk) = VerifyingKey::recover_from_prehash(prehash, &k256_sig, recid) {
            let point = vk.to_encoded_point(false);
            let hash = Keccak256::digest(&point.as_bytes()[1..]);
            if hash[12..] == expected {
                return (k256_sig, recid);
            }
        }
    }
    panic!("signature does not recover to the wallet address");
}

#[tokio::test(flavor = "current_thread")]
async fn a_sends_partial_signature_only_to_b() {
    let shares = setup_2_of_3().await;
    let public_key = *shares[0].shared_public_key;
    let address = eth_address(&public_key);

    // The signing hash of a tx B approved (a dummy here)
    let digest: [u8; 32] = Keccak256::digest(b"approved unsigned tx").into();
    let data =
        DataToSign::<E>::from_scalar(cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(digest));

    // After approval, make a fresh presignature and use it for this one signature only
    let mut presigs = presign(&shares, [A, B]).await.into_iter();
    let presig_a = presigs.next().unwrap();
    let presig_b = presigs.next().unwrap();

    // A's side: only make its partial signature and send it to B
    let partial_a: PartialSignature<E> = presig_a.issue_partial_signature(data);

    // A's partial signature alone is not a valid signature
    let only_a = PartialSignature::combine(std::slice::from_ref(&partial_a)).unwrap();
    assert!(only_a.verify(&public_key, &data).is_err());

    // B's side: combine with its own partial signature and verify
    let partial_b = presig_b.issue_partial_signature(data);
    let sig = PartialSignature::combine(&[partial_a, partial_b]).unwrap();
    sig.verify(&public_key, &data)
        .expect("B obtains a valid signature");

    let (_sig, _recid) = to_recoverable(&sig, &digest, address);

    // `issue_partial_signature(self)` consumes the presignature, so the types prevent reuse too
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_paths_can_sign() {
    let shares = setup_2_of_3().await;
    let public_key = *shares[0].shared_public_key;
    let address = eth_address(&public_key);

    for signers in [[A, C], [B, C]] {
        let digest: [u8; 32] = Keccak256::digest(format!("tx for {signers:?}")).into();
        let data = DataToSign::<E>::from_scalar(
            cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(digest),
        );
        let partials: Vec<_> = presign(&shares, signers)
            .await
            .into_iter()
            .map(|p| p.issue_partial_signature(data))
            .collect();
        let sig = PartialSignature::combine(&partials).unwrap();
        sig.verify(&public_key, &data).unwrap();
        to_recoverable(&sig, &digest, address);
    }
}

#[test]
fn affine_x_is_available() {
    // Check that secp256k1 satisfies the traits needed to compute a presignature's r
    fn assert_has_affine_x<T: HasAffineX<E>>() {}
    assert_has_affine_x::<Point<E>>();
}
