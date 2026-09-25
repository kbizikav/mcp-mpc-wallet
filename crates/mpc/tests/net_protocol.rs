//! プロセスをまたいだ鍵生成と署名(チャネルで 2 プロセスを模す)。
//!
//! A 側プロセスが A(0) と C(2) を、B 側プロセスが B(1) を動かす。
//! 署名は A と B で行い、最終署名は B だけが合成する。

#![allow(clippy::unwrap_used)]

use alloy_primitives::{B256, keccak256};
use futures::channel::mpsc;
use mw_mpc::net::run_parties;
use mw_mpc::protocol::{
    KeyShare, PARTIES, PARTY_A, PARTY_B, PARTY_C, PregeneratedPrimes, SIGNERS_AB, address_of,
    aux_party, combine, complete_share, execution_id, issue_partial, keygen_party, presign_party,
    sign_with_local_shares,
};
use rand_core::{OsRng, RngCore};

fn session() -> [u8; 32] {
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

/// (A 側プロセスのシェア [A, C], B のシェア)
async fn distributed_keygen() -> (Vec<KeyShare>, KeyShare) {
    let s = session();

    let (a_out, b_in) = mpsc::unbounded();
    let (b_out, a_in) = mpsc::unbounded();
    let kg = execution_id(&s, "keygen");
    let (a_incomplete, b_incomplete) = futures::join!(
        run_parties(PARTIES, &[PARTY_A, PARTY_C], a_out, a_in, |i, party| {
            let kg = kg.clone();
            async move { keygen_party(&kg, i, party).await }
        }),
        run_parties(PARTIES, &[PARTY_B], b_out, b_in, |i, party| {
            let kg = kg.clone();
            async move { keygen_party(&kg, i, party).await }
        }),
    );

    let (a_out, b_in) = mpsc::unbounded();
    let (b_out, a_in) = mpsc::unbounded();
    let aux = execution_id(&s, "aux");
    let (a_aux, b_aux) = futures::join!(
        run_parties(PARTIES, &[PARTY_A, PARTY_C], a_out, a_in, |i, party| {
            let aux = aux.clone();
            async move { aux_party(&aux, i, PregeneratedPrimes::generate(&mut OsRng), party).await }
        }),
        run_parties(PARTIES, &[PARTY_B], b_out, b_in, |i, party| {
            let aux = aux.clone();
            async move { aux_party(&aux, i, PregeneratedPrimes::generate(&mut OsRng), party).await }
        }),
    );

    let a_side: Vec<KeyShare> = a_incomplete
        .unwrap()
        .into_iter()
        .zip(a_aux.unwrap())
        .map(|(k, a)| complete_share(k.unwrap(), a.unwrap()).unwrap())
        .collect();
    let b = complete_share(
        b_incomplete.unwrap().pop().unwrap().unwrap(),
        b_aux.unwrap().pop().unwrap().unwrap(),
    )
    .unwrap();
    (a_side, b)
}

#[tokio::test(flavor = "current_thread")]
async fn keygen_and_sign_across_processes() {
    let (a_side, share_b) = distributed_keygen().await;
    let share_a = &a_side[0];
    let share_c = &a_side[1];
    assert_eq!(share_a.shared_public_key, share_b.shared_public_key);
    assert_eq!(share_c.shared_public_key, share_b.shared_public_key);
    let public_key = *share_b.shared_public_key;
    let address = address_of(&public_key);

    let signing_hash: B256 = keccak256(b"approved unsigned tx");
    let eid = execution_id(&session(), "presign");
    let (a_out, b_in) = mpsc::unbounded();
    let (b_out, a_in) = mpsc::unbounded();
    let (a_presig, b_presig) = futures::join!(
        run_parties(2, &[0], a_out, a_in, |i, party| {
            let eid = eid.clone();
            async move { presign_party(&eid, i, &SIGNERS_AB, share_a, party).await }
        }),
        run_parties(2, &[1], b_out, b_in, |i, party| {
            let eid = eid.clone();
            let share_b = &share_b;
            async move { presign_party(&eid, i, &SIGNERS_AB, share_b, party).await }
        }),
    );

    // A は部分署名を作って B に送るだけ
    let partial_a = issue_partial(a_presig.unwrap().pop().unwrap().unwrap(), &signing_hash);
    assert!(combine(std::slice::from_ref(&partial_a), &signing_hash, &public_key).is_none());

    // B が合成し、ウォレットのアドレスに復元できる署名を得る
    let partial_b = issue_partial(b_presig.unwrap().pop().unwrap().unwrap(), &signing_hash);
    let signature = combine(&[partial_a, partial_b], &signing_hash, &public_key).unwrap();
    assert_eq!(
        signature
            .recover_address_from_prehash(&signing_hash)
            .unwrap(),
        address
    );

    // 復旧経路: A+C(B なし)と B+C(A なし)でも署名できる
    for pair in [[share_a, share_c], [&share_b, share_c]] {
        let hash = keccak256(format!("recovery {}", pair[0].i));
        let sig = sign_with_local_shares(pair, &hash).await.unwrap();
        assert_eq!(sig.recover_address_from_prehash(&hash).unwrap(), address);
    }
    let _ = PARTY_B;
}
