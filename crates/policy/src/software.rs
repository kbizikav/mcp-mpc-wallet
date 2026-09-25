//! 開発用のソフトウェアパスキー。本物の認証器と同じ形式の assertion を作る。
//!
//! 秘密鍵をファイルに置くので、本物のパスキー(ユーザーアプリ)ができるまでの開発・テスト専用。

use alloy_primitives::Bytes;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::webauthn::encode_challenge;
use crate::{PasskeyAssertion, RegisteredPasskey, SignedUserOperation, UserOperation};

#[derive(Serialize, Deserialize)]
pub struct SoftwarePasskey {
    pub rp_id: String,
    pub origin: String,
    pub credential_id: Bytes,
    /// P-256 の秘密鍵(32 バイト)
    secret: Bytes,
    pub sign_count: u32,
}

impl SoftwarePasskey {
    pub fn generate(rp_id: &str, origin: &str) -> Self {
        let mut credential_id = [0u8; 16];
        OsRng.fill_bytes(&mut credential_id);
        let key = SigningKey::random(&mut OsRng);
        Self {
            rp_id: rp_id.into(),
            origin: origin.into(),
            credential_id: Bytes::copy_from_slice(&credential_id),
            secret: Bytes::copy_from_slice(&key.to_bytes()),
            sign_count: 0,
        }
    }

    fn key(&self) -> SigningKey {
        SigningKey::from_slice(&self.secret).expect("valid P-256 secret")
    }

    /// B に登録する公開情報。
    pub fn registration(&self) -> RegisteredPasskey {
        RegisteredPasskey {
            credential_id: self.credential_id.clone(),
            public_key: Bytes::copy_from_slice(
                self.key()
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes(),
            ),
            sign_count: 0,
        }
    }

    /// 操作に署名する。呼ぶたびに署名カウンタが 1 増える。
    pub fn sign(&mut self, operation: UserOperation) -> SignedUserOperation {
        self.sign_count += 1;
        let client_data_json = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": encode_challenge(&operation.challenge()),
            "origin": self.origin,
            "crossOrigin": false,
        }))
        .expect("serializable");
        let mut authenticator_data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        authenticator_data.push(0x01 | 0x04);
        authenticator_data.extend_from_slice(&self.sign_count.to_be_bytes());

        let mut message = authenticator_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data_json));
        let signature: Signature = self.key().sign(&message);
        SignedUserOperation {
            operation,
            assertion: PasskeyAssertion {
                credential_id: self.credential_id.clone(),
                authenticator_data: authenticator_data.into(),
                client_data_json: client_data_json.into(),
                signature: Bytes::copy_from_slice(signature.to_der().as_bytes()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, B256};
    use mw_core::Policy;

    use super::*;
    use crate::{PasskeyError, PasskeyVerifier, RegisteredPasskey, RelyingParty};

    const RP: &str = "wallet.example";
    const ORIGIN: &str = "https://wallet.example";

    fn verifier() -> PasskeyVerifier {
        PasskeyVerifier {
            allowed: vec![
                RelyingParty::new(RP, ORIGIN),
                RelyingParty::new("localhost", "http://localhost:8787"),
            ],
        }
    }

    fn set_policy(version: u64) -> UserOperation {
        UserOperation::SetPolicy {
            policy: Policy {
                wallet: Address::repeat_byte(1),
                version,
                text: "small transfers only".into(),
            },
        }
    }

    #[test]
    fn accepts_valid_assertion_and_advances_counter() {
        let mut passkey = SoftwarePasskey::generate(RP, ORIGIN);
        let mut registered = passkey.registration();
        let signed = passkey.sign(set_policy(1));
        registered.sign_count = verifier().verify(&registered, &signed).unwrap();
        assert_eq!(registered.sign_count, 1);
        // 同じ assertion の再送はカウンタで弾かれる
        assert_eq!(
            verifier().verify(&registered, &signed).unwrap_err(),
            PasskeyError::CounterNotIncreased
        );
    }

    #[test]
    fn rejects_tampered_operation() {
        let mut passkey = SoftwarePasskey::generate(RP, ORIGIN);
        let registered = passkey.registration();
        let mut signed = passkey.sign(set_policy(1));
        signed.operation = set_policy(2);
        assert_eq!(
            verifier().verify(&registered, &signed).unwrap_err(),
            PasskeyError::ClientData("challenge")
        );
    }

    #[test]
    fn rejects_other_keys_origins_and_rps() {
        let mut passkey = SoftwarePasskey::generate(RP, ORIGIN);
        let signed = passkey.sign(set_policy(1));

        let mut other = SoftwarePasskey::generate(RP, ORIGIN).registration();
        other.credential_id = passkey.credential_id.clone();
        assert_eq!(
            verifier().verify(&other, &signed).unwrap_err(),
            PasskeyError::BadSignature
        );

        let registered = passkey.registration();
        let wrong_origin = PasskeyVerifier {
            allowed: vec![RelyingParty::new(RP, "https://evil.example")],
        };
        assert_eq!(
            wrong_origin.verify(&registered, &signed).unwrap_err(),
            PasskeyError::ClientData("origin")
        );
        let wrong_rp = PasskeyVerifier {
            allowed: vec![RelyingParty::new("evil.example", ORIGIN)],
        };
        assert_eq!(
            wrong_rp.verify(&registered, &signed).unwrap_err(),
            PasskeyError::WrongRelyingParty
        );
    }

    #[test]
    fn requires_user_verification() {
        let mut passkey = SoftwarePasskey::generate(RP, ORIGIN);
        let registered = passkey.registration();
        let mut signed = passkey.sign(UserOperation::ApproveRequest {
            wallet: Address::ZERO,
            request_id: B256::ZERO,
        });
        let mut auth = signed.assertion.authenticator_data.to_vec();
        auth[32] = 0x01; // UP のみ
        signed.assertion.authenticator_data = auth.into();
        assert_eq!(
            verifier().verify(&registered, &signed).unwrap_err(),
            PasskeyError::UserNotVerified
        );
    }

    #[test]
    fn accepts_each_allowed_relying_party_with_its_own_rp_id() {
        // ブラウザ(localhost)の形式でも、同じ検証器で通る
        let mut browser = SoftwarePasskey::generate("localhost", "http://localhost:8787");
        let registered = browser.registration();
        assert!(
            verifier()
                .verify(&registered, &browser.sign(set_policy(1)))
                .is_ok()
        );

        // origin と RP ID の組が合わないものは通らない
        let mut mixed = SoftwarePasskey::generate(RP, "http://localhost:8787");
        let registered = mixed.registration();
        assert_eq!(
            verifier()
                .verify(&registered, &mixed.sign(set_policy(1)))
                .unwrap_err(),
            PasskeyError::WrongRelyingParty
        );
    }

    #[test]
    fn registration_from_browser_spki() {
        use p256::pkcs8::EncodePublicKey;
        let passkey = SoftwarePasskey::generate(RP, ORIGIN);
        let registration = passkey.registration();
        let key = p256::PublicKey::from_sec1_bytes(&registration.public_key).unwrap();
        let spki = key.to_public_key_der().unwrap();
        let from_spki =
            RegisteredPasskey::from_spki(registration.credential_id.clone(), spki.as_bytes())
                .unwrap();
        assert_eq!(from_spki, registration);
        assert!(RegisteredPasskey::from_spki(Bytes::new(), b"garbage").is_err());
    }

    #[test]
    fn parses_relying_party_arguments() {
        let rp: RelyingParty = "localhost=http://localhost:8787".parse().unwrap();
        assert_eq!(rp, RelyingParty::new("localhost", "http://localhost:8787"));
        assert!("localhost".parse::<RelyingParty>().is_err());
        assert!("=x".parse::<RelyingParty>().is_err());
    }

    #[test]
    fn serde_round_trip_keeps_secret_in_file_format() {
        let passkey = SoftwarePasskey::generate(RP, ORIGIN);
        let json = serde_json::to_string(&passkey).unwrap();
        let back: SoftwarePasskey = serde_json::from_str(&json).unwrap();
        assert_eq!(back.registration(), passkey.registration());
    }
}
