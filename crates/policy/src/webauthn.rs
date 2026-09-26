//! Verifying WebAuthn assertions (the result of navigator.credentials.get).
//!
//! The signed data is `authenticatorData || SHA-256(clientDataJSON)`. All of the following are checked:
//! - clientDataJSON's type is "webauthn.get", its challenge is the operation's hash, and its origin is the expected one
//! - authenticatorData's rpIdHash is the hash of the expected RP ID
//! - The UP (user present) and UV (user verified) flags are set
//! - The signature counter increased since last time (except for authenticators that always use 0)
//! - The ES256 signature is valid for the registered public key

use alloy_primitives::{B256, Bytes};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::SignedUserOperation;

const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const AUTH_DATA_MIN_LEN: usize = 37;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyAssertion {
    pub credential_id: Bytes,
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    /// ECDSA signature in DER form
    pub signature: Bytes,
}

/// The user's passkey registered with B.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredPasskey {
    pub credential_id: Bytes,
    /// P-256 public key in SEC1 form
    pub public_key: Bytes,
    pub sign_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasskeyError {
    #[error("unknown credential")]
    UnknownCredential,
    #[error("malformed assertion: {0}")]
    Malformed(String),
    #[error("client data mismatch: {0}")]
    ClientData(&'static str),
    #[error("assertion is for another relying party")]
    WrongRelyingParty,
    #[error("user presence and verification are required")]
    UserNotVerified,
    #[error("signature counter did not increase (possible cloned authenticator)")]
    CounterNotIncreased,
    #[error("invalid signature")]
    BadSignature,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

/// An accepted RP (a pair of RP ID and the origin of that RP's page).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelyingParty {
    pub rp_id: String,
    pub origin: String,
}

impl RelyingParty {
    pub fn new(rp_id: impl Into<String>, origin: impl Into<String>) -> Self {
        Self {
            rp_id: rp_id.into(),
            origin: origin.into(),
        }
    }
}

impl std::fmt::Display for RelyingParty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}={}", self.rp_id, self.origin)
    }
}

impl std::str::FromStr for RelyingParty {
    type Err = String;

    /// In the form `<rp_id>=<origin>`
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (rp_id, origin) = s
            .split_once('=')
            .ok_or_else(|| format!("expected <rp_id>=<origin>, got {s:?}"))?;
        if rp_id.is_empty() || origin.is_empty() {
            return Err(format!("expected <rp_id>=<origin>, got {s:?}"));
        }
        Ok(Self::new(rp_id, origin))
    }
}

/// Accepts several RPs. The assertion is checked against the RP ID of the RP matching its origin.
pub struct PasskeyVerifier {
    pub allowed: Vec<RelyingParty>,
}

impl PasskeyVerifier {
    /// Verify an operation's signature and, on success, return the new signature counter (the caller stores it).
    pub fn verify(
        &self,
        key: &RegisteredPasskey,
        signed: &SignedUserOperation,
    ) -> Result<u32, PasskeyError> {
        let a = &signed.assertion;
        if a.credential_id != key.credential_id {
            return Err(PasskeyError::UnknownCredential);
        }

        let client: ClientData = serde_json::from_slice(&a.client_data_json)
            .map_err(|e| PasskeyError::Malformed(format!("client data: {e}")))?;
        if client.kind != "webauthn.get" {
            return Err(PasskeyError::ClientData("type"));
        }
        if client.challenge != encode_challenge(&signed.operation.challenge()) {
            return Err(PasskeyError::ClientData("challenge"));
        }
        let rp = self
            .allowed
            .iter()
            .find(|rp| rp.origin == client.origin)
            .ok_or(PasskeyError::ClientData("origin"))?;

        let auth = &a.authenticator_data;
        if auth.len() < AUTH_DATA_MIN_LEN {
            return Err(PasskeyError::Malformed(
                "authenticator data too short".into(),
            ));
        }
        if auth[..32] != Sha256::digest(rp.rp_id.as_bytes())[..] {
            return Err(PasskeyError::WrongRelyingParty);
        }
        let flags = auth[32];
        if flags & FLAG_USER_PRESENT == 0 || flags & FLAG_USER_VERIFIED == 0 {
            return Err(PasskeyError::UserNotVerified);
        }
        let sign_count = u32::from_be_bytes(auth[33..37].try_into().expect("4 bytes"));
        if (sign_count != 0 || key.sign_count != 0) && sign_count <= key.sign_count {
            return Err(PasskeyError::CounterNotIncreased);
        }

        let public_key = VerifyingKey::from_sec1_bytes(&key.public_key)
            .map_err(|e| PasskeyError::Malformed(format!("public key: {e}")))?;
        let signature = Signature::from_der(&a.signature)
            .map_err(|e| PasskeyError::Malformed(format!("signature: {e}")))?;
        let mut message = auth.to_vec();
        message.extend_from_slice(&Sha256::digest(&a.client_data_json));
        public_key
            .verify(&message, &signature)
            .map_err(|_| PasskeyError::BadSignature)?;
        Ok(sign_count)
    }
}

impl RegisteredPasskey {
    /// Build from the browser's `AuthenticatorAttestationResponse.getPublicKey()` (SPKI DER).
    pub fn from_spki(credential_id: Bytes, spki_der: &[u8]) -> Result<Self, PasskeyError> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::pkcs8::DecodePublicKey;
        let key = p256::PublicKey::from_public_key_der(spki_der)
            .map_err(|e| PasskeyError::Malformed(format!("public key: {e}")))?;
        Ok(Self {
            credential_id,
            public_key: Bytes::copy_from_slice(key.to_encoded_point(false).as_bytes()),
            sign_count: 0,
        })
    }
}

/// For tests and software passkeys: the challenge in base64url.
pub fn encode_challenge(challenge: &B256) -> String {
    URL_SAFE_NO_PAD.encode(challenge)
}
