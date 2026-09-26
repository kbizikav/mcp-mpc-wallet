//! Verifying Nitro Enclave attestation documents (A's side).
//!
//! Uses attestation-doc-validation and checks all of the following:
//! - The COSE signature is valid, made with a certificate that chains up to the AWS Nitro root certificate
//! - PCR0 (and PCR1, PCR2 if given) are the values of the expected image
//! - The nonce is the one we sent (prevents reuse)
//! - user_data is the expected value (the hash of the TLS certificate)

use attestation_doc_validation::attestation_doc::PCRProvider;
use attestation_doc_validation::{
    validate_and_parse_attestation_doc, validate_expected_nonce, validate_expected_pcrs,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::TeeError;

/// Expected measurements (hex, lowercase).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedPcrs {
    pub pcr0: String,
    pub pcr1: Option<String>,
    pub pcr2: Option<String>,
}

impl ExpectedPcrs {
    pub fn pcr0(hex_value: &str) -> Result<Self, TeeError> {
        let normalized = hex_value
            .trim()
            .trim_start_matches("0x")
            .to_ascii_lowercase();
        let bytes = hex::decode(&normalized)
            .map_err(|e| TeeError::Attestation(format!("invalid PCR0: {e}")))?;
        if bytes.len() != 48 {
            return Err(TeeError::Attestation(
                "PCR0 must be 48 bytes (SHA-384)".into(),
            ));
        }
        Ok(Self {
            pcr0: normalized,
            pcr1: None,
            pcr2: None,
        })
    }
}

impl PCRProvider for ExpectedPcrs {
    fn pcr_0(&self) -> Option<&str> {
        Some(&self.pcr0)
    }
    fn pcr_1(&self) -> Option<&str> {
        self.pcr1.as_deref()
    }
    fn pcr_2(&self) -> Option<&str> {
        self.pcr2.as_deref()
    }
    fn pcr_8(&self) -> Option<&str> {
        None
    }
}

pub fn verify_nitro_attestation(
    document: &[u8],
    expected: &ExpectedPcrs,
    nonce: &[u8],
    user_data: &[u8],
) -> Result<(), TeeError> {
    let err = |e: &dyn std::fmt::Display| TeeError::Attestation(e.to_string());
    let doc = validate_and_parse_attestation_doc(document).map_err(|e| err(&e))?;
    validate_expected_pcrs(&doc, expected).map_err(|e| err(&e))?;
    validate_expected_nonce(&doc, &STANDARD.encode(nonce)).map_err(|e| err(&e))?;
    match doc.user_data.as_deref() {
        Some(data) if data == user_data => Ok(()),
        _ => Err(TeeError::Attestation(
            "attestation is not bound to this TLS session".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage_documents() {
        let expected = ExpectedPcrs::pcr0(&"00".repeat(48)).unwrap();
        assert!(verify_nitro_attestation(b"not cbor", &expected, b"n", b"u").is_err());
    }

    #[test]
    fn validates_pcr_format() {
        assert!(ExpectedPcrs::pcr0("abcd").is_err());
        assert!(ExpectedPcrs::pcr0("zz").is_err());
        let ok = ExpectedPcrs::pcr0(&format!("0x{}", "AB".repeat(48))).unwrap();
        assert_eq!(ok.pcr0, "ab".repeat(48));
    }
}
