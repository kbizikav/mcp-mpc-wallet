//! Nitro Secure Module(`/dev/nsm`)で attestation document を発行する。Enclave の中でだけ動く。

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;

use crate::{AttestationDocument, Attestor, TeeError};

pub const NITRO_FORMAT: &str = "aws-nitro";

pub struct NsmAttestor;

impl Attestor for NsmAttestor {
    fn attest(&self, user_data: &[u8], nonce: &[u8]) -> Result<AttestationDocument, TeeError> {
        let fd = nsm_init();
        if fd < 0 {
            return Err(TeeError::Attestation("cannot open /dev/nsm".into()));
        }
        let response = nsm_process_request(
            fd,
            Request::Attestation {
                user_data: Some(ByteBuf::from(user_data.to_vec())),
                nonce: Some(ByteBuf::from(nonce.to_vec())),
                public_key: None,
            },
        );
        nsm_exit(fd);
        match response {
            Response::Attestation { document } => Ok(AttestationDocument {
                format: NITRO_FORMAT.into(),
                bytes: document,
            }),
            other => Err(TeeError::Attestation(format!(
                "unexpected NSM response: {other:?}"
            ))),
        }
    }
}
